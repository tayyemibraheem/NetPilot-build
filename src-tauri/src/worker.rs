//! Two helper processes. Guardian owns an independent recovery handle before engine starts.
//! Each helper stops on parent-pipe EOF or an expired heartbeat; the engine also has a lease.
use crate::model::{Config, Status, Update};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
pub fn emit(status: &Status) {
    if let Ok(text) = serde_json::to_string(status) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{text}");
        let _ = out.flush();
    }
}
pub fn message(phase: &str, message: impl Into<String>) -> Status {
    Status {
        phase: phase.into(),
        message: message.into(),
        counters: vec![],
    }
}
fn read_config() -> Result<(Config, BufReader<std::io::Stdin>), String> {
    let mut input = BufReader::new(std::io::stdin());
    let mut line = String::new();
    input.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.len() > 32768 {
        return Err("Session configuration too large".into());
    }
    let c: Config = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    c.validate()?;
    Ok((c, input))
}
struct Heart {
    stop: Arc<AtomicBool>,
    last: Arc<Mutex<Instant>>,
    updates: std::sync::mpsc::Receiver<Update>,
}
impl Heart {
    fn new(mut input: BufReader<std::io::Stdin>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let last = Arc::new(Mutex::new(Instant::now()));
        let (tx, updates) = std::sync::mpsc::channel();
        let s = stop.clone();
        let l = last.clone();
        std::thread::spawn(move || {
            loop {
                let mut text = String::new();
                match input.read_line(&mut text) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if let Some(json) = text.trim().strip_prefix("rule ") {
                            match serde_json::from_str::<Update>(json) {
                                Ok(update) => {
                                    if tx.send(update).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        } else if text.trim() != "tick" {
                            break;
                        }
                        if let Ok(mut t) = l.lock() {
                            *t = Instant::now()
                        } else {
                            break;
                        }
                    }
                }
            }
            s.store(true, Ordering::SeqCst);
        });
        Self {
            stop,
            last,
            updates,
        }
    }
    fn expired(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
            || self
                .last
                .lock()
                .map_or(true, |t| t.elapsed() > Duration::from_secs(3))
    }
}
pub fn spawn(mode: &str, c: &Config) -> Result<(Child, ChildStdin), String> {
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let mut input = child.stdin.take().ok_or("Child stdin unavailable")?;
    let encoded = serde_json::to_string(c).map_err(|e| e.to_string())?;
    if writeln!(input, "{encoded}")
        .and_then(|_| input.flush())
        .is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Unable to configure helper".into());
    }
    Ok((child, input))
}
pub fn read_messages(child: &mut Child) -> std::sync::mpsc::Receiver<Status> {
    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(output) = child.stdout.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                match line
                    .ok()
                    .and_then(|l| serde_json::from_str::<Status>(&l).ok())
                {
                    Some(s) => {
                        if tx.send(s).is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        });
    }
    rx
}
pub fn wait_exit(child: &mut Child, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Err(_) => return false,
            _ => {}
        }
        if start.elapsed() > timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
#[cfg(windows)]
fn guardian() -> Result<(), String> {
    let (c, input) = read_config()?;
    crate::pcap::require_admin()?;
    let _session_lock = crate::pcap::SessionLock::acquire()?;
    crate::platform::validate_current(&c)?;
    // Open the guardian's independent recovery path before the engine may advertise anything.
    let recovery = crate::pcap::Capture::open(&c, false)?;
    let (mut child, mut pipe) = spawn("--netpilot-engine", &c)?;
    let messages = read_messages(&mut child);
    let heart = Heart::new(input);
    let mut failure = None;
    loop {
        if heart.expired() {
            break;
        }
        for update in heart.updates.try_iter() {
            if let Err(e) = update.validate(&c) {
                failure = Some(e);
                break;
            }
            let json = match serde_json::to_string(&update) {
                Ok(s) => s,
                Err(e) => {
                    failure = Some(e.to_string());
                    break;
                }
            };
            if writeln!(pipe, "rule {json}")
                .and_then(|_| pipe.flush())
                .is_err()
            {
                failure = Some("Engine update pipe closed".into());
                break;
            }
        }
        if failure.is_some() {
            break;
        }
        if writeln!(pipe, "tick").and_then(|_| pipe.flush()).is_err() {
            failure = Some("Engine heartbeat pipe closed".to_string());
            break;
        }
        match messages.recv_timeout(Duration::from_millis(250)) {
            Ok(s) => {
                let terminal = s.phase == "error" || s.phase == "stopped";
                emit(&s);
                if terminal {
                    if s.phase == "error" {
                        failure = Some(s.message)
                    }
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                failure = Some("Engine exited unexpectedly".into());
                break;
            }
            Err(_) => {}
        }
        if let Ok(Some(exit)) = child.try_wait() {
            if !exit.success() {
                failure = Some(format!("Engine exited: {exit}"))
            }
            break;
        }
    }
    emit(&message(
        "restoring",
        "Stopping forwarding and restoring original ARP mappings…",
    ));
    drop(pipe);
    if !wait_exit(&mut child, Duration::from_secs(2)) {
        let _ = child.kill();
        let _ = child.wait();
        failure =
            Some("Engine needed forced termination; recovery was attempted by guardian".into());
    }
    match recovery.restore(&c){Ok(())=>emit(&message(if failure.is_some(){"error"}else{"stopped"},failure.unwrap_or_else(||"Stopped. Original ARP mappings sent five times; endpoint acceptance must be verified.".into()))),Err(e)=>emit(&message("error",format!("Recovery send failed: {e}. Reconnect owned devices to refresh ARP.")))}
    Ok(())
}
#[cfg(windows)]
fn engine() -> Result<(), String> {
    use crate::model::{Counters, Direction, Queue};
    let (c, input) = read_config()?;
    crate::pcap::require_admin()?;
    // Guardian already validated current identities before poisoning; engine rechecks config only.
    let capture = crate::pcap::Capture::open(&c, true)?;
    let heart = Heart::new(input);
    struct Recovery<'a> {
        cap: &'a crate::pcap::Capture,
        config: &'a Config,
    }
    impl Drop for Recovery<'_> {
        fn drop(&mut self) {
            let _ = self.cap.restore(self.config);
        }
    }
    let _recovery = Recovery {
        cap: &capture,
        config: &c,
    };
    let now = Instant::now();
    let mut queues: Vec<_> = c
        .rules
        .iter()
        .map(|r| [Queue::new(r.upload, now), Queue::new(r.download, now)])
        .collect();
    let mut runtime = c.rules.clone();
    let mut stats: Vec<_> = c
        .rules
        .iter()
        .map(|r| Counters {
            ip: r.ip.to_string(),
            blocked: r.blocked,
            upload_limit: r.upload,
            download_limit: r.download,
            ..Default::default()
        })
        .collect();
    let deadline = now + Duration::from_secs(c.duration_minutes as u64 * 60);
    let mut arp_at = now;
    let mut stats_at = now;
    let mut started = false;
    loop {
        let now = Instant::now();
        if heart.expired() || now >= deadline {
            break;
        }
        for update in heart.updates.try_iter() {
            update.validate(&c)?;
            let i = runtime
                .iter()
                .position(|r| r.ip == update.ip)
                .ok_or("Device not enrolled")?;
            stats[i].dropped +=
                (queues[i][0].pending_packets() + queues[i][1].pending_packets()) as u64;
            runtime[i].upload = update.upload;
            runtime[i].download = update.download;
            runtime[i].blocked = update.blocked;
            queues[i] = [
                Queue::new(update.upload, Instant::now()),
                Queue::new(update.download, Instant::now()),
            ];
            stats[i].blocked = update.blocked;
            stats[i].upload_limit = update.upload;
            stats[i].download_limit = update.download;
        }
        // Bounded drain prevents a busy adapter starving stop, heartbeat or recovery timers.
        for _ in 0..128 {
            let Some(frame) = capture.next()? else { break };
            if crate::model::identity_changed(&c, &frame) {
                return Err(
                    "An enrolled IP/MAC identity changed. Session stopped and recovery attempted."
                        .into(),
                );
            }
            if let Some((i, d, f)) = crate::model::classify(&c, &frame) {
                if runtime[i].blocked {
                    stats[i].dropped += 1;
                    continue;
                }
                let direction = if d == Direction::Upload { 0 } else { 1 };
                if !queues[i][direction].enqueue(f, Instant::now()) {
                    stats[i].dropped += 1
                }
            }
        }
        for (i, pair) in queues.iter_mut().enumerate() {
            for (d, q) in pair.iter_mut().enumerate() {
                for _ in 0..128 {
                    let Some(frame) = q.pop(Instant::now()) else {
                        break;
                    };
                    capture.send(&frame)?;
                    if d == 0 {
                        stats[i].upload_bytes += frame.len() as u64
                    } else {
                        stats[i].download_bytes += frame.len() as u64
                    }
                }
            }
        }
        let now = Instant::now();
        if now >= arp_at {
            capture.advertise(&c, false)?;
            arp_at = now + Duration::from_secs(2);
            if !started {
                emit(&message("active","IPv4 redirection started. Runtime behavior is unverified; IPv6 is not controlled."));
                started = true
            }
        }
        if now >= stats_at {
            emit(&Status{phase:"active".into(),message:"IPv4 session active. Counters include only frames this engine forwarded; zero is not proof of enforcement.".into(),counters:stats.clone()});
            stats_at = now + Duration::from_secs(1)
        }
        let next = queues
            .iter()
            .flat_map(|q| q.iter())
            .filter_map(|q| q.due())
            .chain([arp_at, stats_at, deadline])
            .min()
            .unwrap_or(now + Duration::from_millis(100));
        let wait = next
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(100) as u32;
        capture.wait(wait)?;
    }
    // Drop recovery before notifying guardian; guardian independently repeats recovery.
    drop(_recovery);
    emit(&message(
        "stopped",
        "Engine stopped; original mappings sent. Guardian will repeat recovery.",
    ));
    Ok(())
}
pub fn helper_mode() -> bool {
    let Some(mode) = std::env::args().nth(1) else {
        return false;
    };
    if mode != "--netpilot-guardian" && mode != "--netpilot-engine" {
        return false;
    }
    #[cfg(windows)]
    let result = if mode == "--netpilot-guardian" {
        guardian()
    } else {
        engine()
    };
    #[cfg(not(windows))]
    let result: Result<(), String> = Err("Networking helpers run only on Windows".into());
    if let Err(e) = result {
        emit(&message("error", e))
    }
    true
}
// Keep helper plumbing out of non-Windows builds while keeping packet tests portable.
