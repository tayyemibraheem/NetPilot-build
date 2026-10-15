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
    Status::new(phase, message)
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
    crate::platform::validate_current(&c).map_err(|e| format!("[NP_PREFLIGHT] {e}"))?;
    // Open the guardian's independent recovery path before the engine may advertise anything.
    let recovery =
        crate::pcap::Capture::open(&c, false).map_err(|e| format!("[NP_RECOVERY_OPEN] {e}"))?;
    let (mut child, mut pipe) = spawn("--netpilot-engine", &c)?;
    let messages = read_messages(&mut child);
    let heart = Heart::new(input);
    let mut failure = None;
    let mut stopped_reason = String::from("stop requested or UI connection closed");
    let mut accumulated = Status::default();
    let mut last_report = Instant::now();
    let mut engine_started = false;
    let lease = Instant::now() + Duration::from_secs(c.duration_minutes as u64 * 60 + 15);
    loop {
        if heart.expired() {
            break;
        }
        if Instant::now() >= lease
            || last_report.elapsed() > Duration::from_secs(if engine_started { 4 } else { 15 })
        {
            failure = Some("[NP_ENGINE_WATCHDOG] Engine lease or progress watchdog expired; recovery requested".into());
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
                last_report = Instant::now();
                engine_started |= s.phase == "active";
                let terminal = s.phase == "error" || s.phase == "stopped";
                accumulated.absorb(s.clone());
                emit(&accumulated);
                if terminal {
                    if let Some(reason) = s.stop_reason {
                        stopped_reason = reason
                    }
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
        if failure.is_none() {
            failure=Some("[NP_ENGINE_TERMINATED] Engine needed forced termination; recovery was attempted by guardian".into());
        }
    }
    // Process exit may precede the stdout reader thread; retain late original failures.
    while let Ok(s) = messages.recv_timeout(Duration::from_millis(200)) {
        if let Some(reason) = &s.stop_reason {
            stopped_reason = reason.clone()
        }
        if let Some(error) = &s.primary_error {
            failure = Some(error.clone())
        }
        accumulated.absorb(s);
    }
    let report = recovery.restore(&c);
    if failure.is_none() && report.unsubmitted_mappings > 0 {
        failure=Some("[NP_RECOVERY_INCOMPLETE] Could not submit all original ARP mappings. Reconnect selected devices.".into())
    }
    let mut final_status = message(
        if failure.is_some() {
            "error"
        } else {
            "stopped"
        },
        report.summary(),
    );
    final_status.primary_error = failure;
    final_status.recovery = Some(report);
    final_status.stop_reason = Some(stopped_reason);
    accumulated.absorb(final_status);
    emit(&accumulated);
    Ok(())
}
#[cfg(windows)]
fn engine() -> Result<(), String> {
    use crate::model::Relay;
    let (c, input) = read_config()?;
    crate::pcap::require_admin()?;
    // Guardian already validated current identities before poisoning; engine rechecks config only.
    let capture =
        crate::pcap::Capture::open(&c, true).map_err(|e| format!("[NP_ENGINE_OPEN] {e}"))?;
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
    let mut relay = Relay::new(&c, now);
    let deadline = now + Duration::from_secs(c.duration_minutes as u64 * 60);
    let mut arp_at = now;
    let mut stats_at = now;
    let mut started = false;
    let stop_reason;
    loop {
        let now = Instant::now();
        if heart.expired() {
            stop_reason = "guardian stop request, pipe closure or heartbeat timeout";
            break;
        }
        if now >= deadline {
            stop_reason = "session lease expired; automatic stop and recovery";
            break;
        }
        for update in heart.updates.try_iter() {
            let role = c
                .rules
                .iter()
                .position(|r| r.ip == update.ip)
                .map(|i| i + 1)
                .unwrap_or(0);
            let blocked = update.blocked;
            relay
                .update(&c, update, Instant::now())
                .map_err(|e| format!("[NP_RULE_UPDATE] {e}"))?;
            emit(&Status {
                phase: "active".into(),
                message: format!("Selected device #{role} rule applied: IPv4 blocked={blocked}."),
                counters: relay.stats.clone(),
                remaining_seconds: Some(
                    deadline.saturating_duration_since(Instant::now()).as_secs(),
                ),
                ..Default::default()
            });
        }
        // Bounded drain prevents a busy adapter starving stop, heartbeat or recovery timers.
        for _ in 0..128 {
            let Some(frame) = capture
                .next()
                .map_err(|e| format!("[NP_CAPTURE_READ] {e}"))?
            else {
                break;
            };
            if crate::model::identity_changed(&c, &frame) {
                return Err(
                    "[NP_IDENTITY_CHANGE] An enrolled IP/MAC identity changed. Session stopped and recovery attempted."
                        .into(),
                );
            }
            relay.receive(&c, &frame, Instant::now());
        }
        relay.forward_due(Instant::now(), |f| {
            capture.send(f).map_err(|e| format!("[NP_FORWARD_TX] {e}"))
        })?;
        let now = Instant::now();
        if now >= arp_at {
            capture
                .advertise(&c, false)
                .map_err(|e| format!("[NP_ARP_REDIRECT] {e}"))?;
            arp_at = now + Duration::from_secs(2);
            if !started {
                emit(&message("active","IPv4 redirection started. Runtime behavior is unverified; IPv6 is not controlled."));
                started = true
            }
        }
        if now >= stats_at {
            relay.sample_rates(now);
            emit(&Status{phase:"active".into(),message:"IPv4 session active. Observed and forwarded rates cover only matching frames reaching NetPilot.".into(),counters:relay.stats.clone(),remaining_seconds:Some(deadline.saturating_duration_since(now).as_secs()),..Default::default()});
            stats_at = now + Duration::from_secs(1)
        }
        let next = relay
            .next_due()
            .into_iter()
            .chain([arp_at, stats_at, deadline])
            .min()
            .unwrap_or(now + Duration::from_millis(100));
        // Round a positive sub-millisecond delay up to avoid a pacing busy-spin.
        let delay = next.saturating_duration_since(Instant::now());
        let wait = delay.as_micros().div_ceil(1000).min(100) as u32;
        capture
            .wait(wait)
            .map_err(|e| format!("[NP_CAPTURE_WAIT] {e}"))?;
    }
    // Drop recovery before notifying guardian; guardian independently repeats recovery.
    drop(_recovery);
    let mut ended = message(
        "stopped",
        "Engine stopped; recovery attempted. Guardian will independently repeat recovery.",
    );
    ended.stop_reason = Some(stop_reason.into());
    ended.counters = relay.stats.clone();
    emit(&ended);
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
