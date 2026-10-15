use crate::{
    diagnostics::{self, Events},
    model::{Config, Status, Update},
    worker,
};
use std::{
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
struct Control {
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
    updates: std::sync::mpsc::Sender<Update>,
    config: Config,
}
#[derive(Default)]
pub struct Service {
    control: Mutex<Option<Control>>,
    status: Arc<Mutex<Status>>,
    events: Events,
    updating: AtomicBool,
}
impl Service {
    pub fn status(&self) -> Status {
        self.status
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| worker::message("error", "[NP_STATUS] Session status unavailable"))
    }
    pub fn report(&self) -> String {
        #[derive(serde::Serialize)]
        struct Report {
            version: &'static str,
            status: Status,
            events: Vec<diagnostics::Event>,
        }
        serde_json::to_string_pretty(&Report {
            version: env!("CARGO_PKG_VERSION"),
            status: self.status(),
            events: self
                .events
                .lock()
                .map(|v| v.iter().cloned().collect())
                .unwrap_or_default(),
        })
        .unwrap_or_else(|_| "Diagnostic report unavailable".into())
    }
    pub fn start(&self, c: Config) -> Result<(), String> {
        if !cfg!(windows) {
            return Err(
                "The redirection backend is Windows-only. No Mac networking was started.".into(),
            );
        }
        if self.updating.load(Ordering::SeqCst) {
            return Err("An update is being installed; new network sessions are disabled.".into());
        }
        c.validate()?;
        let mut control = self
            .control
            .lock()
            .map_err(|_| "Session lock unavailable")?;
        if self.updating.load(Ordering::SeqCst) {
            return Err("Update in progress".into());
        }
        if control.as_ref().is_some_and(|c| !c.join.is_finished()) {
            return Err("Stop the existing session first".into());
        }
        if let Some(old) = control.take() {
            let _ = old.join.join();
        }
        let beginning = Instant::now();
        *self.status.lock().map_err(|_| "Status unavailable")? = Status::default();
        self.events
            .lock()
            .map_err(|_| "Diagnostics unavailable")?
            .clear();
        diagnostics::record(
            &self.status,
            &self.events,
            worker::message(
                "starting",
                "Checking Windows privileges, adapter, Npcap and endpoint identities…",
            ),
            Duration::ZERO,
        );
        let (mut child, mut input) = match worker::spawn("--netpilot-guardian", &c) {
            Ok(s) => s,
            Err(e) => {
                diagnostics::record(
                    &self.status,
                    &self.events,
                    worker::message("error", e.clone()),
                    beginning.elapsed(),
                );
                return Err(e);
            }
        };
        let messages = worker::read_messages(&mut child);
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let status = self.status.clone();
        let events = self.events.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Update>();
        let join = std::thread::spawn(move || {
            let mut last = Instant::now();
            let mut terminal = false;
            let mut last_report = Instant::now();
            let mut had_report = false;
            let mut monitor_failure = None;
            loop {
                if s.load(Ordering::SeqCst) {
                    break;
                }
                if last_report.elapsed() > Duration::from_secs(if had_report { 8 } else { 45 }) {
                    monitor_failure =
                        Some("[NP_GUARDIAN_WATCHDOG] Guardian stopped reporting progress.".into());
                    break;
                }
                for update in rx.try_iter() {
                    if let Ok(json) = serde_json::to_string(&update) {
                        if writeln!(input, "rule {json}")
                            .and_then(|_| input.flush())
                            .is_err()
                        {
                            monitor_failure = Some(
                                "[NP_RULE_PIPE] Could not send rule update to guardian.".into(),
                            );
                            s.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                if last.elapsed() >= Duration::from_millis(800) {
                    if writeln!(input, "tick").and_then(|_| input.flush()).is_err() {
                        monitor_failure =
                            Some("[NP_GUARDIAN_PIPE] Guardian input pipe closed.".into());
                        break;
                    }
                    last = Instant::now()
                }
                match messages.recv_timeout(Duration::from_millis(100)) {
                    Ok(v) => {
                        last_report = Instant::now();
                        had_report = true;
                        terminal = v.phase == "error" || v.phase == "stopped";
                        diagnostics::record(&status, &events, v, beginning.elapsed());
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(_) => {}
                }
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
            }
            let terminal_before_fault = terminal;
            if let Some(error) = &monitor_failure {
                diagnostics::record(
                    &status,
                    &events,
                    worker::message(
                        "restoring",
                        format!("{error} Requesting helper shutdown and recovery."),
                    ),
                    beginning.elapsed(),
                );
            }
            if !terminal {
                diagnostics::record(
                    &status,
                    &events,
                    worker::message(
                        "restoring",
                        "Waiting for helpers to stop and restore original ARP mappings…",
                    ),
                    beginning.elapsed(),
                );
            }
            drop(input);
            let exited = worker::wait_exit(&mut child, Duration::from_secs(6));
            if !exited {
                let _ = child.kill();
                let _ = child.wait();
            }
            while let Ok(v) = messages.recv_timeout(Duration::from_millis(200)) {
                terminal = v.phase == "error" || v.phase == "stopped";
                diagnostics::record(&status, &events, v, beginning.elapsed());
            }
            let current = status.lock().map(|s| s.clone()).unwrap_or_default();
            if let Some(fault) =
                diagnostics::monitor_error(monitor_failure, terminal_before_fault, &current)
            {
                diagnostics::record(&status, &events, fault, beginning.elapsed());
            }
            if !exited || !terminal {
                diagnostics::record(&status,&events,worker::message("error","[NP_RECOVERY_UNCONFIRMED] Helper recovery was not confirmed. Reconnect selected owned devices and verify connectivity before retrying."),beginning.elapsed());
            }
        });
        *control = Some(Control {
            stop,
            join,
            updates: tx,
            config: c,
        });
        Ok(())
    }
    pub fn update(&self, update: Update) -> Result<(), String> {
        if self.updating.load(Ordering::SeqCst) || self.status().phase != "active" {
            return Err("Wait for an active network session; no update may be installing.".into());
        }
        let guard = self
            .control
            .lock()
            .map_err(|_| "Session lock unavailable")?;
        let c = guard.as_ref().ok_or("No running session")?;
        update.validate(&c.config)?;
        c.updates
            .send(update)
            .map_err(|_| "Session has ended".into())
    }
    pub fn stop(&self) {
        if let Ok(mut control) = self.control.lock() {
            if let Some(c) = control.take() {
                c.stop.store(true, Ordering::SeqCst);
                let _ = c.join.join();
            }
        }
    }
    pub fn busy(&self) -> bool {
        self.control
            .lock()
            .map_or(true, |c| c.as_ref().is_some_and(|x| !x.join.is_finished()))
    }
    pub fn prepare_update(&self) -> Result<(), String> {
        if self.updating.swap(true, Ordering::SeqCst) {
            return Err("Another update is already in progress.".into());
        }
        let requires_recovery = self.busy() || !self.status().counters.is_empty();
        self.stop();
        let result = diagnostics::update_ready(self.busy(), requires_recovery, &self.status());
        if result.is_err() {
            self.release_update()
        }
        result
    }
    pub fn release_update(&self) {
        self.updating.store(false, Ordering::SeqCst);
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop();
    }
}
