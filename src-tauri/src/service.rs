use crate::{
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
}
impl Service {
    pub fn status(&self) -> Status {
        self.status
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| worker::message("error", "Session status unavailable"))
    }
    pub fn start(&self, c: Config) -> Result<(), String> {
        if !cfg!(windows) {
            return Err(
                "The redirection backend is Windows-only. No Mac networking was started.".into(),
            );
        }
        c.validate()?;
        let mut control = self
            .control
            .lock()
            .map_err(|_| "Session lock unavailable")?;
        if control.as_ref().is_some_and(|c| !c.join.is_finished()) {
            return Err("Stop the existing session first".into());
        }
        if let Some(old) = control.take() {
            let _ = old.join.join();
        }
        *self.status.lock().map_err(|_| "Status lock unavailable")? = worker::message(
            "starting",
            "Checking Windows privileges, adapter, Npcap and endpoint identities…",
        );
        let (mut child, mut input) = match worker::spawn("--netpilot-guardian", &c) {
            Ok(s) => s,
            Err(e) => {
                *self.status.lock().map_err(|_| "Status unavailable")? =
                    worker::message("error", e.clone());
                return Err(e);
            }
        };
        let messages = worker::read_messages(&mut child);
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let status = self.status.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Update>();
        let join = std::thread::spawn(move || {
            let mut last = Instant::now();
            let mut terminal = false;
            loop {
                if s.load(Ordering::SeqCst) {
                    break;
                }
                for update in rx.try_iter() {
                    if let Ok(json) = serde_json::to_string(&update) {
                        if writeln!(input, "rule {json}")
                            .and_then(|_| input.flush())
                            .is_err()
                        {
                            s.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                if last.elapsed() >= Duration::from_millis(800) {
                    if writeln!(input, "tick").and_then(|_| input.flush()).is_err() {
                        break;
                    }
                    last = Instant::now()
                }
                match messages.recv_timeout(Duration::from_millis(100)) {
                    Ok(v) => {
                        terminal = v.phase == "error" || v.phase == "stopped";
                        if let Ok(mut x) = status.lock() {
                            *x = v
                        } /* guardian may still be performing its final recovery */
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(_) => {}
                }
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
            }
            if !terminal {
                if let Ok(mut x) = status.lock() {
                    *x = worker::message(
                        "restoring",
                        "Waiting for helpers to stop and restore ARP mappings…",
                    )
                }
            }
            drop(input);
            let exited = worker::wait_exit(&mut child, Duration::from_secs(6));
            if !exited {
                let _ = child.kill();
                let _ = child.wait();
            }
            // Reader thread can lag child exit briefly; wait for its final recovery report.
            while let Ok(v) = messages.recv_timeout(Duration::from_millis(200)) {
                terminal = v.phase == "error" || v.phase == "stopped";
                if let Ok(mut x) = status.lock() {
                    *x = v
                }
            }
            if !exited || !terminal {
                if let Ok(mut x) = status.lock() {
                    *x=worker::message("error","Helper recovery was not confirmed. Reconnect selected devices and verify gateway ARP mappings before retrying.")
                }
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
        if self.status().phase != "active" {
            return Err("Wait for an active session".into());
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
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop();
    }
}
