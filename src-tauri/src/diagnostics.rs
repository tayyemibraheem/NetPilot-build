use crate::model::Status;
use serde::Serialize;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
#[derive(Clone, Serialize)]
pub struct Event {
    pub elapsed_ms: u64,
    pub phase: String,
    pub message: String,
}
pub type Events = Arc<Mutex<VecDeque<Event>>>;
pub fn record(status: &Arc<Mutex<Status>>, events: &Events, next: Status, elapsed: Duration) {
    if let Ok(mut log) = events.lock() {
        if !log
            .back()
            .is_some_and(|e| e.phase == next.phase && e.message == next.message)
        {
            if log.len() >= 64 {
                log.pop_front();
            }
            log.push_back(Event {
                elapsed_ms: elapsed.as_millis().min(u64::MAX as u128) as u64,
                phase: next.phase.clone(),
                message: next.message.clone(),
            });
        }
    }
    if let Ok(mut current) = status.lock() {
        current.absorb(next)
    }
}
pub fn update_ready(busy: bool, requires_recovery: bool, status: &Status) -> Result<(), String> {
    if busy {
        return Err("[NP_UPDATE_ACTIVE] Network helpers have not finished stopping.".into());
    }
    if status
        .recovery
        .as_ref()
        .is_some_and(|r| r.unsubmitted_mappings > 0)
        || (requires_recovery && status.recovery.is_none())
        || status
            .primary_error
            .as_ref()
            .is_some_and(|e| e.contains("NP_RECOVERY_UNCONFIRMED"))
    {
        return Err("[NP_UPDATE_RECOVERY] Update was not installed because ARP recovery could not be confirmed. Reconnect the selected owned devices, then restart NetPilot and retry the update.".into());
    }
    Ok(())
}
pub fn monitor_error(
    fault: Option<String>,
    terminal_before_fault: bool,
    status: &Status,
) -> Option<Status> {
    if terminal_before_fault || status.primary_error.is_some() {
        None
    } else {
        fault.map(|e| Status::new("error", e))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn update_refuses_active_or_unconfirmed_recovery() {
        let s = Status::default();
        assert!(update_ready(true, false, &s).is_err());
        assert!(update_ready(false, true, &s).is_err());
        assert!(update_ready(false, false, &s).is_ok());
        let mut s = s;
        s.recovery = Some(crate::model::RecoveryReport {
            mappings: 2,
            unsubmitted_mappings: 1,
            ..Default::default()
        });
        assert!(update_ready(false, true, &s).is_err());
        s.recovery.as_mut().unwrap().unsubmitted_mappings = 0;
        assert!(update_ready(false, true, &s).is_ok());
    }
    #[test]
    fn bounded_events_do_not_erase_first_failure() {
        let state = Arc::new(Mutex::new(Status::default()));
        let log = Arc::new(Mutex::new(VecDeque::new()));
        record(
            &state,
            &log,
            Status::new("error", "[NP_CAPTURE_READ] could not find the device"),
            Duration::ZERO,
        );
        for i in 0..100 {
            record(
                &state,
                &log,
                Status::new("restoring", format!("recovery step {i}")),
                Duration::from_secs(i),
            );
        }
        assert_eq!(log.lock().unwrap().len(), 64);
        assert!(state
            .lock()
            .unwrap()
            .primary_error
            .as_ref()
            .unwrap()
            .contains("NP_CAPTURE_READ"));
    }
    #[test]
    fn late_engine_error_beats_secondary_pipe_failure_and_clean_exit_is_not_an_error() {
        let fault = Some("guardian pipe closed".into());
        let engine = Status::new("error", "[NP_CAPTURE_READ] could not find the device");
        assert!(monitor_error(fault.clone(), false, &engine).is_none());
        assert!(monitor_error(fault.clone(), true, &Status::new("stopped", "recovered")).is_none());
        assert!(monitor_error(fault, false, &Status::new("active", "running")).is_some());
    }
}
