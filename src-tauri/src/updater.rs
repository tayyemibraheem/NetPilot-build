//! Native-only updater: the frontend cannot bypass network shutdown via plugin commands.
use serde::Serialize;
use std::time::Duration;
use tauri::{Emitter, Manager};
use tauri_plugin_updater::UpdaterExt;
#[derive(Serialize)]
pub struct Available {
    pub version: String,
    pub notes: Option<String>,
}
pub async fn check(app: &tauri::AppHandle) -> Result<Option<Available>, String> {
    let updater = app
        .updater_builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    Ok(updater
        .check()
        .await
        .map_err(|e| format!("Update check failed: {e}"))?
        .map(|u| Available {
            version: u.version,
            notes: u.body,
        }))
}
struct InstallGuard(tauri::AppHandle);
impl Drop for InstallGuard {
    fn drop(&mut self) {
        self.0.state::<crate::service::Service>().release_update();
    }
}
#[derive(Clone, Serialize)]
struct Progress {
    stage: &'static str,
    downloaded: u64,
    total: Option<u64>,
}
pub async fn install(app: tauri::AppHandle, expected_version: String) -> Result<(), String> {
    let prepare = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        prepare.state::<crate::service::Service>().prepare_update()
    })
    .await
    .map_err(|e| e.to_string())??;
    let _guard = InstallGuard(app.clone());
    let _ = app.emit(
        "netpilot:update",
        Progress {
            stage: "network_stopped",
            downloaded: 0,
            total: None,
        },
    );
    let updater = app
        .updater_builder()
        .timeout(Duration::from_secs(120))
        .restart_after_install(true)
        .build()
        .map_err(|e| e.to_string())?;
    let update = updater
        .check()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("No newer update is available")?;
    if update.version != expected_version {
        return Err("The available version changed. Check again before installing.".into());
    }
    let mut downloaded = 0u64;
    let progress = app.clone();
    let bytes = update
        .download(
            move |length, total| {
                downloaded += length as u64;
                let _ = progress.emit(
                    "netpilot:update",
                    Progress {
                        stage: "downloading",
                        downloaded,
                        total,
                    },
                );
            },
            || {},
        )
        .await
        .map_err(|e| format!("Signed update download/verification failed: {e}"))?;
    // download verifies the signature and signed app version; installation verifies again.
    let _ = app.emit(
        "netpilot:update",
        Progress {
            stage: "installing_restart",
            downloaded: bytes.len() as u64,
            total: Some(bytes.len() as u64),
        },
    );
    if app.state::<crate::service::Service>().busy() {
        return Err(
            "[NP_UPDATE_ACTIVE] Installation refused: a network session is still active.".into(),
        );
    }
    update
        .install(bytes)
        .map_err(|e| format!("Update installation failed: {e}"))?;
    Ok(()) // Windows exits and its installer restarts the app; no active network state remains.
}
