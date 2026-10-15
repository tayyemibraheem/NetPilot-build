#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod diagnostics;
mod model;
#[cfg(windows)]
mod pcap;
mod platform;
mod service;
#[cfg(windows)]
mod updater;
mod worker;
use tauri::Manager;
#[tauri::command]
fn driver_status() -> platform::DriverStatus {
    platform::driver_status()
}
#[tauri::command]
fn open_npcap_download() -> Result<(), String> {
    #[cfg(windows)]
    {
        pcap::open_official_download()
    }
    #[cfg(not(windows))]
    {
        Err("Windows setup required".into())
    }
}
#[tauri::command]
async fn device_names(index: u32, ips: Vec<std::net::Ipv4Addr>) -> Result<platform::Names, String> {
    tauri::async_runtime::spawn_blocking(move || platform::names(index, ips))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
fn diagnostic_report(state: tauri::State<'_, service::Service>) -> String {
    state.report()
}
#[derive(serde::Serialize)]
struct UpdateInfo {
    version: String,
    notes: Option<String>,
}
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<Option<UpdateInfo>, String> {
    #[cfg(windows)]
    {
        Ok(updater::check(&app).await?.map(|u| UpdateInfo {
            version: u.version,
            notes: u.notes,
        }))
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Err("Updates are supported in the Windows application".into())
    }
}
#[tauri::command]
async fn install_update(app: tauri::AppHandle, version: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        updater::install(app, version).await
    }
    #[cfg(not(windows))]
    {
        let _ = (app, version);
        Err("Windows update installation required".into())
    }
}
#[tauri::command]
async fn adapters() -> Result<Vec<model::Adapter>, String> {
    tauri::async_runtime::spawn_blocking(platform::adapters)
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn discover(index: u32) -> Result<Vec<platform::Neighbor>, String> {
    tauri::async_runtime::spawn_blocking(move || platform::neighbors(index))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn scan(index: u32, owned_network_confirmed: bool) -> Result<platform::Scan, String> {
    tauri::async_runtime::spawn_blocking(move || {
        platform::probe_subnet(index, owned_network_confirmed)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn resolve(index: u32, ip: std::net::Ipv4Addr) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let adapter = platform::adapters()?
            .into_iter()
            .find(|a| a.index == index)
            .ok_or("Adapter unavailable")?;
        if !model::subnet(adapter.ip, ip, adapter.prefix) || ip == adapter.ip {
            return Err("Resolve an on-link device or gateway IPv4".into());
        }
        platform::resolve(adapter.ip, ip)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn start(config: model::Config, state: tauri::State<'_, service::Service>) -> Result<(), String> {
    state.start(config)
}
#[tauri::command]
fn update_rule(
    update: model::Update,
    state: tauri::State<'_, service::Service>,
) -> Result<(), String> {
    state.update(update)
}
#[tauri::command]
async fn stop(app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || app.state::<service::Service>().stop())
        .await
        .map_err(|e| e.to_string())
}
#[derive(serde::Serialize)]
struct Snapshot {
    status: model::Status,
    busy: bool,
}
#[tauri::command]
fn status(state: tauri::State<'_, service::Service>) -> Snapshot {
    Snapshot {
        status: state.status(),
        busy: state.busy(),
    }
}
fn main() {
    if worker::helper_mode() {
        return;
    }
    let builder = tauri::Builder::default().manage(service::Service::default());
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    builder
        .invoke_handler(tauri::generate_handler![
            driver_status,
            open_npcap_download,
            device_names,
            diagnostic_report,
            check_update,
            install_update,
            adapters,
            discover,
            scan,
            resolve,
            start,
            update_rule,
            stop,
            status
        ])
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                window.state::<service::Service>().stop();
            }
        })
        .run(tauri::generate_context!())
        .expect("NetPilot failed to launch");
}
