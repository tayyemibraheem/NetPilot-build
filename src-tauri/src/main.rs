#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod model;
#[cfg(windows)]
mod pcap;
mod platform;
mod service;
mod worker;
use tauri::Manager;
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
    tauri::Builder::default()
        .manage(service::Service::default())
        .invoke_handler(tauri::generate_handler![
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
