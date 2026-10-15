#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod proxy;
use serde::Serialize;
use std::{process::Command, sync::Mutex};
#[derive(Serialize)]
struct Neighbor {
    ip: String,
    mac: String,
}
#[tauri::command]
async fn discover() -> Result<Vec<Neighbor>, String> {
    tauri::async_runtime::spawn_blocking(|| {
  #[cfg(target_os="windows")]
  let output = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", "Get-NetNeighbor -AddressFamily IPv4 | Where-Object {$_.State -ne 'Unreachable' -and $_.State -ne 'Incomplete'} | ForEach-Object { Write-Output ($_.IPAddress + ' ' + $_.LinkLayerAddress) }"]).output();
  #[cfg(not(target_os="windows"))]
  let output = Command::new("/usr/sbin/arp").arg("-an").output();
  let o = output.map_err(|e| e.to_string())?;
  if !o.status.success() { return Err(String::from_utf8_lossy(&o.stderr).to_string()); }
  Ok(parse_neighbors(&String::from_utf8_lossy(&o.stdout)))
 }).await.map_err(|e| e.to_string())?
}
fn parse_neighbors(s: &str) -> Vec<Neighbor> {
    let mut rows = vec![];
    for line in s.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if let Some((i, ip)) = words.iter().enumerate().find_map(|(i, w)| {
            w.trim_matches(['(', ')'])
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(|ip| (i, ip))
        }) {
            if !ip.is_private() {
                continue;
            }
            let mac = words
                .iter()
                .skip(i + 1)
                .find(|w| w.contains(':') || w.contains('-'))
                .unwrap_or(&"unknown")
                .to_string();
            if mac == "(incomplete)" || mac == "ff:ff:ff:ff:ff:ff" || mac == "FF-FF-FF-FF-FF-FF" {
                continue;
            }
            if !rows.iter().any(|n: &Neighbor| n.ip == ip.to_string()) {
                rows.push(Neighbor {
                    ip: ip.to_string(),
                    mac,
                });
            }
        }
    }
    rows
}
#[tauri::command]
async fn start(
    bind: String,
    rules: Vec<proxy::Rule>,
    state: tauri::State<'_, proxy::Service>,
) -> Result<String, String> {
    state.start(bind, rules).await
}
#[tauri::command]
fn stop(state: tauri::State<'_, proxy::Service>) {
    state.stop();
}
#[tauri::command]
fn status(state: tauri::State<'_, proxy::Service>) -> proxy::Status {
    state.status()
}
fn main() {
    tauri::Builder::default()
        .manage(proxy::Service(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![discover, start, stop, status])
        .run(tauri::generate_context!())
        .expect("NetPilot failed to launch");
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_both_platforms() {
        assert_eq!(
            parse_neighbors("? (192.168.1.2) at aa:bb:cc:dd:ee:ff on en0")[0].ip,
            "192.168.1.2"
        );
        assert_eq!(
            parse_neighbors("10.0.0.2 AA-BB-CC-DD-EE-FF")[0].mac,
            "AA-BB-CC-DD-EE-FF"
        );
        assert!(parse_neighbors("224.0.0.1 FF-FF-FF-FF-FF-FF").is_empty());
    }
}
