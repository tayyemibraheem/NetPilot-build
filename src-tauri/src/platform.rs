use crate::model::{Adapter, Config};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
pub struct Neighbor {
    pub ip: String,
    pub mac: String,
    pub index: u32,
}
#[cfg(target_os = "windows")]
fn powershell(script: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("powershell.exe")
        .creation_flags(0x08000000)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_start_matches('\u{feff}')
        .to_string())
}
#[cfg(target_os = "windows")]
pub fn adapters() -> Result<Vec<Adapter>, String> {
    let text = powershell(
        r#"$ErrorActionPreference='Stop'; $rows=@(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up' -and $_.MediaType -eq '802.3'} | ForEach-Object { $a=$_; $cfg=Get-NetIPConfiguration -InterfaceIndex $a.ifIndex; $ip=@($cfg.IPv4Address | Where-Object {$_.IPAddress -like '10.*' -or $_.IPAddress -like '192.168.*' -or $_.IPAddress -like '172.*'}) | Select-Object -First 1; $gw=@($cfg.IPv4DefaultGateway) | Select-Object -First 1; if($ip -and $gw){$f=Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4; [pscustomobject]@{index=[uint32]$a.ifIndex;name=[string]$a.Name;guid=[string]$a.InterfaceGuid;ip=[string]$ip.IPAddress;prefix=[int]$ip.PrefixLength;mac=[string]$a.MacAddress;gateway=[string]$gw.NextHop;forwarding=($f.Forwarding -eq 'Enabled')}} }); ConvertTo-Json -InputObject $rows -Compress"#,
    )?;
    serde_json::from_str(&text).map_err(|e| format!("Adapter inventory: {e}"))
}
#[cfg(not(target_os = "windows"))]
pub fn adapters() -> Result<Vec<Adapter>, String> {
    Err("Windows Ethernet adapters are required. Mac networking is disabled.".into())
}
#[cfg(target_os = "windows")]
pub fn neighbors(index: u32) -> Result<Vec<Neighbor>, String> {
    // Only a parsed integer is inserted, never arbitrary PowerShell source.
    let text=powershell(&format!("$ErrorActionPreference='Stop'; $rows=@(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex {index} | Where-Object {{$_.State -ne 'Unreachable' -and $_.State -ne 'Incomplete'}} | ForEach-Object {{[pscustomobject]@{{ip=[string]$_.IPAddress;mac=[string]$_.LinkLayerAddress;index=[uint32]$_.InterfaceIndex}}}}); ConvertTo-Json -InputObject $rows -Compress"))?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}
#[cfg(not(target_os = "windows"))]
pub fn neighbors(_index: u32) -> Result<Vec<Neighbor>, String> {
    Err("Windows is required".into())
}
#[cfg(target_os = "windows")]
pub fn resolve(source: std::net::Ipv4Addr, dest: std::net::Ipv4Addr) -> Result<String, String> {
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn SendARP(dest: u32, source: u32, buffer: *mut std::ffi::c_void, len: *mut u32) -> u32;
    }
    let mut buffer = [0u32; 2];
    let mut len = 8u32;
    let code = unsafe {
        SendARP(
            u32::from_ne_bytes(dest.octets()),
            u32::from_ne_bytes(source.octets()),
            buffer.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if code != 0 || len != 6 {
        return Err(format!("On-link ARP resolution for {dest} failed (Windows code {code}). Check extender isolation."));
    }
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 6) };
    let m: crate::model::Mac = bytes.try_into().map_err(|_| "Invalid ARP result")?;
    let text = crate::model::mac_text(m);
    crate::model::mac(&text)?;
    Ok(text)
}
#[cfg(not(target_os = "windows"))]
pub fn resolve(_source: std::net::Ipv4Addr, _dest: std::net::Ipv4Addr) -> Result<String, String> {
    Err("Windows is required".into())
}
pub fn validate_current(c: &Config) -> Result<(), String> {
    c.validate()?;
    let current = adapters()?
        .into_iter()
        .find(|a| a.index == c.adapter.index)
        .ok_or("Selected adapter is no longer available")?;
    if current != c.adapter {
        return Err(
            "Adapter, gateway or forwarding state changed. Refresh adapter inventory.".into(),
        );
    }
    let gw = resolve(current.ip, current.gateway)?;
    if crate::model::mac(&gw)? != crate::model::mac(&c.gateway_mac)? {
        return Err("Gateway MAC changed. Refresh before starting.".into());
    }
    for r in &c.rules {
        let m = resolve(current.ip, r.ip)?;
        if crate::model::mac(&m)? != crate::model::mac(&r.mac)? {
            return Err(format!(
                "Device {} MAC changed. Refresh before starting.",
                r.ip
            ));
        }
    }
    Ok(())
}
#[derive(Serialize)]
pub struct Scan {
    pub devices: Vec<Neighbor>,
    pub complete: bool,
    pub probed: usize,
    pub total: usize,
}
pub fn probe_subnet(index: u32, owned_network_confirmed: bool) -> Result<Scan, String> {
    if !cfg!(windows) {
        return Err("Discovery probes are Windows-only".into());
    }
    if !owned_network_confirmed {
        return Err("Confirm this is your home test network before probing".into());
    }
    let a = adapters()?
        .into_iter()
        .find(|a| a.index == index)
        .ok_or("Adapter unavailable")?;
    if !a.ip.is_private() || !(24..=30).contains(&a.prefix) {
        return Err("Active discovery is limited to private /24–/30 subnets. Read the cache or resolve specific owned IPs on larger networks.".into());
    }
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    let network = u32::from(a.ip) & (u32::MAX << (32 - a.prefix));
    let count = (1u32 << (32 - a.prefix)) - 2;
    let next = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(Mutex::new(vec![]));
    let completed = Arc::new(AtomicUsize::new(0));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let next = next.clone();
            let found = found.clone();
            let completed = completed.clone();
            let source = a.ip;
            scope.spawn(move || loop {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                let offset = next.fetch_add(1, Ordering::SeqCst);
                if offset >= count as usize {
                    break;
                }
                let ip = std::net::Ipv4Addr::from(network + 1 + offset as u32);
                if ip != source {
                    if let Ok(mac) = resolve(source, ip) {
                        if let Ok(mut rows) = found.lock() {
                            rows.push(Neighbor {
                                ip: ip.to_string(),
                                mac,
                                index,
                            });
                        }
                    }
                }
                completed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    let probed = completed.load(Ordering::SeqCst);
    let devices = found
        .lock()
        .map_err(|_| "Discovery state unavailable")?
        .clone();
    Ok(Scan {
        devices,
        complete: probed == count as usize,
        probed,
        total: count as usize,
    })
}
