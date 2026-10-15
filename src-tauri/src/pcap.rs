//! Windows-only Npcap bindings. No driver is bundled or silently installed.
use crate::model::Config;
use std::{
    ffi::{c_char, c_int, c_void, CStr, CString},
    ptr,
};
type Handle = *mut c_void;
type Open = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> Handle;
type Close = unsafe extern "C" fn(Handle);
type Send = unsafe extern "C" fn(Handle, *const u8, c_int) -> c_int;
type Next = unsafe extern "C" fn(Handle, *mut *const Header, *mut *const u8) -> c_int;
type Error = unsafe extern "C" fn(Handle) -> *const c_char;
#[repr(C)]
struct Header {
    seconds: i32,
    micros: i32,
    caplen: u32,
    len: u32,
}
#[repr(C)]
struct Bpf {
    len: u32,
    insns: *mut c_void,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
}
#[link(name = "shell32")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
}
pub fn require_admin() -> Result<(), String> {
    if unsafe { IsUserAnAdmin() } == 0 {
        Err("Run NetPilot as administrator. No automatic elevation is attempted.".into())
    } else {
        Ok(())
    }
}
pub struct Capture {
    handle: Handle,
    send: Send,
    next: Next,
    close: Close,
    error: Error,
    event: Handle,
    _library: libloading::os::windows::Library,
}
impl Capture {
    pub fn open(c: &Config, filter: bool) -> Result<Self, String> {
        unsafe {
            let mut path = vec![0u16; 32768];
            let n = GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) as usize;
            if n == 0 || n >= path.len() {
                return Err("Cannot locate Windows system directory".into());
            }
            path.truncate(n);
            let dll = std::path::PathBuf::from(String::from_utf16_lossy(&path))
                .join("Npcap")
                .join("wpcap.dll");
            // Absolute system path; dependencies may load only alongside this DLL or from System32.
            let library = libloading::os::windows::Library::load_with_flags(&dll, 0x100 | 0x800)
                .map_err(|e| {
                    format!(
                        "Install official Npcap first (not bundled). Could not load {}: {e}",
                        dll.display()
                    )
                })?;
            let open: Open = *library
                .get(b"pcap_open_live\0")
                .map_err(|e| e.to_string())?;
            let close: Close = *library.get(b"pcap_close\0").map_err(|e| e.to_string())?;
            let send: Send = *library
                .get(b"pcap_sendpacket\0")
                .map_err(|e| e.to_string())?;
            let next: Next = *library.get(b"pcap_next_ex\0").map_err(|e| e.to_string())?;
            let error: Error = *library.get(b"pcap_geterr\0").map_err(|e| e.to_string())?;
            let event_fn: unsafe extern "C" fn(Handle) -> Handle =
                *library.get(b"pcap_getevent\0").map_err(|e| e.to_string())?;
            let link: unsafe extern "C" fn(Handle) -> c_int =
                *library.get(b"pcap_datalink\0").map_err(|e| e.to_string())?;
            let nonblock: unsafe extern "C" fn(Handle, c_int, *mut c_char) -> c_int = *library
                .get(b"pcap_setnonblock\0")
                .map_err(|e| e.to_string())?;
            let name = CString::new(c.npf_name()).map_err(|e| e.to_string())?;
            let mut err = [0i8; 256];
            let handle = open(name.as_ptr(), 65535, 0, 1, err.as_mut_ptr());
            if handle.is_null() {
                return Err(CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned());
            }
            let mut capture = Self {
                handle,
                send,
                next,
                close,
                error,
                event: ptr::null_mut(),
                _library: library,
            };
            if link(handle) != 1 {
                return Err(
                    "Only Ethernet (DLT_EN10MB) adapters are supported. No redirection started."
                        .into(),
                );
            }
            if nonblock(handle, 1, err.as_mut_ptr()) != 0 {
                return Err(CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned());
            }
            capture.event = event_fn(handle);
            if capture.event.is_null() {
                return Err("Npcap capture event unavailable".into());
            }
            capture.set_filter(if filter {
                capture_filter(c)?
            } else {
                "ether proto 0x0000".into()
            })?;
            Ok(capture)
        }
    }
    fn set_filter(&self, expression: String) -> Result<(), String> {
        unsafe {
            let compile: unsafe extern "C" fn(
                Handle,
                *mut Bpf,
                *const c_char,
                c_int,
                u32,
            ) -> c_int = *self
                ._library
                .get(b"pcap_compile\0")
                .map_err(|e| e.to_string())?;
            let install: unsafe extern "C" fn(Handle, *mut Bpf) -> c_int = *self
                ._library
                .get(b"pcap_setfilter\0")
                .map_err(|e| e.to_string())?;
            let free: unsafe extern "C" fn(*mut Bpf) = *self
                ._library
                .get(b"pcap_freecode\0")
                .map_err(|e| e.to_string())?;
            let text = CString::new(expression).map_err(|e| e.to_string())?;
            let mut bpf = Bpf {
                len: 0,
                insns: ptr::null_mut(),
            };
            if compile(self.handle, &mut bpf, text.as_ptr(), 1, u32::MAX) != 0 {
                return Err(self.last_error());
            }
            let result = install(self.handle, &mut bpf);
            free(&mut bpf);
            if result != 0 {
                return Err(self.last_error());
            }
            Ok(())
        }
    }
    fn last_error(&self) -> String {
        unsafe {
            let p = (self.error)(self.handle);
            if p.is_null() {
                "Npcap error".into()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        }
    }
    pub fn send(&self, packet: &[u8]) -> Result<(), String> {
        if unsafe { (self.send)(self.handle, packet.as_ptr(), packet.len() as c_int) } != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }
    pub fn next(&self) -> Result<Option<Vec<u8>>, String> {
        unsafe {
            let mut header = ptr::null();
            let mut data = ptr::null();
            match (self.next)(self.handle, &mut header, &mut data) {
                0 => Ok(None),
                1 => {
                    if header.is_null() || data.is_null() {
                        return Err("Npcap returned null packet".into());
                    }
                    let h = &*header;
                    if h.caplen != h.len || h.caplen > 65535 {
                        return Ok(None);
                    }
                    Ok(Some(
                        std::slice::from_raw_parts(data, h.caplen as usize).to_vec(),
                    ))
                }
                _ => Err(self.last_error()),
            }
        }
    }
    pub fn wait(&self, millis: u32) -> Result<(), String> {
        match unsafe { WaitForSingleObject(self.event, millis) } {
            0 | 258 => Ok(()),
            _ => Err("Npcap wait failed".into()),
        }
    }
    pub fn advertise(&self, c: &Config, restore: bool) -> Result<(), String> {
        for r in &c.rules {
            for f in crate::model::arp_pair(c, r, restore)? {
                self.send(&f)?
            }
        }
        Ok(())
    }
    pub fn restore(&self, c: &Config) -> Result<(), String> {
        let mut error = None;
        for _ in 0..5 {
            if let Err(e) = self.advertise(c, true) {
                error = Some(e)
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        error.map_or(Ok(()), Err)
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { (self.close)(self.handle) }
    }
}
fn capture_filter(c: &Config) -> Result<String, String> {
    use crate::model::{mac, mac_text};
    let gateway = mac_text(mac(&c.gateway_mac)?);
    let local = mac_text(mac(&c.adapter.mac)?);
    let endpoints = c
        .rules
        .iter()
        .map(|r| {
            let device = mac_text(mac(&r.mac)?);
            Ok(format!(
                "((ether src {device} and src host {}) or (ether src {gateway} and dst host {}))",
                r.ip, r.ip
            ))
        })
        .collect::<Result<Vec<_>, String>>()?
        .join(" or ");
    Ok(format!(
        "arp or (ether dst {local} and ip and ({endpoints}))"
    ))
}
// Prevent two sessions (including sessions in other Windows logins) changing the same LAN.
pub struct SessionLock(Handle);
impl SessionLock {
    pub fn acquire() -> Result<Self, String> {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateMutexW(attributes: *const c_void, owner: i32, name: *const u16) -> Handle;
            fn GetLastError() -> u32;
            fn CloseHandle(h: Handle) -> i32;
        }
        let name: Vec<u16> = "Global\\NetPilotOwnedIPv4Experiment\0"
            .encode_utf16()
            .collect();
        unsafe {
            let h = CreateMutexW(ptr::null(), 1, name.as_ptr());
            if h.is_null() {
                return Err("Cannot acquire the exclusive session lock".into());
            }
            if GetLastError() == 183 {
                CloseHandle(h);
                return Err(
                    "Another NetPilot session is active. Stop it before starting another.".into(),
                );
            }
            Ok(Self(h))
        }
    }
}
impl Drop for SessionLock {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn ReleaseMutex(h: Handle) -> i32;
            fn CloseHandle(h: Handle) -> i32;
        }
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
