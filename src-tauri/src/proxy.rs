use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex as AsyncMutex,
    task::JoinSet,
    time::Instant,
};
#[derive(Clone, Deserialize)]
pub struct Rule {
    pub ip: Ipv4Addr,
    pub upload: u32,
    pub download: u32,
}
#[derive(Clone, Serialize, Default)]
pub struct Status {
    pub running: bool,
    pub endpoint: String,
}
pub struct Service(pub Mutex<Option<(tauri::async_runtime::JoinHandle<()>, String)>>);
impl Service {
    pub async fn start(&self, bind: String, rules: Vec<Rule>) -> Result<String, String> {
        let addr: SocketAddr = bind
            .parse()
            .map_err(|_| "Use a local IPv4 address and port, e.g. 192.168.1.10:8877")?;
        if !matches!(addr.ip(), IpAddr::V4(ip) if ip.is_private() || ip.is_loopback())
            || addr.port() < 1024
        {
            return Err(
                "Bind to a specific private or loopback IPv4 address, port 1024 or higher".into(),
            );
        }
        if rules.is_empty() || rules.len() > 16 {
            return Err("Select 1–16 owned test devices".into());
        }
        let mut allowed = HashMap::new();
        for r in rules {
            if !(r.ip.is_private() || r.ip.is_loopback())
                || r.upload == 0
                || r.download == 0
                || r.upload > 125000
                || r.download > 125000
            {
                return Err(
                    "Each device needs a private IPv4 and limits from 1 to 125000 KiB/s".into(),
                );
            }
            if allowed
                .insert(
                    IpAddr::V4(r.ip),
                    Arc::new(Limits::new(r.upload, r.download)),
                )
                .is_some()
            {
                return Err("Duplicate device IP".into());
            }
        }
        let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
        let mut guard = self.0.lock().map_err(|_| "State unavailable")?;
        if guard.is_some() {
            return Err("Stop the existing session first".into());
        }
        let task = tauri::async_runtime::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                 result=listener.accept() => match result {
                  Ok((mut stream,peer)) => {
                   if let Some(limits)=allowed.get(&peer.ip()).cloned() {
                    if sessions.len()>=64 { continue; }
                    sessions.spawn(async move { let _=tokio::time::timeout(Duration::from_secs(3600), serve(&mut stream,limits)).await; });
                   }
                  },
                  Err(_)=>break,
                 },
                 _=sessions.join_next(), if !sessions.is_empty()=>{}
                }
            }
        });
        *guard = Some((task, bind.clone()));
        Ok(bind)
    }
    pub fn stop(&self) {
        if let Ok(mut g) = self.0.lock() {
            if let Some((task, _)) = g.take() {
                task.abort();
            }
        }
    }
    pub fn status(&self) -> Status {
        self.0
            .lock()
            .ok()
            .and_then(|g| {
                g.as_ref().map(|(_, s)| Status {
                    running: true,
                    endpoint: s.clone(),
                })
            })
            .unwrap_or_default()
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop();
    }
}
struct Pace {
    rate: u32,
    next: AsyncMutex<Instant>,
}
impl Pace {
    fn new(rate: u32) -> Self {
        Self {
            rate,
            next: AsyncMutex::new(Instant::now()),
        }
    }
    async fn wait(&self, n: usize) {
        let mut next = self.next.lock().await;
        *next = (*next).max(Instant::now())
            + Duration::from_secs_f64(n as f64 / (self.rate as f64 * 1024.0));
        tokio::time::sleep_until(*next).await;
    }
}
struct Limits {
    up: Pace,
    down: Pace,
}
impl Limits {
    fn new(up: u32, down: u32) -> Self {
        Self {
            up: Pace::new(up),
            down: Pace::new(down),
        }
    }
}
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_broadcast()
                || v.is_unspecified()
                || v.octets()[0] == 0
                || v.octets()[0] >= 224
                || v.octets()[0] == 127
                || (v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1])))
        }
        IpAddr::V6(_) => false,
    }
}
async fn serve(client: &mut TcpStream, limits: Arc<Limits>) -> std::io::Result<()> {
    let mut header = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let b = client.read_u8().await?;
            header.push(b);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
            if header.len() > 8192 {
                return Err(std::io::Error::other("Header too large"));
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    let text = String::from_utf8_lossy(&header);
    let words: Vec<_> = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    if words.len() != 3 || words[0] != "CONNECT" || !words[1].ends_with(":443") {
        client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
        return Ok(());
    }
    let authority = words[1];
    let addresses =
        tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host(authority)).await??;
    let addr = addresses
        .filter(|a| public(a.ip()))
        .next()
        .ok_or_else(|| std::io::Error::other("No public IPv4 destination"))?;
    let mut remote =
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await??;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let (cr, cw) = client.split();
    let (rr, rw) = remote.split();
    tokio::try_join!(pump(cr, rw, &limits.up), pump(rr, cw, &limits.down))?;
    Ok(())
}
async fn pump<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    pace: &Pace,
) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            w.shutdown().await?;
            return Ok(());
        }
        pace.wait(n).await;
        w.write_all(&buf[..n]).await?;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_local_destinations() {
        for s in [
            "127.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
        ] {
            assert!(!public(s.parse().unwrap()));
        }
        assert!(public("1.1.1.1".parse().unwrap()));
    }
    #[tokio::test]
    async fn aggregate_pacing() {
        let pace = Arc::new(Pace::new(10));
        let start = Instant::now();
        let a = pace.clone();
        let b = pace.clone();
        let (a, b) = tokio::join!(
            tokio::spawn(async move { a.wait(2048).await }),
            tokio::spawn(async move { b.wait(2048).await })
        );
        a.unwrap();
        b.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(400));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[tokio::test]
    async fn copies_actual_bytes() {
        let (mut input, reader) = tokio::io::duplex(8192);
        let (writer, mut output) = tokio::io::duplex(8192);
        input.write_all(b"netpilot").await.unwrap();
        input.shutdown().await.unwrap();
        pump(reader, writer, &Pace::new(1024)).await.unwrap();
        let mut data = vec![];
        output.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"netpilot");
    }
}
