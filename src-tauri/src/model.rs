//! Pure packet/state logic. These tests never open an adapter or transmit traffic.
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
pub type Mac = [u8; 6];
pub fn mac(s: &str) -> Result<Mac, String> {
    let bytes: Result<Vec<_>, _> = s
        .split([':', '-'])
        .map(|b| u8::from_str_radix(b, 16))
        .collect();
    let m: Mac = bytes
        .map_err(|_| "Invalid MAC")?
        .try_into()
        .map_err(|_| "MAC must have six octets")?;
    if m == [0; 6] || m[0] & 1 != 0 {
        return Err("A unicast MAC is required".into());
    }
    Ok(m)
}
pub fn mac_text(m: Mac) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Adapter {
    pub index: u32,
    pub name: String,
    pub guid: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mac: String,
    pub gateway: Ipv4Addr,
    pub forwarding: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub upload: u32,
    pub download: u32,
    #[serde(default)]
    pub blocked: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub adapter: Adapter,
    pub gateway_mac: String,
    pub rules: Vec<Rule>,
    pub owned_confirmed: bool,
    pub duration_minutes: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Update {
    pub ip: Ipv4Addr,
    pub upload: u32,
    pub download: u32,
    pub blocked: bool,
}
impl Update {
    pub fn validate(&self, c: &Config) -> Result<(), String> {
        if !c.rules.iter().any(|r| r.ip == self.ip)
            || self.upload == 0
            || self.download == 0
            || self.upload > 125000
            || self.download > 125000
        {
            return Err("Update must address an enrolled device with limits 1–125000 KiB/s".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub ip: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub dropped: u64,
    pub blocked: bool,
    pub upload_limit: u32,
    pub download_limit: u32,
    pub observed_upload_bytes: u64,
    pub observed_download_bytes: u64,
    pub observed_upload_kib_s: Option<f64>,
    pub observed_download_kib_s: Option<f64>,
    pub forwarded_upload_kib_s: Option<f64>,
    pub forwarded_download_kib_s: Option<f64>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RecoveryReport {
    pub mappings: u32,
    pub attempts: u32,
    pub submitted: u32,
    pub failed_attempts: u32,
    pub unsubmitted_mappings: u32,
    pub last_error: Option<String>,
}
impl RecoveryReport {
    pub fn summary(&self) -> String {
        format!("Original ARP mappings submitted for {}/{} mappings; {}/{} send attempts succeeded. Endpoint acceptance is not confirmed.{}",self.mappings-self.unsubmitted_mappings,self.mappings,self.submitted,self.attempts,self.last_error.as_ref().map(|e|format!(" Last recovery error: {e}")).unwrap_or_default())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Status {
    pub phase: String,
    pub message: String,
    pub counters: Vec<Counters>,
    #[serde(default)]
    pub primary_error: Option<String>,
    #[serde(default)]
    pub recovery: Option<RecoveryReport>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    #[serde(default)]
    pub remaining_seconds: Option<u64>,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            phase: "stopped".into(),
            message: "No interception session is running.".into(),
            counters: vec![],
            primary_error: None,
            recovery: None,
            stop_reason: None,
            remaining_seconds: None,
        }
    }
}
impl Status {
    pub fn new(phase: &str, message: impl Into<String>) -> Self {
        let text = message.into();
        Self {
            phase: phase.into(),
            primary_error: if phase == "error" {
                Some(text.clone())
            } else {
                None
            },
            message: text,
            ..Default::default()
        }
    }
    /// Keep the first failure through cleanup, subsequent errors and helper pipe loss.
    pub fn absorb(&mut self, mut next: Self) {
        if self.primary_error.is_some() {
            next.primary_error = self.primary_error.clone()
        }
        if next.recovery.is_none() {
            next.recovery = self.recovery.clone()
        }
        if next.stop_reason.is_none() {
            next.stop_reason = self.stop_reason.clone()
        }
        if next.counters.is_empty() {
            next.counters = self.counters.clone()
        }
        if next.primary_error.is_some() && next.phase == "stopped" {
            next.phase = "error".into()
        }
        if next.phase != "active" {
            next.remaining_seconds = None
        }
        *self = next;
    }
}
/// Submit every recovery mapping even if another mapping fails. No live I/O in this function.
pub fn restore_with(
    c: &Config,
    rounds: u32,
    mut send: impl FnMut(&[u8]) -> Result<(), String>,
    mut between: impl FnMut(),
) -> RecoveryReport {
    let mut frames = vec![];
    for r in &c.rules {
        match arp_pair(c, r, true) {
            Ok(pair) => frames.extend(pair),
            Err(e) => {
                return RecoveryReport {
                    mappings: (c.rules.len() * 2) as u32,
                    unsubmitted_mappings: (c.rules.len() * 2) as u32,
                    last_error: Some(e),
                    ..Default::default()
                }
            }
        }
    }
    let mut report = RecoveryReport {
        mappings: frames.len() as u32,
        ..Default::default()
    };
    let mut sent = vec![false; frames.len()];
    for round in 0..rounds {
        for (i, f) in frames.iter().enumerate() {
            report.attempts += 1;
            match send(f) {
                Ok(()) => {
                    report.submitted += 1;
                    sent[i] = true
                }
                Err(e) => {
                    report.failed_attempts += 1;
                    report.last_error = Some(e)
                }
            }
        }
        if round + 1 < rounds {
            between()
        }
    }
    report.unsubmitted_mappings = sent.iter().filter(|s| !**s).count() as u32;
    report
}
pub fn measured_rate(bytes: u64, elapsed: Duration) -> Option<f64> {
    if elapsed < Duration::from_millis(250) {
        None
    } else {
        Some(bytes as f64 / 1024. / elapsed.as_secs_f64())
    }
}
/// Match the explicitly chosen Windows GUID, then use the driver's exact device name.
pub fn capture_device_name(guid: &str, candidates: &[String]) -> Result<String, String> {
    let expected = format!("\\Device\\NPF_{{{}}}", guid.trim_matches(['{', '}']));
    candidates.iter().find(|name|name.eq_ignore_ascii_case(&expected)).cloned().ok_or_else(||"[NP_ADAPTER_BINDING] The selected Windows adapter is not in Npcap's capture-device list. Keep the same selected adapter; check its Npcap binding/driver installation and recheck setup. No different adapter was substituted.".into())
}
pub fn subnet(ip: Ipv4Addr, other: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 || prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix);
    u32::from(ip) & mask == u32::from(other) & mask
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        let a = &self.adapter;
        if !self.owned_confirmed {
            return Err("Explicit ownership confirmation is required".into());
        }
        if !a.ip.is_private()
            || !(8..=30).contains(&a.prefix)
            || !subnet(a.ip, a.gateway, a.prefix)
            || a.ip == a.gateway
            || a.forwarding
        {
            return Err("Use a private IPv4 Ethernet subnet with a distinct on-link gateway and Windows IP forwarding disabled".into());
        }
        if self.duration_minutes == 0 || self.duration_minutes > 30 {
            return Err("Test session duration must be 1–30 minutes".into());
        }
        let local = mac(&a.mac)?;
        let gateway = mac(&self.gateway_mac)?;
        if local == gateway {
            return Err("PC and gateway share a MAC; this topology is unsupported".into());
        }
        if self.rules.is_empty() || self.rules.len() > 8 {
            return Err("Select 1–8 owned test devices".into());
        }
        let mut ips = HashSet::from([a.ip, a.gateway]);
        let mut macs = HashSet::from([local, gateway]);
        let network = u32::from(a.ip) & (u32::MAX << (32 - a.prefix));
        let broadcast = network | !(u32::MAX << (32 - a.prefix));
        for r in &self.rules {
            if !r.ip.is_private()
                || !subnet(a.ip, r.ip, a.prefix)
                || u32::from(r.ip) == network
                || u32::from(r.ip) == broadcast
                || !ips.insert(r.ip)
                || !macs.insert(mac(&r.mac)?)
            {
                return Err("Devices must have unique on-link IPv4 and MAC addresses distinct from the PC and gateway. Shared/proxied extender MACs are unsupported.".into());
            }
            if r.upload == 0 || r.download == 0 || r.upload > 125000 || r.download > 125000 {
                return Err("Limits must be 1–125000 KiB/s".into());
            }
        }
        Ok(())
    }
    pub fn npf_name(&self) -> String {
        format!(
            "\\Device\\NPF_{{{}}}",
            self.adapter.guid.trim_matches(['{', '}'])
        )
    }
}
/// Ethernet ARP reply. 'restore' advertises the original mapping, not the PC.
pub fn arp_pair(c: &Config, r: &Rule, restore: bool) -> Result<[Vec<u8>; 2], String> {
    let local = mac(&c.adapter.mac)?;
    let gateway = mac(&c.gateway_mac)?;
    let device = mac(&r.mac)?;
    Ok([
        arp_reply(
            device,
            if restore { gateway } else { local },
            c.adapter.gateway,
            r.ip,
        ),
        arp_reply(
            gateway,
            if restore { device } else { local },
            r.ip,
            c.adapter.gateway,
        ),
    ])
}
fn arp_reply(target: Mac, sender: Mac, claimed: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[..6].copy_from_slice(&target);
    f[6..12].copy_from_slice(&sender);
    f[12..14].copy_from_slice(&[8, 6]);
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
    f[22..28].copy_from_slice(&sender);
    f[28..32].copy_from_slice(&claimed.octets());
    f[32..38].copy_from_slice(&target);
    f[38..42].copy_from_slice(&destination.octets());
    f
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Upload,
    Download,
}
pub fn classify(c: &Config, frame: &[u8]) -> Option<(usize, Direction, Vec<u8>)> {
    if frame.len() < 34
        || frame[12..14] != [8, 0]
        || frame[..6] != mac(&c.adapter.mac).ok()?
        || frame[14] >> 4 != 4
    {
        return None;
    }
    let header = (frame[14] & 15) as usize * 4;
    let total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    if header < 20 || total < header || frame.len() < 14 + total {
        return None;
    }
    let src = Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);
    let dst = Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]);
    if src == c.adapter.ip || dst == c.adapter.ip || dst.is_multicast() || dst.is_broadcast() {
        return None;
    }
    for (i, r) in c.rules.iter().enumerate() {
        let device = mac(&r.mac).ok()?;
        let gateway = mac(&c.gateway_mac).ok()?;
        let (direction, target) = if src == r.ip && frame[6..12] == device {
            (Direction::Upload, gateway)
        } else if dst == r.ip && frame[6..12] == gateway {
            (Direction::Download, device)
        } else {
            continue;
        };
        let mut forwarded = frame[..14 + total].to_vec();
        forwarded[..6].copy_from_slice(&target);
        forwarded[6..12].copy_from_slice(&mac(&c.adapter.mac).ok()?);
        // Ethernet minimum size excludes the FCS, which the NIC supplies.
        forwarded.resize(forwarded.len().max(60), 0);
        return Some((i, direction, forwarded));
    }
    None
}
/// Detect identity changes only for explicitly enrolled endpoints; ignore our advertisements.
pub fn identity_changed(c: &Config, f: &[u8]) -> bool {
    if f.len() < 42 || f[12..14] != [8, 6] || f[14..20] != [0, 1, 8, 0, 6, 4] {
        return false;
    }
    let Ok(local) = mac(&c.adapter.mac) else {
        return true;
    };
    if f[22..28] == local {
        return false;
    }
    let ip = Ipv4Addr::new(f[28], f[29], f[30], f[31]);
    let expected = if ip == c.adapter.gateway {
        Some(c.gateway_mac.as_str())
    } else {
        c.rules.iter().find(|r| r.ip == ip).map(|r| r.mac.as_str())
    };
    expected.is_some_and(|s| mac(s).map_or(true, |m| f[22..28] != m))
}
pub struct Queue {
    rate: u32,
    next: Instant,
    bytes: usize,
    frames: VecDeque<(Instant, Vec<u8>)>,
}
impl Queue {
    pub fn new(rate: u32, now: Instant) -> Self {
        Self {
            rate,
            next: now,
            bytes: 0,
            frames: VecDeque::new(),
        }
    }
    pub fn enqueue(&mut self, frame: Vec<u8>, now: Instant) -> bool {
        let due = self.next.max(now)
            + Duration::from_secs_f64(frame.len() as f64 / (self.rate as f64 * 1024.));
        if self.bytes + frame.len() > 1024 * 1024
            || due.saturating_duration_since(now) > Duration::from_secs(2)
        {
            return false;
        }
        self.next = due;
        self.bytes += frame.len();
        self.frames.push_back((due, frame));
        true
    }
    pub fn pending_packets(&self) -> usize {
        self.frames.len()
    }
    pub fn due(&self) -> Option<Instant> {
        self.frames.front().map(|(t, _)| *t)
    }
    pub fn pop(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.due()? > now {
            return None;
        }
        let (_, f) = self.frames.pop_front()?;
        self.bytes -= f.len();
        Some(f)
    }
}
/// Offline-testable forwarding and live rule state; native code supplies only I/O.
pub struct Relay {
    queues: Vec<[Queue; 2]>,
    rules: Vec<Rule>,
    pub stats: Vec<Counters>,
    sample_at: Instant,
    sampled: Vec<[u64; 4]>,
}
impl Relay {
    pub fn new(c: &Config, now: Instant) -> Self {
        Self {
            sample_at: now,
            sampled: vec![[0; 4]; c.rules.len()],
            queues: c
                .rules
                .iter()
                .map(|r| [Queue::new(r.upload, now), Queue::new(r.download, now)])
                .collect(),
            rules: c.rules.clone(),
            stats: c
                .rules
                .iter()
                .map(|r| Counters {
                    ip: r.ip.to_string(),
                    blocked: r.blocked,
                    upload_limit: r.upload,
                    download_limit: r.download,
                    ..Default::default()
                })
                .collect(),
        }
    }
    pub fn receive(&mut self, c: &Config, frame: &[u8], now: Instant) {
        if let Some((i, d, f)) = classify(c, frame) {
            if d == Direction::Upload {
                self.stats[i].observed_upload_bytes += f.len() as u64
            } else {
                self.stats[i].observed_download_bytes += f.len() as u64
            }
            let direction = if d == Direction::Upload { 0 } else { 1 };
            if self.rules[i].blocked || !self.queues[i][direction].enqueue(f, now) {
                self.stats[i].dropped += 1
            }
        }
    }
    pub fn update(&mut self, c: &Config, u: Update, now: Instant) -> Result<(), String> {
        u.validate(c)?;
        let i = self
            .rules
            .iter()
            .position(|r| r.ip == u.ip)
            .ok_or("Device not enrolled")?;
        self.stats[i].dropped +=
            (self.queues[i][0].pending_packets() + self.queues[i][1].pending_packets()) as u64;
        self.rules[i].upload = u.upload;
        self.rules[i].download = u.download;
        self.rules[i].blocked = u.blocked;
        self.queues[i] = [Queue::new(u.upload, now), Queue::new(u.download, now)];
        self.stats[i].blocked = u.blocked;
        self.stats[i].upload_limit = u.upload;
        self.stats[i].download_limit = u.download;
        Ok(())
    }
    pub fn forward_due(
        &mut self,
        now: Instant,
        mut send: impl FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        for (i, pair) in self.queues.iter_mut().enumerate() {
            for (d, q) in pair.iter_mut().enumerate() {
                for _ in 0..128 {
                    let Some(frame) = q.pop(now) else { break };
                    send(&frame)?;
                    if d == 0 {
                        self.stats[i].upload_bytes += frame.len() as u64
                    } else {
                        self.stats[i].download_bytes += frame.len() as u64
                    }
                }
            }
        }
        Ok(())
    }
    pub fn sample_rates(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.sample_at);
        if elapsed < Duration::from_millis(250) {
            return;
        }
        for (i, c) in self.stats.iter_mut().enumerate() {
            let totals = [
                c.observed_upload_bytes,
                c.observed_download_bytes,
                c.upload_bytes,
                c.download_bytes,
            ];
            let rates = std::array::from_fn::<_, 4, _>(|j| {
                measured_rate(totals[j].saturating_sub(self.sampled[i][j]), elapsed)
            });
            c.observed_upload_kib_s = rates[0];
            c.observed_download_kib_s = rates[1];
            c.forwarded_upload_kib_s = rates[2];
            c.forwarded_download_kib_s = rates[3];
            self.sampled[i] = totals;
        }
        self.sample_at = now;
    }
    pub fn next_due(&self) -> Option<Instant> {
        self.queues
            .iter()
            .flat_map(|q| q.iter())
            .filter_map(|q| q.due())
            .min()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    pub fn config() -> Config {
        Config {
            adapter: Adapter {
                index: 1,
                name: "Ethernet".into(),
                guid: "test".into(),
                ip: "192.168.1.2".parse().unwrap(),
                prefix: 24,
                mac: "02:00:00:00:00:02".into(),
                gateway: "192.168.1.1".parse().unwrap(),
                forwarding: false,
            },
            gateway_mac: "02:00:00:00:00:01".into(),
            rules: vec![Rule {
                ip: "192.168.1.3".parse().unwrap(),
                mac: "02:00:00:00:00:03".into(),
                upload: 10,
                download: 20,
                blocked: false,
            }],
            owned_confirmed: true,
            duration_minutes: 5,
        }
    }
    fn ipv4(c: &Config, down: bool) -> Vec<u8> {
        let mut f = vec![0; 100];
        f[..6].copy_from_slice(&mac(&c.adapter.mac).unwrap());
        f[6..12].copy_from_slice(
            &mac(if down {
                &c.gateway_mac
            } else {
                &c.rules[0].mac
            })
            .unwrap(),
        );
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&86u16.to_be_bytes());
        f[26..30].copy_from_slice(&if down { [1, 1, 1, 1] } else { [192, 168, 1, 3] });
        f[30..34].copy_from_slice(&if down { [192, 168, 1, 3] } else { [1, 1, 1, 1] });
        f
    }
    #[test]
    fn scope_validation() {
        let mut c = config();
        assert!(c.validate().is_ok());
        c.rules[0].mac = c.gateway_mac.clone();
        assert!(c.validate().is_err());
        c = config();
        c.owned_confirmed = false;
        assert!(c.validate().is_err());
        c = config();
        c.rules[0].ip = "10.0.0.1".parse().unwrap();
        assert!(c.validate().is_err());
    }
    #[test]
    fn bidirectional_rewrite_and_loop_exclusion() {
        let c = config();
        for down in [false, true] {
            let f = ipv4(&c, down);
            let (_, dir, out) = classify(&c, &f).unwrap();
            assert_eq!(
                dir,
                if down {
                    Direction::Download
                } else {
                    Direction::Upload
                }
            );
            assert_eq!(&out[14..], &f[14..]);
            assert_eq!(
                &out[..6],
                &mac(if down {
                    &c.rules[0].mac
                } else {
                    &c.gateway_mac
                })
                .unwrap()
            );
            assert!(classify(&c, &out).is_none())
        }
    }
    #[test]
    fn rejects_unselected_malformed_ipv6_and_spoofed_source() {
        let c = config();
        let mut f = ipv4(&c, false);
        f[29] = 99;
        assert!(classify(&c, &f).is_none());
        f = ipv4(&c, false);
        f[6] = 4;
        assert!(classify(&c, &f).is_none());
        f = ipv4(&c, false);
        f[12..14].copy_from_slice(&[0x86, 0xdd]);
        assert!(classify(&c, &f).is_none());
        assert!(classify(&c, &[0; 20]).is_none());
    }
    #[test]
    fn restoration_uses_real_mappings() {
        let c = config();
        let active = arp_pair(&c, &c.rules[0], false).unwrap();
        let restored = arp_pair(&c, &c.rules[0], true).unwrap();
        assert_eq!(&active[0][22..28], &mac(&c.adapter.mac).unwrap());
        assert_eq!(&restored[0][22..28], &mac(&c.gateway_mac).unwrap());
        assert_eq!(&restored[1][22..28], &mac(&c.rules[0].mac).unwrap());
        assert!(!identity_changed(&c, &active[0]));
        assert!(!identity_changed(&c, &restored[0]));
        let mut changed = restored[0].clone();
        changed[22] = 4;
        assert!(identity_changed(&c, &changed));
    }
    #[test]
    fn queues_are_bounded_and_directions_independent() {
        let now = Instant::now();
        let mut up = Queue::new(10, now);
        let mut down = Queue::new(20, now);
        assert!(up.enqueue(vec![1; 10240], now));
        assert!(down.enqueue(vec![2; 10240], now));
        assert!(up.pop(now + Duration::from_millis(999)).is_none());
        assert_eq!(
            down.pop(now + Duration::from_millis(500)).unwrap().len(),
            10240
        );
        assert_eq!(up.pop(now + Duration::from_secs(1)).unwrap().len(), 10240);
        assert!(!up.enqueue(vec![0; 30000], now));
    }
    #[test]
    fn live_block_clears_queued_frames_and_unblock_restarts_forwarding() {
        let c = config();
        let now = Instant::now();
        let mut relay = Relay::new(&c, now);
        let f = ipv4(&c, false);
        relay.receive(&c, &f, now);
        relay
            .update(
                &c,
                Update {
                    ip: c.rules[0].ip,
                    upload: 10,
                    download: 20,
                    blocked: true,
                },
                now,
            )
            .unwrap();
        relay.receive(&c, &f, now);
        let mut sent = 0;
        relay
            .forward_due(now + Duration::from_secs(1), |_| {
                sent += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(sent, 0);
        assert_eq!(relay.stats[0].dropped, 2);
        assert!(relay.stats[0].blocked);
        relay
            .update(
                &c,
                Update {
                    ip: c.rules[0].ip,
                    upload: 30,
                    download: 40,
                    blocked: false,
                },
                now,
            )
            .unwrap();
        relay.receive(&c, &f, now);
        relay
            .forward_due(now + Duration::from_secs(1), |_| {
                sent += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(sent, 1);
        assert_eq!(relay.stats[0].upload_bytes, 100);
        assert_eq!(relay.stats[0].download_bytes, 0);
        assert_eq!(relay.stats[0].upload_limit, 30);
        assert!(!relay.stats[0].blocked);
    }
    #[test]
    fn aggregate_frame_pacing_and_directional_counts() {
        let c = config();
        let now = Instant::now();
        let mut relay = Relay::new(&c, now);
        for _ in 0..10 {
            relay.receive(&c, &ipv4(&c, false), now);
            relay.receive(&c, &ipv4(&c, true), now)
        }
        relay
            .forward_due(now + Duration::from_millis(50), |_| Ok(()))
            .unwrap();
        assert_eq!(relay.stats[0].upload_bytes, 500);
        assert_eq!(relay.stats[0].download_bytes, 1000);
    }
    #[test]
    fn failed_transmit_does_not_increment_forwarded_bytes() {
        let c = config();
        let now = Instant::now();
        let mut relay = Relay::new(&c, now);
        relay.receive(&c, &ipv4(&c, false), now);
        assert!(relay
            .forward_due(now + Duration::from_secs(1), |_| Err(
                "driver failure".into()
            ))
            .is_err());
        assert_eq!(relay.stats[0].upload_bytes, 0);
    }
    #[test]
    fn original_failure_survives_cleanup_and_disconnect() {
        let mut s = Status::new("error", "[NP_CAPTURE_READ] could not find the device");
        s.counters = Relay::new(&config(), Instant::now()).stats;
        s.absorb(Status::new("restoring", "Restoring original mappings"));
        s.absorb(Status::new("error", "[NP_RECOVERY] restore send failed"));
        s.absorb(Status::new("stopped", "Cleanup ended"));
        assert_eq!(
            s.primary_error.as_deref(),
            Some("[NP_CAPTURE_READ] could not find the device")
        );
        assert_eq!(s.phase, "error");
        assert_eq!(s.counters.len(), 1);
    }
    #[test]
    fn recovery_attempts_every_mapping_and_recovers_partial_round() {
        let c = config();
        let mut calls = 0;
        let report = restore_with(
            &c,
            2,
            |_| {
                calls += 1;
                if calls == 1 {
                    Err("first send failed".into())
                } else {
                    Ok(())
                }
            },
            || {},
        );
        assert_eq!(calls, 4);
        assert_eq!(report.failed_attempts, 1);
        assert_eq!(report.submitted, 3);
        assert_eq!(report.unsubmitted_mappings, 0);
        let report = restore_with(
            &c,
            2,
            |f| {
                if f[..6] == mac(&c.gateway_mac).unwrap() {
                    Err("gateway send failed".into())
                } else {
                    Ok(())
                }
            },
            || {},
        );
        assert_eq!(report.attempts, 4);
        assert_eq!(report.unsubmitted_mappings, 1);
    }
    #[test]
    fn rates_use_real_elapsed_time_and_measure_attempted_blocked_traffic() {
        assert_eq!(measured_rate(2048, Duration::from_secs(2)), Some(1.));
        assert_eq!(measured_rate(1024, Duration::from_millis(100)), None);
        let mut c = config();
        c.rules[0].blocked = true;
        let now = Instant::now();
        let mut relay = Relay::new(&c, now);
        for _ in 0..10 {
            relay.receive(&c, &ipv4(&c, false), now)
        }
        relay.sample_rates(now + Duration::from_secs(2));
        assert_eq!(relay.stats[0].observed_upload_kib_s, Some(1000. / 2048.));
        assert_eq!(relay.stats[0].forwarded_upload_kib_s, Some(0.));
        relay.sample_rates(now + Duration::from_secs(3));
        assert_eq!(relay.stats[0].observed_upload_kib_s, Some(0.));
    }
    #[test]
    fn capture_selection_uses_exact_driver_name_for_only_the_selected_guid() {
        let guid = "AB000000-0000-4000-8000-000000000001";
        let actual = "\\Device\\NPF_{ab000000-0000-4000-8000-000000000001}".to_string();
        let other = "\\Device\\NPF_{ab000000-0000-4000-8000-000000000002}".to_string();
        assert_eq!(
            capture_device_name(
                guid,
                &[
                    "\\Device\\NPF_Loopback".into(),
                    other.clone(),
                    actual.clone()
                ]
            )
            .unwrap(),
            actual
        );
        assert!(capture_device_name(guid, &[other]).is_err());
        assert!(capture_device_name(guid, &[]).is_err());
    }
}
