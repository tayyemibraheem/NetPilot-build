# NetPilot — Windows network experiment

Rust + Tauri 2 + React desktop source. **The requested transparent SelfishNet-style upload/download control is not implemented.** This is an experimental discovery UI and a narrower explicit HTTPS CONNECT proxy. It must not be treated as a completed equivalent. Accepting proxy-only behavior is a user scope decision.

## Implemented

- On-demand read of the existing IPv4 neighbor cache: Windows `Get-NetNeighbor`, macOS `arp -an`. No active scanning, probes, ARP poisoning, interception or router changes. Cache entries can be missing, stale or shared behind an extender. IP/MAC is not identity or proof of ownership.
- Explicit selection of 1–16 owned test source IPv4 addresses, independently configured upload/download limits in **KiB/s** (multiply by 0.008192 for approximate Mbps).
- Real CONNECT forwarding to public IPv4 destinations on TCP 443, with aggregate per-source, per-direction pacing shared across connections. A small userspace buffer and OS buffers mean this is application payload pacing, not a hard link-rate guarantee. HTTPS stays encrypted end-to-end; no certificate installation or TLS interception.
- Start/stop; stop aborts the listener and connection tasks. Closing/crashing the process releases its sockets. Limits are session-only; no background service, driver, firewall, router, DNS or neighbor state is installed or changed.

## Coverage and missing requested functionality

The client must explicitly configure this PC as its HTTPS proxy and actually honor that setting. Plain HTTP requests receive 405. UDP, QUIC, applications ignoring proxy settings, direct connections, IPv6, and non-443 traffic are **not controlled**. No total-device throughput measurement or automatic bandwidth enforcement is implemented. Limits cannot block a device from using other paths. The UI contains no simulated rates or fabricated devices.

Transparent control requires packets to traverse the enforcement PC in both directions. On the user's router → Wi-Fi extender → Ethernet PC topology, other devices may communicate directly with the router and never traverse the PC. Extender MAC proxying, client isolation, IPv6 and asymmetric routing can prevent a dependable solution. ARP redirection alone does not establish safe forwarding, shaping, recovery or IPv6 coverage. Windows Filtering Platform sees traffic at specific stack layers; it does not automatically pull other LAN devices' traffic into the PC. A future native forwarding/packet capture and shaping component would need explicit adapter and device validation, administrative privileges, suitable signed drivers if used, bounded queues, a watchdog and recovery on forced termination, plus real Windows tests before enabling it. None is silently installed here.

## Development and Windows build

Per user request, **do not compile on the Mac**. Source was developed there; Windows CI is the intended build environment. No executable is delivered until CI passes. Runtime dependencies: Windows with Edge WebView2; development: Node 22 LTS, stable Rust MSVC, Visual Studio C++ Build Tools with Windows SDK and desktop C++ workload. No elevation is required for the implemented proxy. Windows Firewall may require allowing inbound access on a private network; do not open it to public networks or add broad rules.

The manually dispatched `.github/workflows/windows.yml` runs Rust formatting, unit tests and a Windows Tauri build, then retains the unsigned NSIS installer as a private Actions artifact for 14 days. It does not publish a release. Node/Rust lockfiles should be committed; `npm ci` requires package-lock.json. If building manually on Windows:

```powershell
npm ci
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri build
```

Installer output: `src-tauri/target/release/bundle/nsis/`. Unsigned installers may trigger Windows trust prompts. Do not claim Windows validation from a successful Mac source edit.

## Owned-device validation on Windows

1. Start with one owned device; record its actual Wi-Fi IPv4. Read the neighbor cache, verify identity independently, or manually add it. Do not assume the extender exposes unique client IPs/MACs.
2. Enter the PC's private LAN IPv4 and port 8877. Confirm that test device can reach the PC through the extender. Select it and set upload 128 / download 512 KiB/s. Start the proxy. A bind failure must appear as an error, not active status.
3. Configure only the owned test device's HTTPS proxy to the PC endpoint. With curl on that device, use `curl --proxy http://PC_IP:8877 https://YOUR_OWN_TEST_SERVER/large-file -o test.bin`; use an owned HTTPS upload endpoint for an upload test. Avoid third-party speed tests without permission. App support for system proxy settings varies.
4. Transfer long enough to amortize buffering; verify the download tends toward 512 KiB/s and upload toward 128 KiB/s. Run parallel transfers from the same device to test aggregate limits, and another selected device to test isolation. Verify an unselected source cannot tunnel through the proxy. Confirm plain HTTP is rejected.
5. Stop during an active transfer: transfers must disconnect, port must close, and restarting must bind successfully. Test closing the window and force-killing NetPilot. **Remove the manually configured device proxy afterward**, including after a crash; otherwise configured apps may lose access. No automatic direct fallback is promised.
6. Demonstrate bypass deliberately on an owned device with a direct connection: it should remain uncontrolled. This confirms the scope limitation, not a defect in transparent enforcement, which does not exist.

## Security and operational bounds

The proxy accepts selected source IPs, not authenticated identities; DHCP changes or IP spoofing can invalidate selection. Use only on a trusted private home LAN. The listener requires a specific private/loopback IPv4, no wildcard/public binds, max 64 concurrent tunnels, 8 KiB request headers, ten-second header/DNS/connect timeouts, and a one-hour tunnel lifetime. It permits only public IPv4 port-443 destinations. Proxy errors close connections; no per-connection error telemetry is exposed yet. Active listener/session status is not a throughput monitor. Stop before editing limits or devices.

## Official references

- [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
- [Tauri Rust IPC](https://v2.tauri.app/develop/calling-rust/)
- [Microsoft Get-NetNeighbor](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netneighbor)
- [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform)
- [WFP forwarding layers](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/run-time-filtering-layer-identifiers)
