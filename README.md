# NetPilot

Experimental Windows desktop application in Rust, Tauri 2 and React for selected **owned home test devices**. Implements the requested SelfishNet-style IPv4 mechanism: targeted ARP redirection, Ethernet forwarding, separate upload/download shaping, and temporary IPv4 block/unblock. **Windows runtime is not yet validated. A successful build alone does not establish working enforcement on your extender topology.**

The earlier explicit proxy experiment is preserved locally on branch `experimental/connect-proxy`; it is not the application's current mechanism. No proxy configuration is required on devices.

## What is implemented in source

- Physical Ethernet adapter selection with IPv4 subnet, gateway and forwarding-state inventory. Windows-only network commands; no networking backend runs on the development Mac.
- Cached IPv4 neighbor discovery, explicit on-link address resolution, and optional bounded active discovery on private /24–/30 subnets (ordinary ARP requests, max 16 concurrent requests, 30-second budget plus in-flight Windows ARP calls). Discovery does not establish ownership.
- Explicit ownership confirmation and selection of 1–8 owned test devices with unique on-link IPv4/MAC addresses. Gateway and PC cannot be selected. Shared device/gateway MACs are rejected, including many MAC-proxy extender topologies.
- Npcap raw Ethernet capture/injection on only the selected adapter. Original gateway/device MAC mappings are resolved before redirection. Npcap is loaded from the Windows system Npcap directory, not the current folder. Only DLT_EN10MB Ethernet is accepted.
- Periodic unicast ARP replies tell each selected device that its gateway is at the PC MAC, and tell the gateway that the selected device is at the PC MAC. No unselected endpoint ARP mappings are deliberately changed.
- A bidirectional userspace Ethernet relay forwards selected IPv4 frames, rewriting only Ethernet MACs. IP/TCP/UDP data and checksums remain unchanged. Outgoing reinjected frames do not match the input filter, preventing relay loops. Windows IP forwarding must be disabled; NetPilot does not change that setting.
- Aggregate per-device/per-direction pacing in **KiB/s**, based on forwarded Ethernet frame bytes. Independent bounded queues limit memory to 1 MiB per direction per device and queued delay to two seconds; excess frames are dropped. Low limits and UDP can therefore lose packets; this is not a lossless QoS service. NIC/kernel queues and framing affect observed rates.
- Live upload/download updates and per-device **IPv4 block/unblock**. Blocking discards matching redirected IPv4 frames in both directions and clears queued frames. Changes are confirmed by the engine's next report, not by a mock slider.
- Actual forwarded-byte and userspace dropped-frame counters. These are cumulative counts, not complete device bandwidth measurements or proof of traffic-path coverage. No payload logging or storage.
- Explicit start and stop; session lease 1–30 minutes. Restart requires a new explicit start. A global Windows mutex prevents two guardians from running simultaneously.

## Coverage limits

**IPv6 is neither redirected nor blocked.** No claim of complete internet blocking is made. IPv4 traffic that does not traverse the PC is not controlled. Direct local-LAN traffic generally does not use the gateway and is not covered. VLAN-tagged, non-Ethernet and non-IPv4 frames are not forwarded by the engine. Static ARP, anti-spoof protections, client isolation, extender proxying, captive portals or asymmetric paths can prevent enforcement. No app can infer full-device control from a zero counter.

The user's topology is router Wi-Fi → extender → Ethernet Windows PC; other devices may be on the main router. The extender may bridge source MACs transparently, proxy them, or isolate clients. Distinct device and gateway MACs are a prerequisite here, **not a guarantee** that targeted ARP replies and relayed frames cross the extender. This must be tested with one owned device first. NetPilot does not modify router configuration or require device proxy settings, but deliberately changes temporary ARP mappings during a running experiment.

## Recovery design and limits

The UI spawns a guardian process with an independent Npcap recovery handle **before** it starts the engine process. UI → guardian and guardian → engine pipes carry heartbeats; pipe EOF or a heartbeat gap over three seconds requests shutdown. The guardian also watches engine progress (four-second report gap after startup) and enforces an independent session deadline. The UI detects a silent guardian and closes its pipe. The engine has an independent finite lease and aborts on detected enrolled ARP identity changes or capture/injection errors.

- Normal stop/close: engine stops forwarding and sends each original mapping five times; guardian waits for the engine and repeats recovery with its own handle.
- UI crash: guardian notices closed pipe, stops engine and restores.
- Engine crash: guardian notices exit and restores.
- Guardian crash: engine notices pipe loss and restores using its own handle.
- A stuck engine can be terminated by the guardian, which then attempts recovery independently.

A successful Npcap send confirms transmission submission, **not acceptance by the gateway or device**. Killing both helpers, disabling the adapter, removing the driver, power loss, driver failure or endpoint rejection can prevent recovery. Reconnect the selected device's Wi-Fi/Ethernet to refresh its ARP cache; reboot it/router only if necessary and under your control. Do not treat recovery as guaranteed. No persistent Windows forwarding/firewall/router/DNS changes are made, and no driver/service is installed by NetPilot.

## Windows prerequisites

- Windows 10/11 x64 with WebView2; run NetPilot as administrator. The app reports missing privileges and does not auto-elevate.
- Install Npcap separately from its [official site](https://npcap.com/). NetPilot **does not redistribute, silently install, or auto-download Npcap**. Follow its license terms and installer guidance. This build dynamically loads its API, so the Npcap SDK is not needed to compile.
- Active physical Ethernet adapter with a private IPv4, on-link gateway and Windows IPv4 forwarding disabled. No VPN/virtual/Wi-Fi adapters are accepted by inventory. Check that Windows Internet Connection Sharing/routing is not enabled on the chosen adapter.
- Owned test devices with distinct reachable on-link IPv4/MAC addresses and a topology accepting temporary ARP updates. Verify device ownership independently; MAC addresses are not authentication.

## Build and CI

Per user instruction, no application compilation/builds are performed on the Mac. Windows Actions is manually dispatched and builds an unsigned NSIS installer. The workflow runs frontend typechecking/build, Rust formatting, portable packet/recovery/queue tests, and Windows bundling, then stores private artifacts for 14 days. CI does **not** run ARP redirection, install Npcap, or test the home network.

Developer prerequisites for Windows: Node 22 LTS, stable Rust MSVC, Visual Studio C++ desktop build tools and Windows SDK. Commands on Windows:

```powershell
npm ci
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri build
```

Output: `src-tauri/target/release/bundle/nsis/`. Builds are unsigned and may trigger Windows trust prompts. No public release is created.

Main private source: [MrTayyem/NetPilot](https://github.com/MrTayyem/NetPilot). Build mirror, when created: `tayyemibraheem/NetPilot-build`. Both must remain private; synchronization is an explicit push of the same source commit, with no cross-account credentials stored in the repository. No automatic token-based mirroring is configured.

## First Windows live validation

1. Save work on a single owned test device. Record its real IPv4/MAC, gateway MAC, and normal connectivity before running NetPilot. Keep another device available for recovery. Confirm whether it has IPv6; do not expect IPv6 control.
2. Install Npcap manually, launch NetPilot as administrator, load adapters and choose the extender-connected Ethernet interface. Resolve gateway; confirm the displayed address and MAC. Discovery is on demand only. Verify the owned device, select only it, and use a short one-minute initial lease.
3. Start with generous limits and verify ordinary IPv4 connectivity survives. Independently inspect ARP mappings on owned endpoints where possible: the selected device's gateway and the gateway's selected-device entry should point through the PC during the session. Verify IPv4 frames increment both engine counters; zero in a direction can indicate a failed traffic path.
4. Use your own IPv4 transfer server or a service you are authorized to test. Compare baseline and sustained upload/download separately; e.g. 128 KiB/s upload and 512 KiB/s download. Parallel transfers from the same device must share its directional limit. A second selected device must have independent limits; an unselected device should retain normal operation.
5. Change limits live and confirm the next engine report shows the applied values. Click Block IPv4: selected forwarded IPv4 should stop; IPv6 may still work. Unblock and verify connectivity returns. Do not interpret an IPv6-capable browser loading as proof that IPv4 blocking failed.
6. Stop during traffic. Verify original ARP mappings and normal IPv4 operation return, session exits, and a new session can start. Test lease expiry, closing only UI, force-ending only engine, and force-ending only guardian separately. Do not kill all processes as the first test. The helper processes use the same `netpilot.exe` with `--netpilot-guardian` and `--netpilot-engine` arguments.
7. Test extender isolation or shared MAC refusal without expanding scope to other devices. If a test loses connectivity, stop NetPilot and reconnect the selected device. Record adapter/driver/endpoint behavior before retrying.

## Source map

- `src-tauri/src/model.rs`: validation, ARP frames, IPv4 classification/rewrite, pacing queues, offline tests.
- `pcap.rs`: dynamically loaded Npcap bindings, capture filter, raw transmit, restoration, session mutex.
- `platform.rs`: adapter/neighbor inventory and ordinary SendARP discovery.
- `worker.rs`: guardian, engine, heartbeat/lease handling, forwarding and live rule updates.
- `service.rs`: desktop lifecycle and helper communication.
- `src/main.tsx`: real device/session UI; no mock devices or traffic values.

## Official references

- [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
- [Npcap API and data-link handling](https://npcap.com/guide/wpcap/pcap.html)
- [Npcap packet transmission](https://npcap.com/guide/npcap-tutorial.html)
- [Npcap DLL loading](https://npcap.com/guide/npcap-devguide.html)
- [Npcap nonblocking capture](https://npcap.com/guide/wpcap/pcap_setnonblock.html)
- [Windows SendARP](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp)
- [Windows Get-NetNeighbor](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netneighbor)
