Replay tools for automated vehicle tests
========================================

These utilities let you capture real ECUs or infotainment traffic once and replay the exact responses later. They are handy for regression testing diagnostic scripts, keeping automated integration rigs deterministic, or mocking hard-to-access vehicle modules without booting the entire vehicle network.

Motivation
----------
- Replace flaky test benches with deterministic request/response playback.
- Verify ECU flashers, diagnostics, or telematics flows without generating real bus traffic.
- Feed simulated clients (Telnet, TCP, or ISO-TP) with recorded answers while you iterate on tooling.

can-replay
==========

A small Python 3 CLI to replay ISO-TP replies based on a CAN log, using Linux socketcan + kernel ISO-TP sockets.

Features
- Parse common candump-style logs (auto-detect) and reconstruct ISO-TP PDUs
- Parse CL1000 CSV logs (Timestamp;Type;ID;Data) and reconstruct ISO-TP PDUs
- Build a mapping of request payload → list of reply payloads, per arbitration ID pair
- Serve as an ISO-TP responder on a socketcan interface for 11-bit and 29-bit IDs
- For multiple replies to the same request, cycle through them consecutively
- Optional colorful logs to show request matches and replies
 - Intermediate responses: supports NRC 0x7F .. 0x78 (response pending). When present, they are sent before the final response for a single request.

Requirements
- Linux with socketcan and ISO-TP support (CONFIG_CAN_ISOTP)
- Python 3.9+
- A socketcan interface (e.g., `can0`)

Install (editable)
- `pip install -e .`

Basic usage
- Build and replay in one go:
  `can-replay -i can0 --log /path/to/log.txt --pair 0x7E0:0x7E8 --pair 0x700:0x708`

- Or split steps:
  1) Build mapping from log:
     `can-replay build-index --log vehical_patchv2_log.TXT --pair 0x7E0:0x7E8 -o mapping.json`
  2) Run responder from mapping:
     `can-replay replay -i can0 --mapping mapping.json`
- Drill into logged data:
  `can-replay build-index --log vehical_patchv2_log.TXT --pair 0x7E0:0x7E8 --time-window 1.5 -o uds_mapping.json`
- Replay with deterministic timing:
  `can-replay replay --mapping uds_mapping.json --honor-timing -v`

Flags
- `--pair REQ:RESP`  Hex IDs for request and reply. Repeatable.
- `--iface IFACE`    Socketcan interface (default: can0)
- `--time-window S`  Max seconds from request to match reply (default: 2.0)
- `--cycle/--exhaust` Cycle responses per request (default: cycle)
- `-v/--verbose`     Show colored match logs
- `--no-color`       Disable ANSI colors in logs
 - `--honor-timing`  Honor request→response timing from the log (default off)

Notes
- Extended addressing (ISO-TP data byte addressing) is not used.
- Only normal addressing is supported; both 11 and 29-bit arbitration IDs work.
- If your log format is unusual, use `--format` to force `candump_basic`, `candump_bracket`, `cl1000_csv`, or `auto`.

Auto-detecting ID pairs
- If you do not pass any `--pair`, the tool will infer request→response pairs from the log using ISO-TP PDU timing.
- If you pass at least one `--pair`, auto-detection is skipped.

Behavioral notes
- Logs that start with responses or mid-ISO-TP sequences are ignored for pairing and indexing; only complete reassembled PDUs are used.
- During replay, unmatched requests are logged (when `-v` is enabled) and no reply is sent.
 - When a request maps to multiple responses (e.g., one or more NRC 7F .. 78 followed by a final response), the tool sends the sequence. With `--honor-timing`, inter-response delays match the log.

enet-replay
===========

A companion CLI that replays TCP replies based on a captured pcap/pcapng conversation. It analyzes requester/responder IP pairs and replays the recorded responses over a normal TCP socket.

Features
- Parse pcap/pcapng using scapy and extract TCP payload exchanges.
- Build request payload → sequence of response payloads per requester/responder IP pair.
- Serve the recorded replies from a configurable TCP listening address with optional timing preservation.
- Cycle through multiple recorded sequences for the same request (or exhaust once).
- Colored verbose logs matching requests to responses.
- Detect UDP discovery preambles (broadcast/multicast) that precede the TCP session and replay the discovery replies automatically.
- Preserve the recorded responder/source IP so clients can immediately connect to the replay host, with optional raw-packet spoofing when run with the necessary privileges.

Requirements
- Python 3.9+
- scapy (installed automatically via `pip install -e .`)
- A TCP capture containing the conversation you wish to replay.

Basic usage
- Build mapping JSON from capture:
  `enet-replay build-index --pcap capture.pcapng --pair 192.168.0.100:192.168.0.200 -o tcp_mapping.json`

- Run TCP reply server directly from capture:
  `enet-replay --pcap capture.pcapng --listen 0.0.0.0:502 --pair 192.168.0.100:192.168.0.200`

- Or replay from a saved mapping:
  `enet-replay replay --mapping tcp_mapping.json --listen 0.0.0.0:502 -v`
- Craft ad-hoc sequences for quick tests:
  1) Create `hello.json` with sample request/response pairs.
  2) `enet-replay replay --mapping hello.json --listen 127.0.0.1:2323 -v`
  3) Connect via Telnet and send `hello` to cycle through the canned replies.
- Build and replay in one command:
  `enet-replay --pcap ~/Downloads/vehical_tcp.pcapng --listen [::]:8000 --exhaust`

When a UDP discovery preamble is found, the CLI prints which port and pair were detected, and the replay process enables a UDP listener alongside the TCP server. Point your discovery probe (e.g., broadcast or multicast ping) at the recorded port and the tool will answer with the captured payload before continuing the TCP conversation.

Tips
- The `build-index` command prints the client→server TCP ports captured for each pair. Run the replay server on the same server port (e.g., `--listen 0.0.0.0:6801`) so downstream clients connect successfully.
- Some discovery protocols expect the response to originate from the recorded ECU IP (e.g., a link-local address that is not configured on your host). Run the replay as root (or capture/forge packets with the necessary privileges) so the UDP responder can spoof the source IP, or manually assign an alias IP to your interface before starting `enet-replay`.
- If you cannot spoof the recorded IP, pass `--udp-src-ip <your_host_ip>` so discovery replies advertise an address your machine actually owns.
- If you need to force the announcer IP, you can edit the generated `tcp_mapping.json` preamble section or provide your own mapping file that matches your test environment.

Flags mirror the CAN tool where possible (`--pair`, `--time-window`, `--exhaust`, `--honor-timing`, etc.). For IPv6 endpoints, use `@` to specify ports (e.g., `[fe80::1]@502`). If no `--pair` is provided, the tool attempts to detect requesters and responders heuristically from the capture.
