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
