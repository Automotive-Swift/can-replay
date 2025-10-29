from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .types import (
    Mapping,
    MappingBundle,
    Pair,
    PairKey,
    ReplyEvent,
    TcpSegment,
    UdpDatagram,
    UdpPreamble,
)


@dataclass
class _FlowState:
    req_payload: bytearray = field(default_factory=bytearray)
    req_start: float = 0.0
    seq: List[ReplyEvent] = field(default_factory=list)
    has_request: bool = False
    in_response: bool = False

    def start_request(self, ts: float) -> None:
        if not self.has_request:
            self.req_payload.clear()
            self.req_start = ts
            self.seq.clear()
            self.has_request = True
            self.in_response = False

    def append_request(self, payload: bytes, ts: float) -> None:
        if not self.has_request:
            self.start_request(ts)
        self.req_payload.extend(payload)
        self.in_response = False

    def append_response(self, payload: bytes, dt: float) -> None:
        if not self.has_request:
            return
        self.seq.append(ReplyEvent(payload=bytes(payload), dt=max(0.0, dt)))
        self.in_response = True

    def finalize(self) -> Optional[Tuple[bytes, List[ReplyEvent]]]:
        if self.has_request and self.seq and self.req_payload:
            req_bytes = bytes(self.req_payload)
            seq_copy = list(self.seq)
            self.reset()
            return req_bytes, seq_copy
        self.reset()
        return None

    def drop(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.req_payload.clear()
        self.seq.clear()
        self.has_request = False
        self.in_response = False
        self.req_start = 0.0


@dataclass
class _Orientation:
    client_ip: str
    server_ip: str
    request: UdpDatagram
    response: UdpDatagram


def build_index(
    segments: Iterable[TcpSegment],
    pairs: List[Pair],
    udp_datagrams: Optional[Iterable[UdpDatagram]] = None,
    time_window: float = 2.0,
) -> MappingBundle:
    """Build request→response mapping from TCP segments, orient pairs, and detect UDP discovery preambles."""
    seg_list: List[TcpSegment] = list(segments)
    udp_list: List[UdpDatagram] = list(udp_datagrams or [])

    # Determine earliest TCP activity per unordered IP pair
    first_contact: Dict[frozenset[str], float] = {}
    for seg in seg_list:
        key = frozenset({seg.src_ip, seg.dst_ip})
        first_contact.setdefault(key, seg.ts)

    orientation_map = _infer_udp_orientation(pairs, udp_list, first_contact)

    # Adjust pairs to ensure requester→responder orientation
    adjusted_pairs: List[Pair] = []
    seen_keys: set[PairKey] = set()
    for pair in pairs:
        key = frozenset({pair.req_ip, pair.resp_ip})
        orient = orientation_map.get(key)
        if orient:
            pair = Pair(req_ip=orient.client_ip, resp_ip=orient.server_ip)
        if pair.key not in seen_keys:
            seen_keys.add(pair.key)
            adjusted_pairs.append(pair)

    raw_mapping: Dict[PairKey, Dict[bytes, List[List[ReplyEvent]]]] = {
        pair.key: defaultdict(list) for pair in adjusted_pairs
    }

    states: Dict[Tuple[PairKey, int, int], _FlowState] = {}
    first_request_ts: Dict[PairKey, float] = {}
    port_hints: Dict[PairKey, Tuple[int, int]] = {}

    for seg in seg_list:
        for pair in adjusted_pairs:
            dirn = pair.direction_of(seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port)
            if dirn is None:
                continue
            key = pair.key
            if dirn == "req":
                conn_key = (key, seg.src_port, seg.dst_port)
                state = states.setdefault(conn_key, _FlowState())
                if state.in_response and state.seq:
                    result = state.finalize()
                    if result:
                        req_bytes, seq = result
                        raw_mapping[key][req_bytes].append(seq)
                state.start_request(seg.ts)
                state.append_request(seg.payload, seg.ts)
                if key not in first_request_ts:
                    first_request_ts[key] = seg.ts
                    port_hints[key] = (seg.src_port, seg.dst_port)
            else:
                conn_key = (key, seg.dst_port, seg.src_port)
                state = states.get(conn_key)
                if state is None or not state.has_request:
                    continue
                dt = seg.ts - state.req_start
                if dt > time_window:
                    state.drop()
                    continue
                state.append_response(seg.payload, dt)
                if len(state.seq) == 0:
                    continue

    # Finalize remaining states
    for (key, _req_port, _resp_port), state in states.items():
        result = state.finalize()
        if result:
            req_bytes, seq = result
            raw_mapping[key][req_bytes].append(seq)

    normalized: Mapping = {}
    for key, reqmap in raw_mapping.items():
        normalized[key] = {req: [list(seq) for seq in sequences] for req, sequences in reqmap.items()}

    preambles: List[UdpPreamble] = []
    for key, orient in orientation_map.items():
        pair = Pair(req_ip=orient.client_ip, resp_ip=orient.server_ip)
        pair_key = pair.key
        if pair_key not in normalized:
            continue
        dt = max(0.0, orient.response.ts - orient.request.ts)
        preambles.append(
            UdpPreamble(
                pair_key=pair_key,
                listen_port=orient.response.src_port,
                request_payload=orient.request.payload,
                response_payload=orient.response.payload,
                dt=dt,
                request_dst_ip=orient.request.dst_ip,
                response_src_ip=orient.response.src_ip,
            )
        )

    return MappingBundle(requests=normalized, udp_preambles=preambles, tcp_ports=port_hints)


def _infer_udp_orientation(
    pairs: List[Pair],
    udp_datagrams: List[UdpDatagram],
    first_contact: Dict[frozenset[str], float],
    max_gap: float = 5.0,
) -> Dict[frozenset[str], _Orientation]:
    if not udp_datagrams:
        return {}
    udp_sorted = sorted(udp_datagrams, key=lambda d: d.ts)
    orientation: Dict[frozenset[str], _Orientation] = {}

    for pair in pairs:
        key = frozenset({pair.req_ip, pair.resp_ip})
        if key in orientation:
            continue
        fc = first_contact.get(key)
        if fc is None:
            continue
        req_candidate: Optional[UdpDatagram] = None
        resp_candidate: Optional[UdpDatagram] = None
        for dat in udp_sorted:
            if dat.ts - fc > max_gap:
                break
            if dat.src_ip not in key:
                continue
            if not (_is_broadcast_or_multicast(dat.dst_ip) or dat.dst_ip in key):
                continue
            if req_candidate is None:
                req_candidate = dat
                continue
            if dat.src_ip == req_candidate.src_ip:
                continue
            resp_candidate = dat
            break
        if req_candidate and resp_candidate:
            # Heuristic: request payloads are typically smaller than responses
            if len(req_candidate.payload) > len(resp_candidate.payload):
                req_candidate, resp_candidate = resp_candidate, req_candidate
            orientation[key] = _Orientation(
                client_ip=req_candidate.src_ip,
                server_ip=resp_candidate.src_ip,
                request=req_candidate,
                response=resp_candidate,
            )
    return orientation


def save_mapping(bundle: MappingBundle, path: str) -> None:
    serializable = {
        "pairs": {},
    }
    for (req_ip, req_port, resp_ip, resp_port), reqmap in bundle.requests.items():
        def endpoint(ip: str, port: Optional[int]) -> str:
            if port is None:
                return ip
            return f"{ip}@{port}"

        key = f"{endpoint(req_ip, req_port)}>{endpoint(resp_ip, resp_port)}"
        serializable["pairs"][key] = {
            req.hex(): [
                [{"p": ev.payload.hex(), "dt": round(ev.dt, 6)} for ev in seq]
                for seq in sequences
            ]
            for req, sequences in reqmap.items()
        }
    if bundle.udp_preambles:
        serializable["udp_preambles"] = [
            {
                "pair": key_to_string(pre.pair_key),
                "listen_port": pre.listen_port,
                "request": pre.request_payload.hex(),
                "response": pre.response_payload.hex(),
                "dt": round(pre.dt, 6),
                "request_dst_ip": pre.request_dst_ip,
                "response_src_ip": pre.response_src_ip,
            }
            for pre in bundle.udp_preambles
        ]
    if bundle.tcp_ports:
        serializable["tcp_ports"] = {
            key_to_string(pair_key): [ports[0], ports[1]]
            for pair_key, ports in bundle.tcp_ports.items()
        }
    with open(path, "w") as f:
        import json

        json.dump(serializable, f, indent=2)


def load_mapping(path: str) -> MappingBundle:
    with open(path, "r") as f:
        import json

        data = json.load(f)
    if isinstance(data, dict) and "pairs" in data:
        pairs_section = data.get("pairs", {})
        udp_section = data.get("udp_preambles", [])
        tcp_ports_section = data.get("tcp_ports", {})
    else:
        pairs_section = {k: v for k, v in data.items() if k not in ("udp_preambles", "tcp_ports")}
        udp_section = data.get("udp_preambles", []) if isinstance(data, dict) else []
        tcp_ports_section = data.get("tcp_ports", {}) if isinstance(data, dict) else {}
    result: Mapping = {}
    for key, reqmap in pairs_section.items():
        pair = Pair.from_string(key)
        pair_key = pair.key
        inner: Dict[bytes, List[List[ReplyEvent]]] = {}
        for req_hex, sequences in reqmap.items():
            req_bytes = bytes.fromhex(req_hex)
            seq_list: List[List[ReplyEvent]] = []
            for seq in sequences:
                events: List[ReplyEvent] = []
                for ev in seq:
                    if isinstance(ev, dict):
                        payload = bytes.fromhex(ev.get("p", ""))
                        dt = float(ev.get("dt", 0.0))
                    else:
                        payload = bytes.fromhex(str(ev))
                        dt = 0.0
                    events.append(ReplyEvent(payload=payload, dt=dt))
                seq_list.append(events)
            inner[req_bytes] = seq_list
        result[pair_key] = inner
    preambles: List[UdpPreamble] = []
    if isinstance(udp_section, list):
        for entry in udp_section:
            try:
                parsed_pair = Pair.from_string(entry["pair"])
                pair_key = parsed_pair.key
                listen_port = int(entry["listen_port"])
                request_payload = bytes.fromhex(entry.get("request", ""))
                response_payload = bytes.fromhex(entry.get("response", ""))
                dt = float(entry.get("dt", 0.0))
                request_dst_ip = str(entry.get("request_dst_ip", ""))
                preambles.append(
                    UdpPreamble(
                        pair_key=pair_key,
                        listen_port=listen_port,
                        request_payload=request_payload,
                        response_payload=response_payload,
                        dt=dt,
                        request_dst_ip=request_dst_ip,
                        response_src_ip=str(entry.get("response_src_ip", parsed_pair.resp_ip)),
                    )
                )
            except Exception:
                continue
    tcp_ports: Dict[PairKey, Tuple[int, int]] = {}
    if isinstance(tcp_ports_section, dict):
        for key, ports in tcp_ports_section.items():
            try:
                pair_key = Pair.from_string(key).key
                if isinstance(ports, (list, tuple)) and len(ports) == 2:
                    tcp_ports[pair_key] = (int(ports[0]), int(ports[1]))
            except Exception:
                continue
    return MappingBundle(requests=result, udp_preambles=preambles, tcp_ports=tcp_ports)


def detect_pairs(segments: Iterable[TcpSegment], min_count: int = 5) -> List[Pair]:
    """Heuristic detection of requester/responder IP pairs from TCP traffic."""
    from collections import defaultdict

    conn_roles: Dict[Tuple[str, int, str, int], Tuple[str, str]] = {}
    pair_counts = defaultdict(lambda: {"req": 0, "resp": 0})

    for seg in segments:
        key = (seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port)
        rev = (seg.dst_ip, seg.dst_port, seg.src_ip, seg.src_port)
        role = conn_roles.get(key)
        if role is None:
            if rev in conn_roles:
                role = conn_roles[rev]
            else:
                role = (seg.src_ip, seg.dst_ip)
                conn_roles[key] = role
                conn_roles[rev] = role
        req_ip, resp_ip = role
        if seg.src_ip == req_ip and seg.dst_ip == resp_ip:
            pair_counts[(req_ip, resp_ip)]["req"] += 1
        elif seg.src_ip == resp_ip and seg.dst_ip == req_ip:
            pair_counts[(req_ip, resp_ip)]["resp"] += 1

    pairs: List[Pair] = []
    for (req_ip, resp_ip), counts in pair_counts.items():
        if counts["req"] >= min_count and counts["resp"] >= 1:
            pairs.append(Pair(req_ip=req_ip, resp_ip=resp_ip))
    pairs.sort(key=lambda p: pair_counts[(p.req_ip, p.resp_ip)]["req"], reverse=True)
    return pairs


def key_to_string(key: PairKey) -> str:
    req_ip, req_port, resp_ip, resp_port = key

    def endpoint(ip: str, port: Optional[int]) -> str:
        if port is None:
            return ip
        return f"{ip}@{port}"

    return f"{endpoint(req_ip, req_port)}>{endpoint(resp_ip, resp_port)}"


def _is_broadcast_or_multicast(ip: str) -> bool:
    if not ip:
        return False
    lowered = ip.lower()
    if lowered == "255.255.255.255":
        return True
    if lowered.startswith("255."):
        return True
    if ":" in lowered:
        return lowered.startswith("ff")
    try:
        parts = [int(part) for part in ip.split(".")]
        if len(parts) == 4 and 224 <= parts[0] <= 239:
            return True
    except ValueError:
        return False
    return False
