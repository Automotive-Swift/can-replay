from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .types import Mapping, Pair, PairKey, ReplyEvent, TcpSegment


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


def build_index(
    segments: Iterable[TcpSegment],
    pairs: List[Pair],
    time_window: float = 2.0,
) -> Mapping:
    """Build request→response mapping from TCP segments."""
    raw_mapping: Dict[PairKey, Dict[bytes, List[List[ReplyEvent]]]] = {}
    for pair in pairs:
        raw_mapping[pair.key] = defaultdict(list)

    states: Dict[Tuple[PairKey, int, int], _FlowState] = {}

    for seg in segments:
        for pair in pairs:
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
                # stay open for chained responses; finalize when next request arrives
        # end pair loop

    # Finalize remaining states
    for (key, _req_port, _resp_port), state in states.items():
        result = state.finalize()
        if result:
            req_bytes, seq = result
            raw_mapping[key][req_bytes].append(seq)

    normalized: Mapping = {}
    for key, reqmap in raw_mapping.items():
        normalized[key] = {req: [list(seq) for seq in sequences] for req, sequences in reqmap.items()}
    return normalized


def save_mapping(mp: Mapping, path: str) -> None:
    serializable = {}
    for (req_ip, req_port, resp_ip, resp_port), reqmap in mp.items():
        def endpoint(ip: str, port: Optional[int]) -> str:
            if port is None:
                return ip
            return f"{ip}@{port}"

        key = f"{endpoint(req_ip, req_port)}>{endpoint(resp_ip, resp_port)}"
        serializable[key] = {
            req.hex(): [
                [{"p": ev.payload.hex(), "dt": round(ev.dt, 6)} for ev in seq]
                for seq in sequences
            ]
            for req, sequences in reqmap.items()
        }
    with open(path, "w") as f:
        import json

        json.dump(serializable, f, indent=2)


def load_mapping(path: str) -> Mapping:
    with open(path, "r") as f:
        import json

        data = json.load(f)
    result: Mapping = {}
    for key, reqmap in data.items():
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
    return result


def detect_pairs(segments: Iterable[TcpSegment], min_count: int = 5) -> List[Pair]:
    """Heuristic detection of requester/responder IP pairs."""
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
