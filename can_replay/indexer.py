from __future__ import annotations

import json
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from .types import CanFrame, Pair, Mapping, ReplyEvent
from .isotp_reassembly import Reassembler


def build_index(frames: Iterable[CanFrame], pairs: List[Pair], time_window: float = 2.0) -> Mapping:
    """Build mapping of sequences with timing per request.

    Result structure:
      mapping[(req_id, resp_id)][req_payload] = [ [ReplyEvent, ...], [ReplyEvent, ...], ... ]
    """
    mapping: Mapping = {}
    for p in pairs:
        mapping[(p.req_id, p.resp_id)] = defaultdict(list)

    # Per pair state
    ras_req: Dict[Tuple[int, int], Reassembler] = {}
    ras_resp: Dict[Tuple[int, int], Reassembler] = {}
    # pending holds current sequence for an in-flight request
    pending_req: Dict[Tuple[int, int], Tuple[bytes, float, List[ReplyEvent]]] = {}

    def is_intermediate(pdu: bytes) -> bool:
        # UDS NRC 0x7F .. 0x78 (Response Pending)
        return len(pdu) >= 3 and pdu[0] == 0x7F and pdu[2] == 0x78

    for fr in frames:
        for p in pairs:
            dirn = p.direction_of(fr.can_id)
            if not dirn:
                continue
            key = (p.req_id, p.resp_id)
            if dirn == "req":
                ra = ras_req.setdefault(key, Reassembler())
                payload = ra.push(fr.data)
                if payload is not None:
                    # Start new pending sequence for this request occurrence
                    pending_req[key] = (payload, fr.ts, [])
            else:  # resp
                ra = ras_resp.setdefault(key, Reassembler())
                payload = ra.push(fr.data)
                if payload is not None:
                    pend = pending_req.get(key)
                    if pend is None:
                        # No matching request seen (log may start mid-conv) → ignore
                        continue
                    req_payload, t_req, seq = pend
                    if fr.ts - t_req <= time_window:
                        dt = max(0.0, fr.ts - t_req)
                        seq.append(ReplyEvent(payload=payload, dt=dt))
                        # Close the sequence after a final response; leave open for NRC 0x78
                        if not is_intermediate(payload):
                            mapping[key][req_payload].append(seq.copy())
                            # clear pending
                            pending_req.pop(key, None)
                    else:
                        # stale; drop pending and ignore this response
                        pending_req.pop(key, None)

    # Convert defaultdicts to dicts
    norm: Mapping = {}
    for key, d in mapping.items():
        norm[key] = {k: [list(seq) for seq in v] for k, v in d.items()}
    return norm


def save_mapping(mp: Mapping, path: str) -> None:
    serializable = {
        f"{req_id}:{resp_id}": {
            req.hex(): [
                [{"p": ev.payload.hex(), "dt": round(ev.dt, 6)} for ev in seq]
                for seq in sequences
            ]
            for req, sequences in reqmap.items()
        }
        for (req_id, resp_id), reqmap in mp.items()
    }
    with open(path, "w") as f:
        json.dump(serializable, f, indent=2)


def load_mapping(path: str) -> Mapping:
    with open(path, "r") as f:
        data = json.load(f)
    result: Mapping = {}
    for key, reqmap in data.items():
        req_id_s, resp_id_s = key.split(":")
        req_id = int(req_id_s)
        resp_id = int(resp_id_s)
        inner: Dict[bytes, List[List[ReplyEvent]]] = {}
        for req_hex, sequences in reqmap.items():
            key_bytes = bytes.fromhex(req_hex)
            # Backward compatibility: if sequences is a list of hex strings, wrap as single sequence
            if sequences and isinstance(sequences, list) and all(isinstance(x, str) for x in sequences):
                seq = [ReplyEvent(payload=bytes.fromhex(h), dt=0.0) for h in sequences]
                inner[key_bytes] = [seq]
            else:
                seq_list: List[List[ReplyEvent]] = []
                for seq in sequences:
                    evs: List[ReplyEvent] = []
                    for ev in seq:
                        if isinstance(ev, dict):
                            p = bytes.fromhex(ev.get("p", ""))
                            dt = float(ev.get("dt", 0.0))
                        else:
                            # older nested format fallback
                            p = bytes.fromhex(str(ev))
                            dt = 0.0
                        evs.append(ReplyEvent(payload=p, dt=dt))
                    seq_list.append(evs)
                inner[key_bytes] = seq_list
        result[(req_id, resp_id)] = inner
    return result


def detect_pairs(frames: Iterable[CanFrame], max_gap: float = 0.25, min_count: int = 2) -> List[Tuple[int, int]]:
    """Heuristic detection of request/response ID pairs from ISO-TP PDUs.

    - Reassemble PDUs per CAN ID
    - When a PDU from ID A is followed shortly by a PDU from ID B (A!=B), count (A->B)
    - Return pairs with counts >= min_count
    """
    # Reassemble PDUs per ID while keeping timeline
    ras_by_id: Dict[int, Reassembler] = {}
    pdus: List[Tuple[float, int, bytes]] = []
    for fr in frames:
        ra = ras_by_id.setdefault(fr.can_id, Reassembler())
        payload = ra.push(fr.data)
        if payload is not None:
            pdus.append((fr.ts, fr.can_id, payload))
    pdus.sort(key=lambda x: x[0])

    from collections import Counter
    raw_counts: Counter[Tuple[int, int]] = Counter()
    # Role classification: responder if its PDUs look like UDS responses (0x7F or SID|0x40)
    role_votes = {cid: {"resp": 0, "req": 0} for cid in ras_by_id.keys()}
    for _, cid, pdu in pdus:
        if len(pdu) > 0 and (pdu[0] == 0x7F or (pdu[0] & 0x40) != 0):
            role_votes[cid]["resp"] += 1
        else:
            role_votes[cid]["req"] += 1
    is_responder = {cid: (v["resp"] > v["req"]) for cid, v in role_votes.items()}

    n = len(pdus)
    for i in range(n):
        ts_i, id_i, pdu_i = pdus[i]
        if is_responder.get(id_i, False):
            continue  # start from a requester PDU
        # look ahead for first responder PDU within gap
        j = i + 1
        while j < n and pdus[j][0] - ts_i <= max_gap:
            id_j = pdus[j][1]
            if id_j != id_i and is_responder.get(id_j, False):
                raw_counts[(id_i, id_j)] += 1
                break
            j += 1

    pairs = [pair for pair, c in raw_counts.items() if c >= min_count]
    pairs.sort(key=lambda p: raw_counts[p], reverse=True)
    return pairs
