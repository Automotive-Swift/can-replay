from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple, Dict


@dataclass(frozen=True)
class CanFrame:
    ts: float
    can_id: int
    data: bytes


@dataclass(frozen=True)
class Pair:
    req_id: int
    resp_id: int

    def direction_of(self, can_id: int) -> str | None:
        if can_id == self.req_id:
            return "req"
        if can_id == self.resp_id:
            return "resp"
        return None

@dataclass(frozen=True)
class ReplyEvent:
    payload: bytes
    dt: float  # seconds since request arrival


RequestKey = Tuple[int, int, bytes]  # (req_id, resp_id, payload)
# mapping[(req_id, resp_id)][req_payload] = list of sequences; each sequence is list of ReplyEvent
Mapping = Dict[Tuple[int, int], Dict[bytes, List[List[ReplyEvent]]]]
