from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class TcpSegment:
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes
    seq: int
    ack: int
    flags: int


@dataclass(frozen=True)
class Pair:
    req_ip: str
    resp_ip: str
    req_port: Optional[int] = None
    resp_port: Optional[int] = None

    def direction_of(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> str | None:
        if src_ip == self.req_ip and dst_ip == self.resp_ip:
            if self.req_port is not None and src_port != self.req_port:
                return None
            if self.resp_port is not None and dst_port != self.resp_port:
                return None
            return "req"
        if src_ip == self.resp_ip and dst_ip == self.req_ip:
            if self.resp_port is not None and src_port != self.resp_port:
                return None
            if self.req_port is not None and dst_port != self.req_port:
                return None
            return "resp"
        return None

    @property
    def key(self) -> "PairKey":
        return (
            self.req_ip,
            self.req_port,
            self.resp_ip,
            self.resp_port,
        )

    def endpoint_string(self, ip: str, port: Optional[int]) -> str:
        if port is None:
            return ip
        return f"{ip}@{port}"

    def to_string(self) -> str:
        return f"{self.endpoint_string(self.req_ip, self.req_port)}>{self.endpoint_string(self.resp_ip, self.resp_port)}"

    @classmethod
    def from_string(cls, s: str) -> "Pair":
        if ">" in s:
            left, right = s.split(">", 1)
        else:
            # Fallback for colon-delimited storage
            left, right = s.split(":", 1)
        def parse_endpoint(text: str) -> Tuple[str, Optional[int]]:
            text = text.strip()
            if text.startswith("[") and "]" in text:
                host, rest = text[1:].split("]", 1)
                if rest.startswith(":"):
                    port = int(rest[1:])
                    return host, port
                return host, None
            if "@" in text:
                host, port_s = text.split("@", 1)
                return host, int(port_s)
            return text, None
        left_host, left_port = parse_endpoint(left)
        right_host, right_port = parse_endpoint(right)
        return cls(left_host, right_host, left_port, right_port)


@dataclass(frozen=True)
class ReplyEvent:
    payload: bytes
    dt: float


PairKey = Tuple[str, Optional[int], str, Optional[int]]
Mapping = Dict[PairKey, Dict[bytes, List[List[ReplyEvent]]]]

