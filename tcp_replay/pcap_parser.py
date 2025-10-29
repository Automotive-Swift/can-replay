from __future__ import annotations

from typing import Iterable, Iterator, List, Optional

from .types import TcpSegment


def _iter_tcp_packets(path: str):
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapNgReader, PcapReader
    except ImportError as exc:
        raise RuntimeError(
            "scapy is required to parse pcap files. Install it with 'pip install scapy'."
        ) from exc

    reader = None
    try:
        try:
            reader = PcapNgReader(path)
        except (OSError, EOFError):
            reader = PcapReader(path)
        if reader is None:
            return
        for pkt in reader:
            if pkt is None:
                continue
            if TCP not in pkt:
                continue
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                continue
            tcp = pkt.getlayer(TCP)
            if tcp is None:
                continue
            yield pkt, ip, tcp
    finally:
        if reader is not None:
            reader.close()


def load_tcp_segments(path: str, *, min_payload: int = 1) -> List[TcpSegment]:
    """Load TCP segments with payload >= min_payload bytes from a pcap/pcapng file."""
    segments: List[TcpSegment] = []
    for pkt, ip, tcp in _iter_tcp_packets(path):
        payload = bytes(tcp.payload)
        if len(payload) < min_payload:
            continue
        try:
            ts = float(pkt.time)  # type: ignore[attr-defined]
        except Exception:
            continue
        seg = TcpSegment(
            ts=ts,
            src_ip=str(ip.src),
            src_port=int(tcp.sport),
            dst_ip=str(ip.dst),
            dst_port=int(tcp.dport),
            payload=payload,
            seq=int(tcp.seq),
            ack=int(tcp.ack),
            flags=int(tcp.flags),
        )
        segments.append(seg)
    segments.sort(key=lambda s: s.ts)
    return segments
