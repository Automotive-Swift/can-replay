from __future__ import annotations

import os
from typing import List, Tuple

from .types import TcpSegment, UdpDatagram


def load_capture(path: str, *, min_tcp_payload: int = 1, min_udp_payload: int = 1) -> Tuple[List[TcpSegment], List[UdpDatagram]]:
    """Load TCP and UDP payload-carrying packets from a capture."""
    path = os.path.expanduser(path)
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapNgReader, PcapReader
    except ImportError as exc:
        raise RuntimeError(
            "scapy is required to parse pcap files. Install it with 'pip install scapy'."
        ) from exc

    tcp_segments: List[TcpSegment] = []
    udp_datagrams: List[UdpDatagram] = []
    reader = None
    try:
        try:
            reader = PcapNgReader(path)
        except (OSError, EOFError):
            reader = PcapReader(path)
        if reader is None:
            return tcp_segments, udp_datagrams
        for pkt in reader:
            if pkt is None:
                continue
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                continue
            try:
                ts = float(pkt.time)  # type: ignore[attr-defined]
            except Exception:
                continue

            tcp = pkt.getlayer(TCP)
            if tcp is not None:
                payload = bytes(tcp.payload)
                if len(payload) >= min_tcp_payload:
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
                    tcp_segments.append(seg)
                continue

            udp = pkt.getlayer(UDP)
            if udp is not None:
                payload = bytes(udp.payload)
                if len(payload) >= min_udp_payload:
                    dat = UdpDatagram(
                        ts=ts,
                        src_ip=str(ip.src),
                        src_port=int(udp.sport),
                        dst_ip=str(ip.dst),
                        dst_port=int(udp.dport),
                        payload=payload,
                    )
                    udp_datagrams.append(dat)
    finally:
        if reader is not None:
            reader.close()

    tcp_segments.sort(key=lambda s: s.ts)
    udp_datagrams.sort(key=lambda d: d.ts)
    return tcp_segments, udp_datagrams


def load_tcp_segments(path: str, *, min_payload: int = 1) -> List[TcpSegment]:
    segments, _ = load_capture(path, min_tcp_payload=min_payload)
    return segments
