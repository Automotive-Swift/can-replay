from __future__ import annotations

import asyncio
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .term import VLogger
from .types import Mapping, Pair, PairKey, ReplyEvent, UdpPreamble

try:
    from scapy.all import IP, UDP, Raw, send
except ImportError:  # pragma: no cover - optional
    send = None


class _RequestMatcher:
    def __init__(self, reqmap: Dict[bytes, List[List[ReplyEvent]]]):
        self.reqmap = reqmap
        self.by_first: Dict[int, List[bytes]] = {}
        for key in reqmap.keys():
            if not key:
                continue
            first = key[0]
            self.by_first.setdefault(first, []).append(key)

    def find(self, buffer: bytearray) -> Tuple[Optional[bytes], str]:
        if not buffer:
            return None, "empty"
        first = buffer[0]
        candidates = self.by_first.get(first)
        if not candidates:
            return None, "mismatch"
        partial = False
        view = bytes(buffer)
        for key in candidates:
            if len(view) < len(key):
                if key.startswith(view):
                    partial = True
            elif view.startswith(key):
                return key, "match"
        return None, "partial" if partial else "mismatch"


@dataclass
class _ClientState:
    pair_key: PairKey
    matcher: _RequestMatcher
    buffer: bytearray = field(default_factory=bytearray)


class _UdpDiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        preamble: UdpPreamble,
        pair_label: str,
        log: VLogger,
        honor_timing: bool,
        override_src_ip: Optional[str] = None,
    ):
        self.preamble = preamble
        self.pair_label = pair_label
        self.log = log
        self.honor_timing = honor_timing
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.override_src_ip = override_src_ip

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self.log.note(
            f"UDP discovery listener ready on port {self.preamble.listen_port} for {self.pair_label}"
        )

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if data != self.preamble.request_payload:
            return
        loop = asyncio.get_running_loop()

        async def send_response() -> None:
            if self.honor_timing and self.preamble.dt > 0:
                await asyncio.sleep(self.preamble.dt)
            if isinstance(addr, tuple):
                host = addr[0]
                port = addr[1] if len(addr) > 1 else None
            else:
                host, port = str(addr), None
            sent_with_scapy = False
            send_src_ip = self.override_src_ip or self.preamble.response_src_ip
            if send is not None and port is not None and send_src_ip:
                try:
                    pkt = IP(src=send_src_ip, dst=host) / UDP(
                        sport=self.preamble.listen_port,
                        dport=port,
                    ) / Raw(load=self.preamble.response_payload)
                    send(pkt, verbose=False)
                    sent_with_scapy = True
                except Exception as exc:  # pragma: no cover - raw send failure
                    self.log.warn(
                        f"UDP discovery {self.pair_label} raw send failed ({exc}); falling back to socket"
                    )
            if not sent_with_scapy:
                if self.transport is None:
                    return
                self.transport.sendto(self.preamble.response_payload, addr)
            port_repr = port if port is not None else "?"
            self.log.ok(
                f"UDP discovery {self.pair_label} matched from {host}:{port_repr} "
                f"→ sent {len(self.preamble.response_payload)} bytes"
            )

        loop.create_task(send_response())


class TcpReplayServer:
    def __init__(
        self,
        host: str,
        port: int,
        pairs: List[Pair],
        mapping: Mapping,
        udp_preambles: Optional[List[UdpPreamble]] = None,
        udp_override_src_ip: Optional[str] = None,
        cycle: bool = True,
        verbose: bool = False,
        color: bool | None = None,
        honor_timing: bool = False,
        inter_delay: float = 0.02,
    ):
        self.host = host
        self.port = port
        self.pairs = pairs
        self.mapping = mapping
        self.udp_preambles = list(udp_preambles or [])
        self.udp_override_src_ip = udp_override_src_ip
        self.cycle = cycle
        self.honor_timing = honor_timing
        self.inter_delay = inter_delay
        self.log = VLogger(verbose=verbose, color=color)
        self.next_idx: Dict[Tuple[PairKey, bytes], int] = {}
        self.lock = asyncio.Lock()
        self.matchers: Dict[PairKey, _RequestMatcher] = {}
        self.pair_by_key: Dict[PairKey, Pair] = {pair.key: pair for pair in pairs}
        self.udp_transports: List[asyncio.DatagramTransport] = []
        self.udp_protocols: List['_UdpDiscoveryProtocol'] = []
        for pair in pairs:
            reqmap = mapping.get(pair.key)
            if not reqmap:
                continue
            self.matchers[pair.key] = _RequestMatcher(reqmap)

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        await self._start_udp_listeners(loop)
        server = await asyncio.start_server(self._handle_client, self.host, self.port)
        sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
        self.log.note(f"Starting TCP replay on {sockets} for pairs: " + ", ".join(p.to_string() for p in self.pairs))
        try:
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            raise
        finally:
            server.close()
            await server.wait_closed()
            self._stop_udp_listeners()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if isinstance(peer, (tuple, list)) and len(peer) >= 1 else str(peer)
        pair = self._select_pair_for_peer(peer_ip)
        if pair is None:
            self.log.warn(f"Peer {peer} does not match any pair; closing connection.")
            writer.close()
            await writer.wait_closed()
            return
        matcher = self.matchers.get(pair.key)
        if matcher is None:
            self.log.warn(f"No mapping for pair {pair.to_string()}; closing connection.")
            writer.close()
            await writer.wait_closed()
            return
        state = _ClientState(pair_key=pair.key, matcher=matcher, buffer=bytearray())
        self.log.note(f"Client {peer} attached to pair {pair.to_string()}")
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                state.buffer.extend(data)
                await self._process_buffer(state, writer)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.log.err(f"Client {peer} error: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self.log.note(f"Client {peer} disconnected")

    def _select_pair_for_peer(self, peer_ip: str) -> Optional[Pair]:
        for pair in self.pairs:
            if pair.req_ip == peer_ip:
                return pair
        return self.pairs[0] if self.pairs else None

    async def _process_buffer(self, state: _ClientState, writer: asyncio.StreamWriter) -> None:
        while state.buffer:
            req_payload, status = state.matcher.find(state.buffer)
            if req_payload is not None:
                sequence = await self._next_sequence(state.pair_key, req_payload)
                if sequence is None:
                    self.log.warn(f"No sequence for request {req_payload.hex()} on pair {self._pair_string(state.pair_key)}")
                    del state.buffer[:len(req_payload)]
                    continue
                await self._send_sequence(writer, state.pair_key, req_payload, sequence)
                del state.buffer[:len(req_payload)]
                continue
            if status == "partial":
                return
            if status == "mismatch":
                if state.buffer:
                    snippet = bytes(state.buffer[:16]).hex()
                    self.log.warn(f"Unrecognized request prefix {snippet}; clearing buffer")
                state.buffer.clear()
                return
            return

    async def _next_sequence(self, pair_key: PairKey, req_payload: bytes) -> Optional[List[ReplyEvent]]:
        reqmap = self.mapping.get(pair_key)
        if not reqmap:
            return None
        sequences = reqmap.get(req_payload)
        if not sequences:
            return None
        idx_key = (pair_key, req_payload)
        async with self.lock:
            idx = self.next_idx.get(idx_key, 0)
            if idx >= len(sequences):
                if not self.cycle:
                    return None
                idx = 0
            sequence = sequences[idx]
            next_idx = idx + 1
            if next_idx >= len(sequences):
                next_idx = 0 if self.cycle else idx + 1
            self.next_idx[idx_key] = next_idx
        return sequence

    async def _send_sequence(
        self,
        writer: asyncio.StreamWriter,
        pair_key: PairKey,
        req_payload: bytes,
        sequence: List[ReplyEvent],
    ) -> None:
        req_ip, req_port, resp_ip, resp_port = pair_key
        start = time.monotonic()
        for idx, ev in enumerate(sequence):
            if self.honor_timing:
                elapsed = time.monotonic() - start
                wait = max(0.0, ev.dt - elapsed)
                if wait > 0:
                    await asyncio.sleep(wait)
            else:
                if idx > 0 and self.inter_delay > 0:
                    await asyncio.sleep(self.inter_delay)
            writer.write(ev.payload)
            await writer.drain()
            self.log.ok(
                f"{req_ip} req {req_payload.hex()} → {resp_ip} resp {ev.payload.hex()} "
                f"[step {idx + 1}/{len(sequence)}]"
            )

    def _pair_string(self, pair_key: PairKey) -> str:
        pair = self.pair_by_key.get(pair_key)
        return pair.to_string() if pair else str(pair_key)

    async def _start_udp_listeners(self, loop: asyncio.AbstractEventLoop) -> None:
        if not self.udp_preambles:
            return
        for pre in self.udp_preambles:
            try:
                sock = self._make_udp_socket(pre)
            except OSError as exc:
                self.log.err(f"Unable to bind UDP listener on port {pre.listen_port}: {exc}")
                continue
            try:
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda pre=pre: _UdpDiscoveryProtocol(
                        pre,
                        self._pair_string(pre.pair_key),
                        self.log,
                        self.honor_timing,
                        override_src_ip=self.udp_override_src_ip,
                    ),
                    sock=sock,
                )
                self.udp_transports.append(transport)
                self.udp_protocols.append(protocol)
            except Exception as exc:
                self.log.err(f"Failed to start UDP discovery listener on port {pre.listen_port}: {exc}")
                try:
                    sock.close()
                except Exception:
                    pass

    def _stop_udp_listeners(self) -> None:
        for transport in self.udp_transports:
            try:
                transport.close()
            except Exception:
                pass
        self.udp_transports.clear()
        self.udp_protocols.clear()

    def _make_udp_socket(self, pre: UdpPreamble) -> socket.socket:
        ipv6 = ":" in pre.request_dst_ip
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        bind_addr = ("::", pre.listen_port) if ipv6 else ("0.0.0.0", pre.listen_port)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if not ipv6:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(bind_addr)
        if not ipv6 and _is_ipv4_multicast(pre.request_dst_ip):
            try:
                mreq = struct.pack("=4s4s", socket.inet_aton(pre.request_dst_ip), socket.inet_aton("0.0.0.0"))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError:
                pass
        return sock


def _is_ipv4_multicast(ip: str) -> bool:
    if not ip:
        return False
    try:
        first = int(ip.split(".", 1)[0])
        return 224 <= first <= 239
    except (ValueError, IndexError):
        return False
