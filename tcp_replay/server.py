from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .term import VLogger
from .types import Mapping, Pair, PairKey, ReplyEvent


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


class TcpReplayServer:
    def __init__(
        self,
        host: str,
        port: int,
        pairs: List[Pair],
        mapping: Mapping,
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
        self.cycle = cycle
        self.honor_timing = honor_timing
        self.inter_delay = inter_delay
        self.log = VLogger(verbose=verbose, color=color)
        self.next_idx: Dict[Tuple[PairKey, bytes], int] = {}
        self.lock = asyncio.Lock()
        self.matchers: Dict[PairKey, _RequestMatcher] = {}
        self.pair_by_key: Dict[PairKey, Pair] = {pair.key: pair for pair in pairs}
        for pair in pairs:
            reqmap = mapping.get(pair.key)
            if not reqmap:
                continue
            self.matchers[pair.key] = _RequestMatcher(reqmap)

    async def run(self) -> None:
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
