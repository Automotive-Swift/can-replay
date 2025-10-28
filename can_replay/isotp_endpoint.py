from __future__ import annotations

import os
import selectors
import socket
import struct
import errno
import time
from typing import Dict, List, Optional, Tuple
from .term import VLogger
from .types import ReplyEvent


# Linux PF_CAN / ISO-TP constants
PF_CAN = 29
AF_CAN = PF_CAN
CAN_ISOTP = 6  # protocol

CAN_EFF_FLAG = 0x80000000


def eff_flag_if_needed(can_id: int) -> int:
    return can_id | CAN_EFF_FLAG if can_id > 0x7FF else can_id


class IsoTpSocket:
    """Thin wrapper over Linux kernel ISO-TP socket.

    Bind with (iface, rx_id, tx_id). Use recv() to get request PDUs and send() to transmit replies.
    """

    def __init__(self, iface: str, rx_id: int, tx_id: int, logger: Optional['VLogger']=None):
        self.iface = iface
        self.rx_id = eff_flag_if_needed(rx_id)
        self.tx_id = eff_flag_if_needed(tx_id)
        self.sock = socket.socket(AF_CAN, socket.SOCK_DGRAM, CAN_ISOTP)
        # bind address tuple: (ifname, rx_id, tx_id)
        self.sock.bind((iface, self.rx_id, self.tx_id))
        self.sock.setblocking(False)
        self.logger = logger

    def fileno(self) -> int:
        return self.sock.fileno()

    def recv(self, bufsize: int = 4095) -> Optional[bytes]:
        try:
            return self.sock.recv(bufsize)
        except BlockingIOError:
            return None
        except OSError as e:
            # Common on ISO-TP when kernel attempts FC/send and fails; treat as transient
            if e.errno in (errno.ECOMM, errno.ENOBUFS, errno.ENETDOWN):
                if self.logger:
                    name = {
                        errno.ECOMM: "ECOMM",
                        errno.ENOBUFS: "ENOBUFS",
                        errno.ENETDOWN: "ENETDOWN",
                    }.get(e.errno, str(e.errno))
                    self.logger.warn(
                        f"ISO-TP recv error on {self.iface} {hex(self.rx_id)}<-{hex(self.tx_id)}: {name}. "
                        f"Peer may not accept/send Flow Control or interface down; continuing."
                    )
                return None
            raise

    def send(self, payload: bytes) -> None:
        # Kernel handles segmentation
        try:
            self.sock.send(payload)
        except OSError as e:
            # Log and ignore transient bus errors
            if e.errno in (errno.ECOMM, errno.ENOBUFS, errno.ENETDOWN):
                if self.logger:
                    name = {
                        errno.ECOMM: "ECOMM",
                        errno.ENOBUFS: "ENOBUFS",
                        errno.ENETDOWN: "ENETDOWN",
                    }.get(e.errno, str(e.errno))
                    self.logger.warn(
                        f"ISO-TP send error on {self.iface} {hex(self.rx_id)}->{hex(self.tx_id)}: {name}. "
                        f"Peer may not send Flow Control for multi-frame response; continuing."
                    )
                return
            raise

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


class IsoTpServer:
    """Manage multiple ISO-TP sockets and route replies based on mapping."""

    def __init__(self, iface: str, pairs: List[Tuple[int, int]], mapping, cycle: bool = True, verbose: bool = False, color: bool | None = None, honor_timing: bool = False, inter_delay: float = 0.02):
        self.iface = iface
        self.pairs = pairs
        self.mapping = mapping
        self.cycle = cycle
        self.socks: Dict[Tuple[int, int], IsoTpSocket] = {}
        # next sequence index per (pair, req_payload)
        self.next_idx: Dict[Tuple[int, int, bytes], int] = {}
        self.sel = selectors.DefaultSelector()
        self.log = VLogger(verbose=verbose, color=color)
        self.honor_timing = honor_timing
        self.inter_delay = inter_delay

    def start(self) -> None:
        for req_id, resp_id in self.pairs:
            sock = IsoTpSocket(self.iface, rx_id=req_id, tx_id=resp_id, logger=self.log)
            self.socks[(req_id, resp_id)] = sock
            self.sel.register(sock.sock, selectors.EVENT_READ, data=(req_id, resp_id))

    def run(self) -> None:
        try:
            while True:
                events = self.sel.select(timeout=1.0)
                for key, mask in events:
                    req_id, resp_id = key.data
                    sock = self.socks[(req_id, resp_id)]
                    payload = sock.recv()
                    if payload is None:
                        continue
                    self._handle_request((req_id, resp_id), payload)
        finally:
            for sock in self.socks.values():
                sock.close()

    def _handle_request(self, pair: Tuple[int, int], req_payload: bytes) -> None:
        req_id, resp_id = pair
        reqmap = self.mapping.get(pair)
        if not reqmap:
            self.log.warn(f"{hex(req_id)}→{hex(resp_id)} no mapping for any requests")
            return
        sequences = reqmap.get(req_payload)
        if not sequences:
            self.log.warn(f"{hex(req_id)} req {req_payload.hex()} → no match")
            return
        idx_key = (req_id, resp_id, req_payload)
        i = self.next_idx.get(idx_key, 0)
        if i >= len(sequences):
            if not self.cycle:
                self.log.note(f"{hex(req_id)} req {req_payload.hex()} matched, but exhausted replies")
                return
            i = 0
        seq: List[ReplyEvent] = sequences[i]
        self.next_idx[idx_key] = (i + 1) if (i + 1) < len(sequences) else (0 if self.cycle else i + 1)
        sock = self.socks[pair]
        start = time.monotonic()
        sent = 0
        for k, ev in enumerate(seq):
            wait = 0.0
            if self.honor_timing:
                elapsed = time.monotonic() - start
                wait = max(0.0, ev.dt - elapsed)
            else:
                # small default gap between intermediate responses
                if k > 0:
                    wait = max(0.0, self.inter_delay)
            if wait > 0:
                time.sleep(wait)
            self.log.ok(f"{hex(req_id)} req {req_payload.hex()} → {hex(resp_id)} resp {ev.payload.hex()} [seq {i+1}/{len(sequences)} step {k+1}/{len(seq)}]")
            sock.send(ev.payload)
            sent += 1
