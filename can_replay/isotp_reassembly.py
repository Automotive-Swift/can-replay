from __future__ import annotations

from typing import Optional, Tuple


class Reassembler:
    """Minimal ISO-TP reassembler for normal addressing (no extended addressing).

    - Supports 11-bit and 29-bit arbitration IDs (handled outside via ID value)
    - Ignores Flow Control frames (PCI type 0x3) for purposes of payload reassembly
    - Returns completed payloads as bytes
    """

    def __init__(self) -> None:
        self._buffer: bytearray | None = None
        self._expected_len: int | None = None
        self._next_sn: int = 1

    def push(self, data: bytes) -> Optional[bytes]:
        if not data:
            return None
        pci = data[0]
        ptype = (pci & 0xF0) >> 4
        if ptype == 0x0:  # Single Frame
            sf_len = pci & 0x0F
            payload = data[1:1 + sf_len]
            self._reset()
            return bytes(payload)
        elif ptype == 0x1:  # First Frame
            # 12-bit length: low nibble of first byte + next byte
            total_len = ((pci & 0x0F) << 8) | data[1]
            self._buffer = bytearray()
            self._expected_len = total_len
            self._next_sn = 1
            # FF contains first 6 payload bytes (bytes 2..7)
            chunk = data[2:]
            self._buffer.extend(chunk)
            return None
        elif ptype == 0x2:  # Consecutive Frame
            if self._buffer is None or self._expected_len is None:
                # Unexpected CF
                self._reset()
                return None
            sn = pci & 0x0F
            # do not enforce SN strictly, but reset if grossly invalid
            if sn != (self._next_sn & 0x0F):
                # out of sequence; reset
                self._reset()
                return None
            self._next_sn += 1
            # CF contains up to 7 bytes payload
            space_left = self._expected_len - len(self._buffer)
            if space_left <= 0:
                self._reset()
                return None
            chunk = data[1:1 + min(7, space_left)]
            self._buffer.extend(chunk)
            if len(self._buffer) >= self._expected_len:
                payload = bytes(self._buffer[: self._expected_len])
                self._reset()
                return payload
            return None
        elif ptype == 0x3:  # Flow Control (ignore for payload extraction)
            return None
        else:
            # Unknown / unsupported
            self._reset()
            return None

    def _reset(self) -> None:
        self._buffer = None
        self._expected_len = None
        self._next_sn = 1

