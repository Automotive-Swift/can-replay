from __future__ import annotations

import re
from typing import Iterable, List, Optional

from .types import CanFrame


_RE_CAN_BARE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+(?P<iface>\w+)\s+(?P<id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)$"
)

_RE_CAN_BRACKET = re.compile(
    r"^(?:\((?P<ts>\d+(?:\.\d+)?)\)\s+)?(?P<iface>\w+)\s+(?P<id>[0-9A-Fa-f]+)\s+\[(?P<dlc>\d+)\]\s+(?P<bytes>(?:[0-9A-Fa-f]{2}\s*)+)$"
)


class LogFormat:
    AUTO = "auto"
    CANDUMP_BASIC = "candump_basic"  # e.g., "123#112233"
    CANDUMP_BRACKET = "candump_bracket"  # e.g., "can0 123 [8] 11 22 ..."
    CL1000_CSV = "cl1000_csv"  # e.g., "Timestamp;Type;ID;Data" rows


def _parse_cl1000_time(ts_field: str) -> float:
    # Examples: "01T000036334" => 00:00:36.334 (ignore day)
    if "T" in ts_field:
        _, timepart = ts_field.split("T", 1)
    else:
        timepart = ts_field
    timepart = timepart.strip()
    # Expect HHMMSSmmm (9 digits), but be tolerant
    digits = ''.join(ch for ch in timepart if ch.isdigit())
    if len(digits) >= 6:
        # Pad to at least 7 to have ms
        if len(digits) < 9:
            digits = digits.ljust(9, '0')
        hh = int(digits[0:2])
        mm = int(digits[2:4])
        ss = int(digits[4:6])
        ms = int(digits[6:9])
        return hh * 3600 + mm * 60 + ss + ms / 1000.0
    # fallback to float
    try:
        return float(ts_field)
    except ValueError:
        return 0.0


def parse_log(lines: Iterable[str], fmt: str = LogFormat.AUTO) -> List[CanFrame]:
    frames: List[CanFrame] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        fr: Optional[CanFrame] = None

        if fmt in (LogFormat.AUTO, LogFormat.CANDUMP_BASIC):
            m = _RE_CAN_BARE.match(line)
            if m:
                ts = float(m.group("ts"))
                can_id = int(m.group("id"), 16)
                data_hex = m.group("data")
                data = bytes.fromhex(data_hex) if data_hex else b""
                fr = CanFrame(ts=ts, can_id=can_id, data=data)

        if fr is None and fmt in (LogFormat.AUTO, LogFormat.CANDUMP_BRACKET):
            m = _RE_CAN_BRACKET.match(line)
            if m:
                ts = float(m.group("ts") or 0.0)
                can_id = int(m.group("id"), 16)
                bytes_s = m.group("bytes").strip().split()
                data = bytes(int(b, 16) for b in bytes_s)
                fr = CanFrame(ts=ts, can_id=can_id, data=data)

        # CL1000 CSV style: header lines start with '#', data lines are semicolon-separated
        if fr is None and fmt in (LogFormat.AUTO, LogFormat.CL1000_CSV):
            if line.startswith('#'):
                continue
            if ';' in line:
                parts = line.split(';')
                if len(parts) >= 4:
                    ts_s, typ_s, id_s, data_hex = parts[0], parts[1], parts[2], parts[3]
                    # skip header row
                    if ts_s.lower() == 'timestamp' and typ_s.lower() == 'type':
                        continue
                    try:
                        if typ_s.strip() not in ('0', '1', '2', '3'):  # accept common numeric types, prefer '0'
                            pass
                        ts = _parse_cl1000_time(ts_s)
                        can_id = int(id_s.strip(), 16)
                        data_hex = data_hex.strip()
                        data = bytes.fromhex(data_hex)
                        fr = CanFrame(ts=ts, can_id=can_id, data=data)
                    except Exception:
                        fr = None

        if fr is not None:
            frames.append(fr)
    frames.sort(key=lambda f: f.ts)
    return frames
