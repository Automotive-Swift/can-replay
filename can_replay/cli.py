from __future__ import annotations

import argparse
import sys
from typing import List, Tuple

from .log_parser import LogFormat, parse_log
from .types import Pair
from .indexer import build_index, save_mapping, load_mapping, detect_pairs
from .isotp_endpoint import IsoTpServer


def parse_pair(s: str) -> Tuple[int, int]:
    try:
        left, right = s.split(":", 1)
        def parse_id(v: str) -> int:
            v = v.strip()
            if v.lower().startswith("0x"):
                return int(v, 16)
            return int(v, 16) if any(c in v for c in "abcdefABCDEF") else int(v)
        return parse_id(left), parse_id(right)
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid pair '{s}'. Use REQ:RESP, e.g. 0x7E0:0x7E8") from e


def cmd_build_index(args: argparse.Namespace) -> int:
    with open(args.log, "r") as f:
        frames = parse_log(f, fmt=args.format)
    if args.pair:
        pairs = [Pair(req, resp) for req, resp in args.pair]
    else:
        auto_pairs = detect_pairs(frames)
        if not auto_pairs:
            print("No pairs detected; provide --pair.", file=sys.stderr)
            return 2
        pairs = [Pair(req, resp) for req, resp in auto_pairs]
    mapping = build_index(frames, pairs, time_window=args.time_window)
    out = args.output or "mapping.json"
    save_mapping(mapping, out)
    print(f"Saved mapping to {out} with {sum(len(v) for v in mapping.values())} request keys across {len(mapping)} pairs.")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    if args.mapping:
        mapping = load_mapping(args.mapping)
        pairs = list(mapping.keys())
    else:
        if not args.log:
            print("Either --mapping or --log must be provided.", file=sys.stderr)
            return 2
        with open(args.log, "r") as f:
            frames = parse_log(f, fmt=args.format)
        if args.pair:
            pairs = args.pair
        else:
            detected = detect_pairs(frames)
            if not detected:
                print("No pairs detected; provide --pair.", file=sys.stderr)
                return 2
            pairs = detected
        mapping = build_index(frames, [Pair(req, resp) for req, resp in pairs], time_window=args.time_window)
    color = None if not getattr(args, 'no_color', False) else False
    verbose = bool(getattr(args, 'verbose', False))
    honor_timing = bool(getattr(args, 'honor_timing', False))
    inter_delay = float(getattr(args, 'inter_delay', 0.02))
    server = IsoTpServer(args.iface, pairs=pairs, mapping=mapping, cycle=not args.exhaust, verbose=verbose, color=color, honor_timing=honor_timing, inter_delay=inter_delay)
    print(f"Starting ISO-TP replay on {args.iface} for pairs: " + ", ".join(f"{hex(a)}:{hex(b)}" for a,b in pairs))
    server.start()
    server.run()
    return 0


def main(argv: List[str] | None = None) -> int:
    # Work with a stable argv list so we can decide on help behavior
    raw_argv: List[str] = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="can-replay", description="Replay ISO-TP replies from a CAN log")
    sub = parser.add_subparsers(dest="cmd")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--format", choices=[LogFormat.AUTO, LogFormat.CANDUMP_BASIC, LogFormat.CANDUMP_BRACKET, LogFormat.CL1000_CSV], default=LogFormat.AUTO, help="Log format (default: auto)")
        p.add_argument("--pair", type=parse_pair, action="append", default=[], help="REQ:RESP arbitration ID pair (repeat)")
        p.add_argument("--time-window", type=float, default=2.0, help="Seconds to associate reply with preceding request")

    p_build = sub.add_parser("build-index", help="Parse log and build mapping JSON")
    p_build.add_argument("--log", required=True, help="Path to CAN log file")
    p_build.add_argument("-o", "--output", help="Mapping output JSON (default: mapping.json)")
    add_common(p_build)
    p_build.set_defaults(func=cmd_build_index)

    p_replay = sub.add_parser("replay", help="Run ISO-TP reply server")
    p_replay.add_argument("-i", "--iface", default="can0", help="socketcan interface (default: can0)")
    p_replay.add_argument("-v", "--verbose", action="store_true", help="Verbose colored request/match logs")
    p_replay.add_argument("--no-color", action="store_true", help="Disable ANSI colors in logs")
    p_replay.add_argument("--honor-timing", action="store_true", help="Honor request→response timing from log when sending sequences")
    p_replay.add_argument("--inter-delay", type=float, default=0.02, help="Inter-response delay when not honoring timing (seconds)")
    p_replay.add_argument("--mapping", help="Path to pre-built mapping JSON")
    p_replay.add_argument("--log", help="If provided, build mapping from this log before replay")
    p_replay.add_argument("--exhaust", action="store_true", help="Do not cycle replies; stop after last")
    add_common(p_replay)
    p_replay.set_defaults(func=cmd_replay)

    # Top-level convenience without subcommand
    parser.add_argument("-i", "--iface", default="can0", help="socketcan interface (default: can0)")
    parser.add_argument("--mapping", help="Path to pre-built mapping JSON")
    parser.add_argument("--log", help="If provided, build mapping from this log before replay")
    parser.add_argument("--exhaust", action="store_true", help="Do not cycle replies; stop after last")
    parser.add_argument("--honor-timing", action="store_true", help="Honor request→response timing from log when sending sequences")
    parser.add_argument("--inter-delay", type=float, default=0.02, help="Inter-response delay when not honoring timing (seconds)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose colored request/match logs")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in logs")
    add_common(parser)

    # If no arguments at all, show full usage instead of a terse error
    if len(raw_argv) == 0:
        parser.print_help()
        return 0

    args = parser.parse_args(raw_argv)
    if args.cmd is None:
        # act like replay
        return cmd_replay(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
