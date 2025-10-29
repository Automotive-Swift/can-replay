from __future__ import annotations

import argparse
import asyncio
import sys
from typing import List, Optional, Sequence, Tuple

from .indexer import build_index, detect_pairs, load_mapping, save_mapping
from .pcap_parser import load_tcp_segments
from .server import TcpReplayServer
from .types import Mapping, Pair, PairKey, TcpSegment


def parse_endpoint(text: str) -> Tuple[str, Optional[int]]:
    text = text.strip()
    if not text:
        raise argparse.ArgumentTypeError("Empty endpoint")
    if text.startswith("[") and "]" in text:
        host, rest = text[1:].split("]", 1)
        host = host.strip()
        rest = rest.strip()
        if rest.startswith(":"):
            port = int(rest[1:])
            return host, port
        if rest.startswith("@"):
            port = int(rest[1:])
            return host, port
        return host, None
    if "@" in text:
        host, port_s = text.split("@", 1)
        return host.strip(), int(port_s)
    if ":" in text and text.count(":") == 1:
        host, port_s = text.split(":", 1)
        if port_s.isdigit():
            return host.strip(), int(port_s)
    return text, None


def parse_pair(text: str) -> Pair:
    if ">" in text:
        left, right = text.split(">", 1)
    elif ":" in text:
        left, right = text.split(":", 1)
    else:
        raise argparse.ArgumentTypeError(f"Invalid pair '{text}'. Use REQ_IP>RESP_IP or REQ_IP:RESP_IP")
    req_host, req_port = parse_endpoint(left)
    resp_host, resp_port = parse_endpoint(right)
    return Pair(req_ip=req_host, resp_ip=resp_host, req_port=req_port, resp_port=resp_port)


def parse_listen(value: str) -> Tuple[str, int]:
    value = value.strip()
    if not value:
        raise argparse.ArgumentTypeError("Empty listen address")
    if value.startswith("["):
        if "]" not in value:
            raise argparse.ArgumentTypeError(f"Invalid listen address '{value}'")
        host, rest = value[1:].split("]", 1)
        rest = rest.strip()
        if rest.startswith(":"):
            port = int(rest[1:])
        else:
            raise argparse.ArgumentTypeError(f"Missing port in listen address '{value}'")
        return host, port
    if ":" in value and value.count(":") == 1:
        host, port_s = value.split(":", 1)
        return host or "0.0.0.0", int(port_s)
    raise argparse.ArgumentTypeError(f"Invalid listen address '{value}'. Use host:port or [ipv6]:port")


def pair_from_key(key: PairKey) -> Pair:
    req_ip, req_port, resp_ip, resp_port = key
    return Pair(req_ip=req_ip, resp_ip=resp_ip, req_port=req_port, resp_port=resp_port)


def _ensure_pairs(args_pairs: Sequence[Pair], detected: List[Pair]) -> List[Pair]:
    if args_pairs:
        return list(args_pairs)
    if detected:
        return detected
    raise RuntimeError("No request/response pairs were provided or detected")


def _format_pair_list(pairs: Sequence[Pair]) -> str:
    return ", ".join(pair.to_string() for pair in pairs)


def cmd_build_index(args: argparse.Namespace) -> int:
    try:
        segments = load_tcp_segments(args.pcap)
    except RuntimeError as exc:
        print(f"Error loading capture: {exc}", file=sys.stderr)
        return 2
    if not segments:
        print("No TCP segments with payload found in capture.", file=sys.stderr)
        return 2
    pairs = args.pair or detect_pairs(segments)
    if not pairs:
        print("No pairs detected; please provide --pair.", file=sys.stderr)
        return 2
    mapping = build_index(segments, pairs, time_window=args.time_window)
    output = args.output or "tcp_mapping.json"
    save_mapping(mapping, output)
    total_requests = sum(len(reqs) for reqs in mapping.values())
    print(f"Saved mapping to {output} with {total_requests} unique request payloads across {_format_pair_list(pairs)}")
    return 0


def _filter_mapping(mapping: Mapping, pairs: List[Pair]) -> Mapping:
    if not pairs:
        return mapping
    filtered: Mapping = {}
    keys = {pair.key for pair in pairs}
    for key, reqmap in mapping.items():
        if key in keys:
            filtered[key] = reqmap
    return filtered


def cmd_replay(args: argparse.Namespace) -> int:
    if args.mapping:
        mapping = load_mapping(args.mapping)
        pairs = [pair_from_key(key) for key in mapping.keys()]
    else:
        if not args.pcap:
            print("Either --mapping or --pcap must be provided.", file=sys.stderr)
            return 2
        try:
            segments = load_tcp_segments(args.pcap)
        except RuntimeError as exc:
            print(f"Error loading capture: {exc}", file=sys.stderr)
            return 2
        if not segments:
            print("No TCP segments with payload found in capture.", file=sys.stderr)
            return 2
        auto_pairs = detect_pairs(segments) if not args.pair else []
        pairs = _ensure_pairs(args.pair, auto_pairs)
        mapping = build_index(segments, pairs, time_window=args.time_window)
    if args.pair:
        pairs = list(args.pair)
        mapping = _filter_mapping(mapping, pairs)
    if not pairs:
        print("No pairs available for replay.", file=sys.stderr)
        return 2
    host, port = parse_listen(args.listen)
    color = None if not getattr(args, "no_color", False) else False
    server = TcpReplayServer(
        host=host,
        port=port,
        pairs=pairs,
        mapping=mapping,
        cycle=not args.exhaust,
        verbose=bool(args.verbose),
        color=color,
        honor_timing=bool(args.honor_timing),
        inter_delay=float(getattr(args, "inter_delay", 0.02)),
    )
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        print("Stopped by user.")
    return 0


def main(argv: List[str] | None = None) -> int:
    raw_argv: List[str] = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="enet-replay", description="Replay TCP replies captured in a pcap/pcapng file")
    sub = parser.add_subparsers(dest="cmd")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--pair", type=parse_pair, action="append", default=[], help="Requester→Responder pair, e.g., 192.168.0.2:192.168.0.10 or 192.168.0.2@5000>192.168.0.10@80")
        p.add_argument("--time-window", type=float, default=2.0, help="Seconds to associate replies with preceding request (default: 2.0)")

    p_build = sub.add_parser("build-index", help="Parse pcapng and build mapping JSON")
    p_build.add_argument("--pcap", required=True, help="Path to pcap/pcapng capture file")
    p_build.add_argument("-o", "--output", help="Mapping output JSON (default: tcp_mapping.json)")
    add_common(p_build)
    p_build.set_defaults(func=cmd_build_index)

    p_replay = sub.add_parser("replay", help="Run TCP reply server")
    p_replay.add_argument("--pcap", help="If provided, build mapping from this capture before replay")
    p_replay.add_argument("--mapping", help="Path to pre-built mapping JSON")
    p_replay.add_argument("--listen", default="0.0.0.0:5000", help="Listen address host:port (default: 0.0.0.0:5000)")
    p_replay.add_argument("--exhaust", action="store_true", help="Do not cycle replies; stop after last sequence")
    p_replay.add_argument("--honor-timing", action="store_true", help="Honor timing offsets from capture when sending responses")
    p_replay.add_argument("--inter-delay", type=float, default=0.02, help="Inter-response delay when not honoring timing (seconds)")
    p_replay.add_argument("-v", "--verbose", action="store_true", help="Verbose colored request/match logs")
    p_replay.add_argument("--no-color", action="store_true", help="Disable ANSI colors in logs")
    add_common(p_replay)
    p_replay.set_defaults(func=cmd_replay)

    # Convenience without subcommand defaults to replay
    parser.add_argument("--pcap", help="If provided, build mapping from this capture before replay")
    parser.add_argument("--mapping", help="Path to pre-built mapping JSON")
    parser.add_argument("--listen", default="0.0.0.0:5000", help="Listen address host:port (default: 0.0.0.0:5000)")
    parser.add_argument("--exhaust", action="store_true", help="Do not cycle replies; stop after last sequence")
    parser.add_argument("--honor-timing", action="store_true", help="Honor timing offsets from capture when sending responses")
    parser.add_argument("--inter-delay", type=float, default=0.02, help="Inter-response delay when not honoring timing (seconds)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose colored request/match logs")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in logs")
    add_common(parser)

    if len(raw_argv) == 0:
        parser.print_help()
        return 0

    args = parser.parse_args(raw_argv)
    if args.cmd is None:
        return cmd_replay(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
