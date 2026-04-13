import argparse
from datetime import datetime
from pathlib import Path

from scapy.all import ICMP, IP, Raw, TCP, UDP, get_if_list, sniff, wrpcap


PROFILE_FILTERS = {
    "all": None,
    "ids": "tcp or udp or icmp",
    "web": "tcp port 80 or tcp port 443 or tcp port 8080",
    "auth": "tcp port 21 or tcp port 22 or tcp port 23 or tcp port 3389",
    "dns": "udp port 53 or tcp port 53",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture full network packets from a selected interface."
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Interface name to capture on. If omitted, Scapy default interface is used.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture. Use 0 to capture indefinitely.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Capture timeout in seconds. Use 0 for no timeout.",
    )
    parser.add_argument(
        "--bpf",
        default=None,
        help="Optional BPF filter (example: 'tcp', 'port 80', 'host 192.168.1.1').",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_FILTERS.keys()),
        default="ids",
        help="Capture profile with built-in BPF filter. Ignored if --bpf is provided.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to output PCAP file. If omitted, a timestamped file is created.",
    )
    parser.add_argument(
        "--suspicious-output",
        default=None,
        help="Optional path to save only suspicious packets as a separate PCAP file.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-packet summary printing.",
    )
    return parser


def packet_callback(packet) -> None:
    print(packet.summary(), flush=True)


def resolve_bpf_filter(custom_bpf: str | None, profile: str) -> str | None:
    if custom_bpf:
        return custom_bpf
    return PROFILE_FILTERS.get(profile)


def is_suspicious(packet) -> tuple[bool, str]:
    if IP not in packet:
        return False, ""

    if TCP in packet:
        tcp_layer = packet[TCP]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        flag_str = str(tcp_layer.flags)

        risky_ports = {21, 22, 23, 445, 1433, 3306, 3389}
        if src_port in risky_ports or dst_port in risky_ports:
            return True, f"risky-port-{src_port}->{dst_port}"

        if flag_str == "S":
            return True, "tcp-syn-scan-pattern"

        if flag_str in {"F", "R", "RA"}:
            return True, f"tcp-scan-flag-{flag_str}"

    if UDP in packet:
        udp_layer = packet[UDP]
        dst_port = int(udp_layer.dport)
        if dst_port in {53, 123, 1900, 161} and Raw in packet and len(packet[Raw]) > 512:
            return True, f"large-udp-payload-port-{dst_port}"

    if ICMP in packet and Raw in packet and len(packet[Raw]) > 256:
        return True, "large-icmp-payload"

    return False, ""


def resolve_output_path(output_arg: str | None) -> Path:
    if output_arg:
        return Path(output_arg)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"capture_{ts}.pcap")


def main() -> None:
    args = build_parser().parse_args()

    interfaces = get_if_list()
    print("Available interfaces:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"  {idx}. {iface}")

    output_path = resolve_output_path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    active_filter = resolve_bpf_filter(args.bpf, args.profile)

    suspicious_packets = []

    def capture_callback(packet) -> None:
        suspicious, reason = is_suspicious(packet)
        if suspicious:
            suspicious_packets.append(packet)
            print(f"[ALERT] {reason}: {packet.summary()}", flush=True)
        elif not args.quiet:
            packet_callback(packet)

    sniff_kwargs = {
        "iface": args.iface,
        "filter": active_filter,
        "count": args.count if args.count > 0 else 0,
        "timeout": args.timeout if args.timeout > 0 else None,
        "store": True,
    }

    # Remove None values because Scapy expects omitted options, not None.
    sniff_kwargs = {k: v for k, v in sniff_kwargs.items() if v is not None}

    sniff_kwargs["prn"] = capture_callback

    print("\nStarting packet capture...")
    if args.iface:
        print(f"Interface: {args.iface}")
    else:
        print("Interface: Scapy default")
    print(f"Profile: {args.profile}")
    print(f"Filter: {active_filter or 'None'}")
    print(f"Packet count limit: {args.count if args.count > 0 else 'Unlimited'}")
    print(f"Timeout: {args.timeout if args.timeout > 0 else 'None'}")
    print("Press Ctrl+C to stop capture early.\n")

    captured = []
    try:
        captured = sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")

    total = len(captured)
    if total == 0:
        print("No packets captured.")
        return

    wrpcap(str(output_path), captured)
    print(f"Captured {total} packets.")
    print(f"Saved full packet data to: {output_path.resolve()}")

    suspicious_output = (
        Path(args.suspicious_output)
        if args.suspicious_output
        else output_path.with_name(f"{output_path.stem}_suspicious.pcap")
    )
    suspicious_output.parent.mkdir(parents=True, exist_ok=True)

    if suspicious_packets:
        wrpcap(str(suspicious_output), suspicious_packets)
        print(f"Suspicious packets: {len(suspicious_packets)}")
        print(f"Saved suspicious packet data to: {suspicious_output.resolve()}")
    else:
        print("Suspicious packets: 0")


if __name__ == "__main__":
    main()
