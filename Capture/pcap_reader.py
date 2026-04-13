from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional

from scapy.all import IP, TCP, UDP, Ether, PcapReader, rdpcap


@dataclass
class PacketRecord:
	"""Structured packet data suitable for ML dataset creation."""

	timestamp: float
	src_ip: Optional[str]
	dst_ip: Optional[str]
	src_port: Optional[int]
	dst_port: Optional[int]
	protocol: str
	length: int
	label: str

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)


def _infer_protocol(packet) -> str:
	if TCP in packet:
		return "TCP"
	if UDP in packet:
		return "UDP"
	if IP in packet:
		return f"IP_PROTO_{packet[IP].proto}"
	if Ether in packet:
		return f"ETH_TYPE_{packet[Ether].type}"
	return "UNKNOWN"


def _packet_to_record(packet, label: str = "unlabeled") -> PacketRecord:
	src_ip = packet[IP].src if IP in packet else None
	dst_ip = packet[IP].dst if IP in packet else None

	src_port = None
	dst_port = None
	if TCP in packet:
		src_port = int(packet[TCP].sport)
		dst_port = int(packet[TCP].dport)
	elif UDP in packet:
		src_port = int(packet[UDP].sport)
		dst_port = int(packet[UDP].dport)

	return PacketRecord(
		timestamp=float(getattr(packet, "time", 0.0)),
		src_ip=src_ip,
		dst_ip=dst_ip,
		src_port=src_port,
		dst_port=dst_port,
		protocol=_infer_protocol(packet),
		length=len(packet),
		label=label,
	)


def stream_pcap(
	pcap_path: str | Path,
	label: str = "unlabeled",
	max_packets: Optional[int] = None,
) -> Generator[PacketRecord, None, None]:
	"""
	Stream packets from a PCAP file one by one.

	This is memory-efficient and ideal for large datasets.
	"""
	path = Path(pcap_path)
	if not path.exists():
		raise FileNotFoundError(f"PCAP file not found: {path}")

	yielded = 0
	with PcapReader(str(path)) as reader:
		for packet in reader:
			yield _packet_to_record(packet, label=label)
			yielded += 1
			if max_packets is not None and yielded >= max_packets:
				break


def read_pcap(
	pcap_path: str | Path,
	label: str = "unlabeled",
	max_packets: Optional[int] = None,
) -> List[Dict[str, Any]]:
	"""
	Read a PCAP file into memory and return dataset-ready dictionaries.

	This is convenient for small/medium captures used in model training.
	"""
	path = Path(pcap_path)
	if not path.exists():
		raise FileNotFoundError(f"PCAP file not found: {path}")

	packets = rdpcap(str(path))
	if max_packets is not None:
		packets = packets[:max_packets]

	return [_packet_to_record(packet, label=label).to_dict() for packet in packets]


def merge_labeled_pcaps(sources: Iterable[tuple[str | Path, str]]) -> List[Dict[str, Any]]:
	"""Load multiple PCAP files with labels and merge into one dataset list."""
	dataset: List[Dict[str, Any]] = []
	for pcap_path, label in sources:
		dataset.extend(read_pcap(pcap_path=pcap_path, label=label))
	return dataset


if __name__ == "__main__":
	# Example offline dataset pipeline.
	normal = read_pcap("normal_traffic.pcap", label="normal", max_packets=2000)
	attack = read_pcap("attack_traffic.pcap", label="attack", max_packets=2000)
	print(f"Loaded normal samples: {len(normal)}")
	print(f"Loaded attack samples: {len(attack)}")
	print(f"Total samples: {len(normal) + len(attack)}")
