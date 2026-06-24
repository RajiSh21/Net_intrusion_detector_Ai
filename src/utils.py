"""
NIDS Flow Feature Extraction Utilities
======================================
Computes the 79 CICFlowMeter-style features from raw bidirectional
network flows, mirroring the exact feature set used during training.
"""

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
import time
import struct

# Minimum packet count to consider a flow ready for classification
MIN_FLOW_PACKETS = 2
# Flow timeout in seconds (flows idle for this long are considered finished)
FLOW_TIMEOUT = 120
# Maximum flow duration in seconds
MAX_FLOW_DURATION = 300

# Well-known ports list for heuristic protocol detection
WELL_KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465,
    514, 515, 520, 546, 547, 587, 636, 993, 995, 1194, 1433,
    1434, 1521, 1701, 1723, 1812, 1813, 2049, 2082, 2083,
    3306, 3389, 5060, 5061, 5432, 5900, 5984, 6379, 6443,
    6881, 6888, 8000, 8008, 8080, 8443, 8888, 9000, 9090,
    9200, 9300, 11211, 27017, 27018, 27019, 50000, 50070,
}


@dataclass
class PacketInfo:
    """Lightweight representation of a single captured packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # IP protocol number (6=TCP, 17=UDP)
    length: int  # IP total length
    flags: int = 0  # TCP flags bitmap
    header_len: int = 0  # IP header length + transport header length
    tcp_window: int = 0  # TCP window size
    urgent: bool = False
    push: bool = False


@dataclass
class FlowFeatures:
    """All 79 features extracted from a bidirectional flow, in the EXACT order the XGBoost model expects."""
    # Source Port is dropped by training pipeline
    Destination_Port: float = 0.0
    Protocol: float = 0.0
    Flow_Duration: float = 0.0
    Total_Fwd_Packets: float = 0.0
    Total_Backward_Packets: float = 0.0
    Total_Length_of_Fwd_Packets: float = 0.0
    Total_Length_of_Bwd_Packets: float = 0.0
    Fwd_Packet_Length_Max: float = 0.0
    Fwd_Packet_Length_Min: float = 0.0
    Fwd_Packet_Length_Mean: float = 0.0
    Fwd_Packet_Length_Std: float = 0.0
    Bwd_Packet_Length_Max: float = 0.0
    Bwd_Packet_Length_Min: float = 0.0
    Bwd_Packet_Length_Mean: float = 0.0
    Bwd_Packet_Length_Std: float = 0.0
    Flow_Bytess: float = 0.0
    Flow_Packetss: float = 0.0
    Flow_IAT_Mean: float = 0.0
    Flow_IAT_Std: float = 0.0
    Flow_IAT_Max: float = 0.0
    Flow_IAT_Min: float = 0.0
    Fwd_IAT_Total: float = 0.0
    Fwd_IAT_Mean: float = 0.0
    Fwd_IAT_Std: float = 0.0
    Fwd_IAT_Max: float = 0.0
    Fwd_IAT_Min: float = 0.0
    Bwd_IAT_Total: float = 0.0
    Bwd_IAT_Mean: float = 0.0
    Bwd_IAT_Std: float = 0.0
    Bwd_IAT_Max: float = 0.0
    Bwd_IAT_Min: float = 0.0
    Fwd_PSH_Flags: float = 0.0
    Bwd_PSH_Flags: float = 0.0
    Fwd_URG_Flags: float = 0.0
    Bwd_URG_Flags: float = 0.0
    Fwd_Header_Length: float = 0.0
    Bwd_Header_Length: float = 0.0
    Fwd_Packetss: float = 0.0
    Bwd_Packetss: float = 0.0
    Min_Packet_Length: float = 0.0
    Max_Packet_Length: float = 0.0
    Packet_Length_Mean: float = 0.0
    Packet_Length_Std: float = 0.0
    Packet_Length_Variance: float = 0.0
    FIN_Flag_Count: float = 0.0
    SYN_Flag_Count: float = 0.0
    RST_Flag_Count: float = 0.0
    PSH_Flag_Count: float = 0.0
    ACK_Flag_Count: float = 0.0
    URG_Flag_Count: float = 0.0
    CWE_Flag_Count: float = 0.0
    ECE_Flag_Count: float = 0.0
    Down_Up_Ratio: float = 0.0
    Average_Packet_Size: float = 0.0
    Avg_Fwd_Segment_Size: float = 0.0
    Avg_Bwd_Segment_Size: float = 0.0
    Fwd_Avg_Bytes_Bulk: float = 0.0
    Fwd_Avg_Packets_Bulk: float = 0.0
    Fwd_Avg_Bulk_Rate: float = 0.0
    Bwd_Avg_Bytes_Bulk: float = 0.0
    Bwd_Avg_Packets_Bulk: float = 0.0
    Bwd_Avg_Bulk_Rate: float = 0.0
    Subflow_Fwd_Packets: float = 0.0
    Subflow_Fwd_Bytes: float = 0.0
    Subflow_Bwd_Packets: float = 0.0
    Subflow_Bwd_Bytes: float = 0.0
    Init_Win_bytes_forward: float = 0.0
    Init_Win_bytes_backward: float = 0.0
    act_data_pkt_fwd: float = 0.0
    min_seg_size_forward: float = 0.0
    Active_Mean: float = 0.0
    Active_Std: float = 0.0
    Active_Max: float = 0.0
    Active_Min: float = 0.0
    Idle_Mean: float = 0.0
    Idle_Std: float = 0.0
    Idle_Max: float = 0.0
    Idle_Min: float = 0.0

    def to_list(self) -> List[float]:
        """Return features as a list in the EXACT order the model expects (matching CSV column order)."""
        return [
            self.Destination_Port,
            self.Protocol,
            self.Flow_Duration,
            self.Total_Fwd_Packets,
            self.Total_Backward_Packets,
            self.Total_Length_of_Fwd_Packets,
            self.Total_Length_of_Bwd_Packets,
            self.Fwd_Packet_Length_Max,
            self.Fwd_Packet_Length_Min,
            self.Fwd_Packet_Length_Mean,
            self.Fwd_Packet_Length_Std,
            self.Bwd_Packet_Length_Max,
            self.Bwd_Packet_Length_Min,
            self.Bwd_Packet_Length_Mean,
            self.Bwd_Packet_Length_Std,
            self.Flow_Bytess,
            self.Flow_Packetss,
            self.Flow_IAT_Mean,
            self.Flow_IAT_Std,
            self.Flow_IAT_Max,
            self.Flow_IAT_Min,
            self.Fwd_IAT_Total,
            self.Fwd_IAT_Mean,
            self.Fwd_IAT_Std,
            self.Fwd_IAT_Max,
            self.Fwd_IAT_Min,
            self.Bwd_IAT_Total,
            self.Bwd_IAT_Mean,
            self.Bwd_IAT_Std,
            self.Bwd_IAT_Max,
            self.Bwd_IAT_Min,
            self.Fwd_PSH_Flags,
            self.Bwd_PSH_Flags,
            self.Fwd_URG_Flags,
            self.Bwd_URG_Flags,
            self.Fwd_Header_Length,
            self.Bwd_Header_Length,
            self.Fwd_Packetss,
            self.Bwd_Packetss,
            self.Min_Packet_Length,
            self.Max_Packet_Length,
            self.Packet_Length_Mean,
            self.Packet_Length_Std,
            self.Packet_Length_Variance,
            self.FIN_Flag_Count,
            self.SYN_Flag_Count,
            self.RST_Flag_Count,
            self.PSH_Flag_Count,
            self.ACK_Flag_Count,
            self.URG_Flag_Count,
            self.CWE_Flag_Count,
            self.ECE_Flag_Count,
            self.Down_Up_Ratio,
            self.Average_Packet_Size,
            self.Avg_Fwd_Segment_Size,
            self.Avg_Bwd_Segment_Size,
            self.Fwd_Avg_Bytes_Bulk,
            self.Fwd_Avg_Packets_Bulk,
            self.Fwd_Avg_Bulk_Rate,
            self.Bwd_Avg_Bytes_Bulk,
            self.Bwd_Avg_Packets_Bulk,
            self.Bwd_Avg_Bulk_Rate,
            self.Subflow_Fwd_Packets,
            self.Subflow_Fwd_Bytes,
            self.Subflow_Bwd_Packets,
            self.Subflow_Bwd_Bytes,
            self.Init_Win_bytes_forward,
            self.Init_Win_bytes_backward,
            self.act_data_pkt_fwd,
            self.min_seg_size_forward,
            self.Active_Mean,
            self.Active_Std,
            self.Active_Max,
            self.Active_Min,
            self.Idle_Mean,
            self.Idle_Std,
            self.Idle_Max,
            self.Idle_Min,
        ]


class FlowCollector:
    """Aggregates packets into bidirectional flows and computes CICFlowMeter features."""

    def __init__(self):
        self.flows: Dict[Tuple[str, int, str, int, int], List[PacketInfo]] = defaultdict(list)
        self.last_activity: Dict[Tuple, float] = {}
        self.flow_start: Dict[Tuple, float] = {}

    @staticmethod
    def flow_key(pkt: PacketInfo) -> Tuple[str, int, str, int, int]:
        """Generate a bidirectional flow key (src_ip, src_port, dst_ip, dst_port, proto).
        Forward/backward are determined per-packet by direction."""
        return (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol)

    def add_packet(self, pkt_info: PacketInfo):
        """Add a packet to its flow."""
        key = self.flow_key(pkt_info)
        now = pkt_info.timestamp

        if key not in self.flows:
            self.flow_start[key] = now
        self.flows[key].append(pkt_info)
        self.last_activity[key] = now

    def _separate_directions(self, packets: List[PacketInfo]) -> Tuple[List[PacketInfo], List[PacketInfo]]:
        """Split packets into forward (from flow initiator) and backward directions."""
        if not packets:
            return [], []

        first = packets[0]
        src_ip, dst_ip = first.src_ip, first.dst_ip
        src_port, dst_port = first.src_port, first.dst_port

        fwd_packets = []
        bwd_packets = []

        for pkt in packets:
            if (pkt.src_ip == src_ip and pkt.dst_ip == dst_ip and
                    pkt.src_port == src_port and pkt.dst_port == dst_port):
                fwd_packets.append(pkt)
            else:
                bwd_packets.append(pkt)

        return fwd_packets, bwd_packets

    @staticmethod
    def _safe_mean(data: List[float]) -> float:
        return sum(data) / len(data) if data else 0.0

    @staticmethod
    def _safe_std(data: List[float]) -> float:
        if len(data) < 2:
            return 0.0
        return statistics.stdev(data)

    @staticmethod
    def _safe_min(data: List[float]) -> float:
        return min(data) if data else 0.0

    @staticmethod
    def _safe_max(data: List[float]) -> float:
        return max(data) if data else 0.0

    @staticmethod
    def _safe_var(data: List[float]) -> float:
        if len(data) < 2:
            return 0.0
        return statistics.variance(data)

    def extract_features(self, packets: List[PacketInfo]) -> FlowFeatures:
        """Compute all 79 flow-level features from a list of packets."""
        features = FlowFeatures()

        if not packets or len(packets) < 2:
            return features

        fwd_pkts, bwd_pkts = self._separate_directions(packets)
        all_lengths = [pkt.length for pkt in packets]
        timestamps = sorted([pkt.timestamp for pkt in packets])

        # ---- Basic Flow Metrics ----
        features.Destination_Port = float(packets[0].dst_port)
        features.Protocol = float(packets[0].protocol)
        features.Flow_Duration = (max(timestamps) - min(timestamps)) * 1_000_000  # microseconds
        features.Flow_Bytess = float(sum(all_lengths))
        features.Flow_Packetss = float(len(packets))

        # ---- Forward Packet Statistics ----
        fwd_lengths = [pkt.length for pkt in fwd_pkts]
        features.Total_Fwd_Packets = float(len(fwd_pkts))
        features.Total_Length_of_Fwd_Packets = float(sum(fwd_lengths))
        features.Fwd_Packetss = float(len(fwd_pkts))

        if fwd_lengths:
            features.Fwd_Packet_Length_Max = self._safe_max(fwd_lengths)
            features.Fwd_Packet_Length_Min = self._safe_min(fwd_lengths)
            features.Fwd_Packet_Length_Mean = self._safe_mean(fwd_lengths)
            features.Fwd_Packet_Length_Std = self._safe_std(fwd_lengths)

        # ---- Backward Packet Statistics ----
        bwd_lengths = [pkt.length for pkt in bwd_pkts]
        features.Total_Backward_Packets = float(len(bwd_pkts))
        features.Total_Length_of_Bwd_Packets = float(sum(bwd_lengths))
        features.Bwd_Packetss = float(len(bwd_pkts))

        if bwd_lengths:
            features.Bwd_Packet_Length_Max = self._safe_max(bwd_lengths)
            features.Bwd_Packet_Length_Min = self._safe_min(bwd_lengths)
            features.Bwd_Packet_Length_Mean = self._safe_mean(bwd_lengths)
            features.Bwd_Packet_Length_Std = self._safe_std(bwd_lengths)

        # ---- Global Packet Length Statistics ----
        features.Min_Packet_Length = self._safe_min(all_lengths)
        features.Max_Packet_Length = self._safe_max(all_lengths)
        features.Packet_Length_Mean = self._safe_mean(all_lengths)
        features.Packet_Length_Std = self._safe_std(all_lengths)
        features.Packet_Length_Variance = self._safe_var(all_lengths)

        # ---- Inter-Arrival Time (IAT) ----
        if len(timestamps) >= 2:
            iats = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            iats_us = [iat * 1_000_000 for iat in iats]
            features.Flow_IAT_Mean = self._safe_mean(iats_us)
            features.Flow_IAT_Std = self._safe_std(iats_us)
            features.Flow_IAT_Max = self._safe_max(iats_us)
            features.Flow_IAT_Min = self._safe_min(iats_us)

        # Forward IAT
        fwd_timestamps = sorted([pkt.timestamp for pkt in fwd_pkts])
        if len(fwd_timestamps) >= 2:
            fwd_iats = [fwd_timestamps[i + 1] - fwd_timestamps[i] for i in range(len(fwd_timestamps) - 1)]
            fwd_iats_us = [iat * 1_000_000 for iat in fwd_iats]
            features.Fwd_IAT_Total = sum(fwd_iats_us)
            features.Fwd_IAT_Mean = self._safe_mean(fwd_iats_us)
            features.Fwd_IAT_Std = self._safe_std(fwd_iats_us)
            features.Fwd_IAT_Max = self._safe_max(fwd_iats_us)
            features.Fwd_IAT_Min = self._safe_min(fwd_iats_us)

        # Backward IAT
        bwd_timestamps = sorted([pkt.timestamp for pkt in bwd_pkts])
        if len(bwd_timestamps) >= 2:
            bwd_iats = [bwd_timestamps[i + 1] - bwd_timestamps[i] for i in range(len(bwd_timestamps) - 1)]
            bwd_iats_us = [iat * 1_000_000 for iat in bwd_iats]
            features.Bwd_IAT_Total = sum(bwd_iats_us)
            features.Bwd_IAT_Mean = self._safe_mean(bwd_iats_us)
            features.Bwd_IAT_Std = self._safe_std(bwd_iats_us)
            features.Bwd_IAT_Max = self._safe_max(bwd_iats_us)
            features.Bwd_IAT_Min = self._safe_min(bwd_iats_us)

        # ---- TCP Flag Counts ----
        # TCP flags: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWE=0x80
        fin_count = 0
        syn_count = 0
        rst_count = 0
        psh_count = 0
        ack_count = 0
        urg_count = 0
        cwe_count = 0
        ece_count = 0
        fwd_psh = 0
        bwd_psh = 0
        fwd_urg = 0
        bwd_urg = 0

        for pkt in packets:
            if pkt.flags & 0x01:
                fin_count += 1
            if pkt.flags & 0x02:
                syn_count += 1
            if pkt.flags & 0x04:
                rst_count += 1
            if pkt.flags & 0x08:
                psh_count += 1
            if pkt.flags & 0x10:
                ack_count += 1
            if pkt.flags & 0x20:
                urg_count += 1
            if pkt.flags & 0x40:
                ece_count += 1
            if pkt.flags & 0x80:
                cwe_count += 1

        for pkt in fwd_pkts:
            if pkt.flags & 0x08:
                fwd_psh += 1
            if pkt.flags & 0x20:
                fwd_urg += 1

        for pkt in bwd_pkts:
            if pkt.flags & 0x08:
                bwd_psh += 1
            if pkt.flags & 0x20:
                bwd_urg += 1

        features.FIN_Flag_Count = float(fin_count)
        features.SYN_Flag_Count = float(syn_count)
        features.RST_Flag_Count = float(rst_count)
        features.PSH_Flag_Count = float(psh_count)
        features.ACK_Flag_Count = float(ack_count)
        features.URG_Flag_Count = float(urg_count)
        features.CWE_Flag_Count = float(cwe_count)
        features.ECE_Flag_Count = float(ece_count)
        features.Fwd_PSH_Flags = float(fwd_psh)
        features.Bwd_PSH_Flags = float(bwd_psh)
        features.Fwd_URG_Flags = float(fwd_urg)
        features.Bwd_URG_Flags = float(bwd_urg)

        # ---- Header Lengths ----
        fwd_header_vals = [pkt.header_len for pkt in fwd_pkts]
        bwd_header_vals = [pkt.header_len for pkt in bwd_pkts]
        features.Fwd_Header_Length = sum(fwd_header_vals)
        features.Bwd_Header_Length = sum(bwd_header_vals)

        # ---- Down/Up Ratio ----
        if features.Total_Length_of_Fwd_Packets > 0 and features.Total_Length_of_Bwd_Packets > 0:
            features.Down_Up_Ratio = features.Total_Length_of_Fwd_Packets / features.Total_Length_of_Bwd_Packets
        elif features.Total_Length_of_Bwd_Packets > 0:
            features.Down_Up_Ratio = features.Total_Length_of_Fwd_Packets
        else:
            features.Down_Up_Ratio = 0.0

        # ---- Average Packet Size ----
        features.Average_Packet_Size = features.Flow_Bytess / features.Flow_Packetss if features.Flow_Packetss > 0 else 0.0

        # ---- Avg Segment Size ----
        if features.Fwd_Packetss > 0:
            features.Avg_Fwd_Segment_Size = features.Total_Length_of_Fwd_Packets / features.Fwd_Packetss
        if features.Bwd_Packetss > 0:
            features.Avg_Bwd_Segment_Size = features.Total_Length_of_Bwd_Packets / features.Bwd_Packetss

        # ---- Bulk Transfer Statistics ----
        # Bulk = consecutive packets in same direction above a threshold
        BULK_THRESHOLD = 1.0  # second gap threshold for new bulk
        fwd_bulk_sizes = []
        bwd_bulk_sizes = []
        fwd_bulk_pkt_counts = []
        bwd_bulk_pkt_counts = []
        fwd_bulk_durations = []
        bwd_bulk_durations = []

        # Sort all packets by timestamp
        sorted_pkts = sorted(packets, key=lambda p: p.timestamp)
        current_bulk_bytes = 0
        current_bulk_pkts = 0
        current_bulk_start = None
        current_bulk_dir = None  # 'fwd' or 'bwd'

        for pkt in sorted_pkts:
            is_fwd = pkt in fwd_pkts
            direction = 'fwd' if is_fwd else 'bwd'

            if current_bulk_dir is None:
                current_bulk_dir = direction
                current_bulk_start = pkt.timestamp
                current_bulk_bytes = pkt.length
                current_bulk_pkts = 1
            elif direction == current_bulk_dir and (pkt.timestamp - current_bulk_start) <= BULK_THRESHOLD:
                current_bulk_bytes += pkt.length
                current_bulk_pkts += 1
            else:
                # End current bulk
                if current_bulk_dir == 'fwd':
                    fwd_bulk_sizes.append(current_bulk_bytes)
                    fwd_bulk_pkt_counts.append(current_bulk_pkts)
                    if current_bulk_start:
                        dur = pkt.timestamp - current_bulk_start
                        fwd_bulk_durations.append(dur if dur > 0 else 1e-6)
                else:
                    bwd_bulk_sizes.append(current_bulk_bytes)
                    bwd_bulk_pkt_counts.append(current_bulk_pkts)
                    if current_bulk_start:
                        dur = pkt.timestamp - current_bulk_start
                        bwd_bulk_durations.append(dur if dur > 0 else 1e-6)

                # Start new bulk
                current_bulk_dir = direction
                current_bulk_start = pkt.timestamp
                current_bulk_bytes = pkt.length
                current_bulk_pkts = 1

        # Final bulk
        if current_bulk_dir == 'fwd':
            fwd_bulk_sizes.append(current_bulk_bytes)
            fwd_bulk_pkt_counts.append(current_bulk_pkts)
            fwd_bulk_durations.append(0.001)
        elif current_bulk_dir == 'bwd':
            bwd_bulk_sizes.append(current_bulk_bytes)
            bwd_bulk_pkt_counts.append(current_bulk_pkts)
            bwd_bulk_durations.append(0.001)

        features.Fwd_Avg_Bytes_Bulk = self._safe_mean(fwd_bulk_sizes)
        features.Fwd_Avg_Packets_Bulk = self._safe_mean(fwd_bulk_pkt_counts)
        if fwd_bulk_durations:
            features.Fwd_Avg_Bulk_Rate = self._safe_mean([
                size / dur for size, dur in zip(fwd_bulk_sizes, fwd_bulk_durations)
            ])
        features.Bwd_Avg_Bytes_Bulk = self._safe_mean(bwd_bulk_sizes)
        features.Bwd_Avg_Packets_Bulk = self._safe_mean(bwd_bulk_pkt_counts)
        if bwd_bulk_durations:
            features.Bwd_Avg_Bulk_Rate = self._safe_mean([
                size / dur for size, dur in zip(bwd_bulk_sizes, bwd_bulk_durations)
            ])

        # ---- Subflow Statistics ----
        # Subflow = consecutive packets in same direction
        subflow_fwd_pkts = []
        subflow_fwd_bytes_list = []
        subflow_bwd_pkts = []
        subflow_bwd_bytes_list = []

        current_dir = None
        current_count = 0
        current_bytes = 0

        for pkt in sorted_pkts:
            is_fwd = pkt in fwd_pkts
            direction = 'fwd' if is_fwd else 'bwd'

            if direction == current_dir:
                current_count += 1
                current_bytes += pkt.length
            else:
                if current_dir == 'fwd':
                    subflow_fwd_pkts.append(current_count)
                    subflow_fwd_bytes_list.append(current_bytes)
                elif current_dir == 'bwd':
                    subflow_bwd_pkts.append(current_count)
                    subflow_bwd_bytes_list.append(current_bytes)

                current_dir = direction
                current_count = 1
                current_bytes = pkt.length

        # Final subflow
        if current_dir == 'fwd':
            subflow_fwd_pkts.append(current_count)
            subflow_fwd_bytes_list.append(current_bytes)
        elif current_dir == 'bwd':
            subflow_bwd_pkts.append(current_count)
            subflow_bwd_bytes_list.append(current_bytes)

        features.Subflow_Fwd_Packets = self._safe_mean(subflow_fwd_pkts)
        features.Subflow_Fwd_Bytes = self._safe_mean(subflow_fwd_bytes_list)
        features.Subflow_Bwd_Packets = self._safe_mean(subflow_bwd_pkts)
        features.Subflow_Bwd_Bytes = self._safe_mean(subflow_bwd_bytes_list)

        # ---- Init Window Bytes ----
        features.Init_Win_bytes_forward = fwd_pkts[0].tcp_window if fwd_pkts else 0.0
        features.Init_Win_bytes_backward = bwd_pkts[0].tcp_window if bwd_pkts else 0.0

        # ---- Active Data Packets Forward ----
        features.act_data_pkt_fwd = float(sum(1 for pkt in fwd_pkts if pkt.length > 0 and not (pkt.flags & 0x02)))

        # ---- Min Segment Size Forward ----
        if fwd_lengths:
            features.min_seg_size_forward = min(fwd_lengths)

        # ---- Active/Idle Time Statistics ----
        ACTIVE_THRESHOLD = 1.0  # seconds - gaps smaller than this = active, larger = idle
        active_periods = []
        idle_periods = []

        if len(sorted_pkts) >= 2:
            current_active_start = sorted_pkts[0].timestamp
            prev_time = sorted_pkts[0].timestamp

            for pkt in sorted_pkts[1:]:
                gap = pkt.timestamp - prev_time
                if gap <= ACTIVE_THRESHOLD:
                    pass  # still in active period
                else:
                    active_periods.append(prev_time - current_active_start)
                    idle_periods.append(gap)
                    current_active_start = pkt.timestamp
                prev_time = pkt.timestamp

            # Final active period
            active_periods.append(prev_time - current_active_start)

        if active_periods:
            features.Active_Mean = self._safe_mean(active_periods) * 1_000_000
            features.Active_Std = self._safe_std(active_periods) * 1_000_000
            features.Active_Max = self._safe_max(active_periods) * 1_000_000
            features.Active_Min = self._safe_min(active_periods) * 1_000_000

        if idle_periods:
            features.Idle_Mean = self._safe_mean(idle_periods) * 1_000_000
            features.Idle_Std = self._safe_std(idle_periods) * 1_000_000
            features.Idle_Max = self._safe_max(idle_periods) * 1_000_000
            features.Idle_Min = self._safe_min(idle_periods) * 1_000_000

        return features

    def get_ready_flows(self) -> Dict[Tuple, List[PacketInfo]]:
        """Return flows that are complete (timed out or finished via TCP FIN/RST)."""
        now = time.time()
        ready = {}

        for key, packets in list(self.flows.items()):
            if not packets:
                continue

            # Check for flow termination conditions
            has_fin_or_rst = any(p.flags & 0x01 or p.flags & 0x04 for p in packets)
            flow_duration = now - self.flow_start.get(key, now)
            idle_time = now - self.last_activity.get(key, now)

            if (has_fin_or_rst and len(packets) >= MIN_FLOW_PACKETS) or \
               (idle_time > FLOW_TIMEOUT and len(packets) >= MIN_FLOW_PACKETS) or \
               (flow_duration > MAX_FLOW_DURATION and len(packets) >= MIN_FLOW_PACKETS):
                ready[key] = packets
                del self.flows[key]
                self.last_activity.pop(key, None)
                self.flow_start.pop(key, None)

        return ready

    def cleanup_stale_flows(self, max_age: float = 600):
        """Remove very old incomplete flows."""
        now = time.time()
        stale_keys = [
            key for key, t in self.flow_start.items()
            if now - t > max_age and len(self.flows.get(key, [])) < MIN_FLOW_PACKETS
        ]
        for key in stale_keys:
            self.flows.pop(key, None)
            self.last_activity.pop(key, None)
            self.flow_start.pop(key, None)


def decode_tcp_flags(flags_byte: int) -> int:
    """Decode TCP flags byte into our flag bitmap (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWE=0x80)."""
    result = 0
    if flags_byte & 0x01:
        result |= 0x01  # FIN
    if flags_byte & 0x02:
        result |= 0x02  # SYN
    if flags_byte & 0x04:
        result |= 0x04  # RST
    if flags_byte & 0x08:
        result |= 0x08  # PSH
    if flags_byte & 0x10:
        result |= 0x10  # ACK
    if flags_byte & 0x20:
        result |= 0x20  # URG
    if flags_byte & 0x40:
        result |= 0x40  # ECE  (ECN-Echo)
    if flags_byte & 0x80:
        result |= 0x80  # CWE (CWR / Congestion Window Reduced)
    return result