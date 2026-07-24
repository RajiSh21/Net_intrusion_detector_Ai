#!/usr/bin/env python3
"""
NIDS Live Network Packet Capture & Intrusion Detection
=======================================================
Captures live network packets via Scapy, reconstructs bidirectional flows,
extracts 79 CICFlowMeter features, runs through the trained XGBoost model,
and classifies each flow as BENIGN or a specific attack type.

Usage:
    python scripts/sniffer.py                          # capture on default interface
    python scripts/sniffer.py --interface eth0          # specify interface
    python scripts/sniffer.py --pcap captured.pcap      # analyze from PCAP file
    python scripts/sniffer.py --count 100               # stop after 100 flows
    python scripts/sniffer.py --alert-only              # show only intrusion alerts
    python scripts/sniffer.py --output alerts.csv        # save alerts to CSV
    python scripts/sniffer.py --no-save                 # don't save to alert DB
"""

import os
import sys
import time
import json
import argparse
import logging
import threading
import csv
import pymongo
import socketio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from collections import deque

import numpy as np
import joblib

# ── Colored logging formatter ─────────────────────────────────────────
# Uses ANSI escape codes so intrusion alerts (WARNING) appear in RED
# and other levels get distinct colors.
_RESET = "\033[0m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_BOLD = "\033[1m"

_LEVEL_COLORS = {
    logging.CRITICAL: _BOLD + _RED,
    logging.ERROR:    _RED,
    logging.WARNING:  _RED,
    logging.INFO:     _GREEN,
    logging.DEBUG:    _YELLOW,
}


class ColoredFormatter(logging.Formatter):
    """Log formatter that colourises the level-name / message by severity."""

    def format(self, record: logging.LogRecord) -> str:
        color = _LEVEL_COLORS.get(record.levelno, _RESET)
        # Timestamp + coloured level badge + message
        asctime = self.formatTime(record, self.datefmt)
        levelname = f"{color}[{record.levelname}]{_RESET}"
        msg = record.getMessage()
        # Intrusion alerts (WARNING) get the whole message in red
        if record.levelno == logging.WARNING:
            msg = f"{color}{msg}{_RESET}"
        return f"{asctime} {levelname} {msg}"


_handler = logging.StreamHandler()
_handler.setFormatter(ColoredFormatter('%(asctime)s [%(levelname)s] %(message)s',
                                       datefmt='%Y-%m-%d %H:%M:%S'))
logging.basicConfig(level=logging.INFO, handlers=[_handler])
logger = logging.getLogger("NIDS-Sniffer")

# --- Constants ---
BENIGN_LABEL = "Normal"
ALERT_DB_PATH = "alerts.db"
DEFAULT_INTERFACE = None  # None = auto-detect
DEFAULT_SNAPLEN = 65535
DEFAULT_TIMEOUT = 300  # seconds

# Project root for model loading
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'backend')
sys.path.insert(0, BACKEND_DIR)

from utils import (
    PacketInfo, FlowFeatures, FlowCollector, decode_tcp_flags,
    MIN_FLOW_PACKETS, FLOW_TIMEOUT, MAX_FLOW_DURATION
)


# ============================================================
#  DATA CLEANING & FEATURE PREPROCESSING PIPELINE
# ============================================================
class FeaturePreprocessor:
    """Applies the exact same cleaning + preprocessing pipeline used during training."""

    def __init__(self, scaler_path: str, protocol_encoder_path: Optional[str] = None):
        """
        Load preprocessing artifacts from training.
        
        Args:
            scaler_path: Path to robust_scaler.pkl
            protocol_encoder_path: Path to protocol_encoder.pkl (if exists)
        """
        self.scaler = joblib.load(scaler_path)
        if protocol_encoder_path and os.path.exists(protocol_encoder_path):
            self.proto_encoder = joblib.load(protocol_encoder_path)
        else:
            self.proto_encoder = None

        # Store the feature names in exact order the model expects
        # (after dropping Source Port, Source IP, Dest IP, Timestamp)
        self.feature_names = [
            'Destination Port', 'Protocol', 'Flow Duration',
            'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min',
            'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std',
            'Flow Bytess', 'Flow Packetss',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packetss', 'Bwd Packetss',
            'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'CWE Flag Count', 'ECE Flag Count',
            'Down Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Avg Bytes Bulk', 'Fwd Avg Packets Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes Bulk', 'Bwd Avg Packets Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
        ]

        # Skewed features that need log1p transformation
        self.skewed_features = {
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Flow Bytess', 'Flow Packetss', 'Fwd Packetss', 'Bwd Packetss',
            'Fwd Packet Length Max', 'Bwd Packet Length Max',
            'Fwd Packet Length Mean', 'Bwd Packet Length Mean'
        }

    def clean(self, feature_vector: List[float]) -> np.ndarray:
        """Handle Inf/NaN values and apply preprocessing."""
        arr = np.array(feature_vector, dtype=np.float64)

        # STEP 1: Replace infinite values with NaN
        arr = np.where(np.isinf(arr), np.nan, arr)

        # STEP 2: If any NaN present, replace with 0.0 (the training pipeline drops NaN rows,
        #         but for live classification we impute to avoid losing the flow)
        if np.any(np.isnan(arr)):
            logger.debug("Flow contained NaN/infinite values. Imputing with 0.0 for live classification.")
            arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)

        return arr

    def transform(self, features: FlowFeatures) -> np.ndarray:
        """
        Apply the full preprocessing pipeline:
        1. Extract feature list from FlowFeatures dataclass
        2. Clean Inf/NaN
        3. Apply port binning (replace Destination Port with 3 binary flags)
        4. Apply log1p transformation to skewed features
        5. Scale using the saved StandardScaler
        Returns a 2D array of shape (1, n_features) ready for model inference.
        """
        # Get raw feature list (matches CSV column order from training)
        raw_list = features.to_list()

        # Build a dict for easier manipulation
        feature_dict = dict(zip(self.feature_names, raw_list))

        # STEP 3: BEHAVIORAL PORT BINNING (Destination Port → 3 categories)
        dst_port = feature_dict.get('Destination Port', 0.0)
        feature_dict['PORT_WELL_KNOWN'] = 1.0 if dst_port < 1024 else 0.0
        feature_dict['PORT_REGISTERED'] = 1.0 if 1024 <= dst_port < 49152 else 0.0
        feature_dict['PORT_DYNAMIC'] = 1.0 if dst_port >= 49152 else 0.0

        # STEP 4: LOG TRANSFORM on skewed volumetric features
        for feat_name in self.skewed_features:
            if feat_name in feature_dict:
                val = feature_dict[feat_name]
                feature_dict[feat_name] = np.log1p(max(float(val), 0.0))

        # STEP 5: Protocol encoding (if protocol_encoder exists, apply it)
        # Protocol from Scapy is already numeric (6=TCP, 17=UDP, etc.)
        # The training LabelEncoder mapped text→int; since our capture is already numeric,
        # we keep it as-is (models handle numeric protocols directly)
        if 'Protocol' in feature_dict:
            feature_dict['Protocol'] = float(feature_dict['Protocol'])

        # Build final feature array in the SAME ORDER as training
        # (X has: everything except Source Port, Source IP, Dest IP, Timestamp, target
        #  and with Destination Port replaced by the 3 port binning columns)
        # IMPORTANT: Order must EXACTLY match training (PORT_* columns go LAST, at positions 77-79)
        final_feature_names = [
            'Protocol', 'Flow Duration',
            'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min',
            'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std',
            'Flow Bytess', 'Flow Packetss',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packetss', 'Bwd Packetss',
            'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'CWE Flag Count', 'ECE Flag Count',
            'Down Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Avg Bytes Bulk', 'Fwd Avg Packets Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes Bulk', 'Bwd Avg Packets Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
            'PORT_WELL_KNOWN', 'PORT_REGISTERED', 'PORT_DYNAMIC',
        ]

        final_values = [float(feature_dict.get(name, 0.0)) for name in final_feature_names]
        arr = self.clean(final_values)

        # Reshape to 2D and scale
        arr_2d = arr.reshape(1, -1)
        scaled = self.scaler.transform(arr_2d)

        return scaled


# ============================================================
#  ALERT LOGGING & DATABASE
# ============================================================
class AlertLogger:
    """Logs intrusion alerts to MongoDB and optional CSV, and emits to Socket.IO."""

    def __init__(self, db_path: str = "mongodb://localhost:27017/", csv_path: Optional[str] = None,
                 save_to_db: bool = True):
        self.db_path = db_path
        self.csv_path = csv_path
        self.save_to_db = save_to_db
        
        self.sio = socketio.Client()
        try:
            self.sio.connect('http://localhost:5000')
            logger.info("Connected to local Socket.IO API server.")
        except Exception as e:
            logger.warning(f"Could not connect to Socket.IO API server: {e}")

        self._init_db()
        self._init_csv()

    def _init_db(self):
        if not self.save_to_db:
            return
        try:
            self.mongo_client = pymongo.MongoClient(self.db_path, serverSelectionTimeoutMS=2000)
            self.mongo_client.server_info() # test connection
            self.db = self.mongo_client["nids"]
            self.alerts_collection = self.db["alerts"]
            logger.info(f"Connected to MongoDB at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            self.save_to_db = False

    def _init_csv(self):
        if self.csv_path:
            file_exists = os.path.exists(self.csv_path)
            if not file_exists:
                with open(self.csv_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                        'protocol', 'prediction', 'confidence', 'num_packets',
                        'flow_duration_us', 'total_bytes'
                    ])

    def log_alert(self, prediction: str, confidence: float, flow_info: Dict,
                  features: FlowFeatures, packets: List[PacketInfo]):
        """Record an intrusion alert (and emit all packets to live UI)."""
        timestamp = datetime.now(timezone.utc).isoformat()
        src_ip = flow_info.get('src_ip', '')
        dst_ip = flow_info.get('dst_ip', '')
        src_port = flow_info.get('src_port', 0)
        dst_port = flow_info.get('dst_port', 0)
        protocol = flow_info.get('protocol', 0)
        num_packets = len(packets)
        flow_duration = features.Flow_Duration
        total_bytes = int(features.Flow_Bytess)
        
        packet_data = {
            "timestamp": timestamp,
            "src": src_ip,
            "dst": dst_ip,
            "sport": src_port,
            "dport": dst_port,
            "proto": "TCP" if protocol == 6 else "UDP" if protocol == 17 else "ICMP" if protocol == 1 else str(protocol),
            "verdict": prediction,
            "confidence": confidence,
            "length": total_bytes,
            "latencyMs": (flow_duration / 1000.0) # approx inference/latency representation
        }
        
        # Emit to WebSocket
        if self.sio.connected:
            self.sio.emit('new_packet', packet_data)

        # Only save intrusions to DB
        if prediction != BENIGN_LABEL:
            doc = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "prediction": prediction,
                "confidence": confidence,
                "num_packets": num_packets,
                "flow_duration_us": flow_duration,
                "total_bytes": total_bytes,
                "features": features.to_list()
            }
            if self.save_to_db:
                try:
                    self.alerts_collection.insert_one(doc)
                except Exception as e:
                    logger.error(f"Failed to log alert to MongoDB: {e}")

            # CSV
            if self.csv_path:
                try:
                    with open(self.csv_path, 'a', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            timestamp, src_ip, dst_ip, src_port, dst_port,
                            protocol, prediction, confidence, num_packets,
                            flow_duration, total_bytes
                        ])
                except Exception as e:
                    logger.error(f"Failed to log alert to CSV: {e}")


# ============================================================
#  MODEL LOADER & CLASSIFIER
# ============================================================
class NIDSClassifier:
    """Loads the trained XGBoost model and performs inference."""

    def __init__(self, model_path: str, scaler_path: str,
                 label_encoder_path: str,
                 protocol_encoder_path: Optional[str] = None):
        """
        Args:
            model_path: Path to xgb_nids_engine.json or model.pkl
            scaler_path: Path to robust_scaler.pkl
            label_encoder_path: Path to attack_classes.pkl
            protocol_encoder_path: Path to protocol_encoder.pkl
        """
        logger.info(f"Loading XGBoost model from {model_path}...")
        import xgboost as xgb
        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)
        logger.info("Model loaded successfully.")

        self.label_encoder = joblib.load(label_encoder_path)
        self.preprocessor = FeaturePreprocessor(scaler_path, protocol_encoder_path)

        self.class_names = list(self.label_encoder.classes_)
        self.num_classes = len(self.class_names)
        logger.info(f"Detected {self.num_classes} traffic classes: {self.class_names}")

    def classify(self, features: FlowFeatures) -> Tuple[str, float, np.ndarray]:
        """
        Classify a single flow.
        
        Returns:
            Tuple of (predicted_label, confidence, probability_array)
        """
        X_scaled = self.preprocessor.transform(features)
        probas = self.model.predict_proba(X_scaled)[0]
        predicted_idx = int(np.argmax(probas))
        predicted_label = self.class_names[predicted_idx]
        confidence = float(probas[predicted_idx])
        return predicted_label, confidence, probas

    def is_intrusion(self, label: str) -> bool:
        """Check if a predicted label represents an intrusion."""
        return label != BENIGN_LABEL


# ============================================================
#  PACKET SNIFFER (Scapy-based)
# ============================================================
class LiveSniffer:
    """Captures packets, aggregates into flows, classifies, and alerts."""

    def __init__(self, classifier: NIDSClassifier, alert_logger: AlertLogger,
                 interface: Optional[str] = None, count: int = 0,
                 alert_only: bool = False, pcap_file: Optional[str] = None):
        self.classifier = classifier
        self.alert_logger = alert_logger
        self.interface = interface
        self.max_flows = count  # 0 = unlimited
        self.alert_only = alert_only
        self.pcap_file = pcap_file

        self.flow_collector = FlowCollector()
        self.flow_count = 0
        self.intrusion_count = 0
        self.running = False
        self.lock = threading.Lock()
        self.packet_count = 0
        self.start_time = None
        self.classified_flow_count = 0

        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'intrusion_flows': 0,
            'benign_flows': 0,
            'classification_time_ms': [],
            'recent_alerts': deque(maxlen=20),
        }

    def _scapy_callback(self, pkt):
        """Callback for each captured packet (runs in Scapy thread).
        Silently aggregates packets into flows. No raw packet output."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            from scapy.layers.inet import IP as IPLayer

            if not pkt.haslayer(IPLayer):
                return

            ip_layer = pkt[IPLayer]
            timestamp = pkt.time if hasattr(pkt, 'time') else time.time()

            # Determine protocol
            if pkt.haslayer(TCP):
                proto = 6
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = decode_tcp_flags(pkt[TCP].flags)
                header_len = (ip_layer.ihl * 4) + (pkt[TCP].dataofs * 4) if hasattr(pkt[TCP], 'dataofs') else 40
                tcp_window = pkt[TCP].window if hasattr(pkt[TCP], 'window') else 0
            elif pkt.haslayer(UDP):
                proto = 17
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                flags = 0
                header_len = ip_layer.ihl * 4 + 8  # UDP header is 8 bytes
                tcp_window = 0
            elif pkt.haslayer(ICMP):
                proto = 1
                sport = 0
                dport = 0
                flags = 0
                header_len = ip_layer.ihl * 4 + 8
                tcp_window = 0
            else:
                proto = ip_layer.proto
                sport = 0
                dport = 0
                flags = 0
                header_len = ip_layer.ihl * 4
                tcp_window = 0

            packet_info = PacketInfo(
                timestamp=timestamp,
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=sport,
                dst_port=dport,
                protocol=proto,
                length=ip_layer.len,
                flags=flags,
                header_len=header_len,
                tcp_window=tcp_window,
                urgent=bool(flags & 0x20),
                push=bool(flags & 0x08),
            )

            with self.lock:
                self.packet_count += 1
                self.stats['total_packets'] += 1
                self.flow_collector.add_packet(packet_info)

        except Exception as e:
            logger.debug(f"Error processing packet: {e}")

    def _process_ready_flows(self):
        """Process flows that are ready for classification."""
        ready_flows = self.flow_collector.get_ready_flows()

        for flow_key, packets in ready_flows.items():
            if self.max_flows > 0 and self.flow_count >= self.max_flows:
                break

            try:
                t0 = time.perf_counter()
                features = self.flow_collector.extract_features(packets)
                label, confidence, probas = self.classifier.classify(features)
                elapsed = (time.perf_counter() - t0) * 1000
                self.stats['classification_time_ms'].append(elapsed)

                src_ip, src_port, dst_ip, dst_port, proto = flow_key
                flow_info = {
                    'src_ip': src_ip, 'dst_ip': dst_ip,
                    'src_port': src_port, 'dst_port': dst_port,
                    'protocol': proto,
                }

                is_intrusion = self.classifier.is_intrusion(label)
                self.flow_count += 1
                self.stats['total_flows'] += 1

                # Always log the alert so it emits to the WebSocket UI
                self.alert_logger.log_alert(
                    prediction=label,
                    confidence=confidence,
                    flow_info=flow_info,
                    features=features,
                    packets=packets,
                )

                if is_intrusion:
                    self.intrusion_count += 1
                    self.stats['intrusion_flows'] += 1
                    alert_msg = (
                        f"[!] INTRUSION DETECTED: {label} "
                        f"({confidence*100:.1f}% conf) | "
                        f"{src_ip}:{src_port} → {dst_ip}:{dst_port} "
                        f"proto={proto} | {len(packets)} pkts | "
                        f"duration={features.Flow_Duration:.0f}µs"
                    )
                    logger.warning(alert_msg)
                    self.stats['recent_alerts'].append(alert_msg)
                else:
                    self.stats['benign_flows'] += 1
                    if not self.alert_only:
                        logger.info(
                            f"    BENIGN flow classified | "
                            f"{src_ip}:{src_port} → {dst_ip}:{dst_port} "
                            f"| {label} ({confidence*100:.0f}%)"
                        )

            except Exception as e:
                logger.error(f"Error classifying flow: {e}", exc_info=True)

    def _monitor_loop(self):
        """Background thread that periodically checks for ready flows."""
        while self.running:
            try:
                with self.lock:
                    self._process_ready_flows()
                    # Cleanup stale flows every 60 seconds
                    if self.flow_count % 50 == 0 and self.flow_count > 0:
                        self.flow_collector.cleanup_stale_flows()
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
            time.sleep(1.0)  # Check every second

    def print_banner(self):
        """Display startup banner."""
        banner = """
    ╔══════════════════════════════════════════════════╗
    ║     NIDS - Network Intrusion Detection System    ║
    ║         Live Packet Capture & Classification     ║
    ╚══════════════════════════════════════════════════╝
    """
        logger.info(banner)

    def print_stats(self):
        """Print summary statistics."""
        logger.info("=" * 60)
        logger.info("  CAPTURE STATISTICS")
        logger.info("=" * 60)
        logger.info(f"  Total packets captured:  {self.stats['total_packets']}")
        logger.info(f"  Total flows classified:  {self.stats['total_flows']}")
        logger.info(f"  Benign flows:            {self.stats['benign_flows']}")
        logger.info(f"  Intrusion flows:         {self.stats['intrusion_flows']}")
        if self.stats['classification_time_ms']:
            avg_time = np.mean(self.stats['classification_time_ms'])
            logger.info(f"  Avg classification time: {avg_time:.2f} ms")
        if self.start_time:
            elapsed = time.time() - self.start_time
            logger.info(f"  Total runtime:           {elapsed:.1f}s")
        if self.stats['recent_alerts']:
            logger.info(f"\n  Recent Alerts ({len(self.stats['recent_alerts'])}):")
            for alert in list(self.stats['recent_alerts'])[-10:]:
                logger.info(f"    {alert}")
        logger.info("=" * 60)

    def start(self):
        """Start live capture or PCAP file analysis."""
        self.print_banner()

        if self.pcap_file:
            self._process_pcap(self.pcap_file)
            self.print_stats()
            return

        # Live capture mode
        try:
            import scapy.all as scapy
        except ImportError:
            logger.error(
                "Scapy is required for live packet capture.\n"
                "Install with: pip install scapy"
            )
            sys.exit(1)

        # Auto-detect interface
        if self.interface is None:
            try:
                self.interface = scapy.conf.iface
                logger.info(f"Using default interface: {self.interface}")
            except Exception:
                # Fallback: list available interfaces
                logger.info("No default interface. Available interfaces:")
                try:
                    for iface_name in scapy.get_if_list():
                        logger.info(f"  - {iface_name}")
                except Exception:
                    logger.warning("Could not list interfaces. Trying 'eth0'...")
                self.interface = 'eth0'

        logger.info(f"Starting packet capture on interface: {self.interface}")
        logger.info("Press Ctrl+C to stop capture and view statistics.\n")

        self.running = True
        self.start_time = time.time()

        # Start monitor thread
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()

        try:
            # Start Scapy sniffing (blocking)
            scapy.sniff(
                iface=self.interface,
                prn=self._scapy_callback,
                store=False,  # Don't store packets in memory
                filter=None,  # Capture all traffic
            )
        except PermissionError:
            logger.error(
                "Permission denied. Run with administrator/root privileges:\n"
                "  Windows: Run as Administrator\n"
                "  Linux:   sudo python scripts/sniffer.py"
            )
            self.running = False
            return
        except KeyboardInterrupt:
            logger.info("\nCapture interrupted by user.")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.running = False
            # Wait for remaining flows to complete
            logger.info("Processing remaining flows...")
            time.sleep(2)
            with self.lock:
                self._process_ready_flows()
            self.print_stats()

    def _process_pcap(self, pcap_path: str):
        """Process a pre-recorded PCAP file."""
        try:
            import scapy.all as scapy
        except ImportError:
            logger.error("Scapy is required. Install with: pip install scapy")
            sys.exit(1)

        if not os.path.exists(pcap_path):
            logger.error(f"PCAP file not found: {pcap_path}")
            return

        logger.info(f"Processing PCAP file: {pcap_path}")
        self.running = True
        self.start_time = time.time()

        try:
            # Read all packets from PCAP
            packets = scapy.rdpcap(pcap_path)
            logger.info(f"Loaded {len(packets)} packets from PCAP.")

            for i, pkt in enumerate(packets):
                if self.max_flows > 0 and self.flow_count >= self.max_flows:
                    break
                self._scapy_callback(pkt)
                if i % 10000 == 0 and i > 0:
                    logger.info(f"Processed {i}/{len(packets)} packets...")

            logger.info("All packets processed. Finalizing flows...")

            # Force-classify all remaining flows
            with self.lock:
                remaining = dict(self.flow_collector.flows)
                self.flow_collector.flows.clear()

            for flow_key, flow_packets in remaining.items():
                if len(flow_packets) >= MIN_FLOW_PACKETS:
                    if self.max_flows > 0 and self.flow_count >= self.max_flows:
                        break
                    try:
                        t0 = time.perf_counter()
                        features = self.flow_collector.extract_features(flow_packets)
                        label, confidence, probas = self.classifier.classify(features)
                        elapsed = (time.perf_counter() - t0) * 1000
                        self.stats['classification_time_ms'].append(elapsed)

                        src_ip, src_port, dst_ip, dst_port, proto = flow_key
                        flow_info = {
                            'src_ip': src_ip, 'dst_ip': dst_ip,
                            'src_port': src_port, 'dst_port': dst_port,
                            'protocol': proto,
                        }

                        is_intrusion = self.classifier.is_intrusion(label)
                        self.flow_count += 1
                        self.stats['total_flows'] += 1

                        if is_intrusion:
                            self.intrusion_count += 1
                            self.stats['intrusion_flows'] += 1
                            self.alert_logger.log_alert(
                                prediction=label,
                                confidence=confidence,
                                flow_info=flow_info,
                                features=features,
                                packets=flow_packets,
                            )
                            logger.warning(
                                f"[!] INTRUSION: {label} ({confidence*100:.1f}%) | "
                                f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
                            )
                        else:
                            self.stats['benign_flows'] += 1
                    except Exception as e:
                        logger.error(f"Error classifying flow: {e}")

        except Exception as e:
            logger.error(f"PCAP processing error: {e}")
        finally:
            self.running = False


# ============================================================
#  MAIN ENTRY POINT
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="NIDS Live Packet Capture & Intrusion Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/sniffer.py                          # Live capture on default interface
  python scripts/sniffer.py --interface eth0          # Specific interface
  python scripts/sniffer.py --pcap captured.pcap      # Analyze PCAP file
  python scripts/sniffer.py --count 100               # Stop after 100 flows
  python scripts/sniffer.py --alert-only              # Show only alerts
  python scripts/sniffer.py --output alerts.csv        # Save alerts to CSV
  python scripts/sniffer.py --no-save                 # Don't save to DB
        """
    )
    parser.add_argument('--interface', '-i', type=str, default=None,
                        help='Network interface to capture on (default: auto-detect)')
    parser.add_argument('--pcap', '-p', type=str, default=None,
                        help='PCAP file to analyze instead of live capture')
    parser.add_argument('--count', '-c', type=int, default=0,
                        help='Stop after N flows classified (0=unlimited)')
    parser.add_argument('--alert-only', '-a', action='store_true',
                        help='Only show intrusion alerts (suppress benign flow output)')
    parser.add_argument('--output', '-o', type=str, default=None,
                        help='CSV file path to save intrusion alerts')
    parser.add_argument('--no-save', action='store_true',
                        help='Disable saving alerts to the SQLite database')
    parser.add_argument('--model', '-m', type=str, default=None,
                        help='Path to XGBoost model (default: models/xgb_nids_engine.json)')
    parser.add_argument('--scaler', '-s', type=str, default=None,
                        help='Path to scaler (default: models/robust_scaler.pkl)')
    parser.add_argument('--labels', '-l', type=str, default=None,
                        help='Path to label encoder (default: models/attack_classes.pkl)')

    args = parser.parse_args()

    # Resolve model paths
    model_path = args.model or os.path.join(MODELS_DIR, 'xgb_nids_engine.json')
    scaler_path = args.scaler or os.path.join(MODELS_DIR, 'robust_scaler.pkl')
    labels_path = args.labels or os.path.join(MODELS_DIR, 'attack_classes.pkl')
    proto_encoder_path = os.path.join(MODELS_DIR, 'protocol_encoder.pkl')

    # Verify model files exist
    for path, name in [(model_path, "Model"), (scaler_path, "Scaler"), (labels_path, "Labels")]:
        if not os.path.exists(path):
            logger.error(f"{name} file not found: {path}")
            logger.error("Run 'python run_training.py' first to train the model.")
            sys.exit(1)

    # Initialize components
    logger.info("Initializing NIDS live capture system...")
    classifier = NIDSClassifier(model_path, scaler_path, labels_path, proto_encoder_path)
    alert_logger = AlertLogger(
        db_path="mongodb://localhost:27017/",
        csv_path=args.output,
        save_to_db=not args.no_save,
    )

    sniffer = LiveSniffer(
        classifier=classifier,
        alert_logger=alert_logger,
        interface=args.interface,
        count=args.count,
        alert_only=args.alert_only,
        pcap_file=args.pcap,
    )

    sniffer.start()


if __name__ == '__main__':
    main()