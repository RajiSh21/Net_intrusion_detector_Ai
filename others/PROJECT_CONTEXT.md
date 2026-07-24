# NIDS — Network Intrusion Detection System (AI-Powered)

## Project Overview

This is a **machine learning pipeline** that detects network intrusions in real-time. It uses an **XGBoost classifier** trained on the **IDS2025 network flow dataset** (91,830 rows × 80 features) to classify bidirectional network flows into **7 traffic categories** — 1 benign and 6 attack types.

The project has two modes:
- **Training mode** — Process the IDS2025 CSV dataset, engineer features, optionally augment minority classes with a GAN, train an XGBoost classifier, and save the model.
- **Live detection mode** — Capture live network packets via Scapy, reconstruct bidirectional flows, extract the same 79 CICFlowMeter features, run through the trained model, and output classification results (intrusion or benign). No raw packet data is displayed — only classification decisions.

---

## Target Classes (7)

| Class | Description |
|-------|-------------|
| **Normal** | Benign traffic |
| **Dos/DDos** | Denial of Service / Distributed DoS |
| **PortScan** | Port scanning activity |
| **Brute Force** | Brute force login attempts |
| **Web Attack** | Web-based attacks (SQLi, XSS, etc.) |
| **Botnet ARES** | Botnet command & control traffic |
| **Infiltration** | Network infiltration attempts |

---

## How to Run

The project has two separate entry points — **train once**, then **detect anytime**:

### 🏋️ Train the model (once)

```bash
python src/train_model.py                    # Full pipeline: feature → GAN → XGBoost
python src/train_model.py --skip-gan         # Skip GAN (faster)
python src/train_model.py --phase feature    # Only feature engineering
python src/train_model.py --phase gan        # Only GAN augmentation
python src/train_model.py --phase xgboost    # Only XGBoost training
```

### 🕵️ Run live detection (after training)

```bash
python src/run_detector.py                   # Live capture on default interface
python src/run_detector.py --interface eth0  # Specific interface
python src/run_detector.py --pcap file.pcap  # Analyze PCAP file
python src/run_detector.py --alert-only      # Show only intrusion alerts
python src/run_detector.py --count 100       # Stop after 100 flows
```

---

## Project File Structure

```
Nid/
├── src/                                     # ← Python source code
│   ├── train_model.py                       #   Train the model ONCE
│   ├── run_detector.py                      #   Run live detection anytime
│   ├── sniffer.py                           #   Packet capture & classification engine
│   └── utils.py                             #   Flow feature extraction (79 features)
│
├── notebooks/                               # ← Jupyter notebooks (numbered)
│   ├── 01_data_cleaning.ipynb               #   EDA & data cleaning
│   ├── 02_feature_engineering.ipynb         #   Phase 1: feature engineering
│   ├── 03_gan_augmentation.ipynb            #   Phase 2: GAN data augmentation
│   └── 04_xgboost_training.ipynb            #   Phase 3: XGBoost training
│
├── data/
│   └── raw/
│       └── IDS2025.csv                      # 91,830 rows × 80 columns (CICFlowMeter features)
│
├── models/                                  # ← Trained model artifacts (generated)
│   ├── attack_classes.pkl                   #   LabelEncoder (class name → integer)
│   ├── robust_scaler.pkl                    #   Fitted StandardScaler
│   ├── protocol_encoder.pkl                 #   LabelEncoder for Protocol field (if text)
│   ├── X_train_processed.npy                #   Scaled training features (73,362 × 80)
│   ├── X_test_processed.npy                 #   Scaled test features (18,341 × 80)
│   ├── y_train.npy / y_test.npy             #   Training & test labels
│   ├── X_train_balanced.npy                 #   GAN-augmented balanced features
│   ├── y_train_balanced.npy                 #   GAN-augmented balanced labels
│   ├── xgb_nids_engine.json                 #   Trained XGBoost model (JSON)
│   └── model.pkl                            #   Trained XGBoost model (pickle)
│
├── docs/                                    # ← Project documentation (PDFs)
├── logs/                                    # ← Runtime logs & SQLite alert DB
├── requirements.txt                         # Python dependencies
├── PROJECT_CONTEXT.md                       # This file — full project docs
├── Readme.md                                # Human-readable readme
└── .gitignore
```

---

## Data Pipeline (IDs2025 Dataset)

### Input Dataset Schema
The IDS2025 CSV has **80 columns** in the following exact order:

```
Source Port          # DROPPED (leaky feature)
Destination Port     # BINNED → 3 port category columns
Protocol             # TCP=6, UDP=17, ICMP=1 (numeric or text)
Flow Duration        # microseconds
Total Fwd Packets
Total Backward Packets
Total Length of Fwd Packets
Total Length of Bwd Packets
Fwd Packet Length Max / Min / Mean / Std
Bwd Packet Length Max / Min / Mean / Std
Flow Bytess           # (note: double-s in spelling)
Flow Packetss
Flow IAT Mean / Std / Max / Min
Fwd IAT Total / Mean / Std / Max / Min
Bwd IAT Total / Mean / Std / Max / Min
Fwd PSH Flags
Bwd PSH Flags
Fwd URG Flags
Bwd URG Flags
Fwd Header Length
Bwd Header Length
Fwd Packetss
Bwd Packetss
Min Packet Length
Max Packet Length
Packet Length Mean / Std / Variance
FIN Flag Count
SYN Flag Count
RST Flag Count
PSH Flag Count
ACK Flag Count
URG Flag Count
CWE Flag Count         # CWR (Congestion Window Reduced)
ECE Flag Count         # ECN-Echo
Down Up Ratio
Average Packet Size
Avg Fwd Segment Size
Avg Bwd Segment Size
Fwd Avg Bytes Bulk / Packets Bulk / Bulk Rate
Bwd Avg Bytes Bulk / Packets Bulk / Bulk Rate
Subflow Fwd Packets / Bytes
Subflow Bwd Packets / Bytes
Init_Win_bytes_forward
Init_Win_bytes_backward
act_data_pkt_fwd
min_seg_size_forward
Active Mean / Std / Max / Min
Idle Mean / Std / Max / Min
newLabel              # TARGET (removed from features)
```

> **Note**: The dataset contains `Source IP`, `Dest IP`, and `Timestamp` columns that were in the original but are dropped during feature engineering to prevent data leakage. If present in your CSV, the pipeline handles them automatically.

---

## Phase 1: Feature Engineering Pipeline

**File**: `src/train_model.py` or `notebooks/02_feature_engineering.ipynb`

### Step-by-step processing:

1. **Load CSV** → Read IDS2025.csv into pandas DataFrame
2. **Clean Inf/NaN** → Replace infinite values with NaN, drop rows with missing data
3. **Drop Leaky Features** → Remove `Source Port`, `Source IP`, `Dest IP`, `Timestamp` (these cause overfitting)
4. **Port Binning** → Replace `Destination Port` (numeric) with 3 binary flags:
   - `PORT_WELL_KNOWN` (port < 1024)
   - `PORT_REGISTERED` (1024 ≤ port < 49152)
   - `PORT_DYNAMIC` (port ≥ 49152)
5. **Log Transform** → Apply `log1p` to 10 skewed volumetric features:
   - `Total Length of Fwd Packets`, `Total Length of Bwd Packets`
   - `Flow Bytess`, `Flow Packetss`, `Fwd Packetss`, `Bwd Packetss`
   - `Fwd Packet Length Max`, `Bwd Packet Length Max`
   - `Fwd Packet Length Mean`, `Bwd Packet Length Mean`
6. **Protocol Encoding** → If Protocol column is text-based, encode with LabelEncoder
7. **Target Encoding** → Encode `newLabel` with LabelEncoder → `attack_classes.pkl`
8. **Train/Test Split** → 80/20 stratified split (73,362 train / 18,341 test)
9. **StandardScale** → Fit StandardScaler on training data, transform both sets → `robust_scaler.pkl`

### Final feature order after Phase 1 (80 columns):

```
[0]  Protocol
[1]  Flow Duration
[2]  Total Fwd Packets
[3]  Total Backward Packets
[4]  Total Length of Fwd Packets
...
[73] Idle Mean
[74] Idle Std
[75] Idle Max
[76] Idle Min
[77] PORT_WELL_KNOWN      ← port binning columns go LAST
[78] PORT_REGISTERED
[79] PORT_DYNAMIC
```

**CRITICAL**: The 3 PORT_* columns are appended at positions 77-79 (the end). This order must be exactly replicated during live capture preprocessing.

---

## Phase 2: GAN Data Augmentation (Optional)

**File**: `src/train_model.py` or `notebooks/03_gan_augmentation.ipynb`

### Purpose
The IDS2025 dataset has severe class imbalance:
- Normal: 20,932 samples
- Infiltration: only 23 samples

The GAN generates synthetic samples for each minority class to balance the dataset.

### Architecture
- **Generator**: 3-layer MLP (32→128→256→output_dim) with BatchNorm + ReLU, final Tanh
- **Discriminator**: 3-layer MLP (input→256→128→1) with LeakyReLU(0.2), final Sigmoid
- **Training**: Adam optimizer (lr=0.0002, betas=(0.5, 0.999)), BCELoss, 100 epochs

### Process
1. For each minority class, train a separate GAN for 100 epochs
2. Generate synthetic samples to match majority class size
3. For classes with <10 samples, use random oversampling instead

Outputs: `X_train_balanced.npy`, `y_train_balanced.npy`

> Can be skipped with `--skip-gan` flag. Model still achieves 99% accuracy without GAN.

---

## Phase 3: XGBoost Training

**File**: `run_training.py` (Phase 3 section) or `models/xgboost_training.ipynb`

### Model Hyperparameters
```python
XGBClassifier(
    n_estimators=300,
    max_depth=7,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    objective='multi:softprob',     # multi-class probability
    eval_metric='mlogloss',
    tree_method='hist',
    device='cuda' or 'cpu'
)
```

### Training
- Loads balanced data if GAN was run, otherwise original processed data
- Trains with evaluation on held-out test set (`eval_set`)
- GPU accelerated if CUDA is available

### Model Export
- `xgb_nids_engine.json` — XGBoost native JSON format
- `model.pkl` — Python pickle format

### Performance
```
Overall Accuracy: 99.00%

              precision    recall  f1-score   support
 Botnet ARES       0.99      0.99      0.99       373
 Brute Force       1.00      1.00      1.00      2040
    Dos/DDos       0.98      0.99      0.98      5199
Infiltration       1.00      0.67      0.80         6
      Normal       0.99      0.97      0.98      5233
    PortScan       1.00      1.00      1.00      5077
  Web Attack       1.00      1.00      1.00       413
```

---

## Phase 4: Live Packet Capture & Classification

**File**: `scripts/sniffer.py` (main module), `scripts/utils.py` (feature extraction)

### Architecture Overview

```
Network Interface / PCAP File
        │
        ▼
┌───────────────────┐
│  Scapy Sniffer     │  ← captures every IP packet
│  (silent, no raw   │
│   packet output)   │
└───────┬───────────┘
        │ PacketInfo objects
        ▼
┌───────────────────┐
│  FlowCollector     │  ← groups packets into bidirectional flows
│  (utils.py)        │    keyed by (src_ip, src_port, dst_ip, dst_port, proto)
└───────┬───────────┘
        │ Flow termination detected (FIN/RST/timeout)
        ▼
┌───────────────────┐
│  Feature Extraction│  ← computes all 79 CICFlowMeter features
│  (FlowCollector)   │    from raw packet sequences
└───────┬───────────┘
        │ FlowFeatures dataclass
        ▼
┌───────────────────┐
│  FeaturePreprocessor│ ← 5-step pipeline:
│  (sniffer.py)      │   1. Clean Inf/NaN
│                    │   2. Port binning (Dest Port → 3 flags)
│                    │   3. Log1p transform (10 skewed features)
│                    │   4. Protocol encoding
│                    │   5. StandardScaler normalization
└───────┬───────────┘
        │ numpy array (1, 80)
        ▼
┌───────────────────┐
│  XGBoost Model     │  ← trained classifier
│  (NIDSClassifier)  │
└───────┬───────────┘
        │ (label, confidence, probabilities)
        ▼
┌───────────────────┐
│  AlertLogger       │  ← saves intrusions to SQLite + CSV
│  Classification    │
│  Output            │
└───────────────────┘
        │
        ▼
   BENIGN or INTRUSION output to console
```

### Component Details

#### `PacketInfo` (utils.py)
Lightweight dataclass representing one captured packet:
```python
@dataclass
class PacketInfo:
    timestamp: float        # epoch time
    src_ip: str             # source IP
    dst_ip: str             # destination IP
    src_port: int           # source port
    dst_port: int           # destination port
    protocol: int           # IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    length: int             # IP total length
    flags: int              # TCP flags bitmap (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWE=0x80)
    header_len: int         # IP + transport header length
    tcp_window: int         # TCP window size
```

#### `FlowFeatures` (utils.py)
Dataclass containing all 79 computed features before preprocessing. The `to_list()` method returns them in the exact CSV column order expected by the preprocessing pipeline.

#### `FlowCollector` (utils.py)
- **Flow Aggregation**: Groups packets by 5-tuple flow key
- **Direction Separation**: Splits packets into forward (initiator→responder) and backward directions based on the first packet's direction
- **Flow Termination Detection**:
  - TCP FIN or RST flag seen
  - Idle timeout (120 seconds)
  - Maximum duration exceeded (300 seconds)
- **Feature Extraction**: Computes all 79 features:
  - Basic metrics: destination port, protocol, flow duration, byte/packet counts
  - Forward/backward packet statistics (length max/min/mean/std)
  - Inter-arrival time statistics (flow-level, forward, backward)
  - TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, ECE, CWE)
  - Directional flag counts (fwd_psh, bwd_psh, fwd_urg, bwd_urg)
  - Header lengths
  - Down/up ratio (download/upload bytes)
  - Average packet/segment sizes
  - Bulk transfer statistics (consecutive same-direction packets)
  - Subflow statistics
  - Init window bytes (TCP window from first packet)
  - Active data packets forward
  - Min segment size forward
  - Active/idle time statistics

#### `FeaturePreprocessor` (sniffer.py)
Replicates the exact same preprocessing that was applied during training:
1. Replace `inf` / `-inf` with NaN, then impute NaN with 0.0 (training would drop these rows, but live classification must not lose flows)
2. Port binning: `Destination Port` → `PORT_WELL_KNOWN`, `PORT_REGISTERED`, `PORT_DYNAMIC`
3. `np.log1p()` on 10 skewed volumetric features
4. Protocol encoding (Scapy provides numeric protocols, so this is passthrough)
5. Transform with the saved `robust_scaler.pkl` (StandardScaler)

**CRITICAL**: Feature order after preprocessing is the same 80-column order as training (Protocol first, PORT_* columns last at positions 77-79).

#### `NIDSClassifier` (sniffer.py)
- Loads XGBoost model from `xgb_nids_engine.json`
- Loads LabelEncoder from `attack_classes.pkl`
- `classify(FlowFeatures) → (label, confidence, probas)`:
  1. Preprocess features via FeaturePreprocessor
  2. Run model.predict_proba()
  3. Return predicted class name, confidence, and full probability array

#### `AlertLogger` (sniffer.py)
- Creates SQLite table `alerts` with columns: id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, prediction, confidence, num_packets, flow_duration_us, total_bytes, features_json
- Optional CSV export with same fields
- Only logs intrusion alerts (not benign flows)

#### `LiveSniffer` (sniffer.py)
Main orchestrator class:
- **`_scapy_callback(pkt)`**: Runs for every captured packet. Parses IP/TCP/UDP/ICMP layers. Creates PacketInfo and adds to FlowCollector. **No raw packet output.**
- **`_process_ready_flows()`**: Checks FlowCollector for completed flows. Extracts features, classifies, logs alerts or benign results.
- **`_monitor_loop()`**: Background thread that calls `_process_ready_flows()` every 1 second.
- **`start()`**: Sets up Scapy sniffer on interface, starts monitor thread, blocks on `scapy.sniff()`. Ctrl+C stops gracefully.
- **`_process_pcap(path)`**: Processes a pre-recorded PCAP file offline. Reads all packets, feeds through callback, then force-classifies remaining flows.

### Output Format

```
2026-06-21 10:30:45 [WARNING] [!] INTRUSION DETECTED: PortScan (97.3% conf) | 10.0.0.15:1234 → 192.168.1.5:80 proto=6 | 142 pkts | duration=2450000µs
2026-06-21 10:30:46 [INFO]     BENIGN flow classified | 192.168.1.5:44321 → 8.8.8.8:443 | Normal (99%)
```

---

## Usage Commands

### Full Training Pipeline
```bash
# Train everything (feature engineering + GAN + XGBoost)
python run_training.py

# Train without GAN augmentation (faster)
python run_training.py --skip-gan

# Run only feature engineering
python run_training.py --phase feature

# Run only XGBoost training
python run_training.py --phase xgboost
```

### Live Detection
```bash
# Start live capture with classification output
python run_training.py --phase live

# Show only intrusion alerts
python run_training.py --phase live --alert-only

# Capture on specific interface
python scripts/sniffer.py --interface "Ethernet 2"

# Analyze a PCAP file
python scripts/sniffer.py --pcap captured.pcap

# Save alerts to CSV
python scripts/sniffer.py --output alerts.csv

# Stop after 100 flows
python scripts/sniffer.py --count 100
```

---

## Dependencies

```
numpy
pandas
scikit-learn
xgboost
torch        # For GAN augmentation (optional)
joblib
scapy        # For live packet capture
```

### Additional System Requirements for Live Capture
- **Windows**: Run as Administrator (required for raw socket access)
- **Linux**: Run with `sudo` (required for packet capture)
- **Npcap/WinPcap**: Required on Windows (installed automatically with Scapy)

---

## Key Design Decisions

1. **Feature order is critical**: The XGBoost model was trained with features in a specific order. The live pipeline must produce features in the exact same order. The PORT_* columns go at positions 77-79 (the end), not at the beginning.

2. **NaN handling in live mode**: Training drops rows with NaN. Live mode imputes NaN with 0.0 to avoid losing flows. This is acceptable because NaN in live capture is rare (only from division by zero edge cases).

3. **Flow termination**: Flows are classified when they naturally end (TCP FIN/RST) or after 120 seconds of inactivity or 300 seconds maximum. This prevents memory leaks from long-lived idle connections.

4. **Silent packet capture**: By default, no raw packet information is displayed. The system only outputs classification results. The `--alert-only` flag further suppresses benign flow output.

5. **Bidirectional flow model**: The first packet in a flow determines the "forward" direction. All subsequent packets from the same source→destination are forward; reverse direction packets are backward. This matches how CICFlowMeter defines flow directions.

6. **Protocol handling**: Scapy provides numeric protocol numbers (6=TCP, 17=UDP). If the training dataset used text-based protocol names, a `protocol_encoder.pkl` is saved during training. The live pipeline handles both cases.

---

## Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| `PermissionError` on live capture | Not running as admin/root | Run as Administrator (Windows) or with `sudo` (Linux) |
| `Model file not found` | Model not trained yet | Run `python run_training.py` first |
| `Scapy not installed` | Missing dependency | `pip install scapy` |
| `Feature shape mismatch` | Wrong feature order in sniffer | Verify PORT_* columns are at positions 77-79 |
| `XGBoost GPU error` | CUDA not available | Model automatically falls back to CPU |
| Low detection accuracy | Model trained without GAN on imbalanced data | Run with GAN augmentation (without `--skip-gan`) |



