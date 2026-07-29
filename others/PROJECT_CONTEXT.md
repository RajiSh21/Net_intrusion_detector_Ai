# NIDS — Network Intrusion Detection System (AI-Powered)

## Project Overview

This is a comprehensive **machine learning pipeline and real-time dashboard** that detects network intrusions. It uses an **XGBoost classifier** trained on the **IDS2025 network flow dataset** (91,830 rows × 80 features) to classify bidirectional network flows into **7 traffic categories** — 1 benign and 6 attack types.

The project features a modern full-stack architecture:
- **Backend**: Python-based machine learning pipeline (XGBoost, PyTorch GAN), packet sniffer (Scapy), and a Socket.IO API server.
- **Frontend**: A React + Vite real-time dashboard that connects via WebSockets to visualize network traffic and intrusion alerts.
- **Database**: SQLite for persisting intrusion alerts.

The project has two modes:
- **Training mode** — Process the IDS2025 CSV dataset, engineer features, optionally augment minority classes with a GAN, train an XGBoost classifier, and save the model artifacts.
- **Live detection mode** — Capture live network packets via Scapy, reconstruct bidirectional flows, extract 79 CICFlowMeter features, run through the trained XGBoost model, and beam the classification results in real-time to the React dashboard.

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

## Project Architecture & Tech Stack

### Tools and Frameworks
- **Python 3.10+**: Core programming language for ML and backend.
- **pandas, NumPy**: Data loading, manipulation, and numerical operations.
- **scikit-learn**: Preprocessing (StandardScaler, LabelEncoder), metrics, train/test split.
- **XGBoost**: Gradient boosted tree classifier.
- **PyTorch**: GAN implementation for tabular data augmentation.
- **joblib**: Fast model serialization.
- **Scapy**: Live raw packet capture and parsing.
- **Flask & Flask-SocketIO**: API server and WebSockets for real-time frontend communication.
- **React + Vite**: High-performance interactive dashboard frontend.
- **TailwindCSS**: UI styling for the React frontend.
- **SQLite**: Storage for captured intrusion alerts.

### Project File Structure

```
Nid/
├── backend/                                 # ← Python source code & ML pipeline
│   ├── api_server.py                        #   Socket.IO server bridging sniffer & frontend
│   ├── data_prep.py                         #   Phase 1: Feature engineering
│   ├── gan_augmenter.py                     #   Phase 2: GAN data augmentation
│   ├── run_detector.py                      #   CLI wrapper to run live detection
│   ├── sniffer.py                           #   Packet capture & classification engine
│   ├── train_model.py                       #   Training pipeline orchestrator
│   ├── train_xgboost.py                     #   Phase 3: XGBoost training
│   └── utils.py                             #   Flow feature extraction logic (79 features)
│
├── frontend/                                # ← React-based live dashboard (Vite)
│   ├── src/                                 #   React source code (App, components)
│   ├── public/                              #   Static assets
│   ├── package.json                         #   Node dependencies
│   └── vite.config.js                       #   Vite configuration
│
├── models/                                  # ← Trained model artifacts (generated)
│   ├── attack_classes.pkl                   #   LabelEncoder (class name → integer)
│   ├── robust_scaler.pkl                    #   Fitted StandardScaler
│   ├── xgb_nids_engine.json                 #   Trained XGBoost model (JSON)
│   └── model.pkl                            #   Trained XGBoost model (pickle)
│
├── others/                                  # ← Documentation and Data
│   ├── Data/                                #   raw/IDS2025.csv dataset goes here
│   └── PROJECT_CONTEXT.md                   #   This file — full project docs
│
├── start_all.bat                            # Quick-start script to launch the full system
├── requirements.txt                         # Python dependencies
└── Readme.md                                # Human-readable readme
```

---

## How to Run

### 1. Run the Live Dashboard Ecosystem (Recommended)

Simply double-click the `start_all.bat` script in the root directory **as Administrator** (required for raw packet capture). This automatically opens 3 terminals to start:
1. React frontend UI on `http://localhost:5173`
2. Flask-SocketIO API Server on `http://localhost:5000`
3. Packet Sniffer engine which captures traffic and emits events.

### 2. Train the model (Once)

```bash
python backend/train_model.py                # Full pipeline: feature → GAN → XGBoost
python backend/train_model.py --skip-gan     # Skip GAN (faster)
python backend/train_model.py --phase feature # Only feature engineering
python backend/train_model.py --phase gan    # Only GAN augmentation
python backend/train_model.py --phase xgboost # Only XGBoost training
```

### 3. Run live detection via CLI (Headless)

```bash
python backend/run_detector.py               # Live capture on default interface
python backend/run_detector.py --interface eth0  # Specific interface
python backend/run_detector.py --pcap file.pcap  # Analyze offline PCAP file
python backend/run_detector.py --alert-only  # Show only intrusion alerts
```

---

## Pipeline Overview

### Phase 1: Feature Engineering (`backend/data_prep.py`)
- Reads `IDS2025.csv` (91,830 rows × 80 columns).
- Cleans infinite/NaN values.
- Drops leaky features (`Source IP`, `Dest IP`, `Timestamp`, `Source Port`).
- Bins `Destination Port` into 3 binary flags: Well-Known, Registered, Dynamic.
- Applies `log1p` transformation to 10 skewed volumetric features (byte counts, packet lengths).
- Encodes target labels into numeric using `LabelEncoder`.
- Splits data into 80/20 train/test.
- Applies `StandardScaler` to normalize the data.
- Saves processed `.npy` arrays and fitted `.pkl` scalers/encoders to `models/`.

### Phase 2: GAN Data Augmentation (`backend/gan_augmenter.py`)
- Uses PyTorch to train a separate Generative Adversarial Network for each minority attack class.
- Generator (3-layer MLP) and Discriminator (3-layer MLP) architecture.
- Generates synthetic tabular samples to match the majority class size, resolving severe class imbalances (e.g., Infiltration class with only 23 original samples).
- Outputs balanced `.npy` features and labels.

### Phase 3: XGBoost Training (`backend/train_xgboost.py`)
- Loads balanced data (or original processed data if GAN skipped).
- Trains an XGBoost classifier (`n_estimators=300`, `max_depth=7`, `learning_rate=0.08`).
- Evaluates against the held-out test set to avoid overfitting.
- Achieves **~99.00% accuracy**.
- Exports the model to `models/xgb_nids_engine.json` and `models/model.pkl`.

---

## Live Capture Engine Details (`backend/sniffer.py` & `backend/utils.py`)

The live pipeline accurately replicates the training feature extraction in real-time.

1. **Packet Capture (`Scapy`)**: Sniffs IP packets silently without raw output.
2. **Flow Reconstruction (`utils.FlowCollector`)**: Groups packets bidirectionally using a 5-tuple key (src_ip, src_port, dst_ip, dst_port, protocol). Detects flow termination via TCP FIN/RST flags or timeouts.
3. **Feature Extraction (`utils.FlowFeatures`)**: Computes 79 CICFlowMeter features dynamically (IAT stats, flags counts, packet length stats, etc.).
4. **Preprocessing**: Replaces inf/NaN, performs port binning, applies `log1p`, and transforms using the saved `StandardScaler`. **Critical:** Feature order strictly matches the 80 columns from training.
5. **Classification**: XGBoost predicts probabilities.
6. **Alert Logging & Broadcasting**: Intrusion alerts are saved to SQLite and broadcasted via WebSockets (`api_server.py`) to the React frontend.

---

## Data Input Schema Details
The expected 80 features derived per flow during live capture (and in the CSV) include: Flow Duration, Forward/Backward Packet counts, Protocol, IAT stats, TCP flag counts (FIN, SYN, RST, PSH, ACK, URG), subflow metrics, active/idle time, and ending with the one-hot encoded binned destination port flags (`PORT_WELL_KNOWN`, `PORT_REGISTERED`, `PORT_DYNAMIC`).

## Common Troubleshooting
- **PermissionError on Live Capture**: Sniffer requires Administrator (Windows) or `sudo` (Linux) privileges to bind to raw sockets.
- **FileNotFoundError for Models**: Ensure `python backend/train_model.py` has been executed first.
- **SQLite Connection Error**: Ensure the backend has write permissions to the `logs/alerts.db` file for alert persistence and dashboard stats.
