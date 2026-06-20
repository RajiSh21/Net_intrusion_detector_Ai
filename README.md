-----------------Project Structure---------------------
/NIDS_Project_Root
│
├── /data
│   ├── raw/                 # Original BigFlow-NIDS or IDS2025 dataset
│   ├── processed/           # Cleaned/Log-transformed/Scaled parquet files
│   └── synthetic/           # Output folder for your GAN-generated attack rows
│
├── /models
│   ├── xgb_nids_engine.json # The trained XGBoost model binary
│   ├── robust_scaler.pkl    # The fitted StandardScaler object
│   ├── feature_encoders.pkl # Categorical encoders (e.g., Protocol, Flags)
│   └── attack_classes.pkl   # Mapping of class IDs (0,1,2) to names (Normal, DoS, etc.)
│
├── /scripts
│   ├── train_model.py       # Data cleaning + XGBoost training logic
│   ├── train_gan.py         # GAN training logic for data augmentation
│   ├── sniffer.py           # Live Scapy sniffing & feature engineering loop
│   └── utils.py             # Shared functions (e.g., flow calculation logic)
│
├── /dashboard
│   └── app.py               # Streamlit web app code
│
├── /logs
│   └── alerts.db            # SQLite database storing detected intrusions
│
├── requirements.txt         # List of all Python dependencies
└── README.md                # Project overview, setup, and instructions



























Remove Useless Features
-------------------------------------
Never train on identifiers.
Remove columns like:
[
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp"
]
Why--------------??????
Example:
192.168.1.10 → Attack
The model learns the IP instead of attack behavior.
This causes overfitting.
----------------------------------------