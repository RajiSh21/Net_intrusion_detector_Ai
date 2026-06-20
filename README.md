# Network Intrusion Detection System (NIDS) — AI-Powered

A machine learning pipeline that detects network intrusions using XGBoost trained on the IDS2025 network flow dataset. Includes feature engineering, GAN-based data augmentation for class balancing, and a trained classifier achieving 99% accuracy across 7 attack categories.

---

## Project Structure

```
Nid/
├── Data/
│   ├── raw/                          # Original dataset (IDS2025.csv — 91,830 rows × 80 features)
│   └── processed/
│       └── clean.ipynb               # Exploratory Data Analysis notebook
├── models/
│   ├── featurue_engineering.ipynb    # Phase 1: Feature engineering pipeline
│   ├── train_gan.ipynb               # Phase 2: GAN data augmentation
│   ├── xgboost_training.ipynb        # Phase 3: XGBoost training & evaluation
│   ├── attack_classes.pkl            # Label encoder (class names → IDs)
│   ├── robust_scaler.pkl             # Fitted StandardScaler
│   ├── X_train_processed.npy         # Scaled training features (73,362 × 80)
│   ├── X_test_processed.npy          # Scaled test features (18,341 × 80)
│   ├── y_train.npy / y_test.npy      # Training & test labels
│   ├── xgb_nids_engine.json          # Trained XGBoost model (JSON format)
│   └── model.pkl                     # Trained XGBoost model (pickle format)
├── run_training.py                   # One-command full pipeline runner
├── requirement.ttxt                  # Python dependencies
├── .gitignore
└── Readme.md
```

---

## Dataset: IDS2025

| Property | Value |
|----------|-------|
| Total rows | 91,830 |
| Features | 80 (flow statistics, packet lengths, flags, IAT, etc.) |
| Target column | `newLabel` |
| Classes | 7 |

### Class Distribution (Training Set)

| Class | Samples |
|-------|---------|
| Normal | 20,932 |
| Dos/DDos | 20,794 |
| PortScan | 20,310 |
| Brute Force | 8,158 |
| Web Attack | 1,654 |
| Botnet ARES | 1,491 |
| Infiltration | 23 |

---

## Pipeline Overview

### Phase 1: Feature Engineering (`featurue_engineering.ipynb`)

- Loads IDS2025.csv (91,830 rows × 80 columns)
- Cleans infinite/NaN values (254 bad rows dropped)
- Drops leaky features: `Source IP`, `Dest IP`, `Timestamp`, `Source Port`
- Bins `Destination Port` into 3 behavioral categories (well-known / registered / dynamic)
- Applies log1p transformation to 10 skewed volumetric features (byte counts, packet counts)
- Encodes `Protocol` field (text → numeric via LabelEncoder)
- Encodes target labels (`newLabel`)
- Splits data 80/20 with stratified sampling (73,362 train / 18,341 test)
- Standardizes features with StandardScaler
- Saves: `.npy` arrays, `robust_scaler.pkl`, `attack_classes.pkl`

### Phase 2: GAN Data Augmentation (`train_gan.ipynb`)

- PyTorch GAN with Generator (3-layer) + Discriminator (3-layer)
- Trains a separate GAN for each minority attack class
- Generates synthetic samples to match the majority class size
- Fixes severe class imbalance (e.g., Infiltration: 23 → 20,932 samples)
- Outputs: `X_train_balanced.npy`, `y_train_balanced.npy`

> **Note:** Phase 2 is optional. The pipeline works without it (99% accuracy), but GAN augmentation improves minority-class recall.

### Phase 3: XGBoost Training (`xgboost_training.ipynb`)

- Loads training data (balanced if GAN was run, otherwise original processed data)
- XGBoost classifier: 300 trees, max_depth=7, learning_rate=0.08
- Trains with early stopping monitoring on validation set
- Exports model to `xgb_nids_engine.json` and `model.pkl`

---

## Results

### Model Performance (without GAN augmentation)

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

> Infiltration recall (67%) is low due to only 23 training samples. Running Phase 2 (GAN) resolves this.

---

## How to Run

### Prerequisites

Install dependencies:
```cmd
pip install -r requirement.ttxt
```

### Option 1: One-command full pipeline
```cmd
python run_training.py
```
With `--skip-gan` flag for faster training (skips GAN augmentation):
```cmd
python run_training.py --skip-gan
```

### Option 2: Run notebooks individually in VS Code
1. Open `Data/processed/clean.ipynb` → Run All (EDA)
2. Open `models/featurue_engineering.ipynb` → Run All
3. Open `models/train_gan.ipynb` → Run All (optional)
4. Open `models/xgboost_training.ipynb` → Run All

---

## Bugs Fixed

### `models/featurue_engineering.ipynb`
| Bug | Fix |
|-----|-----|
| `FiileNotFoundError` (typo) | → `FileNotFoundError` |
| Missing indentation on `if missing_count > 0:` block | Added proper indentation |
| `y_raw = df[target_col]` inside error-raising `if` block | Moved outside so it actually executes |
| Dataset path `"IDS2025.csv"` | → `"../Data/raw/IDS2025.csv"` |

### `models/train_gan.ipynb` (12 bugs)
| Bug | Fix |
|-----|-----|
| `np.reandom.seed` | → `np.random.seed` |
| Class name `TabluarzGenerator` | → `TabularGenerator` |
| `nn.linear` | → `nn.Linear` |
| `nn.Tanh` (no parentheses) | → `nn.Tanh()` |
| Class name `TabularDiscriminatore` | → `TabularDiscriminator` |
| `input__dim` (double underscore) | → `input_dim` |
| `X_minority.shappe` | → `X_minority.shape` |
| `discriminator.paramter` | → `discriminator.parameters()` |
| `DataLoader = DataLoader(...)` overwrites import | → `dataloader = DataLoader(...)` |
| `real_samaples` in for-loop | → `real_samples` |
| `real_samples` referenced but undefined | Variable now consistent |
| `nn.Sigmoid` (no parentheses) | → `nn.Sigmoid()` |

### `models/xgboost_training.ipynb`
| Bug | Fix |
|-----|-----|
| `model` out of scope in pickle cell | Pickle logic moved inside function |
| Silent failure when GAN files missing | Falls back to original processed data |
| Missing `pickle` import | Added |

### `Data/processed/clean.ipynb`
| Bug | Fix |
|-----|-----|
| `df['newlabel']` (wrong case) | → `df['newLabel']` |

### `requirement.ttxt`
| Missing | Added |
|---------|-------|
| `numpy`, `torch`, `joblib` | All added |

---

## Tech Stack

- **Python 3.14**
- **pandas** — Data loading & manipulation
- **NumPy** — Numerical operations
- **scikit-learn** — Preprocessing, metrics, train/test split
- **XGBoost** — Gradient boosted tree classifier
- **PyTorch** — GAN implementation for data augmentation
- **joblib** — Model serialization

---

## Intended Future Components (Not Yet Built)

Per the original project design:
- `/scripts/sniffer.py` — Live Scapy packet capture + real-time classification
- `/scripts/train_gan.py` — Standalone GAN training script
- `/scripts/utils.py` — Shared flow calculation utilities
- `/dashboard/app.py` — Streamlit dashboard for monitoring
- `/logs/alerts.db` — SQLite database for detected intrusion logs