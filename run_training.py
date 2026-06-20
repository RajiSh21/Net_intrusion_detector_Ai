"""
NIDS Full Training Pipeline
===========================
Runs: Feature Engineering → GAN Augmentation (optional) → XGBoost Training
Usage:  python run_training.py
        python run_training.py --skip-gan   (skip GAN for faster training)
"""

import os
import sys
import argparse

# ------------------------------------------------------------
# Ensure we work from the models/ directory so all saved
# artifacts land there and load paths are correct.
# ------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
os.chdir(MODELS_DIR)
sys.path.insert(0, MODELS_DIR)

# ============================================================
#  PHASE 1: FEATURE ENGINEERING
# ============================================================
print("=" * 60)
print("  PHASE 1: FEATURE ENGINEERING PIPELINE")
print("=" * 60)

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

CSV_PATH = os.path.join(PROJECT_ROOT, "Data", "raw", "IDS2025.csv")

def run_feature_engineering(file_path):
    print("[*] Launching IDS2025 Feature Engineering Pipeline.....")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target dataset '{file_path}' not found.")
    print("[*] Ingesting CSV rows...")
    df = pd.read_csv(file_path)
    print(f"[+] Data loaded. Dimensions: {df.shape[0]} rows, {df.shape[1]} columns.")

    # STEP 1: CLEAN MATHEMATICAL ANOMALIES (Inf / NaN)
    print("[*] Cleaning network flow math calc limits (Infinities/Nulls)...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    missing_count = df.isnull().sum().sum()
    if missing_count > 0:
        print(f"[!] Warning: Found {missing_count} total missing/infinite data blocks. Clearing records...")
        df.dropna(inplace=True)

    # STEP 2: ISOLATE TARGET LABELS & DROP SOURCE PORT/IPs
    target_col = 'newLabel'
    if target_col not in df.columns:
        raise ValueError(f"Critical target columns '{target_col}' missing from your dataset layout.")
    y_raw = df[target_col]

    features_to_drop = [target_col, 'Source Port']
    for col in ['Source IP', 'Dest IP', 'Timestamp']:
        if col in df.columns:
            features_to_drop.append(col)

    X = df.drop(columns=features_to_drop)

    # STEP 3: BEHAVIORAL PORT BINNING (Destination Ports)
    print("[*] Engineering Destination Port network profiles...")
    if 'Destination Port' in X.columns:
        X['PORT_WELL_KNOWN'] = (X['Destination Port'] < 1024).astype(int)
        X['PORT_REGISTERED'] = ((X['Destination Port'] >= 1024) & (X['Destination Port'] < 49152)).astype(int)
        X['PORT_DYNAMIC'] = (X['Destination Port'] >= 49152).astype(int)
        X.drop(columns=['Destination Port'], inplace=True)

    # STEP 4: LOG TRANSFORM DISTRIBUTIONS FOR VOLUMETRIC DATA
    print("[*] Applying log scale transformation on skewed volumetric parameters...")
    skewed_network_features = [
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Flow Bytess', 'Flow Packetss', 'Fwd Packetss', 'Bwd Packetss',
        'Fwd Packet Length Max', 'Bwd Packet Length Max',
        'Fwd Packet Length Mean', 'Bwd Packet Length Mean'
    ]
    for feature in skewed_network_features:
        if feature in X.columns:
            X[feature] = np.log1p(X[feature])

    # STEP 5: CATEGORICAL PROTOCOL ENCODING
    if 'Protocol' in X.columns:
        if X['Protocol'].dtype == 'object':
            print("[*] Encoding text-based Protocol fields...")
            proto_encoder = LabelEncoder()
            X['Protocol'] = proto_encoder.fit_transform(X['Protocol'].astype(str))
            joblib.dump(proto_encoder, "protocol_encoder.pkl")

    # STEP 6: TARGET ENCODING
    print("[*] Encapsulating threat output class matrices...")
    target_encoder = LabelEncoder()
    y_encoded = target_encoder.fit_transform(y_raw)
    print(f"[+] Map Configuration Classes Verified: {dict(zip(target_encoder.classes_, target_encoder.transform(target_encoder.classes_)))}")

    return X, y_encoded, target_encoder


# Run Phase 1
print("[*] Splitting dataset into training and validation environments...")
X_engineered, y_encoded, target_encoder = run_feature_engineering(CSV_PATH)
X_train, X_test, y_train, y_test = train_test_split(
    X_engineered, y_encoded, test_size=0.2, stratify=y_encoded, random_state=42
)

print("[*] Normalizing continuous features with StandardScaler...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("[*] Serializing engineered scaling artifacts...")
joblib.dump(scaler, "robust_scaler.pkl")
joblib.dump(target_encoder, "attack_classes.pkl")

np.save('X_train_processed.npy', X_train_scaled)
np.save('X_test_processed.npy', X_test_scaled)
np.save('y_train.npy', y_train)
np.save('y_test.npy', y_test)

print("\n" + "=" * 40)
print("[+] SUCCESS: Feature Engineering Pipeline Completed.")
print(f"    Processed Features Shape: {X_train_scaled.shape}")
print("    Saved Artifacts: robust_scaler.pkl, attack_classes.pkl")
print("=" * 40)

# ============================================================
#  PHASE 2: GAN DATA AUGMENTATION (OPTIONAL)
# ============================================================
parser = argparse.ArgumentParser()
parser.add_argument('--skip-gan', action='store_true', help='Skip GAN augmentation')
args, _ = parser.parse_known_args()

if args.skip_gan:
    print("\n" + "=" * 60)
    print("  PHASE 2: GAN DATA AUGMENTATION - SKIPPED")
    print("=" * 60)
else:
    print("\n" + "=" * 60)
    print("  PHASE 2: GAN DATA AUGMENTATION")
    print("=" * 60)

    try:
        import torch
        import torch.nn as nn
        import torch.optim as optim
        from torch.utils.data import DataLoader, TensorDataset

        torch.manual_seed(42)
        np.random.seed(42)

        class TabularGenerator(nn.Module):
            def __init__(self, latent_dim, output_dim):
                super().__init__()
                self.model = nn.Sequential(
                    nn.Linear(latent_dim, 128),
                    nn.BatchNorm1d(128),
                    nn.ReLU(),
                    nn.Linear(128, 256),
                    nn.BatchNorm1d(256),
                    nn.ReLU(),
                    nn.Linear(256, output_dim),
                    nn.Tanh()
                )

            def forward(self, z):
                return self.model(z)

        class TabularDiscriminator(nn.Module):
            def __init__(self, input_dim):
                super().__init__()
                self.model = nn.Sequential(
                    nn.Linear(input_dim, 256),
                    nn.LeakyReLU(0.2),
                    nn.Linear(256, 128),
                    nn.LeakyReLU(0.2),
                    nn.Linear(128, 1),
                    nn.Sigmoid()
                )

            def forward(self, x):
                return self.model(x)

        def train_tabular_gan(X_minority, epochs=150, batch_size=64, latent_dim=32):
            input_dim = X_minority.shape[1]
            generator = TabularGenerator(latent_dim, input_dim)
            discriminator = TabularDiscriminator(input_dim)

            criterion = nn.BCELoss()
            optimizer_G = optim.Adam(generator.parameters(), lr=0.0002, betas=(0.5, 0.999))
            optimizer_D = optim.Adam(discriminator.parameters(), lr=0.0002, betas=(0.5, 0.999))

            dataset = TensorDataset(torch.FloatTensor(X_minority))
            dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=True)

            for epoch in range(epochs):
                for i, (real_samples,) in enumerate(dataloader):
                    current_batch_size = real_samples.size(0)
                    real_labels = torch.ones(current_batch_size, 1)
                    fake_labels = torch.zeros(current_batch_size, 1)

                    # Train Discriminator
                    optimizer_D.zero_grad()
                    outputs_real = discriminator(real_samples)
                    loss_real = criterion(outputs_real, real_labels)

                    z = torch.randn(current_batch_size, latent_dim)
                    fake_samples = generator(z)
                    outputs_fake = discriminator(fake_samples.detach())
                    loss_fake = criterion(outputs_fake, fake_labels)

                    loss_D = loss_real + loss_fake
                    loss_D.backward()
                    optimizer_D.step()

                    # Train Generator
                    optimizer_G.zero_grad()
                    outputs_g_fake = discriminator(fake_samples)
                    loss_G = criterion(outputs_g_fake, real_labels)
                    loss_G.backward()
                    optimizer_G.step()

                if (epoch + 1) % 50 == 0 or epoch == 0:
                    print(f"    [Epoch {epoch+1}/{epochs}] Loss D: {loss_D.item():.4f} | Loss G: {loss_G.item():.4f}")

            return generator

        # ---- Run GAN ----
        X_train = np.load('X_train_processed.npy')
        y_train = np.load('y_train.npy')
        target_encoder = joblib.load('attack_classes.pkl')

        classes, counts = np.unique(y_train, return_counts=True)
        max_samples = np.max(counts)
        normal_class_idx = classes[np.argmax(counts)]

        print(f"[+] Majority baseline target size per class: {max_samples} rows.")

        X_augmented_list = [X_train]
        y_augmented_list = [y_train]

        for class_idx in classes:
            if class_idx == normal_class_idx:
                continue

            class_name = target_encoder.inverse_transform([class_idx])[0]
            class_mask = (y_train == class_idx)
            X_minority = X_train[class_mask]
            samples_to_generate = max_samples - len(X_minority)

            if samples_to_generate <= 0:
                continue

            print(f"[*] Training GAN for minority class: '{class_name}'...")
            print(f"    Target: Fabricating {samples_to_generate} synthetic network signatures...")

            gen_model = train_tabular_gan(X_minority, epochs=100, batch_size=32)

            z_noise = torch.randn(samples_to_generate, 32)
            with torch.no_grad():
                synthetic_features = gen_model(z_noise).numpy()

            synthetic_labels = np.full(samples_to_generate, class_idx)
            X_augmented_list.append(synthetic_features)
            y_augmented_list.append(synthetic_labels)
            print(f"[+] Synthesis complete for class '{class_name}'.")

        X_train_balanced = np.concatenate(X_augmented_list, axis=0)
        y_train_balanced = np.concatenate(y_augmented_list, axis=0)

        print("\n" + "=" * 40)
        print("[+] GAN AUGMENTATION ENGINE COMPLETE")
        print(f"    Original Training Data Shape: {X_train.shape}")
        print(f"    Balanced Training Data Shape: {X_train_balanced.shape}")
        print("=" * 40)

        np.save('X_train_balanced.npy', X_train_balanced)
        np.save('y_train_balanced.npy', y_train_balanced)
        print("[*] Balanced data matrices exported.")

    except ImportError:
        print("[!] PyTorch not installed. Skipping GAN augmentation.")
        print("[!] Install with: pip install torch")

# ============================================================
#  PHASE 3: XGBOOST TRAINING
# ============================================================
print("\n" + "=" * 60)
print("  PHASE 3: XGBOOST TRAINING")
print("=" * 60)

import xgboost as xgb
import pickle
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

target_encoder = joblib.load('attack_classes.pkl')

if os.path.exists('X_train_balanced.npy') and os.path.exists('y_train_balanced.npy'):
    print("[*] Loading BALANCED Training Matrices (Real + GAN Synthetic Data)...")
    X_train = np.load('X_train_balanced.npy')
    y_train = np.load('y_train_balanced.npy')
else:
    print("[!] GAN-balanced data not found. Falling back to ORIGINAL processed data...")
    print("[!] (Run with --skip-gan was used or GAN files missing)")
    X_train = np.load('X_train_processed.npy')
    y_train = np.load('y_train.npy')

print("[*] Loading Unseen Testing Matrices for Validation...")
X_test = np.load('X_test_processed.npy')
y_test = np.load('y_test.npy')

num_classes = len(target_encoder.classes_)
print(f"[+] Data loaded. {num_classes} distinct network traffic profiles.")
print(f"    Training: {X_train.shape[0]} samples x {X_train.shape[1]} features")
print(f"    Testing:  {X_test.shape[0]} samples x {X_test.shape[1]} features")

# Class distribution
classes, counts = np.unique(y_train, return_counts=True)
print(f"\n    Training Class Distribution:")
for cls, cnt in zip(classes, counts):
    name = target_encoder.inverse_transform([cls])[0]
    print(f"      {name}: {cnt} samples")

# Configure XGBoost
print("\n[*] Configuring XGBoost Hyperparameters...")
model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=7,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    objective='multi:softprob',
    num_class=num_classes,
    eval_metric='mlogloss',
    random_state=42,
    tree_method='hist'
)

# Train
print("[*] Training XGBoost (this may take a few minutes)...\n")
model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=25
)
print("\n[+] Model optimization convergence complete.")

# Evaluate
print("\n[*] Evaluating on unseen test data...")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
class_names = [str(cls) for cls in target_encoder.classes_]

print("\n" + "=" * 60)
print(f"   SYSTEM VALIDATION PERFORMANCE: OVERALL ACCURACY = {accuracy*100:.2f}%")
print("=" * 60)
print()
print(classification_report(y_test, y_pred, target_names=class_names))
print("=" * 60)

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
print()
print("   CONFUSION MATRIX (rows=true, cols=predicted):")
print("   " + "-" * 50)
header = "          " + " ".join([f"{str(c):>8s}" for c in class_names])
print(header)
for i, row in enumerate(cm):
    row_str = " ".join([f"{val:8d}" for val in row])
    print(f"   {class_names[i]:>8s} {row_str}")
print("   " + "-" * 50)

# Export model
print()
output_model_path = "xgb_nids_engine.json"
print(f"[*] Exporting model to '{output_model_path}'...")
model.save_model(output_model_path)

with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
print("[+] Model exported as 'xgb_nids_engine.json' and 'model.pkl'.")
print("\n" + "=" * 60)
print("   TRAINING PIPELINE COMPLETE")
print("=" * 60)