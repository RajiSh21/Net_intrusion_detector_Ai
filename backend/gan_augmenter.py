import os
import numpy as np
import joblib

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

    def train_tabular_gan(X_minority, device, epochs=150, batch_size=64, latent_dim=32):
        input_dim = X_minority.shape[1]
        generator = TabularGenerator(latent_dim, input_dim).to(device)
        discriminator = TabularDiscriminator(input_dim).to(device)

        criterion = nn.BCELoss()
        optimizer_G = optim.Adam(generator.parameters(), lr=0.0002, betas=(0.5, 0.999))
        optimizer_D = optim.Adam(discriminator.parameters(), lr=0.0002, betas=(0.5, 0.999))

        effective_batch_size = min(len(X_minority), batch_size)
        effective_batch_size = max(2, effective_batch_size)
        drop_last = len(X_minority) >= effective_batch_size

        X_tensor = torch.tensor(X_minority, dtype=torch.float32, device=device)
        dataset = TensorDataset(X_tensor)
        dataloader = DataLoader(dataset, batch_size=effective_batch_size, shuffle=True, drop_last=drop_last)

        for epoch in range(epochs):
            for i, (real_samples,) in enumerate(dataloader):
                current_batch_size = real_samples.size(0)
                real_labels = torch.ones(current_batch_size, 1, device=device)
                fake_labels = torch.zeros(current_batch_size, 1, device=device)

                optimizer_D.zero_grad()
                outputs_real = discriminator(real_samples)
                loss_real = criterion(outputs_real, real_labels)

                z = torch.randn(current_batch_size, latent_dim, device=device)
                fake_samples = generator(z)
                outputs_fake = discriminator(fake_samples.detach())
                loss_fake = criterion(outputs_fake, fake_labels)

                loss_D = loss_real + loss_fake
                loss_D.backward()
                optimizer_D.step()

                optimizer_G.zero_grad()
                outputs_g_fake = discriminator(fake_samples)
                loss_G = criterion(outputs_g_fake, real_labels)
                loss_G.backward()
                optimizer_G.step()
                
                with torch.no_grad():
                    real_acc = (outputs_real > 0.5).float().mean()
                    fake_acc = (outputs_fake < 0.5).float().mean()
                    d_accuracy = (real_acc + fake_acc) / 2.0 * 100

            if (epoch + 1) % 50 == 0 or epoch == 0:
                print(f"    [Epoch {epoch+1}/{epochs}] Loss D: {loss_D.item():.4f} | Loss G: {loss_G.item():.4f} | D-Accuracy: {d_accuracy.item():.1f}%")

        return generator
    
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False


def run_phase_2(output_dir):
    print("\n" + "=" * 60)
    print("  PHASE 2: GAN DATA AUGMENTATION")
    print("=" * 60)

    if not PYTORCH_AVAILABLE:
        print("[!] PyTorch not installed. Skipping GAN augmentation.")
        print("[!] Install with: pip install torch")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] GAN Augmentation running on device: {device}")

    try:
        X_train = np.load(os.path.join(output_dir, 'X_train_processed.npy'))
        y_train = np.load(os.path.join(output_dir, 'y_train.npy'))
        target_encoder = joblib.load(os.path.join(output_dir, 'attack_classes.pkl'))
    except FileNotFoundError as e:
        print(f"[!] Missing required files for Phase 2: {e}")
        return

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

        if len(X_minority) < 10:
            print(f"    [!] Warning: Extremely few samples ({len(X_minority)}) for class '{class_name}'. Using random oversampling instead of GAN.")
            idx = np.random.choice(len(X_minority), samples_to_generate, replace=True)
            synthetic_features = X_minority[idx]
            synthetic_labels = np.full(samples_to_generate, class_idx)
            X_augmented_list.append(synthetic_features)
            y_augmented_list.append(synthetic_labels)
            print(f"[+] Oversampling complete for class '{class_name}'.")
            continue

        print(f"[*] Training GAN for minority class: '{class_name}'...")
        print(f"    Target: Fabricating {samples_to_generate} synthetic network signatures...")

        gen_model = train_tabular_gan(X_minority, device, epochs=2, batch_size=32)

        z_noise = torch.randn(samples_to_generate, 32, device=device)
        with torch.no_grad():
            synthetic_features = gen_model(z_noise).cpu().numpy()

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

    np.save(os.path.join(output_dir, 'X_train_balanced.npy'), X_train_balanced)
    np.save(os.path.join(output_dir, 'y_train_balanced.npy'), y_train_balanced)
    print("[*] Balanced data matrices exported.")
