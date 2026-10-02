# Detailed Installation Guide — Theme Forge Packages

This document provides in-depth, step-by-step instructions for installing, upgrading, verifying, and uninstalling Theme Forge packages across all supported platforms.

---

## 1. Arch Linux / Pacman

### 1.1 Signature Trust Bootstrap
Pacman relies on GnuPG keyrings managed via `pacman-key`. To trust packages from `knowledge-forge-ai`, import the public key and assign local trust.

```bash
# Fetch and locally sign key
curl -sSfL -o /tmp/knowledge-forge-ai-packages.asc https://knowledge-forge-ai.github.io/theme-forge-packages/keys/knowledge-forge-ai-packages.asc

# Verify fingerprint before importing
gpg --show-keys /tmp/knowledge-forge-ai-packages.asc

# Import into pacman keyring and sign locally
sudo pacman-key --add /tmp/knowledge-forge-ai-packages.asc
FPR=$(gpg --show-keys --with-colons /tmp/knowledge-forge-ai-packages.asc | awk -F: '/^fpr/{print $10; exit}')
sudo pacman-key --lsign-key "$FPR"
rm -f /tmp/knowledge-forge-ai-packages.asc
```

### 1.2 Repository Configuration
Add the repository definition to `/etc/pacman.conf`:
```ini
[knowledge-forge-ai]
SigLevel = Required DatabaseRequired TrustedOnly
Server = https://knowledge-forge-ai.github.io/theme-forge-packages/arch/x86_64
```
*Note on SigLevel*: `DatabaseRequired` forces signature verification on `knowledge-forge-ai.db`. `TrustedOnly` ensures only signatures signed with our imported key are accepted.

### 1.3 Install
```bash
sudo pacman -Sy
sudo pacman -S theme-forge-stellar-burst
sudo pacman -S theme-forge-stellar-loom
sudo pacman -S theme-forge-solar-sail
sudo pacman -S theme-forge-nebular-fusion
```

### 1.4 Verification
```bash
tfsb --version
tfsl --version
tfss --version
tfnf --version
```

### 1.5 Uninstall
```bash
sudo pacman -R theme-forge-stellar-burst theme-forge-stellar-loom theme-forge-solar-sail theme-forge-nebular-fusion
```

---

## 2. Fedora Linux / DNF

### 2.1 Repository Setup
Create `/etc/yum.repos.d/knowledge-forge-ai.repo`:
```ini
[knowledge-forge-ai]
name=Theme Forge Packages
baseurl=https://knowledge-forge-ai.github.io/theme-forge-packages/rpm/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://knowledge-forge-ai.github.io/theme-forge-packages/keys/knowledge-forge-ai-packages.asc
```
*Note*: `gpgcheck=1` verifies individual RPM package signatures. `repo_gpgcheck=1` verifies repodata metadata signatures (`repomd.xml.asc`).

### 2.2 Install
```bash
sudo dnf install theme-forge-stellar-burst
sudo dnf install theme-forge-stellar-loom
sudo dnf install theme-forge-solar-sail
sudo dnf install theme-forge-nebular-fusion
```

### 2.3 Verification
```bash
rpm -q -i theme-forge-stellar-burst
rpm --checksig /var/cache/libdnf5/.../*.rpm 2>/dev/null || true
tfsb --version
tfsl --version
tfss --version
tfnf --version
```

### 2.4 Uninstall
```bash
sudo dnf remove theme-forge-stellar-burst theme-forge-stellar-loom theme-forge-solar-sail theme-forge-nebular-fusion
```

---

## 3. Nix Flake (NixOS, Linux, macOS)

### 3.1 Prerequisites
Ensure Nix is installed with Flakes enabled in `/etc/nix/nix.conf` or `~/.config/nix/nix.conf`:
```text
experimental-features = nix-command flakes
```

### 3.2 Install Packages
```bash
# CLIs
nix profile install github:Knowledge-Forge-AI/theme-forge-packages#theme-forge-stellar-burst
nix profile install github:Knowledge-Forge-AI/theme-forge-packages#theme-forge-stellar-loom
nix profile install github:Knowledge-Forge-AI/theme-forge-packages#theme-forge-solar-sail

# Nebular Fusion GUI Workbench
nix profile install github:Knowledge-Forge-AI/theme-forge-packages#theme-forge-nebular-fusion
```

### 3.3 Verification
```bash
tfsb --version
tfsb-studio-service --version
tfsl --version
tfsl-batch --version
tfss --version
tfnf --version
```

### 3.4 Upgrade
```bash
nix profile upgrade '.*theme-forge.*'
```

### 3.5 Uninstall
```bash
nix profile remove theme-forge-stellar-burst
nix profile remove theme-forge-stellar-loom
nix profile remove theme-forge-solar-sail
nix profile remove theme-forge-nebular-fusion
```
