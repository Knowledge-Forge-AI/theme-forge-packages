# Theme Forge Packages (`Knowledge-Forge-AI/theme-forge-packages`)

Official, signed, reproducible self-distribution repository for the Theme Forge software family across Linux and macOS.

## Released Products

| Product | Version | Bins / Executables | Runtimes / Dependencies |
| :--- | :--- | :--- | :--- |
| **Theme Forge Stellar Burst** | `0.6.1` | `tfsb`, `tfsb-studio-service` | Node.js `>= 22`, native posix-openat addon |
| **Theme Forge Stellar Loom** | `0.4.0` | `tfsl`, `tfsl-batch` | Node.js `>= 22`, zero external deps |
| **Theme Forge Solar Sail** | `0.2.1` | `tfss` | Node.js `>= 22`, zero external deps |
| **Theme Forge Nebular Fusion** | `0.6.1` | `tfnf`, GUI Workbench | Native GTK3/WebKitGTK 4.1 on Linux; macOS `.app` |

---

## 1. Nix Flake Distribution

The repository exposes a self-contained Nix flake that requires no external binary caches or runtime npm fetching.

### Supported Systems:
- **CLIs** (`tfsb`, `tfsl`, `tfss`): `x86_64-linux`, `aarch64-linux`, `aarch64-darwin`, `x86_64-darwin`
- **Nebular Fusion** (`tfnf`): `x86_64-linux`, `aarch64-linux`, `aarch64-darwin`

### Installation:
```bash
# Install CLI packages
nix profile install github:Knowledge-Forge-AI/theme-forge-packages#theme-forge-stellar-burst
nix profile install github:Knowledge-Forge-AI/theme-forge-packages#theme-forge-stellar-loom
nix profile install github:Knowledge-Forge-AI/theme-forge-packages#theme-forge-solar-sail

# Install Nebular Fusion desktop workbench
nix profile install github:Knowledge-Forge-AI/theme-forge-packages#theme-forge-nebular-fusion
```

### Direct Execution:
```bash
nix run github:Knowledge-Forge-AI/theme-forge-packages#tfsb -- --version
nix run github:Knowledge-Forge-AI/theme-forge-packages#tfsl -- --version
nix run github:Knowledge-Forge-AI/theme-forge-packages#tfss -- --version
nix run github:Knowledge-Forge-AI/theme-forge-packages#tfnf -- --version
```

### Upgrading:
```bash
nix profile upgrade '.*theme-forge.*'
```

### Uninstallation:
```bash
nix profile remove theme-forge-stellar-burst
nix profile remove theme-forge-stellar-loom
nix profile remove theme-forge-solar-sail
nix profile remove theme-forge-nebular-fusion
```

---

## 2. Pacman Custom Signed Repository (Arch Linux)

The `knowledge-forge-ai` pacman repository serves signed Arch Linux packages and signed repository databases.

### Supported Architectures:
- `x86_64` (official self-hosted repository; community multi-architecture builds available via AUR)

### Trust Bootstrap:
Import the official project OpenPGP signing key and locally sign/trust it:
```bash
# Method A: Direct public key import (Recommended)
curl -sSfL -o /tmp/kfa-packages.asc https://knowledge-forge-ai.github.io/theme-forge-packages/keys/knowledge-forge-ai-packages.asc
sudo pacman-key --add /tmp/kfa-packages.asc
FPR=$(gpg --show-keys --with-colons /tmp/kfa-packages.asc | awk -F: '/^fpr/{print $10; exit}')
sudo pacman-key --lsign-key "$FPR"
rm /tmp/kfa-packages.asc

# Method B: Keyserver import (once published to public keyservers by operator)
# sudo pacman-key --recv-keys --keyserver keyserver.ubuntu.com <DISTRIBUTION_KEY_FINGERPRINT>
# sudo pacman-key --lsign-key <DISTRIBUTION_KEY_FINGERPRINT>
```

### Repository Configuration:
Add the repository to `/etc/pacman.conf` with hardened signature checking:
```ini
[knowledge-forge-ai]
SigLevel = Required DatabaseRequired TrustedOnly
Server = https://knowledge-forge-ai.github.io/theme-forge-packages/arch/x86_64
```

### Installation:
```bash
sudo pacman -Sy
sudo pacman -S theme-forge-stellar-burst theme-forge-stellar-loom theme-forge-solar-sail theme-forge-nebular-fusion
```

### Upgrading:
```bash
sudo pacman -Syu
```

### Uninstallation:
```bash
sudo pacman -R theme-forge-stellar-burst theme-forge-stellar-loom theme-forge-solar-sail theme-forge-nebular-fusion
```

---

## 3. DNF / RPM Repository (Fedora Linux)

The RPM repository provides signed RPMs with signed repository metadata (`repomd.xml.asc`).

### Supported Architectures:
- `x86_64`
- `aarch64`

### Repository Setup:
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

### Installation:
```bash
sudo dnf install theme-forge-stellar-burst theme-forge-stellar-loom theme-forge-solar-sail theme-forge-nebular-fusion
```

### Upgrading:
```bash
sudo dnf upgrade 'theme-forge-*'
```

### Uninstallation:
```bash
sudo dnf remove theme-forge-stellar-burst theme-forge-stellar-loom theme-forge-solar-sail theme-forge-nebular-fusion
```

---

## 4. Arch User Repository (AUR Readiness)

AUR recipes are fully prepared and linted in `aur/`:
- `theme-forge-stellar-burst`
- `theme-forge-stellar-loom`
- `theme-forge-solar-sail`
- `theme-forge-nebular-fusion-bin`

See [AUR-READINESS.md](AUR-READINESS.md) for instructions on submitting to the AUR once account registration is open.

---

## 5. Security & Verification

- **Offline Primary Key**: Distribution root key is maintained offline. Only revocable signing subkeys are used in GitHub Actions.
- **Detached Signatures**: All RPMs, Pacman packages, Pacman databases, and repomd metadata have detached signatures.
- **Standalone Verification Tools**: See `tools/verification/` for offline verification scripts.
- **Publication Provenance**: Each publication cycle generates a cryptographic provenance file in `provenance/publication-provenance.json`.
