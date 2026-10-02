# Arch User Repository (AUR) Readiness & Activation Guide

## 1. Background & Current Status

AUR live publication is deferred by project owner direction because new user registration on `aur.archlinux.org` is temporarily suspended/unavailable.

All package recipes, metadata, source integrity hashes, and packaging validations are **100% prepared, linted, and ready** in `aur/`:
- `aur/theme-forge-stellar-burst/`
- `aur/theme-forge-stellar-loom/`
- `aur/theme-forge-solar-sail/`
- `aur/theme-forge-nebular-fusion-bin/`

*Note on Naming*: `theme-forge-nebular-fusion-bin` adopts the standard Arch Linux `-bin` convention because it packages upstream prebuilt native binaries. It includes `provides=('theme-forge-nebular-fusion')` and `conflicts=('theme-forge-nebular-fusion')`.

---

## 2. Directory Structure of Prepared Recipes

Each directory contains:
1. `PKGBUILD`: Arch Linux package build recipe consuming frozen upstream assets and enforcing Node `>= 22` or native GTK3/WebKitGTK dependencies.
2. `.SRCINFO`: Machine-readable package metadata generated via `makepkg --printsrcinfo`.

---

## 3. Activation Steps When Registration Resumes

Once AUR registration is restored, execute the following steps to publish:

### Step 1: Create AUR Account & Configure SSH
1. Register an account at [https://aur.archlinux.org/register/](https://aur.archlinux.org/register/).
2. Add your public SSH key (`~/.ssh/id_ed25519.pub`) in your AUR account profile.
3. Configure your local `~/.ssh/config`:
   ```text
   Host aur.archlinux.org
     IdentityFile ~/.ssh/id_ed25519
     User aur
   ```

### Step 2: Initialize AUR Git Repositories
For each of the four packages:
```bash
# Clone the AUR repository namespace
git clone ssh://aur@aur.archlinux.org/theme-forge-stellar-burst.git /tmp/aur-burst
git clone ssh://aur@aur.archlinux.org/theme-forge-stellar-loom.git /tmp/aur-loom
git clone ssh://aur@aur.archlinux.org/theme-forge-solar-sail.git /tmp/aur-sail
git clone ssh://aur@aur.archlinux.org/theme-forge-nebular-fusion-bin.git /tmp/aur-nebular
```

### Step 3: Copy Prepared Recipes & Verify
```bash
# Copy prepared assets
cp -a aur/theme-forge-stellar-burst/* /tmp/aur-burst/
cp -a aur/theme-forge-stellar-loom/* /tmp/aur-loom/
cp -a aur/theme-forge-solar-sail/* /tmp/aur-sail/
cp -a aur/theme-forge-nebular-fusion-bin/* /tmp/aur-nebular/

# Verify sources and lint
for pkg in burst loom sail nebular; do
  dir="/tmp/aur-$pkg"
  echo "Validating $dir..."
  (cd "$dir" && makepkg --verifysource && namcap PKGBUILD)
done
```

### Step 4: Commit and Publish
```bash
for pkg in /tmp/aur-burst /tmp/aur-loom /tmp/aur-sail /tmp/aur-nebular; do
  (
    cd "$pkg"
    git add PKGBUILD .SRCINFO
    git commit -m "feat: initial release for Theme Forge family"
    git push origin master
  )
done
```

---

## 4. Maintenance & Upstream Sync

When a new product release occurs:
1. Update `pkgver` and reset `pkgrel=1`.
2. Update the `sha256sums` with the new asset hash.
3. Regenerate `.SRCINFO`:
   ```bash
   makepkg --printsrcinfo > .SRCINFO
   ```
4. Commit and push to AUR git repository.
