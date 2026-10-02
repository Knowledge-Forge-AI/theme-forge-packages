# Package Signing & Trust Bootstrap Guide

This guide details the cryptographic key architecture, generation procedures, GitHub Actions secret configuration, and rotation policies for the Theme Forge distribution infrastructure.

---

## 1. Security Architecture & Threat Model

```text
+----------------------------------------------------------------+
|                 OFFLINE PRIMARY CERTIFY KEY [C]                |
|  - 4096-bit RSA or Ed25519 (Certify only)                      |
|  - Air-gapped / Hardware token / Offline storage               |
|  - NEVER exposed to GitHub Actions, CI, or internet hosts      |
|  - Used solely to issue subkeys and revocation certificates    |
+-------------------------------+--------------------------------+
                                |
                   Certifies    |
                                v
+----------------------------------------------------------------+
|                   CI SIGNING SUBKEY [S]                        |
|  - 4096-bit RSA Signing Subkey (validity: 12 months)           |
|  - Stored encrypted in GitHub Actions Secret:                  |
|    `PACKAGE_SIGNING_KEY` on `github-pages` environment         |
|  - Signs Pacman packages (.pkg.tar.zst.sig), Pacman DBs,       |
|    RPM packages (.rpm), and repomd.xml.asc                     |
|  - Revocable instantly without changing public key identity    |
+-------------------------------+--------------------------------+
                                |
                   Published as |
                                v
+----------------------------------------------------------------+
|                    PUBLIC KEY BUNDLE                           |
|  - `keys/knowledge-forge-ai-packages.asc`                      |
|  - Published on static Pages site & Ubuntu/OpenPGP keyservers  |
|  - Imported by users to bootstrap package verification         |
+-------------------------------+--------------------------------+
```

### Critical Security Directives for Operators

> [!CAUTION]
> **NEVER upload, paste, or expose private key material or passphrases** to ChatGPT, LLMs, GitHub issues, pull requests, CI workflow artifacts, commit logs, or public repositories.
>
> - **Only the public key bundle** (`keys/knowledge-forge-ai-packages.asc`) ever enters git commits or public repositories.
> - **Primary certify private key** must remain strictly offline and must NEVER touch CI, network hosts, or batch configuration files.
> - **CI signing subkey secret** (`PACKAGE_SIGNING_KEY` and `PACKAGE_SIGNING_PASSPHRASE`) is configured in the protected repository environment (`github-pages`) strictly **AFTER** exact-commit hosted validation succeeds.
> - **CI passphrase isolation**: The signing subkey is re-protected with a distinct CI-only passphrase in an isolated staging `GNUPGHOME` before export. The offline primary master passphrase NEVER touches CI or batch configuration files.
> - **Offline primary private material is never usable from the CI bundle**: GnuPG's `--export-secret-subkeys "${SIGNING_SUBKEY_FPR}!"` command exports only secret subkey material and substitutes a dummy/stub primary secret key record (`gnu-dummy` / card-stub). The offline master certify private key material is neither present nor recoverable from the exported CI secret bundle.

---

## 2. Key Generation Runbook (Attended / Offline)

Execute these commands on a secure, offline workstation. All passphrases are entered interactively through attended pinentry prompts and are never written to batch files, scripts, or disk.

### Step 1: Create an Isolated Temporary Environment
```bash
export GNUPGHOME="$(mktemp -d -t gpg-bootstrap-XXXXXX)"
chmod 700 "$GNUPGHOME"
```

### Step 2: Generate Master Certify Key (Attended / Interactive Pinentry)
```bash
# Attended interactive generation: GnuPG prompts for a strong master passphrase via pinentry.
# DO NOT write passphrases into batch files, config files, or command line arguments.
gpg --quick-generate-key "Theme Forge Distribution Authority <packages@knowledgeforge.ai>" rsa4096 cert never
```

### Step 3: Extract Master Key ID and Fingerprint
```bash
MASTER_KEY_ID=$(gpg --list-keys --with-colons packages@knowledgeforge.ai | awk -F: '/^pub/{print $5}')
MASTER_FPR=$(gpg --list-keys --with-colons packages@knowledgeforge.ai | awk -F: '/^fpr/{print $10; exit}')
echo "Master Key ID: $MASTER_KEY_ID"
echo "Master Key Fingerprint: $MASTER_FPR"
```

### Step 4: Generate CI Signing Subkey (1-Year Expiration, Attended Pinentry)
```bash
# Attended interactive subkey generation: GnuPG prompts for the subkey passphrase via pinentry.
gpg --quick-add-key "$MASTER_FPR" rsa4096 sign 1y
SIGNING_SUBKEY_FPR=$(gpg --list-keys --with-colons packages@knowledgeforge.ai | awk -F: '/^sub/{getline; if ($1 == "fpr") print $10; exit}')
echo "Signing Subkey Fingerprint: $SIGNING_SUBKEY_FPR"
```

### Step 5: Generate Pre-Computed Revocation Certificate
```bash
gpg --armor --output "revocation-${MASTER_KEY_ID}.asc" --gen-revoke "$MASTER_KEY_ID"
# Store this revocation certificate in secure offline cold storage (e.g. encrypted media).
```

### Step 6: Export Public Key Bundle & Run Attended Bootstrap Tool
```bash
gpg --armor --export packages@knowledgeforge.ai > production-packages.asc
# Verify exported public key structure
gpg --show-keys production-packages.asc

# CRITICAL OPERATOR STEP (Mandatory First-Push Gate):
# Run the attended bootstrap operator tool with the exported production public key bundle.
# This validates key structure, rejects fixture keys, writes keys/knowledge-forge-ai-packages.asc,
# runs all static projection validators, and updates the projection binding manifest:
node tools/distribution/bootstrap-public-repo.mjs --production-key production-packages.asc
```

### Step 7: Isolate CI Passphrase via Staging GNUPGHOME & Export Final CI Bundle

To enforce strict cryptographic isolation between your offline master passphrase and CI automation:

1. **Export Secret Subkey to Staging**:
   Export secret material using the exact fingerprint selector (`${SIGNING_SUBKEY_FPR}!`) so only the designated subkey is exported:
   ```bash
   gpg --armor --export-secret-subkeys "${SIGNING_SUBKEY_FPR}!" > staging-signing-subkey.asc
   ```

2. **Import into Clean Temporary Staging GNUPGHOME**:
   ```bash
   export STAGING_GNUPGHOME="$(mktemp -d -t gpg-staging-XXXXXX)"
   chmod 700 "$STAGING_GNUPGHOME"
   GNUPGHOME="$STAGING_GNUPGHOME" gpg --batch --import staging-signing-subkey.asc

   # Verify stub primary (sec#) and active subkey (ssb)
   GNUPGHOME="$STAGING_GNUPGHOME" gpg --list-secret-keys
   ```

3. **Re-protect Subkey with Distinct CI-Only Passphrase (Attended Pinentry)**:
   ```bash
   GNUPGHOME="$STAGING_GNUPGHOME" gpg --edit-key "$SIGNING_SUBKEY_FPR"
   # In GnuPG interactive menu:
   # > key 1
   # > passwd
   # (Enter current master passphrase, then enter NEW distinct CI-only passphrase)
   # > save
   ```
   Always run `passwd` inside the staging `GNUPGHOME`, never in the offline master keyring: in the master keyring GnuPG also re-protects the primary key with the new passphrase. In staging, GnuPG prints `error changing passphrase: No secret key` for the stub primary (and for any public-only subkey) and exits non-zero; this is expected. The signing subkey is still re-protected, which the final export with the new CI-only passphrase confirms.

4. **Export Final CI Secret Bundle**:
   ```bash
   GNUPGHOME="$STAGING_GNUPGHOME" gpg --armor --export-secret-subkeys "${SIGNING_SUBKEY_FPR}!" > ci-signing-subkey.asc
   rm -rf "$STAGING_GNUPGHOME" staging-signing-subkey.asc
   ```

### Step 8: Clean Up Local Environment
```bash
# Securely backup GNUPGHOME and the revocation certificate to encrypted offline cold storage
# (e.g., LUKS encrypted drive or VeraCrypt container).
# Once backed up to encrypted offline media, remove the temporary working directory:
rm -rf "$GNUPGHOME"
```

---

## 3. GitHub Actions Secret Configuration

1. In the public repository (`Knowledge-Forge-AI/theme-forge-packages`), navigate to **Settings** > **Environments**.
2. Create or open the environment: **`github-pages`**.
3. Under **Environment secrets**, add:
   - Name: `PACKAGE_SIGNING_KEY`
     - Value: The complete ASCII-armored content of `ci-signing-subkey.asc`.
   - Name: `PACKAGE_SIGNING_PASSPHRASE`
     - Value: The distinct CI-only passphrase configured for the signing subkey during attended re-protection in Step 7. (MANDATORY: The `publish.yml` workflow strictly requires this secret to unlock the subkey when signing RPM packages, RPM `repomd.xml`, and Pacman databases; workflow fails closed immediately if unset or empty).
4. Under **Deployment protection rules**, enable **Required reviewers** to prevent automated or unauthorized releases.

---

## 4. Annual Subkey Rotation Runbook

Every 12 months, or in case of suspected CI environment compromise, the signing subkey must be rotated under the same isolation and security discipline as initial key bootstrap.

> [!CAUTION]
> **Mandatory Attended Interactive Pinentry & LLM Redaction Policy**:
> - Never hardcode or pass the master passphrase or CI passphrase on the command line, in environment variables, or in shell history.
> - All passphrase entries must be performed via attended interactive pinentry prompts.
> - Never upload, paste, or expose private key material or passphrases to ChatGPT, LLMs, external chatbots, or unvetted cloud services.

### 4.1 Step-by-Step Rotation Sequence

1. **Keep Primary Offline**: The offline master certify key remains on the secure, air-gapped administrator workstation.
2. **Generate New 1-Year Signing Subkey**:
   ```bash
   # Attended interactive pinentry prompt for master key passphrase
   gpg --quick-add-key "$MASTER_FPR" rsa4096 sign 1y
   ```
3. **Identify the Exact New Signing Subkey Fingerprint**:
   Query GnuPG colons for active signing-capable (`s`) subkeys to avoid selecting encryption or inactive subkeys:
   ```bash
   NEW_SIGNING_SUBKEY_FPR=$(gpg --list-keys --with-colons "$MASTER_FPR" | awk -F: '$1=="sub" && $12 ~ /s/ {subfpr=$5} $1=="fpr" && subfpr {print $10; subfpr=""}' | tail -n 1)
   echo "New Signing Subkey FPR: $NEW_SIGNING_SUBKEY_FPR"
   ```
4. **Retire and Revoke the Old CI Signing Subkey**:
   The CI bundle and public key bundle must contain **exactly ONE active signing subkey** (preflight fails closed if multiple active signing subkeys exist).
   ```bash
   gpg --edit-key "$MASTER_FPR"
   # gpg> key <index-of-old-subkey>
   # gpg> revkey
   # Select: 2 (Key is superseded)
   # Description: Superseded by annual rotation
   # Confirm with 'y' and attended master passphrase pinentry
   # gpg> save
   ```
5. **Re-Export Committed Public Key Bundle**:
   Export the updated public key bundle (contains primary key, revoked old subkey, and new active subkey) and commit it to the repository:
   ```bash
   gpg --armor --export "$MASTER_FPR" > keys/knowledge-forge-ai-packages.asc
   ```
6. **Export Exact New Subkey Material**:
   Export **strictly the new subkey** using its exact fingerprint with trailing exclamation mark `!`:
   ```bash
   gpg --armor --export-secret-subkeys "${NEW_SIGNING_SUBKEY_FPR}!" > staging-new-signing-subkey.asc
   ```
7. **Isolate in Clean Temporary Staging GNUPGHOME**:
   ```bash
   CLEAN_STAGING_GNUPGHOME=$(mktemp -d -t staging-gpg-XXXXXX)
   chmod 700 "$CLEAN_STAGING_GNUPGHOME"

   # Import public bundle and secret subkey into staging
   GNUPGHOME="$CLEAN_STAGING_GNUPGHOME" gpg --batch --import keys/knowledge-forge-ai-packages.asc
   GNUPGHOME="$CLEAN_STAGING_GNUPGHOME" gpg --batch --import staging-new-signing-subkey.asc
   rm -f staging-new-signing-subkey.asc
   ```
8. **Re-Protect with a Newly Chosen CI-Only Passphrase**:
   Set a new, distinct CI-only passphrase isolated from the master passphrase:
   ```bash
   # Attended interactive pinentry: enter master passphrase, then new CI-only passphrase
   GNUPGHOME="$CLEAN_STAGING_GNUPGHOME" gpg --edit-key "$NEW_SIGNING_SUBKEY_FPR"
   # gpg> passwd
   # gpg> save
   ```
   As in Step 7, `error changing passphrase: No secret key` for the stub primary and the public-only retired subkey is expected; only the new signing subkey has secret material in staging.
9. **Export Final CI Bundle & Verify Primary Stub**:
   Verify the primary key in staging is a stub (`sec#`), then export the final CI bundle:
   ```bash
   GNUPGHOME="$CLEAN_STAGING_GNUPGHOME" gpg --list-secret-keys
   # Confirm: primary key is sec#, signing subkey is ssb

   GNUPGHOME="$CLEAN_STAGING_GNUPGHOME" gpg --armor --export-secret-subkeys "${NEW_SIGNING_SUBKEY_FPR}!" > new-ci-signing-subkey.asc
   rm -rf "$CLEAN_STAGING_GNUPGHOME"
   ```
10. **Preflight Verification**:
    Run `preflight-signing-key.mjs` in attended interactive mode against the new bundle and committed public key. GnuPG prompts for the new CI-only passphrase through pinentry; in this mode the tool never reads `PACKAGE_SIGNING_KEY` or `PACKAGE_SIGNING_PASSPHRASE` and never uses loopback:
    ```bash
    export GPG_TTY="$(tty)"
    node tools/verification/preflight-signing-key.mjs keys/knowledge-forge-ai-packages.asc \
      --secret-key-file new-ci-signing-subkey.asc \
      --interactive
    ```
    The preflight runs in an isolated temporary `GNUPGHOME`, so a `pinentry-program` configured in your own `gpg-agent.conf` (for example `pinentry-mac`) is not inherited. To use it, add `--pinentry-program <path-to-pinentry>`; that option is rejected outside `--interactive` mode.
11. **Atomically Replace Both GitHub Environment Secrets Together**:
    In GitHub Repository Settings -> Environments -> `github-pages`:
    - Replace `PACKAGE_SIGNING_KEY` with the full armored contents of `new-ci-signing-subkey.asc`.
    - Replace `PACKAGE_SIGNING_PASSPHRASE` with the newly chosen CI passphrase.
    - Delete `new-ci-signing-subkey.asc` securely (`shred -u` or `rm -P`).
