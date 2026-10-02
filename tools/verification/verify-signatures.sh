#!/usr/bin/env bash
set -euo pipefail

# Verifies package signatures against public key bundle:
# 1. Detached OpenPGP signatures (.sig, .asc) for Pacman packages and repository databases.
# 2. Detached signatures for RPM repodata (repomd.xml.asc).
# 3. Internal RPM package signatures (rpm --checksig) when rpm tool is available.
#
# Usage: ./verify-signatures.sh [--expected-subkey <FPR>] [--expected-primary <FPR>] [pubkey.asc] [file_or_directory]

EXPECTED_SUBKEY=""
EXPECTED_PRIMARY=""
PUBKEY=""
TARGET=""

while [ $# -gt 0 ]; do
  case "$1" in
    --expected-subkey|-s)
      EXPECTED_SUBKEY="$2"
      shift 2
      ;;
    --expected-primary|-p)
      EXPECTED_PRIMARY="$2"
      shift 2
      ;;
    *)
      if [ -z "$PUBKEY" ]; then
        PUBKEY="$1"
      elif [ -z "$TARGET" ]; then
        TARGET="$1"
      elif [ -z "$EXPECTED_SUBKEY" ]; then
        EXPECTED_SUBKEY="$1"
      fi
      shift
      ;;
  esac
done

PUBKEY="${PUBKEY:-keys/knowledge-forge-ai-packages.asc}"
TARGET="${TARGET:-.}"

NORM_EXPECTED=""
if [ -n "$EXPECTED_SUBKEY" ]; then
  NORM_EXPECTED=$(echo "$EXPECTED_SUBKEY" | tr '[:lower:]' '[:upper:]' | tr -d ' !')
fi

NORM_EXPECTED_PRIMARY=""
if [ -n "$EXPECTED_PRIMARY" ]; then
  NORM_EXPECTED_PRIMARY=$(echo "$EXPECTED_PRIMARY" | tr '[:lower:]' '[:upper:]' | tr -d ' !')
fi

if [ ! -f "$PUBKEY" ]; then
  echo "Error: Public key bundle not found: $PUBKEY" >&2
  exit 1
fi

# Explicit template: BSD mktemp on macOS ignores $TMPDIR when called without one.
TMP_GNUPG=$(mktemp -d "${TMPDIR:-/tmp}/verify-signatures-gnupg.XXXXXX")
TMP_RPMDB=""
if command -v rpm >/dev/null 2>&1; then
  TMP_RPMDB=$(mktemp -d "${TMPDIR:-/tmp}/verify-signatures-rpmdb.XXXXXX")
  rpm --dbpath "$TMP_RPMDB" --initdb
  rpm --dbpath "$TMP_RPMDB" --import "$PUBKEY"
fi

cleanup() {
  rm -rf "$TMP_GNUPG"
  if [ -n "$TMP_RPMDB" ] && [ -d "$TMP_RPMDB" ]; then
    rm -rf "$TMP_RPMDB"
  fi
}
trap cleanup EXIT

export GNUPGHOME="$TMP_GNUPG"
gpg --batch --quiet --import "$PUBKEY"

FAILED=0
CHECKED=0

check_detached_sig() {
  local sig="$1"
  local target="${sig%.sig}"
  if [ "$target" = "$sig" ]; then
    target="${sig%.asc}"
  fi

  if [ ! -f "$target" ]; then
    echo "[FAIL] Missing target file for signature: $sig (expected $target)" >&2
    FAILED=$((FAILED + 1))
    CHECKED=$((CHECKED + 1))
    return
  fi

  CHECKED=$((CHECKED + 1))
  local status_file="$TMP_GNUPG/gpg_status.txt"
  if gpg --batch --status-fd 1 --verify "$sig" "$target" > "$status_file" 2>&1; then
    local sig_fpr
    local primary_fpr
    sig_fpr=$(awk '/^\[GNUPG:\] VALIDSIG / { print toupper($3); exit }' "$status_file")
    primary_fpr=$(awk '/^\[GNUPG:\] VALIDSIG / { print toupper($NF); exit }' "$status_file")

    if [ -z "$sig_fpr" ]; then
      echo "[FAIL] Missing VALIDSIG in gpg status output for $sig" >&2
      FAILED=$((FAILED + 1))
      return
    fi

    if [ -n "$NORM_EXPECTED" ]; then
      if [ "$sig_fpr" != "$NORM_EXPECTED" ]; then
        echo "[FAIL] Signature on $sig subkey attribution mismatch: expected $NORM_EXPECTED, got $sig_fpr" >&2
        FAILED=$((FAILED + 1))
        return
      fi
    fi

    if [ -n "$NORM_EXPECTED_PRIMARY" ]; then
      if [ "$primary_fpr" != "$NORM_EXPECTED_PRIMARY" ]; then
        echo "[FAIL] Signature on $sig primary key attribution mismatch: expected $NORM_EXPECTED_PRIMARY, got $primary_fpr" >&2
        FAILED=$((FAILED + 1))
        return
      fi
    fi

    echo "[PASS] Signature valid and attributed to subkey: $sig for $(basename "$target") (signer: $sig_fpr)"
  else
    echo "[FAIL] Signature INVALID: $sig for $(basename "$target")" >&2
    cat "$status_file" >&2
    FAILED=$((FAILED + 1))
  fi
}

check_rpm() {
  local rpm_file="$1"
  CHECKED=$((CHECKED + 1))
  if command -v rpm >/dev/null 2>&1; then
    local rpm_out
    if rpm_out=$(rpm --dbpath "$TMP_RPMDB" --checksig "$rpm_file" 2>&1); then
      if echo "$rpm_out" | grep -Eq "(digests signatures OK|gpg OK|pgp OK)"; then
        if [ -n "$NORM_EXPECTED" ]; then
          local signer_key_id
          # Query native signature tags via rpm queryformat
          local qf_out
          qf_out=$(rpm --dbpath "$TMP_RPMDB" -qp --queryformat '%{RSAHEADER:pgpsig}\n%{SIGGPG:pgpsig}\n%{SIGPGP:pgpsig}\n%{DSAHEADER:pgpsig}\n' "$rpm_file" 2>/dev/null || true)
          signer_key_id=$(echo "$qf_out" | grep -oiE "Key ID [0-9a-fA-F]+" | awk '{print toupper($3)}' | head -n 1)

          if [ -z "$signer_key_id" ]; then
            # Fall back to rpm -qip if queryformat produced no match
            signer_key_id=$(rpm --dbpath "$TMP_RPMDB" -qip "$rpm_file" 2>/dev/null | grep -oiE "Key ID [0-9a-fA-F]+" | awk '{print toupper($3)}' | head -n 1)
          fi

          local expected_long_id="$NORM_EXPECTED"
          if [ "${#NORM_EXPECTED}" -ge 16 ]; then
            expected_long_id="${NORM_EXPECTED: -16}"
          fi

          if [ -z "$signer_key_id" ]; then
            echo "[FAIL] Could not extract signer Key ID from RPM: $rpm_file" >&2
            FAILED=$((FAILED + 1))
            return
          fi

          if [ "$signer_key_id" != "$expected_long_id" ]; then
            echo "[FAIL] RPM signature on $rpm_file was signed by Key ID $signer_key_id, expected $expected_long_id" >&2
            FAILED=$((FAILED + 1))
            return
          fi

          if [ -n "$NORM_EXPECTED_PRIMARY" ]; then
            local primary_fpr
            primary_fpr=$(rpm --dbpath "$TMP_RPMDB" -Kv "$rpm_file" 2>/dev/null | grep -oiE "key fingerprint: [0-9a-fA-F]+" | awk '{print toupper($3)}' | head -n 1)
            if [ -n "$primary_fpr" ] && [ "$primary_fpr" != "$NORM_EXPECTED_PRIMARY" ]; then
              echo "[FAIL] RPM signature on $rpm_file primary fingerprint mismatch: expected $NORM_EXPECTED_PRIMARY, got $primary_fpr" >&2
              FAILED=$((FAILED + 1))
              return
            fi
          fi

          echo "[PASS] RPM signature valid and attributed to expected subkey: $(basename "$rpm_file") (Key ID: $signer_key_id)"
        else
          echo "[PASS] RPM signature valid: $(basename "$rpm_file")"
        fi
      else
        echo "[FAIL] RPM signature check failed for $rpm_file: $rpm_out" >&2
        FAILED=$((FAILED + 1))
      fi
    else
      echo "[FAIL] RPM signature check failed for $rpm_file: $rpm_out" >&2
      FAILED=$((FAILED + 1))
    fi
  else
    echo "[FAIL] rpm binary not present; cannot verify internal RPM header check for $rpm_file" >&2
    FAILED=$((FAILED + 1))
  fi
}

if [ -f "$TARGET" ]; then
  if [[ "$TARGET" =~ \.rpm$ ]]; then
    check_rpm "$TARGET"
  elif [[ "$TARGET" =~ \.(sig|asc)$ ]]; then
    check_detached_sig "$TARGET"
  else
    if [ -f "${TARGET}.sig" ]; then
      check_detached_sig "${TARGET}.sig"
    elif [ -f "${TARGET}.asc" ]; then
      check_detached_sig "${TARGET}.asc"
    else
      echo "No signature found for $TARGET" >&2
      exit 1
    fi
  fi
elif [ -d "$TARGET" ]; then
  # 1. Verify all detached signatures
  while IFS= read -r sig_file; do
    check_detached_sig "$sig_file"
  done < <(find "$TARGET" -type f \( -name "*.sig" -o -name "*.asc" \) ! -path "*/keys/*" ! -path "*/test-fixtures/*" ! -name "*key*.asc" ! -name "*packages.asc*")

  # 2. Verify all RPM internal signatures
  rpm_count=$(find "$TARGET" -type f -name "*.rpm" | wc -l | tr -d ' ')
  if [ "$rpm_count" -gt 0 ]; then
    if ! command -v rpm >/dev/null 2>&1; then
      echo "[FAIL] Found $rpm_count RPM file(s) in $TARGET but 'rpm' command is not available to verify signatures." >&2
      FAILED=$((FAILED + rpm_count))
      CHECKED=$((CHECKED + rpm_count))
    else
      while IFS= read -r rpm_file; do
        check_rpm "$rpm_file"
      done < <(find "$TARGET" -type f -name "*.rpm")
    fi
  fi
fi

echo ""
if [ "$CHECKED" -eq 0 ]; then
  echo "Error: No signatures found to verify in $TARGET" >&2
  exit 1
elif [ "$FAILED" -gt 0 ]; then
  echo "Signature verification FAILED: $FAILED errors out of $CHECKED checks." >&2
  exit 1
else
  echo "Signature verification PASSED: $CHECKED verified."
  exit 0
fi
