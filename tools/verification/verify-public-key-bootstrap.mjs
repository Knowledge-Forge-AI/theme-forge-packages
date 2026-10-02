#!/usr/bin/env node

/**
 * Static validator and gate check for the public repository production public key.
 *
 * Enforces the first-push gate required before repository creation or initial push:
 * 1. Target key path must be explicitly supplied, exist, and be non-empty.
 * 2. File must be plain OpenPGP armored data (starting with -----BEGIN PGP PUBLIC KEY BLOCK----- on line 1, no prepended comments).
 * 3. Must NOT contain private key material.
 * 4. Must parse with system GnuPG (gpg) binary (fail-closed; weaker fallbacks prohibited).
 * 5. Must NOT be the validation fixture key (F51DA0906E548DA39E267AFA64D6C54B40CC3656).
 * 6. Primary key must NOT be revoked or expired.
 * 7. Must contain at least one valid, unrevoked, unexpired signing-capable subkey ('s').
 * 8. Supports positive pinning against expected production primary fingerprint.
 *
 * Exit codes:
 *   0: Production key bootstrap verified and valid.
 *   1: Verification failed; first public push is blocked.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const FIXTURE_FINGERPRINT = "F51DA0906E548DA39E267AFA64D6C54B40CC3656";
export const FIXTURE_KEY_ID = "64D6C54B40CC3656";

export function resolveGpg(options = {}) {
  const candidate = options.gpgBin || process.env.GPG_BIN || "gpg";
  try {
    const res = spawnSync(candidate, ["--version"], { encoding: "utf8" });
    if (res.status === 0) {
      return candidate;
    }
  } catch {}
  return null;
}

export async function verifyPublicKeyBootstrap(pubkeyPath, options = {}) {
  if (!pubkeyPath) {
    throw new Error("[GATE BLOCKED] Missing required public key path argument. Human-supplied path is mandatory.");
  }

  const resolvedPubkey = resolve(pubkeyPath);
  if (!existsSync(resolvedPubkey)) {
    throw new Error(`[GATE BLOCKED] Production public key not found: ${resolvedPubkey}. An authentic production public key must be bootstrapped before the first public push.`);
  }

  const rawBytes = readFileSync(resolvedPubkey, "utf8");
  if (rawBytes.length === 0) {
    throw new Error(`[GATE BLOCKED] Public key file is empty: ${resolvedPubkey}`);
  }

  // M5 plain armor enforcement: line 1 must be exact armor header
  const lines = rawBytes.split(/\r?\n/);
  const firstLine = lines[0];
  if (firstLine !== "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
    throw new Error(
      `[GATE BLOCKED] Invalid public key file format in ${resolvedPubkey}: line 1 must be exact plain armor header '-----BEGIN PGP PUBLIC KEY BLOCK-----'. Non-armor comments, explanatory metadata, or leading whitespace prepended to the key block are strictly prohibited.`
    );
  }

  if (rawBytes.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
    throw new Error(`[GATE BLOCKED] Private key material detected in ${resolvedPubkey}! Only public key material may ever be placed at the trust-anchor path.`);
  }

  if (!rawBytes.includes("-----END PGP PUBLIC KEY BLOCK-----")) {
    throw new Error(`[GATE BLOCKED] ${resolvedPubkey} does not contain closing '-----END PGP PUBLIC KEY BLOCK-----'.`);
  }

  const gpgBin = resolveGpg(options);
  if (!gpgBin) {
    throw new Error(
      "[GATE BLOCKED] GnuPG (gpg) binary is required for security-critical public key verification but was not found in PATH or via --gpg-bin / GPG_BIN. Weak fallbacks are prohibited."
    );
  }

  return verifyWithGpg(resolvedPubkey, gpgBin, options);
}

function verifyWithGpg(resolvedPubkey, gpgBin, options = {}) {
  const tempGnuPg = mkdtempSync(join(tmpdir(), "gpg-bootstrap-check-"));
  const env = { ...process.env, GNUPGHOME: tempGnuPg };

  try {
    // Import public key into isolated temp keyring
    const importRes = spawnSync(gpgBin, ["--batch", "--quiet", "--import", resolvedPubkey], { env, encoding: "utf8" });
    if (importRes.status !== 0) {
      throw new Error(`[GATE BLOCKED] Failed to import public key with gpg: ${importRes.stderr || "Unknown gpg error"}`);
    }

    const pubColons = execFileSync(gpgBin, ["--batch", "--quiet", "--list-keys", "--with-colons"], { env, encoding: "utf8" });
    const colonLines = pubColons.split("\n");

    let primaryFpr = null;
    let primaryKeyId = null;
    let primaryStatus = null;
    let primaryExpires = null;
    const uids = [];
    const subkeys = [];

    let currentSubkey = null;
    for (const line of colonLines) {
      const parts = line.split(":");
      const recordType = parts[0];

      if (recordType === "pub") {
        primaryStatus = parts[1]; // 'r' = revoked, 'e' = expired, 'd' = disabled, 'v' = valid
        primaryKeyId = parts[4];
        primaryExpires = parts[6] ? parseInt(parts[6], 10) : null;
      } else if (recordType === "fpr" && !primaryFpr) {
        primaryFpr = parts[9];
      } else if (recordType === "uid") {
        uids.push(parts[9]);
      } else if (recordType === "sub") {
        currentSubkey = {
          status: parts[1], // 'r' = revoked, 'e' = expired, 'd' = disabled
          keyId: parts[4],
          created: parts[5] ? parseInt(parts[5], 10) : null,
          expires: parts[6] ? parseInt(parts[6], 10) : null,
          usage: parts[11] || "",
          fpr: null,
        };
        subkeys.push(currentSubkey);
      } else if (recordType === "fpr" && currentSubkey && !currentSubkey.fpr) {
        currentSubkey.fpr = parts[9];
      }
    }

    if (!primaryFpr) {
      throw new Error("[GATE BLOCKED] Unable to extract primary public key fingerprint from OpenPGP bundle.");
    }

    // Fixture rejection
    if (primaryFpr.toUpperCase() === FIXTURE_FINGERPRINT || primaryKeyId === FIXTURE_KEY_ID) {
      throw new Error(`[GATE BLOCKED] Refusing public push: ${primaryFpr} is the known test fixture key. You must supply an authentic production public key.`);
    }

    for (const uid of uids) {
      if (/fixture|test-packages@knowledgeforge\.ai|validation@knowledgeforge\.ai/i.test(uid)) {
        throw new Error(`[GATE BLOCKED] Refusing public push: Key UID "${uid}" indicates test fixture material.`);
      }
    }

    // Primary revocation check
    if (primaryStatus === "r") {
      throw new Error(`[GATE BLOCKED] Primary public key ${primaryFpr} is revoked! Revoked keys cannot be used as production trust anchors.`);
    }
    if (primaryStatus === "e") {
      throw new Error(`[GATE BLOCKED] Primary public key ${primaryFpr} is marked expired by GnuPG!`);
    }
    if (primaryStatus === "d") {
      throw new Error(`[GATE BLOCKED] Primary public key ${primaryFpr} is disabled!`);
    }

    // Expiration check
    const nowSec = Math.floor(Date.now() / 1000);
    if (primaryExpires && primaryExpires <= nowSec) {
      throw new Error(`[GATE BLOCKED] Primary public key ${primaryFpr} expired on ${new Date(primaryExpires * 1000).toISOString()}!`);
    }

    // Positive primary fingerprint verification
    if (options.expectedFingerprint) {
      const expNorm = options.expectedFingerprint.replace(/\s+/g, "").toUpperCase();
      const actualNorm = primaryFpr.replace(/\s+/g, "").toUpperCase();
      if (expNorm !== actualNorm) {
        throw new Error(
          `[GATE BLOCKED] Primary public key fingerprint mismatch: expected ${expNorm}, found ${actualNorm}. Refusing unpinned public key.`
        );
      }
    }

    // Subkey checks: must have signing capability, unrevoked, unexpired
    const validSigningSubkeys = subkeys.filter(sub => {
      const canSign = sub.usage.includes("s") || sub.usage.includes("S");
      const notRevoked = sub.status !== "r";
      const notDisabled = sub.status !== "d";
      const notExpiredStatus = sub.status !== "e";
      const notExpiredDate = !sub.expires || sub.expires > nowSec;
      return canSign && notRevoked && notDisabled && notExpiredStatus && notExpiredDate;
    });

    if (validSigningSubkeys.length === 0) {
      throw new Error(`[GATE BLOCKED] Public key bundle has no valid, unrevoked, unexpired signing-capable subkeys ('s'). Packages cannot be signed.`);
    }

    return {
      status: "verified",
      primaryFingerprint: primaryFpr,
      primaryKeyId,
      uids,
      signingSubkeyFingerprint: validSigningSubkeys[0].fpr,
      signingSubkeyId: validSigningSubkeys[0].keyId,
      totalSigningSubkeys: validSigningSubkeys.length,
    };
  } finally {
    rmSync(tempGnuPg, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  let pubkeyArg = null;
  let expectedFpr = null;
  let gpgBin = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--expected-fpr" && args[i + 1]) {
      expectedFpr = args[++i];
    } else if (args[i] === "--gpg-bin" && args[i + 1]) {
      gpgBin = args[++i];
    } else if (!args[i].startsWith("--") && !pubkeyArg) {
      pubkeyArg = args[i];
    }
  }

  if (!pubkeyArg) {
    console.error("Usage: node verify-public-key-bootstrap.mjs <path-to-public-key.asc> [--expected-fpr <FPR>] [--gpg-bin <path>]");
    process.exit(1);
  }

  verifyPublicKeyBootstrap(pubkeyArg, { expectedFingerprint: expectedFpr, gpgBin })
    .then((res) => {
      console.log(`[PASS] Production public key bootstrap verified: primary ${res.primaryFingerprint}, signing subkey ${res.signingSubkeyFingerprint}`);
      process.exit(0);
    })
    .catch((err) => {
      console.error(err.message);
      process.exit(1);
    });
}

