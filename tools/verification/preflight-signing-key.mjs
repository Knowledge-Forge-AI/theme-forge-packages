#!/usr/bin/env node

/**
 * Preflight verification tool for production distribution package signing.
 *
 * Enforces:
 * 1. Committed public key bundle (keys/knowledge-forge-ai-packages.asc) is valid OpenPGP.
 * 2. Rejects validation fixture key (F51DA0906E548DA39E267AFA64D6C54B40CC3656) or test purpose.
 * 3. Primary 'sec' key is recognized as primary identity only (strictly excluded from being selected as signing subkey).
 * 4. Selects only explicit 'ssb' subkeys with signing capability ('s') that are not revoked, disabled, or expired.
 *    Enforces that exactly one matching active signing subkey is present (no ambiguity).
 * 5. Verifies selected secret subkey exists in the committed public key bundle.
 * 6. Executes test detached signature with forced subkey selection ('FPR!') and verifies against committed public key.
 * 7. Two strictly separated modes:
 *    - CI mode (default): PACKAGE_SIGNING_KEY + PACKAGE_SIGNING_PASSPHRASE, noninteractive loopback.
 *    - Attended mode (--interactive): secret subkey read only from --secret-key-file; the passphrase is
 *      entered through GnuPG pinentry (--pinentry-mode ask). No --batch, no loopback, no passphrase
 *      argv/stdin/env, and no fallback to the CI environment secrets.
 * 8. Emits signing_fpr to $GITHUB_OUTPUT and SIGNING_FPR to $GITHUB_ENV.
 * 9. Fails closed before any package build if checks fail.
 * 10. Stops the temporary gpg-agent processes so unlocked key material is not left cached.
 *
 * Requires system GnuPG (gpg) binary; weak fallbacks are prohibited.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FIXTURE_FINGERPRINT, FIXTURE_KEY_ID, resolveGpg } from "./verify-public-key-bootstrap.mjs";

export function redactPassphrase(text, passphrase) {
  if (!text || typeof text !== "string") return text;
  if (!passphrase || typeof passphrase !== "string" || passphrase.length === 0) {
    return text;
  }
  return text.replaceAll(passphrase, "******");
}

export function redactSecrets(text, secrets = []) {
  if (!text || typeof text !== "string") return text;
  let result = text;
  for (const s of secrets) {
    if (s && typeof s === "string" && s.length > 0) {
      result = result.replaceAll(s, "******");
    }
  }
  return result;
}

export async function preflightSigningKey(pubkeyPath, options = {}) {
  const resolvedPubkey = resolve(pubkeyPath);
  if (!existsSync(resolvedPubkey)) {
    throw new Error(`Committed public key bundle not found: ${resolvedPubkey}`);
  }

  const pubContent = readFileSync(resolvedPubkey, "utf8");
  if (!pubContent.includes("BEGIN PGP PUBLIC KEY BLOCK")) {
    throw new Error(`Invalid public key format in: ${resolvedPubkey}`);
  }

  const gpgBin = resolveGpg(options);
  if (!gpgBin) {
    throw new Error(
      "GnuPG (gpg) binary is required for security-critical signing key preflight, but was not found in PATH or via --gpg-bin / GPG_BIN."
    );
  }

  return runWithGpg(resolvedPubkey, gpgBin, options);
}

// gpgconf is resolved next to the resolved gpg binary first, then from PATH.
function resolveGpgconf(gpgBin) {
  const candidates = [];
  try {
    const gpgPath = gpgBin.includes("/")
      ? gpgBin
      : spawnSync("which", [gpgBin], { encoding: "utf8" }).stdout.trim();
    if (gpgPath) {
      candidates.push(join(dirname(gpgPath), "gpgconf"));
      candidates.push(join(dirname(realpathSync(gpgPath)), "gpgconf"));
    }
  } catch {}
  candidates.push("gpgconf");
  for (const c of candidates) {
    try {
      if (spawnSync(c, ["--version"], { encoding: "utf8" }).status === 0) return c;
    } catch {}
  }
  return null;
}

function killAgent(gpgconfBin, home, env) {
  if (!gpgconfBin || !existsSync(home)) return;
  spawnSync(gpgconfBin, ["--homedir", home, "--kill", "gpg-agent"], { env, stdio: "ignore" });
}

// GnuPG agent sockets live inside GNUPGHOME; macOS limits socket paths to 104 bytes.
function shortTempBase() {
  const base = tmpdir();
  return process.platform === "darwin" && base.length > 60 ? "/tmp" : base;
}

function runWithGpg(resolvedPubkey, gpgBin, options) {
  const isInteractive = Boolean(options.interactive);

  // Attended mode never consumes CI secrets and never accepts a passphrase from the caller.
  if (isInteractive) {
    if (options.passphrase !== undefined) {
      throw new Error("Attended --interactive mode does not accept a passphrase; it must be entered through pinentry.");
    }
    if (!options.secretKeyFile) {
      throw new Error("Attended --interactive mode requires --secret-key-file <path>.");
    }
    if (options.secretKey) {
      throw new Error("Attended --interactive mode reads secret key material only from --secret-key-file.");
    }
  } else if (options.pinentryProgram) {
    throw new Error("--pinentry-program is only valid in attended --interactive mode.");
  }

  let passphrase = null;
  if (!isInteractive) {
    passphrase = options.passphrase !== undefined ? options.passphrase : process.env.PACKAGE_SIGNING_PASSPHRASE;
    if (typeof passphrase !== "string" || passphrase.length === 0) {
      throw new Error("PACKAGE_SIGNING_PASSPHRASE is required and cannot be empty.");
    }
  }

  let secretKeyData = options.secretKey || "";
  if (options.secretKeyFile) {
    const resolvedSecretKeyFile = resolve(options.secretKeyFile);
    if (!existsSync(resolvedSecretKeyFile)) {
      throw new Error(`Secret key file not found: ${resolvedSecretKeyFile}`);
    }
    secretKeyData = readFileSync(resolvedSecretKeyFile, "utf8");
  } else if (!secretKeyData && !isInteractive) {
    secretKeyData = process.env.PACKAGE_SIGNING_KEY || "";
  }

  const tempBase = shortTempBase();
  const tempGnuPg = mkdtempSync(join(tempBase, "gpg-preflight-"));
  const env = { ...process.env, GNUPGHOME: tempGnuPg };
  if (isInteractive) {
    delete env.PACKAGE_SIGNING_KEY;
    delete env.PACKAGE_SIGNING_PASSPHRASE;
    if (options.pinentryProgram) {
      const pinentryPath = resolve(options.pinentryProgram);
      if (!existsSync(pinentryPath)) {
        rmSync(tempGnuPg, { recursive: true, force: true });
        throw new Error(`Pinentry program not found: ${pinentryPath}`);
      }
      writeFileSync(join(tempGnuPg, "gpg-agent.conf"), `pinentry-program ${pinentryPath}\n`, { mode: 0o600 });
    }
  }
  const gpgconfBin = resolveGpgconf(gpgBin);
  let verifyGnuPg = null;

  const secretsToRedact = [passphrase, secretKeyData].filter((s) => typeof s === "string" && s.length > 0);

  try {
    // 1. Import committed public key
    const importPubRes = spawnSync(gpgBin, ["--batch", "--quiet", "--import", resolvedPubkey], { env, encoding: "utf8" });
    if (importPubRes.status !== 0) {
      throw new Error(`Failed to import committed public key: ${importPubRes.stderr || "Unknown gpg error"}`);
    }

    // 2. Parse primary key fingerprint & subkeys from committed public key
    const pubColons = execFileSync(gpgBin, ["--batch", "--quiet", "--list-keys", "--with-colons"], { env, encoding: "utf8" });
    const pubLines = pubColons.split("\n");

    let primaryFpr = null;
    let primaryKeyId = null;
    let uids = [];
    const publicSubkeyFprs = new Set();
    let curPubSub = null;

    for (let i = 0; i < pubLines.length; i++) {
      const parts = pubLines[i].split(":");
      if (parts[0] === "pub") {
        primaryKeyId = parts[4];
      } else if (parts[0] === "fpr" && !primaryFpr) {
        primaryFpr = parts[9];
      } else if (parts[0] === "uid") {
        uids.push(parts[9]);
      } else if (parts[0] === "sub") {
        curPubSub = { keyId: parts[4] };
      } else if (parts[0] === "fpr" && curPubSub) {
        publicSubkeyFprs.add(parts[9].toUpperCase());
        curPubSub = null;
      }
    }

    if (!primaryFpr) {
      throw new Error("Could not parse primary public key fingerprint from committed public key.");
    }

    console.log(`[PREFLIGHT] Committed public key primary fingerprint: ${primaryFpr}`);
    console.log(`[PREFLIGHT] Committed public key UIDs: ${uids.join(", ")}`);

    // 3. Strict rejection of fixture key
    if (primaryFpr.toUpperCase() === FIXTURE_FINGERPRINT || primaryKeyId === FIXTURE_KEY_ID) {
      throw new Error(
        `REJECTED: Committed public key ${primaryFpr} is the test fixture key! ` +
        `Production publication requires bootstrapping an authentic production key as described in PACKAGE-SIGNING-BOOTSTRAP.md.`
      );
    }

    for (const uid of uids) {
      if (/test-packages@knowledgeforge\.ai|fixture/i.test(uid)) {
        throw new Error(`REJECTED: Public key UID "${uid}" indicates a test fixture key.`);
      }
    }

    // 4. Inspect secret signing key
    if (!secretKeyData || secretKeyData.trim() === "") {
      throw new Error(
        isInteractive
          ? "Secret key file is empty or not provided."
          : "PACKAGE_SIGNING_KEY secret is not configured or empty."
      );
    }

    const secKeyFile = join(tempGnuPg, "sec.asc");
    writeFileSync(secKeyFile, secretKeyData.trim() + "\n", { mode: 0o600 });
    const importSecRes = spawnSync(gpgBin, ["--batch", "--quiet", "--import", secKeyFile], { env, encoding: "utf8" });
    rmSync(secKeyFile, { force: true });
    if (importSecRes.status !== 0) {
      throw new Error(`Failed to import secret key: ${importSecRes.stderr || "Unknown gpg error"}`);
    }

    // 5. Parse secret keys with colon output
    const secColons = execFileSync(gpgBin, ["--batch", "--quiet", "--list-secret-keys", "--with-colons"], { env, encoding: "utf8" });
    const secLines = secColons.split("\n");

    let secretPrimaryFpr = null;
    const secretSubkeys = [];
    let curRecord = null;

    for (let i = 0; i < secLines.length; i++) {
      const parts = secLines[i].split(":");
      if (parts[0] === "sec") {
        curRecord = {
          type: "sec",
          status: parts[1],
          keyId: parts[4],
          created: parts[5] ? parseInt(parts[5], 10) : null,
          expires: parts[6] ? parseInt(parts[6], 10) : null,
          capabilities: parts[11] || "",
          fpr: null,
        };
      } else if (parts[0] === "ssb") {
        curRecord = {
          type: "ssb",
          status: parts[1],
          keyId: parts[4],
          created: parts[5] ? parseInt(parts[5], 10) : null,
          expires: parts[6] ? parseInt(parts[6], 10) : null,
          capabilities: parts[11] || "",
          fpr: null,
        };
        secretSubkeys.push(curRecord);
      } else if (parts[0] === "fpr" && curRecord && !curRecord.fpr) {
        curRecord.fpr = parts[9];
        if (curRecord.type === "sec" && !secretPrimaryFpr) {
          secretPrimaryFpr = parts[9];
        }
      }
    }

    if (!secretPrimaryFpr) {
      throw new Error("Unable to extract primary key fingerprint from imported secret key.");
    }

    if (secretPrimaryFpr.toUpperCase() !== primaryFpr.toUpperCase()) {
      throw new Error(
        `Imported secret key primary fingerprint (${secretPrimaryFpr}) does not match committed public key fingerprint (${primaryFpr})!`
      );
    }

    if (secretSubkeys.length === 0) {
      throw new Error("No secret subkeys ('ssb') found in imported PACKAGE_SIGNING_KEY. Primary 'sec' key cannot be used for package signing.");
    }

    // Filter strictly for explicit 'ssb' subkeys with signing capability ('s' or 'S')
    const nowSec = Math.floor(Date.now() / 1000);
    const validSigningSubkeys = secretSubkeys.filter((k) => {
      if (k.type !== "ssb") return false; // Primary sec is strictly excluded
      const hasSigningCap = k.capabilities.includes("s") || k.capabilities.includes("S");
      const notRevoked = k.status !== "r";
      const notDisabled = k.status !== "d";
      const notExpiredStatus = k.status !== "e";
      const notExpiredDate = !k.expires || k.expires > nowSec;
      return hasSigningCap && notRevoked && notDisabled && notExpiredStatus && notExpiredDate;
    });

    if (validSigningSubkeys.length === 0) {
      throw new Error("Imported secret key contains no active, unrevoked, unexpired signing subkeys ('ssb' with 's' capability).");
    }

    // Verify selected subkey exists in committed public key bundle
    const matchingSubkeys = validSigningSubkeys.filter((k) => publicSubkeyFprs.has(k.fpr.toUpperCase()));
    if (matchingSubkeys.length === 0) {
      throw new Error(
        `None of the available secret signing subkeys exist in the committed public key bundle! Public subkeys: [${Array.from(publicSubkeyFprs).join(", ")}]`
      );
    }
    if (matchingSubkeys.length > 1) {
      throw new Error(
        `Ambiguous secret key: found ${matchingSubkeys.length} valid signing subkeys in PACKAGE_SIGNING_KEY. Exactly one active signing subkey must be present in CI.`
      );
    }
    const matchingSubkey = matchingSubkeys[0];

    console.log(`[PREFLIGHT] Valid signing subkey: ${matchingSubkey.fpr} (Key ID: ${matchingSubkey.keyId})`);

    // 6. Test actual sign operation with loopback passphrase, forcing exact subkey syntax (FPR!)
    const testData = "theme-forge-preflight-signing-test-" + Date.now();
    const testInput = join(tempGnuPg, "test.txt");
    const testSig = join(tempGnuPg, "test.txt.sig");
    writeFileSync(testInput, testData);

    // Attended mode: GnuPG asks the agent's pinentry for the passphrase. stdin/stdout are inherited
    // so a console pinentry can reach the operator's terminal; nothing is written to gpg's stdin.
    const signArgs = isInteractive
      ? [
          "--pinentry-mode",
          "ask",
          "--yes",
          "--detach-sign",
          "--armor",
          "-u",
          `${matchingSubkey.fpr}!`,
          "--output",
          testSig,
          testInput,
        ]
      : [
          "--batch",
          "--yes",
          "--pinentry-mode",
          "loopback",
          "--passphrase-fd",
          "0",
          "--detach-sign",
          "--armor",
          "-u",
          `${matchingSubkey.fpr}!`,
          "--output",
          testSig,
          testInput,
        ];

    const signRes = isInteractive
      ? spawnSync(gpgBin, signArgs, { env, stdio: ["inherit", "inherit", "pipe"] })
      : spawnSync(gpgBin, signArgs, { env, input: passphrase });
    if (signRes.status !== 0) {
      const errOut = signRes.stderr ? signRes.stderr.toString("utf8") : "Unknown gpg error";
      const redactedErr = isInteractive ? errOut : redactPassphrase(errOut, passphrase);
      throw new Error(`Signing key test failed: ${redactedErr}`);
    }

    // Verify signature strictly with committed public key in isolated clean keyring
    verifyGnuPg = mkdtempSync(join(tempBase, "gpg-verify-"));
    try {
      execFileSync(gpgBin, ["--batch", "--quiet", "--import", resolvedPubkey], {
        env: { ...process.env, GNUPGHOME: verifyGnuPg },
      });
      const verifyRes = spawnSync(gpgBin, ["--batch", "--verify", testSig, testInput], {
        env: { ...process.env, GNUPGHOME: verifyGnuPg },
      });
      if (verifyRes.status !== 0) {
        throw new Error("Test signature failed verification against committed public key in clean keyring!");
      }
    } finally {
      killAgent(gpgconfBin, verifyGnuPg, env);
      rmSync(verifyGnuPg, { recursive: true, force: true });
    }

    console.log(`[PREFLIGHT] Test detached signature verified successfully with committed public key.`);

    if (process.env.GITHUB_OUTPUT) {
      appendFileSync(process.env.GITHUB_OUTPUT, `signing_fpr=${matchingSubkey.fpr}\n`);
      console.log(`[PREFLIGHT] Exported signing_fpr=${matchingSubkey.fpr} to $GITHUB_OUTPUT.`);
    }

    if (process.env.GITHUB_ENV) {
      appendFileSync(process.env.GITHUB_ENV, `SIGNING_FPR=${matchingSubkey.fpr}\n`);
      console.log(`[PREFLIGHT] Exported SIGNING_FPR=${matchingSubkey.fpr} to $GITHUB_ENV.`);
    }

    return {
      status: "passed",
      primaryFingerprint: primaryFpr,
      signingSubkeyFingerprint: matchingSubkey.fpr,
      signingKeyId: matchingSubkey.keyId,
    };
  } catch (err) {
    const redacted = redactSecrets(err.message, secretsToRedact);
    throw new Error(redacted);
  } finally {
    killAgent(gpgconfBin, tempGnuPg, env);
    rmSync(tempGnuPg, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  let pubkeyArg = null;
  let gpgBin = null;
  let secretKeyFile = null;
  let pinentryProgram = null;
  let interactive = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--gpg-bin" && args[i + 1]) {
      gpgBin = args[++i];
    } else if (args[i] === "--secret-key-file" && args[i + 1]) {
      secretKeyFile = args[++i];
    } else if (args[i] === "--pinentry-program" && args[i + 1]) {
      pinentryProgram = args[++i];
    } else if (args[i] === "--interactive") {
      interactive = true;
    } else if (!args[i].startsWith("--") && !pubkeyArg) {
      pubkeyArg = args[i];
    } else {
      console.error(`\n[FATAL] Key preflight FAILED: unrecognized or incomplete argument: ${args[i]}`);
      process.exit(1);
    }
  }

  if (interactive && !secretKeyFile) {
    console.error("\n[FATAL] Key preflight FAILED: --interactive mode requires --secret-key-file <path>");
    process.exit(1);
  }

  const resolvedPubkeyArg = pubkeyArg || "keys/knowledge-forge-ai-packages.asc";

  preflightSigningKey(resolvedPubkeyArg, { gpgBin, secretKeyFile, interactive, pinentryProgram })
    .then((res) => {
      console.log(`\n[PASS] Key preflight PASSED: primary ${res.primaryFingerprint}, subkey ${res.signingSubkeyFingerprint}`);
      process.exit(0);
    })
    .catch((err) => {
      console.error(`\n[FATAL] Key preflight FAILED: ${err.message}`);
      process.exit(1);
    });
}

