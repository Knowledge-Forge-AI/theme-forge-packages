#!/usr/bin/env node

/**
 * Verifies local or downloaded release assets against release-lock.json.
 * Supports --require-assets and --assets-dir <dir>.
 * Zero external dependencies; standard Node.js runtime.
 */
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

function hashFile(path) {
  const buf = readFileSync(path);
  return createHash("sha256").update(buf).digest("hex");
}

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function main() {
  const args = process.argv.slice(2);
  const requireAssets = args.includes("--require-assets");

  const assetsDirIndex = args.indexOf("--assets-dir");
  const assetsDir = assetsDirIndex !== -1 && args[assetsDirIndex + 1]
    ? resolve(args[assetsDirIndex + 1])
    : process.cwd();

  const nonFlagArgs = args.filter((a, i) => !a.startsWith("--") && (i === 0 || args[i - 1] !== "--assets-dir"));
  const lockArg = nonFlagArgs[0] || "release-lock.json";
  const lockPath = resolve(lockArg);

  if (!existsSync(lockPath)) {
    console.error(`Error: release lock file not found: ${lockPath}`);
    process.exit(1);
  }

  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  if (lock.schema !== "tfsb.dist1-release-lock-v1") {
    console.error(`[FAIL] Invalid schema: ${lock.schema}`);
    process.exit(1);
  }
  console.log(`Verifying against release lock schema: ${lock.schema}, version: ${lock.lockVersion}`);
  console.log(`Assets directory: ${assetsDir}`);

  let failures = 0;
  let definitions = 0;
  let verifiedOnDisk = 0;

  const hexShaRegex = /^[a-f0-9]{64}$/i;

  // 1. Verify product artifacts
  for (const [name, entry] of Object.entries(lock.products || {})) {
    if (entry.asset && entry.sha256) {
      definitions++;
      if (!hexShaRegex.test(entry.sha256)) {
        console.error(`[FAIL] ${name}: Invalid SHA-256 format for ${entry.asset}`);
        failures++;
      }
      const assetPath = join(assetsDir, entry.asset);
      if (existsSync(assetPath)) {
        const actual = hashFile(assetPath);
        if (actual === entry.sha256) {
          console.log(`[PASS] ${name}: ${entry.asset} (${actual})`);
          verifiedOnDisk++;
        } else {
          console.error(`[FAIL] ${name}: ${entry.asset} expected ${entry.sha256}, got ${actual}`);
          failures++;
        }
      } else if (requireAssets) {
        console.error(`[FAIL] ${name}: Required asset missing: ${entry.asset} (searched: ${assetPath})`);
        failures++;
      } else {
        console.log(`[SKIP] ${name}: ${entry.asset} (file not present locally)`);
      }
    }

    if (entry.rawArchives) {
      for (const [arch, rawEntry] of Object.entries(entry.rawArchives)) {
        definitions++;
        if (!hexShaRegex.test(rawEntry.sha256)) {
          console.error(`[FAIL] ${name} [${arch}]: Invalid SHA-256 format for ${rawEntry.asset}`);
          failures++;
        }
        const archivePath = join(assetsDir, rawEntry.asset);
        if (existsSync(archivePath)) {
          const actual = hashFile(archivePath);
          if (actual === rawEntry.sha256) {
            console.log(`[PASS] ${name} [${arch}]: ${rawEntry.asset} (${actual})`);
            verifiedOnDisk++;

            // If raw executable path and sha256 are locked, verify the executable inside archive
            if (rawEntry.executablePath && rawEntry.executableSha256) {
              try {
                const rawBinary = execFileSync("tar", ["-xzOf", archivePath, rawEntry.executablePath], {
                  maxBuffer: 100 * 1024 * 1024,
                });
                const exeActual = sha256Hex(rawBinary);
                if (exeActual === rawEntry.executableSha256) {
                  console.log(`[PASS] ${name} [${arch}] executable invariant verified: ${rawEntry.executablePath} (${exeActual})`);
                } else {
                  console.error(`[FAIL] ${name} [${arch}] executable mismatch: expected ${rawEntry.executableSha256}, got ${exeActual}`);
                  failures++;
                }
              } catch (err) {
                console.error(`[FAIL] ${name} [${arch}] failed to extract executable: ${err.message}`);
                failures++;
              }
            }
          } else {
            console.error(`[FAIL] ${name} [${arch}]: ${rawEntry.asset} expected ${rawEntry.sha256}, got ${actual}`);
            failures++;
          }
        } else if (requireAssets) {
          console.error(`[FAIL] ${name} [${arch}]: Required asset missing: ${rawEntry.asset} (searched: ${archivePath})`);
          failures++;
        } else {
          console.log(`[SKIP] ${name} [${arch}]: ${rawEntry.asset} (file not present locally)`);
        }
      }
    }
  }

  // 2. Verify runtime dependencies
  for (const [dep, entry] of Object.entries(lock.runtimeDependencies || {})) {
    definitions++;
    if (!hexShaRegex.test(entry.sha256)) {
      console.error(`[FAIL] runtime dependency ${dep}: Invalid SHA-256 format for ${entry.tarball}`);
      failures++;
    }
    const depPath = join(assetsDir, entry.tarball);
    if (existsSync(depPath)) {
      const actual = hashFile(depPath);
      if (actual === entry.sha256) {
        console.log(`[PASS] runtime dependency ${dep}: ${entry.tarball} (${actual})`);
        verifiedOnDisk++;
      } else {
        console.error(`[FAIL] runtime dependency ${dep}: ${entry.tarball} expected ${entry.sha256}, got ${actual}`);
        failures++;
      }
    } else if (requireAssets) {
      console.error(`[FAIL] runtime dependency ${dep}: Required asset missing: ${entry.tarball} (searched: ${depPath})`);
      failures++;
    } else {
      console.log(`[SKIP] runtime dependency ${dep}: ${entry.tarball} (file not present locally)`);
    }
  }

  if (requireAssets && verifiedOnDisk === 0) {
    console.error("\n[FAIL] --require-assets specified but 0 assets were found on disk!");
    failures++;
  }

  if (failures > 0) {
    console.error(`\nVerification FAILED with ${failures} error(s).`);
    process.exit(1);
  } else {
    console.log(`\nVerification PASSED (${definitions} definitions validated, ${verifiedOnDisk} files verified on disk).`);
    process.exit(0);
  }
}

main();
