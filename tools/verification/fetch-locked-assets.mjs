#!/usr/bin/env node

/**
 * Downloads and cryptographically authenticates all locked upstream release assets
 * and runtime dependencies against release-lock.json.
 *
 * Ensures all downstream package builds consume authenticated local files.
 * Zero external dependencies; standard Node.js runtime.
 */
import { createWriteStream, existsSync, mkdirSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import https from "node:https";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function downloadFile(url, dest, expectedSha) {
  return new Promise((res, rej) => {
    console.log(`Downloading: ${url} -> ${dest}`);
    function fetchUrl(currentUrl, redirectCount = 0) {
      if (redirectCount > 10) {
        return rej(new Error(`Too many redirects fetching ${url}`));
      }
      https.get(currentUrl, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          return fetchUrl(response.headers.location, redirectCount + 1);
        }
        if (response.statusCode !== 200) {
          return rej(new Error(`HTTP ${response.statusCode} fetching ${currentUrl}`));
        }
        const fileStream = createWriteStream(dest);
        const hash = createHash("sha256");
        response.on("data", (chunk) => hash.update(chunk));
        response.pipe(fileStream);
        fileStream.on("finish", () => {
          fileStream.close(() => {
            const actualSha = hash.digest("hex");
            if (actualSha !== expectedSha) {
              return rej(new Error(`SHA-256 mismatch for ${dest}: expected ${expectedSha}, got ${actualSha}`));
            }
            console.log(`[PASS] ${dest} (${actualSha})`);
            res(actualSha);
          });
        });
      }).on("error", rej);
    }
    fetchUrl(url);
  });
}

export async function fetchLockedAssets(options = {}) {
  const rootDir = options.rootDir || process.cwd();
  const lockPath = resolve(options.lockPath || join(rootDir, "release-lock.json"));
  const destDir = resolve(options.destDir || join(rootDir, "upstream-assets"));

  if (!existsSync(lockPath)) {
    throw new Error(`Release lock not found: ${lockPath}`);
  }

  mkdirSync(destDir, { recursive: true });

  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  console.log(`Fetching locked upstream assets according to ${lockPath}...`);

  const downloadTasks = [];

  let authenticatedCount = 0;

  // 1. Runtime dependencies
  for (const [dep, info] of Object.entries(lock.runtimeDependencies || {})) {
    if (!info?.tarball || !info?.sha256 || !info?.resolved) {
      throw new Error(`Runtime dependency ${dep} missing required lock fields (tarball, sha256, resolved)`);
    }
    const dest = join(destDir, info.tarball);
    if (existsSync(dest) && sha256Hex(readFileSync(dest)) === info.sha256) {
      console.log(`[CACHED] ${dest} (${info.sha256})`);
      authenticatedCount++;
    } else {
      downloadTasks.push(
        downloadFile(info.resolved, dest, info.sha256).then(() => {
          authenticatedCount++;
        })
      );
    }
  }

  // 2. Product npm tarballs
  const npmProducts = ["theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail"];
  for (const prod of npmProducts) {
    const info = lock.products[prod];
    if (!info?.asset || !info?.sha256) {
      throw new Error(`Product ${prod} missing asset or sha256 in release lock!`);
    }
    const dest = join(destDir, info.asset);
    if (existsSync(dest) && sha256Hex(readFileSync(dest)) === info.sha256) {
      console.log(`[CACHED] ${dest} (${info.sha256})`);
      authenticatedCount++;
    } else {
      const url = `https://registry.npmjs.org/@knowledge-forge-ai/${prod}/-/${info.asset}`;
      downloadTasks.push(
        downloadFile(url, dest, info.sha256).then(() => {
          authenticatedCount++;
        })
      );
    }
  }

  // 3. Nebular Fusion raw archives
  const nebular = lock.products["theme-forge-nebular-fusion"];
  if (!nebular?.rawArchives || Object.keys(nebular.rawArchives).length === 0) {
    throw new Error("theme-forge-nebular-fusion missing rawArchives in release lock!");
  }
  for (const [arch, rawInfo] of Object.entries(nebular.rawArchives)) {
    if (!rawInfo?.asset || !rawInfo?.sha256) {
      throw new Error(`Nebular Fusion ${arch} missing asset or sha256 in release lock!`);
    }
    const dest = join(destDir, rawInfo.asset);
    if (existsSync(dest) && sha256Hex(readFileSync(dest)) === rawInfo.sha256) {
      console.log(`[CACHED] ${dest} (${rawInfo.sha256})`);
      authenticatedCount++;
    } else {
      const url = `https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v${nebular.version}/${rawInfo.asset}`;
      downloadTasks.push(
        downloadFile(url, dest, rawInfo.sha256).then(() => {
          authenticatedCount++;
        })
      );
    }
  }

  await Promise.all(downloadTasks);
  console.log(`All ${authenticatedCount} assets authenticated in ${destDir}.`);

  // 4. Verify raw executable digests from authenticated archives
  if (nebular?.rawArchives) {
    console.log("Verifying Nebular raw executable binary bytes from authenticated archives...");
    for (const [arch, rawInfo] of Object.entries(nebular.rawArchives)) {
      if (rawInfo.executableSha256 && rawInfo.executablePath) {
        const archivePath = join(destDir, rawInfo.asset);
        // Extract raw executable into temporary buffer using tar
        try {
          const rawBinary = execFileSync("tar", ["-xzOf", archivePath, rawInfo.executablePath], {
            maxBuffer: 100 * 1024 * 1024,
          });
          const actualExeSha = sha256Hex(rawBinary);
          if (actualExeSha !== rawInfo.executableSha256) {
            throw new Error(`Executable SHA-256 mismatch for ${arch} (${rawInfo.executablePath}): expected ${rawInfo.executableSha256}, got ${actualExeSha}`);
          }
          console.log(`[PASS] Nebular executable (${arch}) verified: ${actualExeSha}`);
        } catch (err) {
          throw new Error(`Failed to extract and verify executable for ${arch} from ${archivePath}: ${err.message}`);
        }
      }
    }
  }

  return { destDir, totalAssets: authenticatedCount };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const destIndex = args.indexOf("--dest");
  const destDir = destIndex !== -1 ? args[destIndex + 1] : "upstream-assets";
  const lockIndex = args.indexOf("--lock");
  const lockPath = lockIndex !== -1 ? args[lockIndex + 1] : (args[0] && !args[0].startsWith("--") ? args[0] : "release-lock.json");

  fetchLockedAssets({ destDir, lockPath })
    .then(() => {
      console.log("\n[SUCCESS] Upstream assets authenticated successfully.");
      process.exit(0);
    })
    .catch((err) => {
      console.error(`\n[FATAL] ${err.message}`);
      process.exit(1);
    });
}
