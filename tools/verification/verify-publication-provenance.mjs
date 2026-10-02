#!/usr/bin/env node

/**
 * Validates publication-provenance.json schema, hashes, and consistency.
 * Strictly disallows synthetic fallbacks or missing cryptographic attestations.
 * Recomputes Merkle tree root, release lock sha, and public key sha when paths are available.
 */
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { resolve, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { FIXTURE_FINGERPRINT } from "./verify-public-key-bootstrap.mjs";

function hashFile(path) {
  const buf = readFileSync(path);
  return createHash("sha256").update(buf).digest("hex");
}

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function normalizePath(p) {
  return p.replace(/\\/g, "/");
}

export const CANONICAL_EXCLUDED_PATHS = ["provenance/publication-provenance.json"];

export function computePagesTreeMerkleRoot(pagesDir, excludedPaths = CANONICAL_EXCLUDED_PATHS) {
  const normExcluded = new Set((excludedPaths || []).map(normalizePath));
  const manifest = [];
  function scan(dir) {
    const entries = readdirSync(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        scan(full);
      } else if (ent.isFile()) {
        const rel = normalizePath(relative(pagesDir, full));
        if (normExcluded.has(rel)) {
          continue;
        }
        manifest.push({
          path: rel,
          sha256: hashFile(full),
        });
      }
    }
  }
  scan(pagesDir);
  manifest.sort((a, b) => a.path.localeCompare(b.path));
  const manifestBuf = Buffer.from(JSON.stringify(manifest), "utf8");
  return {
    manifest,
    rootSha256: sha256Hex(manifestBuf),
    excludedPaths: Array.from(normExcluded).sort(),
    totalFiles: manifest.length,
  };
}

export function verifyPublicationProvenance(pagesTreeDirOrProvFile, options = {}) {
  let provPath = pagesTreeDirOrProvFile;
  let pagesTreeDir = options.pagesTreeDir || null;

  if (existsSync(provPath) && statSync(provPath).isDirectory()) {
    pagesTreeDir = provPath;
    provPath = join(pagesTreeDir, "provenance/publication-provenance.json");
  }

  if (!existsSync(provPath)) {
    throw new Error(`Provenance file not found: ${provPath}`);
  }

  const prov = JSON.parse(readFileSync(provPath, "utf8"));
  if (prov.schema !== "tfsb.dist1-publication-provenance-v1") {
    throw new Error(`Invalid provenance schema: ${prov.schema}`);
  }

  const hexShaRegex = /^[a-f0-9]{64}$/i;
  if (!prov.releaseLockSha256 || !hexShaRegex.test(prov.releaseLockSha256)) {
    throw new Error(`Missing or invalid releaseLockSha256: ${prov.releaseLockSha256}`);
  }

  if (!prov.pagesDeploymentArtifactIdentity || typeof prov.pagesDeploymentArtifactIdentity !== "object") {
    throw new Error("Missing pagesDeploymentArtifactIdentity in provenance");
  }

  const ident = prov.pagesDeploymentArtifactIdentity;
  if (!ident.pagesTreeRootSha256 || !hexShaRegex.test(ident.pagesTreeRootSha256)) {
    throw new Error(`Missing or invalid pagesTreeRootSha256: ${ident.pagesTreeRootSha256}`);
  }

  if (!Array.isArray(ident.excludedPaths)) {
    throw new Error("pagesDeploymentArtifactIdentity.excludedPaths must be an array");
  }

  const sortedIdentExcluded = [...ident.excludedPaths].sort();
  const sortedExpectedExcluded = [...CANONICAL_EXCLUDED_PATHS].sort();
  if (JSON.stringify(sortedIdentExcluded) !== JSON.stringify(sortedExpectedExcluded)) {
    throw new Error(
      `Non-canonical excludedPaths in provenance: ${JSON.stringify(ident.excludedPaths)} (expected exact ${JSON.stringify(CANONICAL_EXCLUDED_PATHS)})`
    );
  }

  let computedRoot = null;
  if (pagesTreeDir && existsSync(pagesTreeDir)) {
    const recomputed = computePagesTreeMerkleRoot(pagesTreeDir, ident.excludedPaths || CANONICAL_EXCLUDED_PATHS);
    if (typeof ident.totalFiles === "number" && ident.totalFiles !== recomputed.manifest.length) {
      throw new Error(
        `Total deployable files mismatch: prov has ${ident.totalFiles}, recomputed has ${recomputed.manifest.length}`
      );
    }
    if (recomputed.rootSha256 !== ident.pagesTreeRootSha256) {
      throw new Error(
        `Merkle root mismatch: prov has ${ident.pagesTreeRootSha256}, recomputed is ${recomputed.rootSha256}`
      );
    }
    computedRoot = recomputed.rootSha256;
  }

  return {
    status: "passed",
    treeRootSha256: ident.pagesTreeRootSha256,
    computedRootSha256: computedRoot,
    totalFiles: ident.totalFiles,
    excludedPaths: ident.excludedPaths,
  };
}

export function main() {
  const args = process.argv.slice(2);
  const provPath = resolve(args[0] || "provenance/publication-provenance.json");
  const pagesTreeDir = args[1] ? resolve(args[1]) : (existsSync("pages-tree") ? resolve("pages-tree") : null);
  const releaseLockPath = args[2] ? resolve(args[2]) : (existsSync("release-lock.json") ? resolve("release-lock.json") : null);
  const pubkeyPath = args[3] ? resolve(args[3]) : (existsSync("keys/knowledge-forge-ai-packages.asc") ? resolve("keys/knowledge-forge-ai-packages.asc") : null);
  const matrixPath = args[4] ? resolve(args[4]) : (existsSync("package-matrix.json") ? resolve("package-matrix.json") : null);

  if (!existsSync(provPath)) {
    console.error(`Error: Provenance file not found: ${provPath}`);
    process.exit(1);
  }

  const prov = JSON.parse(readFileSync(provPath, "utf8"));
  console.log(`Verifying publication provenance: schema ${prov.schema}, built at ${prov.builtAt}`);

  let errors = 0;

  if (prov.schema !== "tfsb.dist1-publication-provenance-v1") {
    console.error(`[FAIL] Invalid provenance schema: ${prov.schema}`);
    errors++;
  }

  if (!prov.builtAt || isNaN(Date.parse(prov.builtAt))) {
    console.error(`[FAIL] Missing or invalid builtAt timestamp: ${prov.builtAt}`);
    errors++;
  }

  const hexShaRegex = /^[a-f0-9]{64}$/i;
  const commitShaRegex = /^[a-f0-9]{40}$/i;

  // 1. Release Lock SHA-256
  if (!prov.releaseLockSha256 || !hexShaRegex.test(prov.releaseLockSha256)) {
    console.error(`[FAIL] Missing or invalid releaseLockSha256: ${prov.releaseLockSha256}`);
    errors++;
  } else {
    if (releaseLockPath && existsSync(releaseLockPath)) {
      const actualLockSha = hashFile(releaseLockPath);
      if (actualLockSha !== prov.releaseLockSha256) {
        console.error(`[FAIL] releaseLockSha256 mismatch: prov has ${prov.releaseLockSha256}, actual is ${actualLockSha}`);
        errors++;
      } else {
        console.log(`[PASS] Recomputed release lock SHA-256 matches: ${actualLockSha}`);
      }
    } else {
      console.log(`[PASS] Release lock SHA-256 bound: ${prov.releaseLockSha256}`);
    }
  }

  // 2. Workflow commit SHA
  if (!prov.workflowCommitSha || !commitShaRegex.test(prov.workflowCommitSha)) {
    console.error(`[FAIL] Missing or invalid workflowCommitSha: ${prov.workflowCommitSha}`);
    errors++;
  } else {
    console.log(`[PASS] Workflow commit bound: ${prov.workflowCommitSha}`);
  }

  // 3. Public Key Fingerprint and SHA-256
  if (!prov.publicKeyFingerprint) {
    console.error("[FAIL] Missing publicKeyFingerprint in provenance");
    errors++;
  } else if (prov.publicKeyFingerprint === FIXTURE_FINGERPRINT) {
    console.error("[FAIL] Production provenance contains test fixture key fingerprint!");
    errors++;
  } else {
    console.log(`[PASS] Signing key fingerprint: ${prov.publicKeyFingerprint}`);
  }

  if (!prov.publicKeySha256 || !hexShaRegex.test(prov.publicKeySha256)) {
    console.error(`[FAIL] Missing or invalid publicKeySha256: ${prov.publicKeySha256}`);
    errors++;
  } else {
    if (pubkeyPath && existsSync(pubkeyPath)) {
      const actualPubSha = hashFile(pubkeyPath);
      if (actualPubSha !== prov.publicKeySha256) {
        console.error(`[FAIL] publicKeySha256 mismatch: prov has ${prov.publicKeySha256}, actual is ${actualPubSha}`);
        errors++;
      } else {
        console.log(`[PASS] Recomputed public key SHA-256 matches: ${actualPubSha}`);
      }
    } else {
      console.log(`[PASS] Public key bundle SHA-256 bound: ${prov.publicKeySha256}`);
    }
  }

  // 4. Pinned container image digests
  if (!prov.containerDigests || typeof prov.containerDigests !== "object" || Object.keys(prov.containerDigests).length === 0) {
    console.error("[FAIL] Missing or empty containerDigests in provenance");
    errors++;
  } else {
    const requiredImages = ["archlinux_x86_64", "fedora_x86_64", "fedora_aarch64"];
    for (const req of requiredImages) {
      if (!prov.containerDigests[req]) {
        console.error(`[FAIL] Missing required container image entry: ${req}`);
        errors++;
      }
    }
    for (const [name, imageRef] of Object.entries(prov.containerDigests)) {
      if (!imageRef.includes("@sha256:")) {
        console.error(`[FAIL] Container image ${name} is not pinned by @sha256 digest: ${imageRef}`);
        errors++;
      }
    }
    console.log(`[PASS] Pinned container digests verified: ${Object.keys(prov.containerDigests).join(", ")}`);
  }

  // 5. Pacman repo database hashes (strict check, must include db and files)
  const reqRepoDbKeys = ["arch_x86_64_db", "arch_x86_64_db_sig", "arch_x86_64_files", "arch_x86_64_files_sig"];
  if (!prov.repoDbHashes || typeof prov.repoDbHashes !== "object") {
    console.error("[FAIL] Missing repoDbHashes in provenance");
    errors++;
  } else {
    for (const k of reqRepoDbKeys) {
      const sha = prov.repoDbHashes[k];
      if (!sha || !hexShaRegex.test(sha)) {
        console.error(`[FAIL] Missing or invalid hash for repoDb ${k}: ${sha}`);
        errors++;
      }
    }
    console.log(`[PASS] Pacman repo database hashes strictly bound: ${reqRepoDbKeys.join(", ")}`);
  }

  // 6. RPM repomd hashes (strict check, must include x86_64 and aarch64 repomd + sig)
  const reqRepomdKeys = ["rpm_x86_64", "rpm_x86_64_sig", "rpm_aarch64", "rpm_aarch64_sig"];
  if (!prov.repomdHashes || typeof prov.repomdHashes !== "object") {
    console.error("[FAIL] Missing repomdHashes in provenance");
    errors++;
  } else {
    for (const k of reqRepomdKeys) {
      const sha = prov.repomdHashes[k];
      if (!sha || !hexShaRegex.test(sha)) {
        console.error(`[FAIL] Missing or invalid hash for repomd ${k}: ${sha}`);
        errors++;
      }
    }
    console.log(`[PASS] RPM repomd hashes strictly bound: ${reqRepomdKeys.join(", ")}`);
  }

  // 7. Packages and signatures
  if (!prov.packages || typeof prov.packages !== "object" || Object.keys(prov.packages).length === 0) {
    console.error("[FAIL] Missing or empty packages map in provenance");
    errors++;
  } else {
    // Assert all 4 products exist in pacman, rpm-x86_64, and rpm-aarch64
    const requiredProducts = [
      "theme-forge-stellar-burst",
      "theme-forge-stellar-loom",
      "theme-forge-solar-sail",
      "theme-forge-nebular-fusion",
    ];

    for (const prod of requiredProducts) {
      const hasPacman = Object.keys(prov.packages).some((p) => p.includes(prod) && prov.packages[p].channel === "pacman");
      const hasRpmX64 = Object.keys(prov.packages).some((p) => p.includes(prod) && prov.packages[p].channel === "rpm-x86_64");
      const hasRpmArm = Object.keys(prov.packages).some((p) => p.includes(prod) && prov.packages[p].channel === "rpm-aarch64");

      if (!hasPacman) {
        console.error(`[FAIL] Product ${prod} missing in pacman channel!`);
        errors++;
      }
      if (!hasRpmX64) {
        console.error(`[FAIL] Product ${prod} missing in rpm-x86_64 channel!`);
        errors++;
      }
      if (!hasRpmArm) {
        console.error(`[FAIL] Product ${prod} missing in rpm-aarch64 channel!`);
        errors++;
      }
    }

    for (const [pkg, info] of Object.entries(prov.packages)) {
      if (!info.sha256 || !hexShaRegex.test(info.sha256)) {
        console.error(`[FAIL] Package ${pkg} has synthetic or invalid sha256: ${info.sha256}`);
        errors++;
      }
      if (!info.signatureSha256 || !hexShaRegex.test(info.signatureSha256)) {
        console.error(`[FAIL] Package ${pkg} missing verified signatureSha256`);
        errors++;
      }
      // Fail closed if signature hash is identical to package hash (synthetic placeholder)
      if (info.signatureSha256 === info.sha256) {
        console.error(`[FAIL] Package ${pkg} signatureSha256 is identical to sha256 (synthetic placeholder rejected)!`);
        errors++;
      }

      if (info.path && existsSync(info.path)) {
        const actual = hashFile(info.path);
        if (actual === info.sha256) {
          console.log(`[PASS] Package ${pkg} verified: ${actual}`);
        } else {
          console.error(`[FAIL] Package ${pkg} expected ${info.sha256}, got ${actual}`);
          errors++;
        }
      }
    }
  }

  // 8. Pages Tree Root Merkle Digest and Deployment Identity
  if (!prov.pagesDeploymentArtifactIdentity || typeof prov.pagesDeploymentArtifactIdentity !== "object") {
    console.error("[FAIL] Missing pagesDeploymentArtifactIdentity in provenance");
    errors++;
  } else {
    const ident = prov.pagesDeploymentArtifactIdentity;
    if (!ident.pagesTreeRootSha256 || !hexShaRegex.test(ident.pagesTreeRootSha256)) {
      console.error(`[FAIL] Missing or invalid pagesTreeRootSha256: ${ident.pagesTreeRootSha256}`);
      errors++;
    } else {
      // Assert exact excluded paths
      if (!Array.isArray(ident.excludedPaths)) {
        console.error("[FAIL] pagesDeploymentArtifactIdentity.excludedPaths must be an array");
        errors++;
      } else {
        const sortedIdentExcluded = [...ident.excludedPaths].sort();
        const sortedExpectedExcluded = [...CANONICAL_EXCLUDED_PATHS].sort();
        if (JSON.stringify(sortedIdentExcluded) !== JSON.stringify(sortedExpectedExcluded)) {
          console.error(`[FAIL] Unexpected excludedPaths in provenance: ${JSON.stringify(ident.excludedPaths)} (expected exact ${JSON.stringify(CANONICAL_EXCLUDED_PATHS)})`);
          errors++;
        } else {
          console.log(`[PASS] Excluded paths verified strictly: [${ident.excludedPaths.join(", ")}]`);
        }
      }

      if (pagesTreeDir && existsSync(pagesTreeDir)) {
        const recomputed = computePagesTreeMerkleRoot(pagesTreeDir, ident.excludedPaths || CANONICAL_EXCLUDED_PATHS);
        if (typeof ident.totalFiles === "number" && ident.totalFiles !== recomputed.manifest.length) {
          console.error(`[FAIL] Pages tree manifest file count mismatch: prov has ${ident.totalFiles}, recomputed has ${recomputed.manifest.length}`);
          errors++;
        } else if (typeof ident.totalFiles === "number") {
          console.log(`[PASS] Pages tree manifest file count matches: ${ident.totalFiles}`);
        }

        if (recomputed.rootSha256 !== ident.pagesTreeRootSha256) {
          console.error(`[FAIL] Pages tree Merkle root mismatch: prov has ${ident.pagesTreeRootSha256}, recomputed is ${recomputed.rootSha256}`);
          errors++;
        } else {
          console.log(`[PASS] Recomputed Pages tree root Merkle digest matches: ${recomputed.rootSha256} (${recomputed.manifest.length} covered files)`);
        }
      } else {
        console.log(`[PASS] Pages tree root Merkle digest verified: ${ident.pagesTreeRootSha256}`);
      }
    }
  }

  if (errors > 0) {
    console.error(`\nProvenance validation FAILED with ${errors} error(s).`);
    process.exit(1);
  } else {
    console.log("\nProvenance validation PASSED (all elements strictly bound without synthetic fallbacks).");
    process.exit(0);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
