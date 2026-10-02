#!/usr/bin/env node

/**
 * Generates strict publication-provenance.json for Theme Forge Packages publication.
 * Shared with verify-publication-provenance.mjs for canonical Merkle root calculation.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CANONICAL_EXCLUDED_PATHS, computePagesTreeMerkleRoot } from "./verify-publication-provenance.mjs";

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function hashFile(p) {
  if (!existsSync(p)) {
    throw new Error(`Missing file to hash: ${p}`);
  }
  return sha256Hex(readFileSync(p));
}

export function extractPublicKeyFingerprint(pubKeyPath, gpgBin = "gpg") {
  const colons = execFileSync(gpgBin, ["--batch", "--show-keys", "--with-colons", pubKeyPath], {
    encoding: "utf8",
  });
  let pubFpr = null;
  for (const line of colons.split("\n")) {
    const parts = line.split(":");
    if (parts[0] === "fpr" && !pubFpr) {
      pubFpr = parts[9];
      break;
    }
  }
  if (!pubFpr) {
    throw new Error(`Could not extract public key fingerprint from ${pubKeyPath}`);
  }
  return pubFpr.toUpperCase();
}

export async function generatePublicationProvenance(options = {}) {
  const pagesDir = resolve(options.pagesDir || "pages-tree");
  const releaseLockPath = resolve(options.releaseLock || "release-lock.json");
  const pubKeyPath = resolve(options.publicKey || join(pagesDir, "keys/knowledge-forge-ai-packages.asc"));
  const commitSha = options.commitSha || process.env.COMMIT_SHA;
  const outPath = resolve(options.out || join(pagesDir, "provenance/publication-provenance.json"));
  const gpgBin = options.gpgBin || process.env.GPG_BIN || "gpg";
  const rpmBin = options.rpmBin || process.env.RPM_BIN || "rpm";

  if (!existsSync(pagesDir)) {
    throw new Error(`Pages tree directory not found: ${pagesDir}`);
  }
  if (!existsSync(releaseLockPath)) {
    throw new Error(`Release lock file not found: ${releaseLockPath}`);
  }
  if (!existsSync(pubKeyPath)) {
    throw new Error(`Public key file not found: ${pubKeyPath}`);
  }
  if (!commitSha) {
    throw new Error("Missing required commitSha (specify --commit-sha or set COMMIT_SHA)");
  }

  const lockSha = hashFile(releaseLockPath);
  const pubKeySha = hashFile(pubKeyPath);
  const pubFpr = extractPublicKeyFingerprint(pubKeyPath, gpgBin);

  // Collect repository DB and metadata hashes
  const repoDbHashes = {
    arch_x86_64_db: hashFile(join(pagesDir, "arch/x86_64/knowledge-forge-ai.db.tar.gz")),
    arch_x86_64_db_sig: hashFile(join(pagesDir, "arch/x86_64/knowledge-forge-ai.db.tar.gz.sig")),
    arch_x86_64_files: hashFile(join(pagesDir, "arch/x86_64/knowledge-forge-ai.files.tar.gz")),
    arch_x86_64_files_sig: hashFile(join(pagesDir, "arch/x86_64/knowledge-forge-ai.files.tar.gz.sig")),
  };

  const repomdHashes = {
    rpm_x86_64: hashFile(join(pagesDir, "rpm/x86_64/repodata/repomd.xml")),
    rpm_x86_64_sig: hashFile(join(pagesDir, "rpm/x86_64/repodata/repomd.xml.asc")),
    rpm_aarch64: hashFile(join(pagesDir, "rpm/aarch64/repodata/repomd.xml")),
    rpm_aarch64_sig: hashFile(join(pagesDir, "rpm/aarch64/repodata/repomd.xml.asc")),
  };

  // Collect every package and its genuine signature hash
  const packages = {};

  function scanPackageDir(subDir, channel) {
    const fullDir = join(pagesDir, subDir);
    if (!existsSync(fullDir)) {
      throw new Error(`Missing repository directory: ${fullDir}`);
    }
    const entries = readdirSync(fullDir);
    entries.sort();
    for (const f of entries) {
      const full = join(fullDir, f);
      if (f.endsWith(".rpm")) {
        let sigArmor = "";
        try {
          sigArmor = execFileSync(rpmBin, ["-qp", "--qf", "%{RSAHEADER:armor}", full], {
            encoding: "utf8",
          });
        } catch {
          sigArmor = "";
        }
        if (!sigArmor || !sigArmor.includes("BEGIN PGP SIGNATURE")) {
          try {
            sigArmor = execFileSync(rpmBin, ["-qp", "--qf", "%{SIGGPG:armor}", full], {
              encoding: "utf8",
            });
          } catch {}
        }
        if (!sigArmor || !sigArmor.includes("BEGIN PGP SIGNATURE")) {
          try {
            sigArmor = execFileSync(rpmBin, ["-qp", "--qf", "%{OPENPGP:armor}", full], {
              encoding: "utf8",
            });
          } catch {}
        }
        if (!sigArmor || !sigArmor.includes("BEGIN PGP SIGNATURE")) {
          throw new Error(`Could not extract valid OpenPGP signature header from ${full}`);
        }
        const sigSha = sha256Hex(Buffer.from(sigArmor.trim()));
        packages[`${f} [${channel}]`] = {
          channel,
          path: full,
          sha256: hashFile(full),
          signatureSha256: sigSha,
        };
      } else if (f.endsWith(".pkg.tar.zst")) {
        const sigPath = `${full}.sig`;
        packages[f] = {
          channel,
          path: full,
          sha256: hashFile(full),
          signatureSha256: hashFile(sigPath),
        };
      }
    }
  }

  scanPackageDir("arch/x86_64", "pacman");
  scanPackageDir("rpm/x86_64", "rpm-x86_64");
  scanPackageDir("rpm/aarch64", "rpm-aarch64");

  // Compute Pages directory Merkle root using shared canonical verifier implementation
  const { rootSha256: pagesTreeRootSha256, manifest } = computePagesTreeMerkleRoot(
    pagesDir,
    CANONICAL_EXCLUDED_PATHS
  );

  const provenance = {
    schema: "tfsb.dist1-publication-provenance-v1",
    builtAt: new Date().toISOString(),
    releaseLockSha256: lockSha,
    workflowCommitSha: commitSha,
    publicKeyFingerprint: pubFpr,
    publicKeySha256: pubKeySha,
    containerDigests: {
      archlinux_x86_64: "archlinux:base@sha256:b21322c663be387c0ed9cbc7bbbfe18e41633ad4e7b7c77cfad45f128be20040",
      fedora_x86_64: "fedora@sha256:a651ddf48ea28a06ed4e1e6519f51c9f47e7a5a138722ade87369b8fbb7e5b42",
      fedora_aarch64: "fedora@sha256:a651ddf48ea28a06ed4e1e6519f51c9f47e7a5a138722ade87369b8fbb7e5b42",
    },
    repoDbHashes,
    repomdHashes,
    packages,
    pagesDeploymentArtifactIdentity: {
      workflowCommitSha: commitSha,
      pagesTreeRootSha256,
      totalFiles: manifest.length,
      excludedPaths: [...CANONICAL_EXCLUDED_PATHS],
    },
  };

  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(provenance, null, 2) + "\n", "utf8");
  console.log(
    `Strict publication provenance generated: ${Object.keys(packages).length} packages, tree root ${pagesTreeRootSha256}`
  );
  console.log(`Emitted provenance: ${outPath}`);

  return provenance;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opts = {};

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--pages-dir" && args[i + 1]) {
      opts.pagesDir = args[++i];
    } else if (args[i] === "--release-lock" && args[i + 1]) {
      opts.releaseLock = args[++i];
    } else if (args[i] === "--public-key" && args[i + 1]) {
      opts.publicKey = args[++i];
    } else if (args[i] === "--commit-sha" && args[i + 1]) {
      opts.commitSha = args[++i];
    } else if (args[i] === "--out" && args[i + 1]) {
      opts.out = args[++i];
    } else if (args[i] === "--gpg-bin" && args[i + 1]) {
      opts.gpgBin = args[++i];
    } else if (args[i] === "--rpm-bin" && args[i + 1]) {
      opts.rpmBin = args[++i];
    }
  }

  generatePublicationProvenance(opts)
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(`\n[FATAL] Failed to generate publication provenance: ${err.message}`);
      process.exit(1);
    });
}
