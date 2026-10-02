// @ts-check
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

/**
 * Authoritative exclusions for public repository projection root calculation.
 * These paths are excluded from the canonical projection Merkle tree manifest.
 */
export const CANONICAL_PROJECTION_EXCLUDED_PATHS = Object.freeze([
  ".git",
  "HOSTED-VALIDATION-GATE-RECEIPT.json",
  "theme-forge-packages.tar.gz",
  "GENERATOR-PROJECTION-BINDING.json",
  "PROJECTION-BOOTSTRAP-RECEIPT.json",
]);

/**
 * Returns hex SHA-256 digest of Buffer or string.
 * @param {Buffer | Uint8Array | string} buf
 * @returns {string}
 */
export function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Normalizes relative path with POSIX separators and Unicode NFC normalization.
 * @param {string} p
 * @returns {string}
 */
export function normalizePath(p) {
  return p.split(sep).join("/").normalize("NFC");
}

/**
 * Deterministically scans a projection directory and returns sorted file entries.
 * @param {string} repoDir
 * @param {readonly string[]} [excludedPaths]
 * @returns {Array<{ path: string, bytes: number, sha256: string }>}
 */
export function scanProjectionFiles(repoDir, excludedPaths = CANONICAL_PROJECTION_EXCLUDED_PATHS) {
  const normExcluded = new Set((excludedPaths || []).map(normalizePath));
  const fileManifest = [];

  function scan(currentDir) {
    const entries = readdirSync(currentDir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      if (ent.name.startsWith("._") || ent.name === ".DS_Store") {
        throw new Error(`Unsafe sidecar file detected in projection: ${join(currentDir, ent.name)}`);
      }
      const full = join(currentDir, ent.name);
      const rel = normalizePath(relative(repoDir, full));
      if (normExcluded.has(rel)) continue;

      if (ent.isDirectory()) {
        scan(full);
      } else if (ent.isFile()) {
        const buf = readFileSync(full);
        fileManifest.push({
          path: rel,
          bytes: buf.length,
          sha256: sha256Hex(buf),
        });
      }
    }
  }

  scan(repoDir);
  fileManifest.sort((a, b) => a.path.localeCompare(b.path));
  return fileManifest;
}

/**
 * Computes canonical Merkle root SHA-256 digest of the projection directory.
 * @param {string} repoDir
 * @param {readonly string[]} [excludedPaths]
 * @returns {string}
 */
export function computeProjectionRoot(repoDir, excludedPaths = CANONICAL_PROJECTION_EXCLUDED_PATHS) {
  const files = scanProjectionFiles(repoDir, excludedPaths);
  return sha256Hex(Buffer.from(JSON.stringify(files)));
}

/**
 * Computes canonical projection manifest object containing files, totalFiles, and root digest.
 * @param {string} repoDir
 * @param {readonly string[]} [excludedPaths]
 * @returns {{ treeManifestSha256: string, files: Array<{ path: string, bytes: number, sha256: string }>, totalFiles: number }}
 */
export function computeProjectionManifest(repoDir, excludedPaths = CANONICAL_PROJECTION_EXCLUDED_PATHS) {
  const files = scanProjectionFiles(repoDir, excludedPaths);
  const treeManifestSha256 = sha256Hex(Buffer.from(JSON.stringify(files)));
  return {
    treeManifestSha256,
    files,
    totalFiles: files.length,
  };
}
