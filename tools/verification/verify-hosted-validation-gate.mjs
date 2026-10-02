#!/usr/bin/env node

/**
 * Gate Verifier for GitHub Actions Hosted Validation (validate.yml).
 *
 * Enforces fail-closed validation of:
 * 1. Exact GitHub Actions workflow run ID on exact commit.
 * 2. Exact workflow path: .github/workflows/validate.yml (no loose suffixes).
 * 3. Workflow run status: 'completed' and conclusion: 'success'.
 * 4. Fetch & cryptographic bind of .github/workflows/validate.yml at commit.
 * 5. Logical job key existence in workflow YAML (validate-linux, validate-nix-darwin).
 * 6. Live job presence, numeric IDs, and conclusions ('success') for all required definitions.
 * 7. Verification of committed production public key bundle.
 * 8. Fresh local recomputation and comparison of authoritative projection root and release lock.
 * 9. Live re-query when verifying existing publication receipts (--verify-receipt).
 *
 * In live/publication mode, ANY missing binding, HTTP failure, hash mismatch, or job failure
 * causes an immediate fail-closed termination.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  computeProjectionRoot,
  computeProjectionManifest,
  CANONICAL_PROJECTION_EXCLUDED_PATHS,
  sha256Hex as canonicalSha256Hex,
  normalizePath,
} from "./projection-identity.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export const REQUIRED_JOB_DEFINITIONS = Object.freeze([
  {
    jobKey: "validate-linux",
    displayName: "Validate Linux Packages (x86_64)",
    matrixArch: "x86_64",
    coverageMapping: "Nix x86_64-linux, Pacman x86_64, Fedora RPM x86_64 + noarch",
  },
  {
    jobKey: "validate-linux",
    displayName: "Validate Linux Packages (aarch64)",
    matrixArch: "aarch64",
    coverageMapping: "Nix aarch64-linux, Fedora RPM aarch64",
  },
  {
    jobKey: "validate-nix-darwin",
    displayName: "Validate Hosted Nix on macOS (aarch64-darwin)",
    matrixArch: "aarch64-darwin",
    coverageMapping: "Nix aarch64-darwin (.app, bundle launcher, executable verification)",
  },
]);

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

export function gitBlobSha(buf) {
  const header = Buffer.from(`blob ${buf.length}\0`);
  return createHash("sha1").update(header).update(buf).digest("hex");
}

export function extractYamlJobKeys(yamlText) {
  // 1. Try python3 pyyaml if present
  try {
    const pyRes = spawnSync(
      "python3",
      ["-c", "import yaml, sys, json; print(json.dumps(list(yaml.safe_load(sys.stdin).get('jobs', {}).keys())))"],
      { input: yamlText, encoding: "utf8" }
    );
    if (pyRes.status === 0 && pyRes.stdout.trim()) {
      return JSON.parse(pyRes.stdout.trim());
    }
  } catch {}

  // 2. Pure line-by-line fallback
  const jobKeys = [];
  const lines = yamlText.split(/\r?\n/);
  let inJobs = false;
  for (const line of lines) {
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      continue;
    }
    if (inJobs) {
      if (/^[a-zA-Z0-9_-]+:/.test(line)) {
        break;
      }
      const match = line.match(/^ {2}([a-zA-Z0-9_-]+):\s*$/);
      if (match) {
        jobKeys.push(match[1]);
      }
    }
  }
  return jobKeys;
}

async function loadVerifyPublicKeyBootstrap() {
  if (existsSync(join(__dirname, "verify-public-key-bootstrap.mjs"))) {
    const mod = await import("./verify-public-key-bootstrap.mjs");
    return mod.verifyPublicKeyBootstrap;
  }
  if (existsSync(join(__dirname, "templates/verification/verify-public-key-bootstrap.mjs"))) {
    const mod = await import("./templates/verification/verify-public-key-bootstrap.mjs");
    return mod.verifyPublicKeyBootstrap;
  }
  return null;
}

export async function verifyHostedValidationGate(options = {}) {
  // Direct dispatch for receipt verification mode
  if (options.verifyReceipt) {
    return verifyReceiptFile(options.verifyReceipt, options);
  }

  const isOfflineTest = Boolean(options.offlineReceipt || options.offline || options.testOnly);

  if (options.offlineReceipt && options.out && resolve(options.out) === resolve(options.offlineReceipt)) {
    throw new Error(`[FAIL] Output path cannot overwrite offline input receipt fixture: ${resolve(options.out)}`);
  }

  // 1. Validate repository argument (H2: explicit repo required; no default)
  const repo = options.repo;
  if (!repo) {
    if (isOfflineTest) {
      // Allow fallback repo in offline test mode only
    } else {
      throw new Error("Missing required argument: --repo <owner/repo> (H2: repository identity must be explicit; no default).");
    }
  }
  const resolvedRepo = repo || "Knowledge-Forge-AI/theme-forge-packages";
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(resolvedRepo)) {
    throw new Error(`Invalid repository name: ${resolvedRepo}`);
  }

  // 2. Validate commit SHA
  const commitSha = options.commitSha;
  if (!commitSha) {
    throw new Error("Missing required argument: --commit <commit-sha>.");
  }
  if (!/^[0-9a-f]{40}$/i.test(commitSha)) {
    throw new Error(`Invalid commit SHA (must be 40 hex chars): ${commitSha}`);
  }

  // 3. Resolve and verify release lock
  let releaseLockPath = options.releaseLock ? resolve(options.releaseLock) : null;
  if (!isOfflineTest) {
    if (!releaseLockPath || !existsSync(releaseLockPath)) {
      throw new Error("Missing required argument: --release-lock <path> (file not found).");
    }
  } else {
    if (!releaseLockPath || !existsSync(releaseLockPath)) {
      const candidates = [
        resolve("release-lock.json"),
        resolve(__dirname, "release-lock.json"),
        resolve(__dirname, "../../release-lock.json"),
        resolve(__dirname, "../release-lock.json"),
      ];
      for (const c of candidates) {
        if (existsSync(c)) {
          releaseLockPath = c;
          break;
        }
      }
    }
    if (!releaseLockPath || !existsSync(releaseLockPath)) {
      throw new Error("Missing required argument: --release-lock <path> (file not found).");
    }
  }
  const dynamicReleaseLockSha = sha256Hex(readFileSync(releaseLockPath));

  // 4. Resolve and verify production public key (H1: mandatory fail-closed verification in live mode)
  let keyInfo = null;
  if (isOfflineTest) {
    keyInfo = {
      primaryFingerprint: "1111222233334444555566667777888899990000",
      signingSubkeyFingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
    };
  } else {
    const productionKeyPath = options.productionKey ? resolve(options.productionKey) : null;
    if (!productionKeyPath || !existsSync(productionKeyPath)) {
      throw new Error("Missing required argument: --production-key <path> (file not found).");
    }

    const verifyKeyFn = await loadVerifyPublicKeyBootstrap();
    if (!verifyKeyFn) {
      throw new Error("Security check failed: verifyPublicKeyBootstrap function could not be loaded.");
    }

    try {
      keyInfo = await verifyKeyFn(productionKeyPath);
    } catch (keyErr) {
      throw new Error(`[GATE FAILED] Production public key verification failed (H1): ${keyErr.message}`);
    }
  }

  const primaryFpr = keyInfo.primaryFingerprint;
  const subkeyFpr = keyInfo.signingSubkeyFingerprint;
  if (!primaryFpr || !subkeyFpr) {
    throw new Error("[GATE FAILED] Could not extract primary or signing subkey fingerprint from verified production key.");
  }

  // 5. Authoritative projection identity resolution & fresh recomputation
  let projectionDir = options.projectionDir ? resolve(options.projectionDir) : null;
  if (!isOfflineTest) {
    if (!projectionDir || !existsSync(projectionDir)) {
      throw new Error("Missing required argument: --projection-dir <path> (directory not found).");
    }
  } else if (!projectionDir) {
    const candidateSub = join(dirname(releaseLockPath), "theme-forge-packages");
    projectionDir = existsSync(candidateSub) ? candidateSub : dirname(releaseLockPath);
  }
  const freshlyComputedProjectionRoot = computeProjectionRoot(projectionDir);

  let expectedProjectionRoot = options.projectionRootSha || options.projectionRoot || null;
  let expectedReleaseLockSha = options.expectedReleaseLock || null;

  // If projection binding file specified or present, read authoritative expected values
  let bindingPath = options.projectionBinding ? resolve(options.projectionBinding) : null;
  if (!isOfflineTest) {
    if (!bindingPath || !existsSync(bindingPath)) {
      throw new Error("Missing required argument: --projection-binding <path> (file not found).");
    }
  } else {
    if (!bindingPath || !existsSync(bindingPath)) {
      const bindingCandidates = [
        join(projectionDir, "GENERATOR-PROJECTION-BINDING.json"),
        resolve("GENERATOR-PROJECTION-BINDING.json"),
        resolve(__dirname, "GENERATOR-PROJECTION-BINDING.json"),
        resolve(__dirname, "../GENERATOR-PROJECTION-BINDING.json"),
      ];
      for (const b of bindingCandidates) {
        if (existsSync(b)) {
          bindingPath = b;
          break;
        }
      }
    }
  }

  if (bindingPath && existsSync(bindingPath)) {
    try {
      const bindingInfo = JSON.parse(readFileSync(bindingPath, "utf8"));
      expectedProjectionRoot = expectedProjectionRoot || bindingInfo.treeManifestSha256;
      expectedReleaseLockSha = expectedReleaseLockSha || bindingInfo.releaseLockSha256;
    } catch (err) {
      throw new Error(`Failed to parse projection binding file ${bindingPath}: ${err.message}`);
    }
  }

  if (!expectedProjectionRoot) {
    throw new Error(
      "Missing authoritative projection identity: specify --projection-root <sha> or --projection-binding <path>."
    );
  }

  if (freshlyComputedProjectionRoot !== expectedProjectionRoot) {
    throw new Error(
      `[GATE FAILED] Freshly computed projection root '${freshlyComputedProjectionRoot}' does not match authoritative root '${expectedProjectionRoot}'!`
    );
  }

  if (expectedReleaseLockSha && dynamicReleaseLockSha !== expectedReleaseLockSha) {
    throw new Error(
      `[GATE FAILED] Current release lock digest '${dynamicReleaseLockSha}' does not match authoritative binding '${expectedReleaseLockSha}'!`
    );
  }

  console.log("=== Hosted Validation Gate Verifier ===");
  console.log(`Repository:            ${resolvedRepo}`);
  console.log(`Commit SHA:            ${commitSha}`);
  console.log(`Release Lock SHA-256:  ${dynamicReleaseLockSha}`);
  console.log(`Projection Root SHA:   ${freshlyComputedProjectionRoot}`);
  console.log(`Primary Key FPR:       ${primaryFpr}`);
  console.log(`Signing Subkey FPR:    ${subkeyFpr}`);

  let runData = null;
  let mode = "live-github-api";
  let gateStatus = "PASSED";

  if (isOfflineTest) {
    mode = "offline-receipt-test";
    gateStatus = "TEST_ONLY";
    if (options.offlineReceipt) {
      console.log(`[INFO] Evaluating offline receipt fixture: ${options.offlineReceipt}`);
      const resolvedOffline = resolve(options.offlineReceipt);
      if (existsSync(resolvedOffline)) {
        runData = JSON.parse(readFileSync(resolvedOffline, "utf8"));
      }
    }
    if (!runData) {
      runData = {
        runId: 100000001,
        runUrl: `https://github.com/${resolvedRepo}/actions/runs/100000001`,
        headSha: commitSha,
        headBranch: "main",
        event: "push",
        workflowFileBlobSha: "0000000000000000000000000000000000000000",
        workflowFileSha256: "0000000000000000000000000000000000000000000000000000000000000000",
        jobs: REQUIRED_JOB_DEFINITIONS.map((def, idx) => ({
          id: 1000 + idx,
          numericId: 1000 + idx,
          name: def.displayName,
          displayName: def.displayName,
          conclusion: "success",
          status: "completed",
        })),
      };
    }
  } else {
    // Live GitHub state lookup: requires explicit run-id
    const runId = options.runId;
    if (!runId) {
      throw new Error("Missing required argument: --run-id <id> in live mode.");
    }

    console.log(`Querying GitHub API for workflow run ${runId} on commit ${commitSha}...`);
    runData = await fetchLiveRunData(resolvedRepo, commitSha, runId, options);
  }

  if (!runData || !runData.runId) {
    throw new Error("Invalid or empty workflow run data returned.");
  }

  console.log(`Workflow Run ID:       ${runData.runId}`);
  console.log(`Workflow Run URL:      ${runData.runUrl || "N/A"}`);
  console.log(`Workflow File Blob:    ${runData.workflowFileBlobSha}`);
  console.log(`Workflow File SHA-256: ${runData.workflowFileSha256}`);

  // Match and verify each required job (displayName, conclusion success, valid numeric ID)
  const verifiedJobs = [];
  const reportedJobs = runData.jobs || [];

  for (const def of REQUIRED_JOB_DEFINITIONS) {
    const matched = reportedJobs.find(
      (j) => j.displayName === def.displayName || j.name === def.displayName
    );

    if (!matched) {
      throw new Error(
        `[GATE FAILED] Required hosted validation job missing: '${def.displayName}' (jobKey: ${def.jobKey})`
      );
    }

    if (matched.status !== "completed") {
      throw new Error(
        `[GATE FAILED] Job '${def.displayName}' is not completed! Status was '${matched.status}' (expected 'completed').`
      );
    }

    if (matched.conclusion !== "success") {
      throw new Error(
        `[GATE FAILED] Job '${def.displayName}' did not succeed! Conclusion was '${matched.conclusion}' (expected 'success').`
      );
    }

    const numericId = Number(matched.numericId || matched.id);
    if (!numericId || isNaN(numericId)) {
      throw new Error(
        `[GATE FAILED] Job '${def.displayName}' missing valid numeric ID (got: ${matched.numericId || matched.id})`
      );
    }

    verifiedJobs.push({
      jobKey: def.jobKey,
      displayName: def.displayName,
      numericId,
      conclusion: "success",
      coverageMapping: def.coverageMapping,
    });
    console.log(`  [PASS] Job '${def.displayName}' (numeric ID: ${numericId}) -> conclusion: success`);
  }

  // Construct receipt with factual workflow metadata (H3)
  const receipt = {
    schema: "tfsb.dist1-hosted-validation-gate-receipt-v1",
    repository: resolvedRepo,
    commitSha,
    runId: Number(runData.runId),
    runUrl: runData.runUrl || `https://github.com/${resolvedRepo}/actions/runs/${runData.runId}`,
    workflowPath: ".github/workflows/validate.yml",
    workflowFileCommitSha: commitSha,
    workflowFileBlobSha: runData.workflowFileBlobSha,
    workflowFileSha256: runData.workflowFileSha256,
    runHeadSha: runData.headSha || commitSha,
    runHeadBranch: runData.headBranch || null,
    runEvent: runData.event || null,
    requiredJobs: verifiedJobs,
    projectionRootSha256: freshlyComputedProjectionRoot,
    releaseLockSha256: dynamicReleaseLockSha,
    productionPublicKeyPrimaryFingerprint: primaryFpr,
    productionSigningSubkeyFingerprint: subkeyFpr,
    gateStatus,
    evaluatedAt: new Date().toISOString(),
    mode,
  };

  const defaultOut = options.offlineReceipt
    ? join(tmpdir(), `offline-gate-receipt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.json`)
    : join(dirname(releaseLockPath), "HOSTED-VALIDATION-GATE-RECEIPT.json");
  const outPath = resolve(options.out || defaultOut);
  if (options.offlineReceipt && resolve(outPath) === resolve(options.offlineReceipt)) {
    throw new Error(`[FAIL] Output path cannot overwrite offline input receipt fixture: ${outPath}`);
  }
  writeFileSync(outPath, JSON.stringify(receipt, null, 2) + "\n", "utf8");
  console.log(`\n[${gateStatus}] Emitted receipt to: ${outPath} (gateStatus: ${gateStatus}, mode: ${mode})`);

  return receipt;
}

export async function verifyReceiptFile(receiptPath, options = {}) {
  const resolvedPath = resolve(receiptPath);
  if (!existsSync(resolvedPath)) {
    throw new Error(`Receipt file not found: ${resolvedPath}`);
  }
  const receipt = JSON.parse(readFileSync(resolvedPath, "utf8"));

  if (receipt.schema !== "tfsb.dist1-hosted-validation-gate-receipt-v1") {
    throw new Error(`[VERIFY FAILED] Invalid receipt schema: ${receipt.schema}`);
  }

  const isTestMode = Boolean(options.testOnly || options.offline);

  // Production receipt verification: rejects non-live mode unconditionally (Major 2)
  if (!isTestMode && receipt.mode !== "live-github-api") {
    throw new Error(
      `[VERIFY FAILED] Receipt mode '${receipt.mode}' is not live (only 'live-github-api' is valid for publication)`
    );
  }

  if (!isTestMode && receipt.gateStatus !== "PASSED") {
    throw new Error(`[VERIFY FAILED] Receipt gateStatus is '${receipt.gateStatus}' (expected 'PASSED')`);
  }

  // If in production mode, re-query live GitHub API and re-verify all local bindings (Major 2)
  if (!isTestMode) {
    const repo = options.repo;
    if (!repo) {
      throw new Error("Missing required argument: --repo <owner/repo> for live receipt verification.");
    }
    const commitSha = options.commitSha;
    if (!commitSha) {
      throw new Error("Missing required argument: --commit <sha> for live receipt verification.");
    }
    const runId = options.runId;
    if (!runId) {
      throw new Error("Missing required argument: --run-id <id> for live receipt verification.");
    }

    const productionKeyPath = options.productionKey ? resolve(options.productionKey) : null;
    if (!productionKeyPath || !existsSync(productionKeyPath)) {
      throw new Error("Missing required argument: --production-key <path> (file not found) for live receipt verification.");
    }

    const releaseLockPath = options.releaseLock ? resolve(options.releaseLock) : null;
    if (!releaseLockPath || !existsSync(releaseLockPath)) {
      throw new Error("Missing required argument: --release-lock <path> (file not found) for live receipt verification.");
    }

    const bindingPath = options.projectionBinding ? resolve(options.projectionBinding) : null;
    if (!bindingPath || !existsSync(bindingPath)) {
      throw new Error("Missing required argument: --projection-binding <path> (file not found) for live receipt verification.");
    }

    if (receipt.repository !== repo) {
      throw new Error(`[VERIFY FAILED] Receipt repository '${receipt.repository}' does not match expected '${repo}'`);
    }
    if (receipt.commitSha !== commitSha) {
      throw new Error(`[VERIFY FAILED] Receipt commitSha '${receipt.commitSha}' does not match expected '${commitSha}'`);
    }
    if (String(receipt.runId) !== String(runId)) {
      throw new Error(`[VERIFY FAILED] Receipt runId '${receipt.runId}' does not match expected '${runId}'`);
    }

    console.log(`[RECEIPT-VERIFY] Re-querying live GitHub API for run ${runId} at commit ${commitSha}...`);
    const liveRun = await fetchLiveRunData(repo, commitSha, runId, options);

    if (receipt.workflowPath !== ".github/workflows/validate.yml") {
      throw new Error(`[VERIFY FAILED] Receipt workflowPath is '${receipt.workflowPath}' (expected '.github/workflows/validate.yml')`);
    }
    if (receipt.workflowFileBlobSha !== liveRun.workflowFileBlobSha) {
      throw new Error(
        `[VERIFY FAILED] Receipt workflowFileBlobSha '${receipt.workflowFileBlobSha}' does not match live '${liveRun.workflowFileBlobSha}'`
      );
    }
    if (receipt.workflowFileSha256 !== liveRun.workflowFileSha256) {
      throw new Error(
        `[VERIFY FAILED] Receipt workflowFileSha256 '${receipt.workflowFileSha256}' does not match live '${liveRun.workflowFileSha256}'`
      );
    }
    if (receipt.runHeadSha !== liveRun.headSha) {
      throw new Error(
        `[VERIFY FAILED] Receipt runHeadSha '${receipt.runHeadSha}' does not match live '${liveRun.headSha}'`
      );
    }

    // Verify local production public key
    const verifyKeyFn = await loadVerifyPublicKeyBootstrap();
    if (!verifyKeyFn) {
      throw new Error("Unable to load verifyPublicKeyBootstrap function.");
    }
    const keyInfo = await verifyKeyFn(productionKeyPath);
    if (receipt.productionPublicKeyPrimaryFingerprint !== keyInfo.primaryFingerprint) {
      throw new Error(
        `[VERIFY FAILED] Receipt primary fingerprint '${receipt.productionPublicKeyPrimaryFingerprint}' does not match verified key '${keyInfo.primaryFingerprint}'`
      );
    }
    if (
      receipt.productionSigningSubkeyFingerprint &&
      receipt.productionSigningSubkeyFingerprint !== keyInfo.signingSubkeyFingerprint
    ) {
      throw new Error(
        `[VERIFY FAILED] Receipt signing subkey fingerprint '${receipt.productionSigningSubkeyFingerprint}' does not match verified key '${keyInfo.signingSubkeyFingerprint}'`
      );
    }

    // Verify local release lock
    const currentLockSha = sha256Hex(readFileSync(releaseLockPath));
    if (receipt.releaseLockSha256 !== currentLockSha) {
      throw new Error(
        `[VERIFY FAILED] Receipt releaseLockSha256 '${receipt.releaseLockSha256}' does not match local '${currentLockSha}'`
      );
    }

    // Verify projection binding
    const bindingInfo = JSON.parse(readFileSync(bindingPath, "utf8"));
    if (bindingInfo.releaseLockSha256 !== currentLockSha) {
      throw new Error(
        `[VERIFY FAILED] Projection binding releaseLockSha256 '${bindingInfo.releaseLockSha256}' does not match local '${currentLockSha}'`
      );
    }

    // Verify freshly computed projection root
    let projectionDir = options.projectionDir ? resolve(options.projectionDir) : null;
    if (!isTestMode) {
      if (!projectionDir || !existsSync(projectionDir)) {
        throw new Error("Missing required argument: --projection-dir <path> (directory not found).");
      }
    } else if (!projectionDir) {
      const candidateSub = join(dirname(releaseLockPath), "theme-forge-packages");
      projectionDir = existsSync(candidateSub) ? candidateSub : dirname(releaseLockPath);
    }
    const freshlyComputedRoot = computeProjectionRoot(projectionDir);
    if (receipt.projectionRootSha256 !== freshlyComputedRoot) {
      throw new Error(
        `[VERIFY FAILED] Receipt projectionRootSha256 '${receipt.projectionRootSha256}' does not match freshly recomputed '${freshlyComputedRoot}'`
      );
    }
    if (bindingInfo.treeManifestSha256 !== freshlyComputedRoot) {
      throw new Error(
        `[VERIFY FAILED] Projection binding treeManifestSha256 '${bindingInfo.treeManifestSha256}' does not match freshly recomputed '${freshlyComputedRoot}'`
      );
    }

    // Verify required jobs match live jobs
    for (const def of REQUIRED_JOB_DEFINITIONS) {
      const liveJob = (liveRun.jobs || []).find((j) => j.displayName === def.displayName || j.name === def.displayName);
      if (!liveJob) {
        throw new Error(`[VERIFY FAILED] Live run missing required job '${def.displayName}'`);
      }
      if (liveJob.status !== "completed") {
        throw new Error(`[VERIFY FAILED] Live job '${def.displayName}' status is '${liveJob.status}' (expected 'completed')`);
      }
      if (liveJob.conclusion !== "success") {
        throw new Error(`[VERIFY FAILED] Live job '${def.displayName}' conclusion is '${liveJob.conclusion}' (expected 'success')`);
      }
      const receiptJob = (receipt.requiredJobs || []).find((j) => j.displayName === def.displayName && j.jobKey === def.jobKey);
      if (!receiptJob) {
        throw new Error(`[VERIFY FAILED] Receipt missing required job '${def.displayName}'`);
      }
      if (Number(receiptJob.numericId) !== Number(liveJob.id)) {
        throw new Error(
          `[VERIFY FAILED] Receipt numericId ${receiptJob.numericId} for job '${def.displayName}' does not match live ${liveJob.id}`
        );
      }
    }

    console.log(`[PASS] Hosted validation gate receipt LIVE RE-QUERY VERIFIED: ${resolvedPath} (runId: ${receipt.runId})`);
  } else {
    // Offline sanity verification
    if (options.commitSha && receipt.commitSha !== options.commitSha) {
      throw new Error(`[VERIFY FAILED] Receipt commitSha ${receipt.commitSha} does not match expected ${options.commitSha}`);
    }
    if (options.runId && String(receipt.runId) !== String(options.runId)) {
      throw new Error(`[VERIFY FAILED] Receipt runId ${receipt.runId} does not match expected ${options.runId}`);
    }
    console.log(`[OFFLINE TEST ONLY - NOT PUBLISHABLE] Hosted validation gate receipt offline sanity verified: ${resolvedPath}`);
    console.log(`[NOTICE] Offline test mode confers NO publication authority.`);
  }

  return receipt;
}

export async function fetchLiveRunData(repo, commitSha, runId, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const token = options.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "theme-forge-hosted-gate-verifier",
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  // 1. Fetch exact run
  const runUrl = `https://api.github.com/repos/${repo}/actions/runs/${runId}`;
  const runRes = await fetchFn(runUrl, { headers });
  if (!runRes.ok) {
    throw new Error(`GitHub API returned HTTP ${runRes.status} for run ${runId}: ${await runRes.text()}`);
  }
  const selectedRun = await runRes.json();

  if (selectedRun.head_sha !== commitSha) {
    throw new Error(
      `[GATE FAILED] Run ${runId} head_sha '${selectedRun.head_sha}' does not match expected commit '${commitSha}'!`
    );
  }
  if (selectedRun.path !== ".github/workflows/validate.yml") {
    throw new Error(
      `[GATE FAILED] Run ${runId} workflow is '${selectedRun.path}' (expected exact '.github/workflows/validate.yml')!`
    );
  }
  if (selectedRun.status !== "completed") {
    throw new Error(
      `[GATE FAILED] Run ${runId} status is '${selectedRun.status}' (expected 'completed')!`
    );
  }
  if (selectedRun.conclusion !== "success") {
    throw new Error(
      `[GATE FAILED] Run ${runId} conclusion is '${selectedRun.conclusion}' (expected 'success')!`
    );
  }

  // 2. Fetch jobs for run
  const jobsUrl = `https://api.github.com/repos/${repo}/actions/runs/${selectedRun.id}/jobs?per_page=100`;
  const jobsRes = await fetchFn(jobsUrl, { headers });
  if (!jobsRes.ok) {
    throw new Error(`GitHub API returned HTTP ${jobsRes.status} for jobs of run ${runId}: ${await jobsRes.text()}`);
  }
  const jobsBody = await jobsRes.json();
  const rawJobs = jobsBody.jobs || [];

  const jobs = rawJobs.map((j) => ({
    id: j.id,
    numericId: j.id,
    name: j.name,
    displayName: j.name,
    conclusion: j.conclusion,
    status: j.status,
  }));

  // 3. Mandatory contents API query to bind workflow file at exact commit (Major 1)
  const contentUrl = `https://api.github.com/repos/${repo}/contents/.github/workflows/validate.yml?ref=${commitSha}`;
  const contentRes = await fetchFn(contentUrl, { headers });
  if (!contentRes.ok) {
    throw new Error(
      `[GATE FAILED] Contents API returned HTTP ${contentRes.status} fetching .github/workflows/validate.yml at commit ${commitSha}: ${await contentRes.text()}`
    );
  }
  const contentJson = await contentRes.json();
  if (!contentJson || !contentJson.content) {
    throw new Error(
      `[GATE FAILED] Empty workflow content returned from Contents API for .github/workflows/validate.yml at commit ${commitSha}`
    );
  }

  const decoded = Buffer.from(contentJson.content, "base64");
  const workflowFileSha256 = sha256Hex(decoded);
  const computedBlobSha = gitBlobSha(decoded);
  if (!contentJson.sha || !/^[0-9a-f]{40}$/i.test(contentJson.sha)) {
    throw new Error(`[GATE FAILED] Contents API response missing valid 40-hex Git blob sha: '${contentJson.sha}'`);
  }
  if (contentJson.sha.toLowerCase() !== computedBlobSha.toLowerCase()) {
    throw new Error(
      `[GATE FAILED] Contents API sha '${contentJson.sha}' does not match computed Git blob sha '${computedBlobSha}' for fetched .github/workflows/validate.yml!`
    );
  }
  const workflowFileBlobSha = computedBlobSha;

  // Verify all required logical job keys are defined in the workflow YAML
  const jobKeys = extractYamlJobKeys(decoded.toString("utf8"));
  for (const def of REQUIRED_JOB_DEFINITIONS) {
    if (!jobKeys.includes(def.jobKey)) {
      throw new Error(
        `[GATE FAILED] Logical job key '${def.jobKey}' missing from validate.yml at commit ${commitSha}! Found keys: [${jobKeys.join(", ")}]`
      );
    }
  }

  return {
    runId: selectedRun.id,
    runUrl: selectedRun.html_url || `https://github.com/${repo}/actions/runs/${selectedRun.id}`,
    headSha: selectedRun.head_sha || commitSha,
    headBranch: selectedRun.head_branch || null,
    event: selectedRun.event || null,
    workflowFileBlobSha,
    workflowFileSha256,
    jobs,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opts = {};

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--commit" && args[i + 1]) {
      opts.commitSha = args[++i];
    } else if (args[i] === "--run-id" && args[i + 1]) {
      opts.runId = args[++i];
    } else if (args[i] === "--repo" && args[i + 1]) {
      opts.repo = args[++i];
    } else if (args[i] === "--token" && args[i + 1]) {
      opts.token = args[++i];
    } else if (args[i] === "--release-lock" && args[i + 1]) {
      opts.releaseLock = args[++i];
    } else if (args[i] === "--production-key" && args[i + 1]) {
      opts.productionKey = args[++i];
    } else if (args[i] === "--projection-root" && args[i + 1]) {
      opts.projectionRootSha = args[++i];
    } else if (args[i] === "--projection-binding" && args[i + 1]) {
      opts.projectionBinding = args[++i];
    } else if (args[i] === "--projection-dir" && args[i + 1]) {
      opts.projectionDir = args[++i];
    } else if (args[i] === "--out" && args[i + 1]) {
      opts.out = args[++i];
    } else if (args[i] === "--offline-receipt" && args[i + 1]) {
      opts.offlineReceipt = args[++i];
    } else if (args[i] === "--verify-receipt" && args[i + 1]) {
      opts.verifyReceipt = args[++i];
    } else if (args[i] === "--test-only") {
      opts.testOnly = true;
    }
  }

  verifyHostedValidationGate(opts)
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(`\n[FATAL] ${err.message}`);
      process.exit(1);
    });
}
