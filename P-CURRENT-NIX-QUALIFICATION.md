# P current Nix native-three candidate qualification

Status: runnable private source proposal, with no native run or remote workflow activation performed. Actual qualification evidence is pending. Production/publication remain held. P recipes, pinned nixpkgs, derivations and materialization require their own native proof; RS9 receipts and matching upstream hashes cannot qualify them.

## Native route

Current overlay validate.yml admits the actual Knowledge-Forge-AI/theme-forge-packages repository on manual dispatch only during the minimal process-predicate preparation stage, and retains the full P own-native-three jobs/checks unchanged. Current publish.yml is a permissions-empty, dispatch-only explicit failing notice pending qualified RS9 inputs, P native-three and signing preflight. The historical DEFAULT templates/output remain byte-identical; their old jobs are not inherited into this current overlay. This is interim current-generation safety routing, not a final production pipeline. There is no impossible repository sentinel, dead acceptance flag or runtime approval gate in this private proposal. Remote activation remains outside preparation and follows independent review of the concrete source and runner policy.

The matrix is x86_64-linux on ubuntu-24.04, aarch64-linux on ubuntu-24.04-arm and aarch64-darwin on macos-15, reusing existing action and Nix-installer pins. Linux requires the existing xvfb-run and dbus-run-session tool classes; missing tools fail as prerequisites rather than trigger installation or fallback. No new dependency, signing capability, deployment step or APT builder is introduced.

The P AppArmor user-namespace guard differs from maintained RS9 source only in its exact P repository-admission literal. Read, bounded admission, signal/EXIT restoration and restore verification are otherwise byte-identical. GitHub identity is never spoofed. Its runner-policy adaptation is disclosed for review before any remote activation; the historical un-restored sysctl write is not used.

Each native system builds all four P products and the raw Nebular payload, runs P flake checks, and records exact derivations/outPaths/recursive closures. It probes all six real public commands against current released implementation/command contracts. Burst installed loader and addon bytes bind current release artifacts; the exact Nix Node interpreter selected from its actual wrapper must select and load/backend/ABI the expected native target. Host-Node fallback is forbidden.

## Test-only launcher adaptation

The actual current Nebular source is pinned to commit cadb40c4972f68f314096ff60fbcfb4da950c161 and tree 27c643b6375c2aafde314799c4f08e844c14992c. The original native smoke and verifier source blobs remain checked inputs.

p-nix-launcher-adapter.mjs verifies the pinned original harness hash and derives a separately named sibling module without overwriting upstream source. It changes exactly one process-spawn target: spawn(launchTarget, ...) becomes spawn(<actual canonical P Nix public wrapper>, ...). Original relative imports remain in the same tools directory. No other source line changes.

All original raw payload, raw launcher, runtime, source, protocol, scenario, fixture/user-state, sandbox and cleanup checks remain byte-identical. The installed raw payload root remains the harness launch-root for those checks. It is never replaced by a wrapper view, symlink overlay or renamed raw launcher. The actual public wrapper is used only at the process-spawn boundary.

The driver executes A on Apple Silicon, B on Linux ARM64, and both C and C-signal on Linux x64 through that adapter. Adapted bytes are expressly P-owned test code, not unchanged upstream source. The raw-archive source flag describes the verified payload input; the separate adapter receipt identifies actual public-wrapper execution and derived harness provenance.

## Evidence binding and acceptance

The adapter binding separately records original source hash, exact one-line diff and hash, adapted source hash, upstream commit/tree, actual P derivations and closure hashes, materialized outPaths, canonical public wrapper path/hash/type/link target/resolved path, and installed raw payload root. The original and adapted source plus wrapper bytes are rechecked after every scenario. Original scenario stdout/stderr/application receipts/run reports remain under public-wrapper-gui evidence.

Candidate qualification can succeed only after every P build/wrapper/closure/native-addon and adapted GUI scenario succeeds. Its receipt grants no signing or publication authority and does not clear release-lock publicationStatus. Default production fetch/verify continue refusing held snapshots; explicit candidate-validation retains identity/hash/path checks and emits authority flags false. The authentic public production key is byte-preserved; no private key or signing secret is read.

## PID and environment conditions

The original harness receipt PID equality, direct child.pid C-signal target, orphan checks and cleanup remain unchanged. If a particular buildFHSEnv wrapper forks or namespaces PIDs so that those assertions no longer describe the actual app, the run must fail and retain evidence. This proposal does not infer a mapping, relax the assertion or signal an entire process group instead of the application in C-signal. That is a concrete runtime condition to observe in native qualification, not an approval gate or claimed pass.

Linux GUI execution must remain inside the actual public FHS wrapper with Xvfb/D-Bus available. No WebKit sandbox suppression is set. Missing runtime/closure/display capabilities fail normally with retained operation/scenario diagnostics. Any later PID-aware interface or product wrapper change needs its own proved contract; it cannot be silently folded into this one-line test adaptation.

## Static verification limits

Pure checks verify the exact single-line adaptation and execute its actual spawn statement with a harmless wrapper fixture for A/B/C/C-signal argv. They verify that an exec-preserving fixture retains child PID and that original source/raw identity bytes remain unchanged. This is spawn wiring evidence only. No GUI, Nix build, package code, native addon, signing or hosted run was executed during preparation. No native outPath, derivation, closure or GUI acceptance result is fabricated.

The maintained pure test is `tools/distribution/test-current-nix-launcher-adapter.mjs`; it takes the exact pinned upstream smoke source and an explicit owned test-output directory. It adds no package runner configuration or dependency.

Harness import integrity is authenticated by the exact current Git commit/tree and clean tracked-worktree readback before and after execution. The individually pinned smoke/verifier files are additional checks, not a claim to enumerate the harness import closure. Only P-adapted public-wrapper scenarios run; no unmodified raw-harness scenario is claimed. Studio probing requires a validated initialize/initialized/shutdown/exit exchange. Tool doubles produce fixture-only, non-admitting results. Final native receipts bind each actual scenario run/application receipt file plus hosted source/run/workflow/attempt and observed Nix-version facts.

Nix build/check use --no-update-lock-file: an inherited input/lock mismatch refuses instead of resolving a different input in memory. The actual flake.lock SHA-256 is recorded and rechecked; no lockfile or pin is changed. Fresh result-* out-links live in a sibling RUNNER_TEMP work directory outside uploaded evidence; store paths, derivations, closures and wrapper identities remain in receipts. Product CLI probes use clean Node environments, retaining explicit environment fields while removing NODE_OPTIONS and NODE_PATH.

## Predicate preparation stage

The retained strict single-spawn full GUI route is not claimed natively qualifiable on Linux: the bubblewrap monitor differs from the application process. The manual two-Linux-host `probe-current-process-predicate.yml` proposal prepares the bounded observer predicate first, with Node owning the monitor and sibling Python controlling held pidfds. Both native host results must pass before a separately reviewed full GUI-controller implementation. No upstream harness or product recipe changes occur here. The locked NixPython test dependency and proc/pidfd/STOP/CONT/watchdog policy are PENDING exact owner approval before hosted execution. See [process-predicate-policy.md](docs/process-predicate-policy.md).
