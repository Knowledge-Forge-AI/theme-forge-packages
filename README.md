# Theme Forge current-four distribution preparation

This projection binds the current upstream releases. Current signed repository publication and native installation acceptance are held. See [CURRENT-GENERATION-STATUS.json](CURRENT-GENERATION-STATUS.json). It is a review candidate. Current validate.yml retains the own-native-three jobs with manual dispatch only during the predicate preparation stage; current publish.yml is a dispatch-only explicit refusal while production publication remains held.

| Product | Upstream version | Commands |
| --- | --- | --- |
| theme-forge-stellar-burst | 0.7.0 | tfsb, tfsb-studio-service |
| theme-forge-stellar-loom | 0.5.0 | tfsl, tfsl-batch |
| theme-forge-solar-sail | 0.3.0 | tfss |
| theme-forge-nebular-fusion | 0.7.1 | tfnf |

## Channel targets and installation status

All four products, including Nebular Fusion GUI, are in scope for Homebrew, Nix, APT, DNF and pacman. AUR remains deferred.

| Channel | Target | Current installation status |
| --- | --- | --- |
| Homebrew | Knowledge-Forge-AI/tap; support determined by its own receipts | Separate current Homebrew work; no acceptance claimed here |
| Nix | x86_64-linux, aarch64-linux, aarch64-darwin | Current input mapping prepared; evaluation, builds and native acceptance not run |
| APT | Ubuntu 26.04 resolute; amd64, arm64 | Held pending RS9 unsigned-package bridge, key-preserving signing and repository URL evidence |
| DNF | x86_64, aarch64 | Held pending RS9 unsigned-package bridge and protected signer/Pages publication |
| pacman | x86_64 | Held pending RS9 unsigned-package bridge and protected signer/Pages publication |
| AUR | Deferred | Historical readiness recipes only; no current activation claim |

Nebular Linux consumes the approximately 54 MB thin raw archives and system WebKitGTK 4.1. The 219-225 MB portable archives are excluded from this generation. The macOS source is the native app archive.

## Installation after acceptance

Do not use historical repository commands as proof that these current versions are published. Before adding current native install commands, bind the qualified unsigned RS9 output, production key continuity, signed repository metadata, exact publication receipt and a native consumer installation receipt. The APT repository URL and Signed-By identity remain unset until that bridge exists.

After the reviewed Nix mapping is promoted and native-three acceptance passes, the package attributes are `theme-forge-stellar-burst`, `theme-forge-stellar-loom`, `theme-forge-solar-sail` and `theme-forge-nebular-fusion` in `github:Knowledge-Forge-AI/theme-forge-packages`. No Nix installation has been qualified by this preparation.

## Preserved authorities

The existing theme-forge-packages production repository owns the signer, key continuity and Pages deployer. RS9 supplies qualified unsigned native packages; this preparation creates no APT backend. In this current overlay, validate.yml retains P own-native-three candidate qualification jobs with manual dispatch only during the process-predicate preparation stage, using the restoring Linux user-namespace/AppArmor guard under the bounded test-class and source-preparation approval recorded on 2026-10-30. Hosted execution remains a parent-controlled manual public-CI action using that exact guarded route; the class approval does not itself start a run or establish native acceptance. Current publish.yml is a permissions-empty, dispatch-only explicit refusal awaiting qualified RS9 inputs, P native-three and signing preflight. This is interim current-generation safety routing, not a final production pipeline. Historical default workflow templates and output remain byte-identical; their old validation/signing jobs are not emitted in this current overlay. Legacy RPM/pacman/AUR templates remain historical reference material and are not current build authority. Older releases and receipts remain historical.

Burst 0.7.0 requires smol-toml 1.9.1. The exact 31,492-byte registry archive is authenticated against the tagged lockfile SHA512; its SHA-256 is recorded in release-lock.json and the Nix mapping. Build and runtime acceptance remain held. No old npmDepsHash is reused as current qualification.

The manual `probe-current-process-predicate.yml` proposal tests the Linux monitor/application predicate on x86_64-linux and aarch64-linux using the locked NixPython test-tool class. The bounded locked Python/procfs/pidfd/STOP/CONT/watchdog test class and source preparation were approved on 2026-10-30. Hosted invocation remains separately parent-controlled through the exact reviewed guard and must retain its own native evidence. That recorded approval need not be repeated; it does not approve a later full GUI-controller adaptation or grant signing/publication acceptance. See [process-predicate-policy.md](docs/process-predicate-policy.md).
