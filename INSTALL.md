# Current-four installation

Signed APT, DNF and pacman repositories are published at https://tf.rs9.knowledge-forge.ai/ for both Linux architectures, including pacman AArch64. Nebular Fusion is 0.8.0; the CLI versions in the table are unchanged. See the [publication receipt](https://github.com/Knowledge-Forge-AI/theme-forge-packages/releases/tag/packages-current-202611-nebular080) and [CURRENT-GENERATION-STATUS.json](CURRENT-GENERATION-STATUS.json).

| Product | Upstream version | Commands |
| --- | --- | --- |
| theme-forge-stellar-burst | 0.7.0 | tfsb, tfsb-studio-service |
| theme-forge-stellar-loom | 0.5.0 | tfsl, tfsl-batch |
| theme-forge-solar-sail | 0.3.0 | tfss |
| theme-forge-nebular-fusion | 0.8.0 | tfnf |

## Channel targets and installation status

All four products, including Nebular Fusion GUI, are in scope for Homebrew, Nix, APT, DNF and pacman. AUR remains deferred.

| Channel | Target | Current installation status |
| --- | --- | --- |
| Homebrew | Knowledge-Forge-AI/tap; support determined by its own receipts | Separate current Homebrew work; no acceptance claimed here |
| Nix | x86_64-linux, aarch64-linux, aarch64-darwin (macOS 13.3+) | Published at nix-current-202611, source35266dbd, including Nebular 0.8.0; three-host campaign42507224940 and exact260-file/mode tag readback passed. Later signer projections require their own source-bound gates. |
| APT | Ubuntu 26.04 resolute; amd64, arm64 | Published; amd64 and arm64 native clients passed signature/trust, install and cleanup checks |
| DNF | x86_64, aarch64 | Published; both architecture-specific native clients passed signature/trust, install and cleanup checks |
| pacman | x86_64, aarch64 | Published; both architecture-specific native clients passed signature/trust, install and cleanup checks |
| AUR | Deferred | Historical readiness recipes only; no current activation claim |

Nebular Linux consumes approximately 57 MB thin raw archives and system WebKitGTK 4.1. The 219-225 MB portable archives are excluded from this generation. The macOS source is the native app archive.

## Signed repository installation

Use the [installation guide](https://tfnf.knowledge-forge.ai/#install) to configure the signed repository for your package manager, then select package names from the product table. The repository base is `https://tf.rs9.knowledge-forge.ai/`; the existing public certificate is [`keys/knowledge-forge-ai-packages.asc`](https://tf.rs9.knowledge-forge.ai/keys/knowledge-forge-ai-packages.asc). Its primary fingerprint remains `7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF`, and the CI signing subkey remains `C021E00EE3D37C459B0E1CB3199F8028126E8A8C`.

The accepted package source is `97f6895f465dbd86000025805135e50f653f28a5`. Original signing/client run [42855446431](https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/42855446431) passed all seven jobs; GUI run [42855418851](https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/42855418851) passed all three native hosts. Protected production run [42859410403](https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/42859410403) deployed the retained qualified bytes without rebuilding or resigning. All 75 served files match the qualified inventory.

The published qualified Nix reference is `github:Knowledge-Forge-AI/theme-forge-packages/nix-current-202611`, source `35266dbd6449432a540f3a1cc630d501c0d67911`, including Nebular `0.8.0`. Its three-host campaign is [42507224940](https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/42507224940); the published tag received exact 260-file body and executable-mode readback. Package attributes are `theme-forge-stellar-burst`, `theme-forge-stellar-loom`, `theme-forge-solar-sail` and `theme-forge-nebular-fusion`. This qualifies that exact Nix source/ref. The signed OS repositories have their separate qualified source and receipts above; neither result qualifies arbitrary later source changes.

## Preserved authorities

The existing theme-forge-packages production repository owns the signer, key continuity and Pages deployer. RS9 supplies qualified unsigned native packages; this preparation creates no APT backend. In this current overlay, validate.yml retains P own-native-three candidate qualification jobs with manual dispatch only during the process-predicate preparation stage, using the restoring Linux user-namespace/AppArmor guard under the bounded test-class and source-preparation approval recorded on 2026-10-30. Hosted execution remains a parent-controlled manual public-CI action using that exact guarded route; the class approval does not itself start a run or establish native acceptance. Current publish.yml has permissions-empty workflow defaults, a contents/actions-read admission job and a protected Pages deployment job. It admits original signing/client and GUI qualification runs at the same P commit before staging retained repository bytes. The github-pages review remains required; this source description grants no deployment or native-acceptance authority. Historical default workflow templates and output remain byte-identical; their old validation/signing jobs are not emitted in this current overlay. Legacy RPM/pacman/AUR templates remain historical reference material and are not current build authority. Older releases and receipts remain historical.

Burst 0.7.0 requires smol-toml 1.9.1. The exact 31,492-byte registry archive is authenticated against the tagged lockfile SHA512; its SHA-256 is recorded in release-lock.json and the Nix mapping. Nix command and addon acceptance is recorded for exact source35266dbd at nix-current-202611. The signed OS projection has the separate exact-source acceptance above. Later source changes still require their own qualification.

The manual `probe-current-process-predicate.yml` proposal tests the Linux monitor/application predicate on x86_64-linux and aarch64-linux using the locked NixPython test-tool class. The bounded locked Python/procfs/pidfd/STOP/CONT/watchdog test class and source preparation were approved on 2026-10-30. Hosted invocation remains separately parent-controlled through the exact reviewed guard and must retain its own native evidence. That recorded approval need not be repeated; it does not approve a later full GUI-controller adaptation or grant signing/publication acceptance. See [process-predicate-policy.md](docs/process-predicate-policy.md).

The release-lock and generated-binding `publicationStatus` retain their existing candidate-validation guard. Observed publication is recorded separately in `CURRENT-GENERATION-STATUS.json` and the exact-source receipt above; these records grant no execution authority.

RPM qualification retains the [release-scoped preservation exceptions](https://github.com/Knowledge-Forge-AI/release-starport-9/blob/bcd741657372c9bb01cfe214d6f2a30f9ecad7a5/operators/theme-forge-current-202610/rpm-lint-policy-nebular080.json). Raw lint findings remain visible; publication does not claim raw RPM-lint cleanliness or official Fedora qualification. The release-lock retains its preparation-era description and candidate-admission controls; publication availability is recorded by the exact-source receipt above.
