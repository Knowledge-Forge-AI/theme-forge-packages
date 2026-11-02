# Synthetic current C6 APT native probe policy

Status: prepared, not adopted or authorized for hosted execution.

Purpose: qualify the existing CI signing subkey through the new fixed public C6 APT Release API and concrete APT public verifier, in a non-admitting synthetic slice. The fixed Release describes no release packages. It is never a repository publication or SignedStore/live-lease admission.

The proposed job uses the existing Ubuntu24.04 public host and prepared Fedora43 B3 image/tool class. The container retains network none. No dependency, container capability, permission, timeout, signing identity or environment protection is added. The job retains contents:read, the exact repository/main condition, existing 30-minute timeout and protected github-pages environment with its existing reviewer. Existing key provisioning, guard, locked-Python and prior GPG-purpose approvals remain valid.

The distinct purpose is two fixed signatures (InRelease and Release.gpg) through ProtectedSigningRuntime.execute_apt_release. That public API owns key import, CI secret-subkey validation, passphrase transport, supervised agent, bounded finite consumers, input/output identity and cleanup. After confirmed private-work removal, two fresh public-only AptSignatureAdapter instances verify exact plaintext, detached bytes and expected primary/subkey identity through the public C6 native process owner. No second lifecycle supervisor or caller-controlled command template is introduced.

Secrets travel from the two existing environment entries through the existing length-delimited stdin frame into the disposable container. They are never command arguments, files, artifact fields or container environment variables. Mutable input buffers are cleared; C6 retains uncertain resources and errors rather than claiming cleanup. Public verification also retains uncertain process or staged-file custody. The probe will not delete its root after such uncertainty. The outer job still tears down only its exact phase-owned container and builder image under the existing isolation contract.

Retained evidence is named safe JSON: source authentication, two availability booleans, measured B3 metadata/lifecycle, signature/public-key/input/executable digests, fixed error codes and cleanup booleans. No key bytes, passphrase, raw native diagnostics, signature payload or private resource identifiers are uploaded. Failure messages are not serialized.

Success requires native signing observation, both native signature verifications, exact expected issuer/subkey, held Release equality, no retained custody, private-work removal and complete probe-root cleanup. Availability alone is insufficient. Fixture observations never qualify the native slice. A pass qualifies only this synthetic APT slice; full production signer, RPM/repo-add, authenticated unsigned inputs, live importer, signed repository metadata and publication remain separately held.

The prepared source also refreshes the existing GPG probe's runtime digest to the new C6 body; its workflow, key purpose and command behavior otherwise remain fixed. Prior GPG run41385843035 passed at source00db6cf797a96760c1a8390247631d7bd8a7acc2 and does not qualify the new source.

Proposed attended decision: adopt the exact reviewed source/pin changes and this purpose; run one protected synthetic APT probe plus one existing three-platform GUI campaign for the successor projection. The operator must approve the exact github-pages deployment in GitHub. No production publication is triggered by this decision. All later source corrections or further campaigns need their own evidence and authority.

Availability framing reuses the existing GPG frame emitter and availability schema. Its two booleans describe only whether the environment inputs are present and bounded; its source digest identifies that shared emitter. The separate APT Stage1 authentication artifact binds the APT probe, tests, adapter and runtime. The secret-bearing host emitter authenticates public code without applying the credential-free-container environment check; native execution still enforces that check inside the container.
