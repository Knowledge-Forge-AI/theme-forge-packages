# Current native Nix candidate qualification

The manual validation workflow qualifies the four current Theme Forge packages, including Nebular's GUI, on native Apple Silicon, Linux ARM64 and Linux AMD64 GitHub-hosted runners. It is candidate qualification; production signing and repository deployment remain separate gates.

## Declared routes

The source-owned version 2 plan declares one GUI profile per native system:

| System | Profile | Scenarios |
| --- | --- | --- |
| aarch64-darwin | p-single-spawn-target-v1 | A |
| aarch64-linux | p-linux-gui-controller-v1 | B |
| x86_64-linux | p-linux-gui-controller-v1 | C, C-signal |

Darwin retains the existing public-wrapper spawn adaptation. Linux requires the explicit controller route; a plain legacy fallback is refused. The actual selected adapter must match the declared profile. Qualification receipts use the version 2 schema and include guiProfile.

The workflow builds actual Nix recipes, checks installed public commands, verifies Burst's native artifact target/backend/ABI, records derivations and recursive runtime closure, and exercises the immutable current Nebular smoke source against the installed raw payload. Linux additionally binds the wrapper monitor separately from the application and preserves an exact C-signal application witness. See [the controller contract](docs/p-native-gui-controller.md).

## Source and execution boundaries

The tagged Nebular source remains unchanged. Derived harnesses and controller files are staged outside its checkout. The Linux observer authenticates the wrapper's declared bytes and fresh argument vector before the public wrapper launches. It does not suppress sandbox checks, add product dependencies, replace the payload, or treat fixture JSON as a live resolver capability.

The manual workflow runs only on main with read-only repository access. New GUI process-control and workflow policy requires explicit owner approval before source adoption and the selected public native run. The earlier independent two-host process predicate established only the underlying observation/control primitive; it does not qualify this full GUI route.

A successful candidate needs all three native jobs and every required check. A failed or skipped job cannot be a publication result. Fixture and parser checks are nonadmitting. Version 2 publication checking must explicitly select the manual-main profile, validate the exact source and original artifact bytes, and join controller, raw application receipt and signal evidence. It must preserve legacy checking as a separate profile.

## Limits and production handoff

Application arguments, receipt judgments, fixture effects, persistent-state checks, native dependency checks and required failure outcomes remain enforced. C-signal distinguishes the application's SIGTERM witness from the monitor's code 143. Failure cleanup uses held process identities; an unprovable cleanup remains failed and relies on disposable runner teardown.

The generator binds the complete candidate source projection. Public native evidence must name the exact approved commit/tree and workflow. Production import, authentic key continuity, package signatures, consumer checks and protected deployment must pass independently before the repositories are published.
