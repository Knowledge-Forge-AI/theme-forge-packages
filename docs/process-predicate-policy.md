# Linux process predicate preparation

Status: SOURCE PREPARATION ONLY. The bounded two-host Nix test class and
process-predicate probe preparation were approved on 2026-10-30. That approval
covers this pinned test-only class and its source/static preparation; it does
not record a native process observation, Nix evaluation/build, GUI acceptance,
product qualification or publication. Any hosted invocation remains a
parent-controlled public-CI action using the exact guarded route. Current
`validate.yml` retains its complete native-three jobs but is manual-only during
this stage. Current `publish.yml` remains the permissions-empty manual refusal.
Historical default generation is unchanged.

The separate manual `probe-current-process-predicate.yml` targets the public
Ubuntu 24.04 x64 and ARM64 hosts. It uses contents-read permission, credential-
free checkout, the existing pinned Node/Nix-installer/artifact classes, and the
maintained restoring userns AppArmor guard with explicit P repository admission.
The approved class retains the locked Python/procfs/pidfd/STOP/CONT/watchdog
policy. This document neither activates a hosted run nor supplies native
results; the parent-controlled public-CI route must retain the exact guard and
record its own observations.

## Test tool and dependency review

`testTools.<linux-system>.pidObserverPython` selects `pkgs.python3` from the
unchanged Nixpkgs lock at `b6c8664de9b6cc07fe5666a29f91884ba81197c4`.
This is a NEW TEST DEPENDENCY CLASS, even though the helper uses only Python's
standard library. At this exact Nixpkgs pin, python3 aliases python314: full,
GIL-enabled CPython 3.14.7, with declared source SRI
sha256-O0jayPtZ9i6qZ6yDwesSvaG3oIQG3ShuJSwRpmvif4E=. Its package metadata is
lib.licenses.psfl, whose pinned SPDX label is Python-2.0. The source contains
the PSF/history notice bundle and incorporated-software notices; this is not a
claim that the complete Python output or closure has one license. Readline and
GDBM are known GPL-3.0-or-later inputs. The source-bundled pip wheel has
separate vendor notices, including MPL-2.0 data; --without-ensurepip disables
bootstrap and does not establish wheel absence. The probe invokes no
pip/npm/package installation.

Static source admission and the known notice families support the approved
pinned test-only class, including future realization/inventory verification
and use in the reviewed hosted probe. Realized version, derivation, interpreter
identity, complete dependency graphs/closures, installed notices and actual
external/transitive license inventory remain required native evidence. This is
within the approved class, not a second selection or attendance requirement.
It does not blanket-approve unknown license conditions or product
redistribution. Existing source/installer pins remain; no new lock or separate
package dependency is selected. No PATH Python fallback is permitted.

Alternatives: Node has no existing pidfd control primitive; numeric PID signals
fail the identity contract. A new third-party Linux process binding adds a larger
dependency class. A separately compiled observer introduces a compiler/tool
artifact contract. Locked Python supplies the required pidfd APIs and isolation
flags with a small source-only helper within this approved test-only class.
Rollback removes the
independent testTools output, helper, baseline and manual probe workflow; product
recipes, release assets, public key, lock, runtime wrappers and upstream harness
remain unchanged. Native product outputs, full recursive derivation graph and
runtime closure are compared against a retained r5 product-only flake. Shared
existing store libraries are allowed. Preexisting Python build dependencies may
exist; equality must hold, the new Python root must be absent from product runtime
closure, and probe/init roots must be absent from the product dependency graph.

## Authenticated observation and sealed surrogate

The driver authenticates the locked buildFHSEnv source hash and the actual public
wrapper's realized bytes against its declared writeShellScript derivation text.
It refuses opaque producers or any unsupported shell shape. A disclosed derived
copy changes exactly the unique terminal `exec "${cmd[@]}"` to a NUL `printf`.
It runs the original authenticated array construction, using its locked Bash
interpreter and the same cwd/environment, without launching bubblewrap. It is not
a general shell parser. The resulting NUL argv has closed option arities from
the reviewed source; namespace, capability, helper-FD and unknown options refuse.
The expected bubblewrap executable comes independently from locked Nixpkgs, and
is opened/hashed before native launch. The original container-init must belong
to the unchanged product derivation graph and runtime closure. Original profile,
launcher, wrapper, declaration, observation, init and argv hashes are bound
separately. No argv, environment or proc-buffer dump is retained.

The only native argv delta is the unique `/init` symlink source to a separately
sealed test init plus the fixed `term` or `normal143` case argument. The original
`/etc/profile`, namespace/security flags, actual FHS root, mounts and already
provided `/nix` visibility remain. Missing visibility refuses; no additional
mount, privilege, capability, sandbox toggle or AppArmor workaround is added.
The harmless surrogate uses that exact locked interpreter and a waiting worker
thread. The monitor and controller must have the same actual Node parent; the
application must be a direct monitor child. Python never claims child waitability. Its credentials/dumpability do not establish GUI process observability.

## Predicate and failure custody

Node owns the actual original monitor ChildProcess PID and wait status. Its sibling Python controller binds the opened proc directory, start time,
all UID/GID fields, group-leader status, untraced status, host PID namespace,
single-thread monitor, exact argv and independently opened expected exe object.
It discovers exactly one direct application child with the independently sealed
Python exe identity and at least two threads. Receipt PIDs do not select targets.
Every control uses an originally held pidfd after identity/fdinfo validation;
there is no numeric or process-group signal fallback.

Discovery is bounded by 10 seconds. At commit, a nonrenewable 40-second watchdog
lease is armed before STOP. STOP prephase is at most 2 seconds. From application
TERM, death is at most 24 seconds; within the next second the monitor must be
ordinary `T`, two unchanged group-leader `Z` tuples must agree on PID, parent,
start and field-52 status, then the monitor must still be `T`. Exact raw status
15, non-core WIFSIGNALED/SIGTERM, is required. Ordinary exit143 (`143 << 8`),
zero/redacted/missing/reaped status, tracing stop, changed identity or ambiguity
refuse. CONT and normal monitor exit143 have at most four more seconds; the
composed transaction must finish strictly within 30 seconds. No phase borrowing.

The separate-session watchdog inherits a duplicate of the original monitor
pidfd and a lifetime read FD. In the controller-death negative exercise only, it
also inherits the already bound application pidfd for failure-only exact cleanup. It does not inherit the writer and never reopens a
pidfd by PID. Closed nonce/sequence JSON ARM/HEARTBEAT/DISARM messages are bounded.
EOF, malformed input, missed heartbeat or fixed deadline causes fail-only CONT
through the held handle and invalidates acceptance. Disarm requires the bound
identity, witness digest and observed resume/exit; acknowledgement is retained in
the transaction. Once Node has reaped an exited monitor, the originally held
readable pidfd plus fdinfo PID -1 proves death; it never selects a replacement.
Node independently requires its actual monitor wait to be normal exit143. On failure CONT precedes exact-handle cleanup. Failure-only
SIGKILL is confined to owned processes. This does not survive simultaneous loss
of watchdog/controller or VM destruction. No full GUI-controller adaptation is
included; both actual Linux predicate results must pass before that next slice.

## Clarified ownership and controller-death recovery

The unchanged wrapper includes `--die-with-parent`. Reviewed bubblewrap 0.12.0
source lines 366–373 and 3117–3118 sets `PR_SET_PDEATHSIG(SIGKILL)` on the original
monitor. Node, matching the reviewed harness, remains that monitor's launch/wait
owner. Python is a separate sibling child of Node, and its separate-session
watchdog is a controller child. The bindings require
`monitor.ppid == controller.ppid == Node PID` and `app.ppid == monitor PID`.
No persistent service or changed product process graph is introduced.

The controller-death negative exercise arms and STOPs the owned monitor, then
exits73 and closes its sole lifetime writer. While Node remains alive, watchdog
EOF rescue sends CONT through its inherited monitor pidfd, then SIGKILL through
its inherited, already-bound application pidfd for failure cleanup. Node must
observe the controller's actual normal73 exit and monitor's actual normal137
exit after it consumes the SIGCHLD. This establishes resume/cleanup of a failed
transaction; it is not a signal witness or GUI qualification. Watchdog stdout
may lose its reader with controller death; a surviving Node wait observation is
required instead. Node death invokes unchanged PDEATHSIG containment and fails
the run; it is never called successful watchdog resume. The superseded
Python-parent intermediate is preserved privately and is not the active route.

This source-model clarification is the bounded parent disposition after
Design2 review, not a flag removal, privilege change, new parent-access shortcut
or product alteration. Both actual Linux-host results remain unobserved.

Accepted source review permits predicate preparation only. The reviewed source
hash joins are in `tools/predicate/reviewed-source-binding.json`. Pure tests
produce fixture-mode, non-admitting evidence. Future predicate receipts remain
distinct from GUI, client installation, signing and publication receipts.

## Corrected source contracts after implementation review1

The normal143 negative must pass the same stable monitor-T/group-leader-Z/direct-
parent bracket as TERM, then refuse only exact SIGTERM semantics. Immediately
after STOP, monitor thread count and app direct parent, UID/GID, untraced status
and shared PID namespace are rechecked. One CONT deadline, fixed before CONT,
covers both resume and monitor exit. Cleanup independently attempts CONT, lease
failure handling and each exact-handle KILL before reporting any cleanup error.
Proc discovery uses transient closed views for unbound PIDs; fdinfo accepts only
ASCII decimal FD members. Every probe row is non-admitting; the aggregate receipt
has an explicit predicate-scoped pass only after ordered TERM, ordinary143 and
controller-death cases. Context security defaults are labelled declared constants.

Pinned container-init is static C++ ELF, not a shell script. Exact source hash and
its actual declared native compiler command/input are checked. The source spawns
only ldconfig before exec, waits/reaps it, then execv replaces the same process
with /init. This preserves the final app's direct monitor parent; no persistent
helper remains. The original shell init still uses authenticated declared_text.
Verbatim primary fixtures prove the actual cmd prefix, --bind /nix, initial option
order and /etc/profile symlink/ro-bind handling against pinned buildFHSEnv. The
review's shell-only/no-wait prescription for the ELF is corrected by these exact
primary sources; other grounded findings are fixed. Original Muse preparation
disposition remains separate from implementation review1 REVISE and pending
re-review. No native acceptance, GUI acceptance, product qualification, or
publication authority is inferred.
