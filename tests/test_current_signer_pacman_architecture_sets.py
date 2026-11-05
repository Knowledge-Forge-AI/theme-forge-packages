"""Inert tests for the two-architecture Pacman repository sets.

Exercises real source selection/binding/admission functions, the real
_pacman_repository/_metadata_tool_env path and the real Pacman signing branch
(_sign_pacman_object with the real _write_output). Native repo-add/GPG, the
GnuPG status grammar and the pacman database archive parse are stubbed; database
members produced by those stubs live only in an in-memory filesystem overlay.
On disk only inert package/signature fixtures and owned 0700 scratch/output
directories under an ordinary temporary directory are created: no .db/.files
database, alias, SQLite, tar, key, agent, container or process. Nothing here is
native qualification or integration.
"""
from contextlib import contextmanager
import inspect
import os
import shutil
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SIGNER = HERE.parent / "tools/verification/current_signer"
sys.path.insert(0, str(SIGNER))
import current_protected_signing as signing_mod  # noqa: E402
import protected_signing_runtime as runtime_mod  # noqa: E402
import repository_metadata_assembly as metadata  # noqa: E402
from current_protected_signing import ProtectedSigningError, UnsignedObject  # noqa: E402
# Real R-backed linkage is mandatory: rs9 must resolve through ordinary imports.
import public_repository_linkage as LINKAGE  # noqa: E402

assert Path(LINKAGE.__file__).resolve() == (SIGNER / "public_repository_linkage.py").resolve()

X86, ARM = "x86_64", "aarch64"
BURST, NEBULAR = "theme-forge-stellar-burst", "theme-forge-nebular-fusion"
LOOM, SOLAR = "theme-forge-stellar-loom", "theme-forge-solar-sail"
VERSIONS = {BURST: "0.7.0", NEBULAR: "0.7.1", LOOM: "0.5.0", SOLAR: "0.3.0"}
ORIGIN = "inert-fixture-origin"
PASSPHRASE = b"INERT FIXTURE"  # not a secret; no key or agent is ever created
DB, FILES = metadata.PACMAN_DATABASE, metadata.PACMAN_FILES
_REAL_LIST_DIRECTORY, _REAL_RECORD = metadata._list_directory, metadata._record


def _name(product, arch):
    return f"{product}-{VERSIONS[product]}-1-{arch}.pkg.tar.zst"


def _rows():
    rows = [{"product": p, "architecture": a, "name": _name(p, a), "version": VERSIONS[p]}
            for p in (BURST, NEBULAR) for a in (X86, ARM)]
    rows += [{"product": p, "architecture": "any", "name": _name(p, "any"), "version": VERSIONS[p]}
             for p in (LOOM, SOLAR)]
    for row in rows:
        row["body"] = b"PUBLIC INERT PACKAGE " + row["name"].encode()
        row["sig"] = b"\x89PUBLIC INERT SIGNATURE " + row["name"].encode()
    return rows


def _code(error):
    return getattr(error, "code", None) or (error.args[0] if error.args else None)


def _obj(product, arch, body=b"PUBLIC INERT PACKAGE", *, channel="pacman"):
    """Inert descriptor; its path is never created or read."""
    return UnsignedObject(channel=channel, product=product, version=VERSIONS[product], architecture=arch,
                          origin=ORIGIN, path=Path("/inert-never-created") / channel / _name(product, arch),
                          sha256=signing_mod._sha256(body), size=len(body))


class _InertRunner:
    def __call__(self, *_args, **_kwargs):
        raise AssertionError("no process runner may be reached")


def _runtime():
    return runtime_mod.ProtectedSigningRuntime(runner=_InertRunner())


class RuntimeOutputSelectionTests(unittest.TestCase):
    root = Path("/inert-output-root")

    def test_architecture_sets_share_one_source(self):
        self.assertEqual(runtime_mod.LIVE_PACMAN_ARCHITECTURES, (X86, ARM))
        self.assertEqual(metadata.PACMAN_ARCHITECTURES, runtime_mod.LIVE_PACMAN_ARCHITECTURES)
        self.assertEqual(metadata.PACMAN_ARCHITECTURE, X86)

    def test_live_any_is_copied_to_both_repositories(self):
        self.assertEqual(runtime_mod._pacman_output_directories(self.root, "any", live=True),
                         (self.root / "arch" / X86, self.root / "arch" / ARM))

    def test_live_native_selects_only_its_own_repository(self):
        for arch in (X86, ARM):
            self.assertEqual(runtime_mod._pacman_output_directories(self.root, arch, live=True),
                             (self.root / "arch" / arch,))

    def test_live_foreign_native_refused(self):
        with self.assertRaises(ProtectedSigningError) as got:
            runtime_mod._pacman_output_directories(self.root, "armv7h", live=True)
        self.assertEqual(got.exception.code, "ARCHITECTURE")

    def test_legacy_route_layout_unchanged(self):
        for arch in ("any", X86):
            self.assertEqual(runtime_mod._pacman_output_directories(self.root, arch, live=False),
                             (self.root / "pacman" / X86,))

    def test_legacy_route_refuses_every_other_architecture(self):
        for arch in (ARM, "armv7h", "i686", "noarch", "all", ""):
            with self.subTest(arch=arch), self.assertRaises(ProtectedSigningError) as got:
                runtime_mod._pacman_output_directories(self.root, arch, live=False)
            self.assertEqual(got.exception.code, "ARCHITECTURE")


class PacmanAdmissionOwnershipTests(unittest.TestCase):
    """Global legacy set stays x86_64-only; only sealed live intake admits aarch64."""

    def test_global_pacman_set_is_x86_64_only(self):
        self.assertEqual(signing_mod.CHANNEL_ARCHITECTURES["pacman"], frozenset({X86}))
        self.assertIs(runtime_mod.CHANNEL_ARCHITECTURES, signing_mod.CHANNEL_ARCHITECTURES)

    def test_raw_validator_refuses_aarch64_before_any_read(self):
        reads = []
        with mock.patch.object(signing_mod, "_read_stable", lambda *a, **k: reads.append(a)):
            with self.assertRaises(ProtectedSigningError) as got:
                signing_mod.validate_unsigned_objects([_obj(BURST, ARM)], ORIGIN)
            self.assertEqual(got.exception.code, "ARCHITECTURE")
            self.assertEqual(reads, [])
            # Control: x86_64 passes the architecture gate and reaches the read seam.
            signing_mod.validate_unsigned_objects([_obj(BURST, X86)], ORIGIN)
        self.assertEqual(len(reads), 1)

    def test_raw_execute_entry_refuses_aarch64_before_path_or_output(self):
        output = Path("/inert-never-created-output")
        reads, created = [], []
        with mock.patch.object(signing_mod, "_read_stable", lambda *a, **k: reads.append(a)), \
                mock.patch.object(runtime_mod, "_read_stable", lambda *a, **k: reads.append(a)), \
                mock.patch.object(runtime_mod, "_new_owned_directory", lambda *a, **k: created.append(a)):
            with self.assertRaises(ProtectedSigningError) as got:
                _runtime().execute([_obj(BURST, ARM)], origin=ORIGIN, output_root=output,
                                   public_key_bytes=b"", private_key_bytes=b"", passphrase=b"")
        self.assertEqual(got.exception.code, "ARCHITECTURE")
        self.assertEqual((reads, created), ([], []))
        self.assertFalse(os.path.lexists(output))

    def test_live_intake_admits_native_pacman_architectures(self):
        objects = (_obj(BURST, X86), _obj(BURST, ARM), _obj(NEBULAR, ARM), _obj(LOOM, "any"),
                   _obj(BURST, ARM, channel="rpm"))
        self.assertIs(runtime_mod._live_object_shapes(objects, ORIGIN), objects)

    def test_live_intake_refuses_foreign_or_pure_misuse(self):
        for product, arch in ((BURST, "armv7h"), (BURST, "i686"), (BURST, "any"), (LOOM, "noarch")):
            with self.subTest(product=product, arch=arch), self.assertRaises(ProtectedSigningError) as got:
                runtime_mod._live_object_shapes((_obj(product, arch),), ORIGIN)
            self.assertEqual(got.exception.code, "ARCHITECTURE")


class MetadataSelectionTests(unittest.TestCase):
    def refused(self, code, function, *args, **kwargs):
        with self.assertRaises(ProtectedSigningError) as got:
            function(*args, **kwargs)
        self.assertEqual(got.exception.code, code)

    def test_each_set_is_own_native_plus_shared_any(self):
        sets = metadata._pacman_architecture_sets(_rows())
        self.assertEqual(set(sets), {X86, ARM})
        for arch, other in ((X86, ARM), (ARM, X86)):
            self.assertEqual(sets[arch], tuple(sorted(
                [_name(BURST, arch), _name(NEBULAR, arch), _name(LOOM, "any"), _name(SOLAR, "any")])))
            self.assertFalse(any(name.endswith(f"-{other}.pkg.tar.zst") for name in sets[arch]))

    def test_missing_native_row_refused(self):
        rows = [row for row in _rows() if row["name"] != _name(NEBULAR, ARM)]
        self.refused("REPOSITORY_METADATA", metadata._pacman_architecture_sets, rows)
        rows = [row for row in _rows() if row["architecture"] != ARM]
        self.refused("REPOSITORY_METADATA", metadata._pacman_architecture_sets, rows)

    def test_foreign_native_row_refused(self):
        rows = _rows() + [{"product": BURST, "architecture": "armv7h", "name": _name(BURST, "armv7h")}]
        self.refused("REPOSITORY_METADATA", metadata._pacman_architecture_sets, rows)

    def test_row_filename_must_name_its_architecture(self):
        rows = _rows()
        rows[1] = dict(rows[1], name=_name(BURST, X86).replace("-1-", "-2-"))  # aarch64 row, x86_64 file
        self.refused("REPOSITORY_METADATA", metadata._pacman_architecture_sets, rows)

    def test_any_product_cannot_also_be_native(self):
        rows = _rows() + [{"product": LOOM, "architecture": X86, "name": _name(LOOM, X86)},
                          {"product": LOOM, "architecture": ARM, "name": _name(LOOM, ARM)}]
        self.refused("REPOSITORY_METADATA", metadata._pacman_architecture_sets, rows)

    def test_paired_any_bytes_and_signature(self):
        name = _name(LOOM, "any")
        pacman = {arch: {name: b"PKG", name + ".sig": b"SIG"} for arch in (X86, ARM)}
        metadata._paired_any(pacman, [name])
        for relative in (name, name + ".sig"):
            changed = {X86: dict(pacman[X86]), ARM: dict(pacman[ARM], **{relative: b"OTHER"})}
            self.refused("PACKAGE_MUTATED", metadata._paired_any, changed, [name])

    def test_repository_inputs_bound_to_architecture(self):
        native, shared = _name(BURST, X86), _name(LOOM, "any")
        inputs = {native: b"P", native + ".sig": b"S", shared: b"P", shared + ".sig": b"S"}
        self.assertEqual(metadata._pacman_inputs_for(X86, inputs), sorted([native, shared]))
        self.refused("OUTPUT_INVENTORY", metadata._pacman_inputs_for, ARM, inputs)
        self.refused("OUTPUT_INVENTORY", metadata._pacman_inputs_for, X86, {native: b"P"})
        self.refused("REPOSITORY_METADATA", metadata._pacman_inputs_for, "armv7h", inputs)


class MetadataAssemblyRoutingTests(unittest.TestCase):
    """assemble_live_repository_metadata with in-memory registered outputs."""

    def run_assembly(self, rows, *, mutate=None):
        root = Path("/inert-output-root")
        store = {}
        for row in rows:
            for arch in ((X86, ARM) if row["architecture"] == "any" else (row["architecture"],)):
                base = root / "arch" / arch
                store.setdefault(base, {}).update({row["name"]: row["body"], row["name"] + ".sig": row["sig"]})
        rpm = {"loom-0.5.0-1.noarch.rpm": b"RPM"}
        for arch in (X86, ARM):
            store[root / "rpm" / arch] = {"Packages/" + name: data for name, data in rpm.items()}
        if mutate:
            mutate(store, root)
        runtime = types.SimpleNamespace(_active_live_lease=None, _output_root=types.SimpleNamespace(path=root))
        runtime._active_live_lease = lease = object()
        runtime._output_files = {base / rel: None for base, members in store.items() for rel in members}
        calls = []

        def registered(_runtime, base, relatives):
            if set(store.get(base, {})) != set(relatives):
                metadata._fail("OUTPUT_INVENTORY", "Registered package outputs differ before repository metadata")
            return {relative: store[base][relative] for relative in relatives}

        def pacman_repository(_runtime, inputs, *_args, arch):
            calls.append((arch, dict(inputs)))
            path = root / "arch" / arch / metadata.PACMAN_DATABASE
            runtime._output_files[path] = None
            return {path}

        result_rows = [{"channel": "pacman", "product": r["product"], "architecture": r["architecture"],
                        "name": r["name"], "package_sha256": metadata._sha256(r["body"])} for r in rows]
        result_rows.append({"channel": "rpm", "architecture": "noarch", "name": "loom-0.5.0-1.noarch.rpm"})
        with mock.patch.object(metadata, "_registered", registered), \
                mock.patch.object(metadata, "_rpm_repository", lambda *a, **k: set()), \
                mock.patch.object(metadata, "_pacman_repository", pacman_repository):
            metadata.assemble_live_repository_metadata(
                runtime, lease, tuple(result_rows), home=Path("/h"), work=Path("/w"), staging=Path("/s"),
                output=runtime._output_root, passphrase=b"unused")
        return calls

    def test_two_repositories_with_identical_any(self):
        rows = _rows()
        calls = self.run_assembly(rows)
        self.assertEqual([arch for arch, _ in calls], [X86, ARM])
        for arch, inputs in calls:
            expected = {r["name"] for r in rows if r["architecture"] in (arch, "any")}
            self.assertEqual(set(inputs), {*expected, *(n + ".sig" for n in expected)})
        for row in rows:
            if row["architecture"] == "any":
                self.assertEqual(calls[0][1][row["name"]], calls[1][1][row["name"]])
                self.assertEqual(calls[0][1][row["name"] + ".sig"], calls[1][1][row["name"] + ".sig"])

    def assert_refused(self, code, rows, mutate):
        with self.assertRaises(ProtectedSigningError) as got:
            self.run_assembly(rows, mutate=mutate)
        self.assertEqual(got.exception.code, code)

    def test_paired_any_signature_mismatch_refused(self):
        name = _name(SOLAR, "any") + ".sig"
        self.assert_refused("PACKAGE_MUTATED", _rows(),
                            lambda store, root: store[root / "arch" / ARM].__setitem__(name, b"\x89OTHER"))

    def test_paired_any_byte_mismatch_refused(self):
        name = _name(LOOM, "any")
        self.assert_refused("PACKAGE_MUTATED", _rows(),
                            lambda store, root: store[root / "arch" / ARM].__setitem__(name, b"OTHER"))

    def test_foreign_native_output_in_repository_refused(self):
        stray = _name(BURST, X86)
        self.assert_refused("OUTPUT_INVENTORY", _rows(),
                            lambda store, root: store[root / "arch" / ARM].update({stray: b"P", stray + ".sig": b"S"}))

    def test_missing_native_output_refused(self):
        name = _name(NEBULAR, ARM)
        self.assert_refused("OUTPUT_INVENTORY", _rows(),
                            lambda store, root: store[root / "arch" / ARM].pop(name))


def _db(arch):
    return b"INERT IN-MEMORY DATABASE MEMBER " + arch.encode()


def _files(arch):
    return b"INERT IN-MEMORY FILES MEMBER " + arch.encode()


@unittest.skipIf(os.geteuid() == 0, "owned-scratch custody assertions require a nonroot uid")
class RealPacmanRepositoryTests(unittest.TestCase):
    """Real _pacman_repository, _metadata_tool_env, _snapshot/_same, _sign and _verify.

    Seams: runtime._run (native repo-add/GPG), runtime._write_output (output
    registration recorder, so no published database leaf is written),
    _status_proof (native GnuPG status grammar), _pacman_entries (database
    archive parse) and an in-memory overlay of _list_directory/_record holding
    every repo-add/GPG-produced member. Real disk holds only inert package
    inputs in owned 0700 scratch; no database, alias or signature file exists.
    """

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()  # resolved: no symlinked ancestors
        self.work = self.base / "work"
        self.work.mkdir(mode=0o700)
        self.home = self.work / "gnupg"
        self.home.mkdir(mode=0o700)
        self.staging = self.work / "staging"
        self.staging.mkdir(mode=0o700)
        self.root = self.base / "output-never-created"
        self.rows = _rows()
        self.rt = _runtime()
        self.rt._run = self.run_native
        self.rt._write_output = self.write_output
        self.virtual, self.flags = {}, {}
        self.alias_form = "copy"
        self.entries = {}
        for arch in (X86, ARM):
            self.entries[_db(arch)] = self.entries[_files(arch)] = self.known(arch)
        self.reset()

    def reset(self):
        self.calls, self.writes, self.scratch, self.entry_calls, self.proofs = [], [], [], [], []

    def inputs(self, arch):
        result = {}
        for row in self.rows:
            if row["architecture"] in (arch, "any"):
                result[row["name"]], result[row["name"] + ".sig"] = row["body"], row["sig"]
        return result

    def known(self, arch):
        return {r["name"]: (signing_mod._sha256(r["body"]), len(r["body"]), r["sig"])
                for r in self.rows if r["architecture"] in (arch, "any")}

    # In-memory filesystem overlay for native-produced members.
    def add(self, path, payload, *, link=False, nlink=1, inode=None):
        self.assertFalse(os.path.lexists(path), "in-memory member must never exist on disk")
        self.assertNotIn(path, self.virtual)
        inode = 1_000_000 + len(self.virtual) if inode is None else inode
        mode = (stat.S_IFLNK | 0o777) if link else (stat.S_IFREG | 0o600)
        self.virtual[path] = ((0, inode, mode, nlink, len(payload), 0, 0), payload)
        return inode

    def list_directory(self, path):
        real = _REAL_LIST_DIRECTORY(path)
        virtual = {member.name for member in self.virtual if member.parent == path}
        self.assertFalse(virtual & set(real))
        return tuple(sorted({*real, *virtual}))

    def record(self, path, *, alias=False, shared=False):
        if path in self.virtual:
            self.flags[path] = (alias, shared)
            return self.virtual[path]
        return _REAL_RECORD(path, alias=alias, shared=shared)

    def create_database_members(self, repo, arch):
        for alias, target in metadata.PACMAN_ALIASES.items():
            data = _db(arch) if target == DB else _files(arch)
            if self.alias_form == "hardlink":
                inode = self.add(repo / target, data, nlink=2)
                self.add(repo / alias, data, nlink=2, inode=inode)
            elif self.alias_form == "symlink":
                self.add(repo / target, data)
                self.add(repo / alias, target.encode(), link=True)
            else:
                self.add(repo / target, data)
                self.add(repo / alias, b"OTHER" if self.alias_form == "bad-copy" else data)

    # Native seams.
    def run_native(self, argv, *, cwd, env, stdin, phase, **extra):
        umask = os.umask(0o077)
        os.umask(umask)
        argv = tuple(argv)
        self.calls.append({"argv": argv, "cwd": cwd, "env": dict(env), "stdin": stdin, "phase": phase,
                           "umask": umask, "extra": extra})
        if phase == "pacman-database-create":
            tmp = Path(env["TMPDIR"])
            info = os.lstat(tmp)
            self.scratch.append((tmp, stat.S_ISDIR(info.st_mode), stat.S_IMODE(info.st_mode), info.st_uid))
            repo = Path(argv[3]).parent
            self.create_database_members(repo, repo.name.removeprefix("pacman-repository-"))
            return runtime_mod.ProcessResult(0)
        if phase == "pacman-database-sign":
            target = Path(argv[argv.index("--output") + 1])
            self.add(target, b"\x89INERT IN-MEMORY SIGNATURE " + f"{target.parent.name}/{target.name}".encode())
            return runtime_mod.ProcessResult(0)
        if phase == "pacman-database-verify":
            return runtime_mod.ProcessResult(0, b"[GNUPG:] INERT FIXTURE STATUS\n")
        raise AssertionError(f"unexpected native phase {phase}")

    def status_proof(self, inspect_fn, code, message, data, binding, **kwargs):
        self.proofs.append((inspect_fn, code, data, binding, kwargs))
        return {}

    def pacman_entries(self, data, *, files):
        self.entry_calls.append((data, files))
        return self.entries[data]

    def write_output(self, phase, path, data, label):
        self.writes.append((phase, path, data, label))

    def build(self, arch, inputs=None):
        self.reset()
        inputs = self.inputs(arch) if inputs is None else inputs
        with mock.patch.object(metadata, "_list_directory", self.list_directory), \
                mock.patch.object(metadata, "_record", self.record), \
                mock.patch.object(metadata, "_pacman_entries", self.pacman_entries), \
                mock.patch.object(runtime_mod, "_status_proof", self.status_proof):
            return metadata._pacman_repository(self.rt, inputs, self.home, self.work, self.staging,
                                               self.root, PASSPHRASE, arch=arch)

    def refused(self, code, arch, inputs=None):
        with self.assertRaises(ProtectedSigningError) as got:
            self.build(arch, inputs)
        self.assertEqual(got.exception.code, code)

    def leaf(self, arch):
        return "metadata-tmp-pacman" if arch == X86 else "metadata-tmp-pacman-" + arch

    def check(self, arch, written):
        repo = self.staging / f"pacman-repository-{arch}"
        inputs = self.inputs(arch)
        packages = sorted(r["name"] for r in self.rows if r["architecture"] in (arch, "any"))
        gpg = self.rt._gpg_base(self.home)
        self.assertEqual([c["phase"] for c in self.calls], [
            "pacman-database-create", "pacman-database-sign", "pacman-database-verify",
            "pacman-database-sign", "pacman-database-verify"])
        create = self.calls[0]
        self.assertEqual(create["argv"], (runtime_mod.NATIVE_REPO_ADD, "--nocolor", "--include-sigs",
                                          str(repo / DB), *(str(repo / name) for name in packages)))
        self.assertEqual((create["cwd"], create["stdin"], create["extra"], create["umask"]),
                         (self.work, b"", {}, 0o077))
        self.assertEqual(create["env"], {"HOME": str(self.home), "GNUPGHOME": str(self.home),
                                         "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                                         "TMPDIR": str(self.staging / self.leaf(arch))})
        self.assertEqual(self.scratch, [(self.staging / self.leaf(arch), True, 0o700, os.getuid())])
        for call, archive in zip(self.calls[1::2], (DB, FILES)):
            self.assertEqual(call["argv"], (*gpg, "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                                            "--detach-sign", "--output", str(repo / (archive + ".sig")), "-u",
                                            f"{self.rt.binding.signing_subkey_fingerprint}!", str(repo / archive)))
            self.assertEqual((call["cwd"], call["stdin"], call["umask"]), (self.work, PASSPHRASE, 0o077))
        for call, archive in zip(self.calls[2::2], (DB, FILES)):
            self.assertEqual(call["argv"], (*gpg, "--status-fd", "1", "--verify",
                                            str(repo / (archive + ".sig")), str(repo / archive)))
            self.assertEqual((call["cwd"], call["stdin"]), (self.work, b""))
        self.assertEqual([(p[0], p[1], p[2], p[4]) for p in self.proofs],
                         [(runtime_mod.inspect_detached_verification, "PACMAN_DATABASE_VERIFY_STATUS",
                           b"[GNUPG:] INERT FIXTURE STATUS\n", {"returncode": 0})] * 2)
        self.assertEqual(self.entry_calls, [(_db(arch), False), (_files(arch), True)])
        # Real scratch holds exactly the per-arch inert inputs and nothing produced natively.
        self.assertEqual(sorted(os.listdir(repo)), sorted(inputs))
        for name, data in inputs.items():
            self.assertEqual((repo / name).read_bytes(), data)
        for alias, target in metadata.PACMAN_ALIASES.items():
            self.assertEqual(self.flags[repo / target], (False, True))
            self.assertEqual(self.flags[repo / alias], (True, False))
            self.assertEqual(self.flags[repo / (target + ".sig")], (False, False))
        base = self.root / "arch" / arch
        order = [name for alias, target in metadata.PACMAN_ALIASES.items()
                 for name in (target, target + ".sig", alias, alias + ".sig")]
        self.assertEqual([(w[0], w[1]) for w in self.writes],
                         [("pacman-database-output", base / name) for name in order])
        payload = {w[1].name: w[2] for w in self.writes}
        for alias, target in metadata.PACMAN_ALIASES.items():
            data = _db(arch) if target == DB else _files(arch)
            signature = self.virtual[repo / (target + ".sig")][1]
            self.assertEqual((payload[target], payload[alias]), (data, data))
            self.assertEqual((payload[target + ".sig"], payload[alias + ".sig"]), (signature, signature))
        self.assertEqual(written, {base / name for name in order})

    def assert_disk_holds_only_inputs(self):
        allowed = {name for arch in (X86, ARM) for name in self.inputs(arch)}
        for _directory, _names, files in os.walk(self.base):
            self.assertTrue(set(files) <= allowed, files)
        self.assertFalse(os.path.lexists(self.root))

    def test_metadata_module_uses_this_runtime_module(self):
        self.assertIs(metadata._rt, runtime_mod)

    def test_real_repository_for_both_architectures(self):
        written = {}
        for arch in (X86, ARM):
            written[arch] = self.build(arch)
            self.check(arch, written[arch])
        self.assertFalse(written[X86] & written[ARM])
        created = {"pacman-repository-x86_64", "metadata-tmp-pacman",
                   "pacman-repository-aarch64", "metadata-tmp-pacman-aarch64"}
        self.assertEqual(set(os.listdir(self.staging)), created)
        for name in created:
            info = os.lstat(self.staging / name)
            self.assertTrue(stat.S_ISDIR(info.st_mode))
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid), (0o700, os.getuid()))
        self.assert_disk_holds_only_inputs()

    def test_symlink_and_hardlink_aliases_publish_target_copies(self):
        for form in ("symlink", "hardlink"):
            with self.subTest(form=form):
                self.alias_form = form
                for name in os.listdir(self.staging):
                    shutil.rmtree(self.staging / name)
                self.virtual.clear()
                self.check(ARM, self.build(ARM))
                self.assert_disk_holds_only_inputs()

    def test_alias_payload_mismatch_refused(self):
        self.alias_form = "bad-copy"
        self.refused("OUTPUT_INVENTORY", ARM)
        self.assertEqual([c["phase"] for c in self.calls], ["pacman-database-create"])
        self.assertEqual(self.writes, [])

    def test_database_entries_must_bind_exact_arch_inputs(self):
        self.entries[_db(ARM)] = self.known(X86)
        self.refused("PACKAGE_MUTATED", ARM)
        self.assertEqual([c["phase"] for c in self.calls], ["pacman-database-create"])
        self.assertEqual(self.writes, [])

    def test_foreign_inputs_refused_before_scratch(self):
        self.refused("OUTPUT_INVENTORY", ARM, self.inputs(X86))
        self.assertEqual((os.listdir(self.staging), self.calls, self.writes), ([], [], []))

    def test_arch_keyword_is_required(self):
        parameter = inspect.signature(metadata._pacman_repository).parameters["arch"]
        self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect.Parameter.empty)
        with self.assertRaises(TypeError):
            metadata._pacman_repository(self.rt, self.inputs(X86), self.home, self.work, self.staging,
                                        self.root, PASSPHRASE)
        self.assertEqual((os.listdir(self.staging), self.calls), ([], []))


class _PhaseLease:
    """Minimal lease: records only the assembly phases _write_output enters."""

    def __init__(self):
        self.phases = []

    @contextmanager
    def assembly_phase(self, phase):
        self.phases.append(("enter", phase))
        try:
            yield
        finally:
            self.phases.append(("exit", phase))


@unittest.skipIf(os.geteuid() == 0, "owned-output custody assertions require a nonroot uid")
class PacmanSigningBranchTests(unittest.TestCase):
    """Real ProtectedSigningRuntime._sign_pacman_object and real _write_output.

    Only _pacman_sign/_pacman_verify (native GPG) are stubbed. No key, agent,
    runner or process is created; the passphrase is the inert fixture literal.
    """

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name).resolve()
        self.output = runtime_mod._new_owned_directory(base / "output", "inert signing output")
        self.staging = runtime_mod._new_owned_directory(base / "staging", "inert staging").path
        self.home, self.work = base / "home-never-created", base / "work-never-created"
        self.rt = _runtime()
        self.rt._output_root = self.output
        self.rt._output_files = {}
        self.lease = _PhaseLease()
        self.rt._active_live_lease = self.lease
        self.native, self.mutate = [], False
        self.rt._pacman_sign = self.sign
        self.rt._pacman_verify = self.verify

    def sign(self, stage, signature, home, work, passphrase):
        self.native.append(("sign", stage, signature, home, work, passphrase))
        runtime_mod._exclusive_write(signature, b"\x89INERT FIXTURE SIGNATURE " + stage.name.encode(),
                                     "inert fixture signature")
        if self.mutate:
            os.unlink(stage)
            runtime_mod._exclusive_write(stage, b"MUTATED INERT PACKAGE", "inert mutated package")

    def verify(self, stage, signature, home, work):
        self.native.append(("verify", stage, signature, home, work))

    def sign_one(self, product, arch):
        name = _name(product, arch)
        body = b"PUBLIC INERT PACKAGE " + name.encode()
        stage = self.staging / name
        runtime_mod._exclusive_write(stage, body, "inert staged package")
        row = self.rt._sign_pacman_object(_obj(product, arch, body), name, body, stage, staging=self.staging,
                                          home=self.home, work=self.work, output_root=self.output.path,
                                          passphrase=PASSPHRASE)
        return name, body, row

    def assert_outputs(self, expected):
        self.assertEqual(set(self.rt._output_files), set(expected))
        for path, data in expected.items():
            self.assertEqual(runtime_mod._read_regular_unpinned(path, "inert output"), data)
            self.assertEqual(self.rt._output_files[path][1:], (signing_mod._sha256(data), len(data)))

    def native_count(self, kind, name):
        return sum(1 for call in self.native if call[0] == kind and call[1].name == name)

    def signature(self, name):
        return b"\x89INERT FIXTURE SIGNATURE " + name.encode()

    def test_execution_loop_calls_the_extracted_method(self):
        source = inspect.getsource(runtime_mod.ProtectedSigningRuntime._execute_checked)
        self.assertIn("self._sign_pacman_object(", source)
        self.assertNotIn("self._pacman_sign(", source)

    def test_any_signed_once_and_native_only_in_its_repository(self):
        shared, shared_body, shared_row = self.sign_one(LOOM, "any")
        self.assertEqual((self.native_count("sign", shared), self.native_count("verify", shared)), (1, 1))
        sign_call = next(call for call in self.native if call[0] == "sign")
        self.assertEqual(sign_call[2:], (self.staging / (shared + ".sig"), self.home, self.work, PASSPHRASE))
        any_outputs = {self.output.path / "arch" / arch / leaf: data for arch in (X86, ARM)
                       for leaf, data in ((shared, shared_body), (shared + ".sig", self.signature(shared)))}
        self.assert_outputs(any_outputs)
        self.assertEqual(self.lease.phases, [(step, phase) for _ in (X86, ARM)
                                             for phase in ("pacman-output", "signature-output")
                                             for step in ("enter", "exit")])

        native, native_body, native_row = self.sign_one(BURST, ARM)
        self.assertEqual((self.native_count("sign", native), self.native_count("verify", native)), (1, 1))
        self.assert_outputs({**any_outputs, self.output.path / "arch" / ARM / native: native_body,
                             self.output.path / "arch" / ARM / (native + ".sig"): self.signature(native)})
        self.assertFalse(os.path.lexists(self.output.path / "arch" / X86 / native))
        self.assertEqual(len(self.native), 4)
        self.assertEqual(shared_row, {"channel": "pacman", "product": LOOM, "architecture": "any",
                                      "name": shared, "package_sha256": signing_mod._sha256(shared_body)})
        self.assertEqual(native_row, {"channel": "pacman", "product": BURST, "architecture": ARM,
                                      "name": native, "package_sha256": signing_mod._sha256(native_body)})

    def assert_refused_without_outputs(self, code, product, arch):
        with self.assertRaises(ProtectedSigningError) as got:
            self.sign_one(product, arch)
        self.assertEqual(got.exception.code, code)
        self.assertEqual((self.rt._output_files, self.lease.phases, os.listdir(self.output.path)), ({}, [], []))

    def test_mutation_refused_before_outputs(self):
        self.mutate = True
        self.assert_refused_without_outputs("PACKAGE_MUTATED", BURST, ARM)

    def test_live_foreign_architecture_refused_before_outputs(self):
        # Guard order is preserved: sign/verify/mutation check precede routing.
        self.assert_refused_without_outputs("ARCHITECTURE", BURST, "armv7h")
        self.assertEqual([call[0] for call in self.native], ["sign", "verify"])

    def test_legacy_route_refuses_native_aarch64(self):
        self.rt._active_live_lease = None
        self.assert_refused_without_outputs("ARCHITECTURE", BURST, ARM)

    def test_legacy_route_layout_unchanged(self):
        self.rt._active_live_lease = None
        name, body, _row = self.sign_one(BURST, X86)
        base = self.output.path / "pacman" / X86
        self.assert_outputs({base / name: body, base / (name + ".sig"): self.signature(name)})
        self.assertEqual(self.lease.phases, [])


class PublicLinkageTests(unittest.TestCase):
    """Real _pacman_linkage; _signature/_pacman_archive replaced by recorders."""

    def build(self, rows):
        unsigned = {f"{r['name']}@unsigned/pacman/{r['name']}": r["body"] for r in rows}
        output = {}
        for arch in (X86, ARM):
            base = f"arch/{arch}"
            for row in rows:
                if row["architecture"] in (arch, "any"):
                    output[f"{base}/{row['name']}"], output[f"{base}/{row['name']}.sig"] = row["body"], row["sig"]
            for archive, alias in zip(LINKAGE.PACMAN_ARCHIVES, metadata.PACMAN_ALIASES):
                data, sig = b"INERT INDEX " + f"{base}/{archive}".encode(), b"\x89INERT " + archive.encode()
                output.update({f"{base}/{archive}": data, f"{base}/{archive}.sig": sig,
                               f"{base}/{alias}": data, f"{base}/{alias}.sig": sig})
        return unsigned, output

    def link(self, rows, unsigned, output, archive=None):
        seen = []

        def take(relative):
            if relative not in output:
                LINKAGE.fail("OUTPUT_INVENTORY", "Signed output member is missing")
            return output[relative]

        def record(data, *, files, known, identities):
            seen.append((data, files, dict(known), dict(identities)))

        with mock.patch.object(LINKAGE, "_signature", lambda data, **_: data), \
                mock.patch.object(LINKAGE, "_pacman_archive", archive or record):
            companions, signed = LINKAGE._pacman_linkage(rows, unsigned, take)
        return companions, signed, seen

    def refused(self, rows, unsigned, output, archive=None):
        with self.assertRaises(LINKAGE.PublicJoinError) as got:
            self.link(rows, unsigned, output, archive)
        self.assertEqual(_code(got.exception), "PACMAN_LINKAGE")

    def test_each_index_bound_to_its_architecture_set(self):
        rows = _rows()
        companions, signed, seen = self.link(rows, *self.build(rows))
        self.assertEqual(len(seen), 4)
        for index, arch in enumerate((X86, X86, ARM, ARM)):
            data, files, known, identities = seen[index]
            expected = {r["name"] for r in rows if r["architecture"] in (arch, "any")}
            self.assertEqual(set(known), expected)
            self.assertEqual(set(identities), expected)
            self.assertIn(f"arch/{arch}/".encode(), data)
            self.assertEqual(files, index % 2 == 1)
        kinds = [obj.kind for obj in signed]
        self.assertEqual((kinds.count("pacman-package"), kinds.count("pacman-database")), (8, 4))
        for row in rows:
            if row["architecture"] == "any":
                pair = [obj for obj in signed if obj.rel_path.endswith("/" + row["name"] + ".sig")]
                self.assertEqual([obj.rel_path.split("/")[1] for obj in pair], [X86, ARM])
                self.assertEqual(len({(obj.unsigned, obj.signed) for obj in pair}), 1)
        self.assertFalse(set(companions) & {obj.deploy_path for obj in signed})

    def test_missing_native_rows_refused(self):
        rows = [row for row in _rows() if row["architecture"] != ARM]
        self.refused(rows, *self.build(rows))

    def test_foreign_native_row_refused(self):
        rows = _rows() + [{"product": BURST, "architecture": "armv7h", "name": _name(BURST, "armv7h"),
                           "version": VERSIONS[BURST], "body": b"P", "sig": b"S"}]
        self.refused(rows, *self.build(rows))

    def test_paired_any_signature_mismatch_refused(self):
        rows = _rows()
        unsigned, output = self.build(rows)
        output[f"arch/{ARM}/{_name(LOOM, 'any')}.sig"] = b"\x89DIFFERENT"
        self.refused(rows, unsigned, output)

    def test_paired_any_byte_mismatch_refused(self):
        rows = _rows()
        unsigned, output = self.build(rows)
        output[f"arch/{ARM}/{_name(SOLAR, 'any')}"] = b"DIFFERENT"
        self.refused(rows, unsigned, output)

    def test_index_listing_foreign_native_refused_by_real_archive_binding(self):
        rows = _rows()
        stray = {_name(BURST, ARM): ("0" * 64, 1, b"S")}

        def entries(_data, *, files):
            return stray  # never equals the x86_64 known set

        with mock.patch.object(LINKAGE.metadata, "_pacman_entries", entries):
            with self.assertRaises(LINKAGE.PublicJoinError) as got:
                with mock.patch.object(LINKAGE, "_signature", lambda data, **_: data):
                    unsigned, output = self.build(rows)
                    LINKAGE._pacman_linkage(rows, unsigned, output.__getitem__)
        self.assertEqual(_code(got.exception), "PACMAN_LINKAGE")


if __name__ == "__main__":
    unittest.main()
