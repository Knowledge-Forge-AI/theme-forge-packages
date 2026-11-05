"""Pure tests for the sixth current signer client lane, pacman-aarch64.

Run with python3 -I -B tests/test_current_signer_archarm_client.py --r-root ../r.
The R checkout is read-only. No container, package manager, GPG, network or
child process runs: rs9.archarm_sdk, R client_cycle and every provisioner are
in-memory recording fakes. Only owned temporary directories and inert files are
created. Nothing here is native qualification, SDK evidence, source adoption,
signing or publication authority.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path, PurePosixPath
import argparse
import copy
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "tools/verification/current_signer"
WORKFLOW = ROOT / ".github/workflows/qualify-current-signer.yml"
_args = argparse.ArgumentParser()
_args.add_argument("--r-root", required=True, type=Path)
options, remaining = _args.parse_known_args()
sys.path[:0] = [str(SIGNER), str(options.r_root.resolve() / "src")]

import package_client_qualification as subject  # noqa: E402
import client_artifact_input as cai  # noqa: E402
import publication_github_api as gh  # noqa: E402
import rs9.hosted_deb as hosted_deb  # noqa: E402
import rs9.hosted_native as hosted_native  # noqa: E402
import rs9.hosted_pins as hosted_pins  # noqa: E402
import rs9.rpm_client_runtime as rpm_client_runtime  # noqa: E402
from rs9.build_native import CommandReceipt  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.hosted_deb import PACMAN_CONF, SERVER_ROOT, _printf_file  # noqa: E402

ARM, X86 = "pacman-aarch64", "pacman-x86_64"
PREVIOUS_FIVE = {
    "apt-amd64": ("apt-amd64", "apt", "deb", "amd64", "x86_64", "x86_64-linux", "linux/amd64"),
    "apt-arm64": ("apt-arm64", "apt", "deb", "arm64", "aarch64", "aarch64-linux", "linux/arm64"),
    "dnf-x86_64": ("dnf-x86_64", "dnf", "rpm", "x86_64", "x86_64", "x86_64-linux", "linux/amd64"),
    "dnf-aarch64": ("dnf-aarch64", "dnf", "rpm", "aarch64", "aarch64", "aarch64-linux", "linux/arm64"),
    "pacman-x86_64": ("pacman-x86_64", "pacman", "pacman", "x86_64", "x86_64", "x86_64-linux", "linux/amd64"),
}
SIX = (*PREVIOUS_FIVE, ARM)
SOURCE = {"p_commit": "a" * 40, "p_tree": "b" * 40, "r_commit": "c" * 40, "r_tree": "d" * 40,
          "source_closure_sha256": "e" * 64, "rs9_run": 4242}
BURST_RECORD = {"platform_specific": True, "target_system": "aarch64-linux",
                "target_native_addon": {"path": "package/prebuilds/inert.node", "sha256": "1" * 64},
                "native_loader": {"path": "package/dist/directory-snapshot-native.js", "sha256": "2" * 64}}
NONROOT = os.geteuid() != 0


def _code(error):
    return getattr(error, "code", None)


def _uname(sysname, machine):
    return types.SimpleNamespace(sysname=sysname, nodename="inert", release="0", version="0", machine=machine)


def _pacman_spec_with_architecture(real):
    """Model of the parent-owned R addition: default x86_64, only the Architecture line varies."""
    def spec(pacman_dir, keys_dir, fingerprint, *, architecture="x86_64"):
        value = real(pacman_dir, keys_dir, fingerprint)
        conf = ["[options]", f"Architecture = {architecture}", "SigLevel = Required DatabaseRequired", "[rs9]",
                f"Server = file://{SERVER_ROOT}/pacman/$arch"]
        value["configure"] = [_printf_file(PACMAN_CONF, conf), *value["configure"][1:]]
        return value
    return spec


REAL_PACMAN_SPEC = hosted_deb.pacman_spec


def _expected_context(source=SOURCE):
    return {"architecture": "aarch64", "family": "pacman", "generation": gh.CURRENT_GENERATION,
            "lane": ARM, "platform": "linux/arm64", "source": dict(source), "system": "aarch64-linux"}


class FakeSdk:
    """In-memory stand-in for the authenticated R rs9.archarm_sdk module; runs nothing."""

    def __init__(self, r_root, *, mutate=None, exit_error=False, write_file=True):
        self.calls, self.closed, self.leases = [], 0, []
        self.path = Path(r_root) / subject.ARCHARM_SDK_REL_PATH
        if write_file:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("# inert test placeholder; never executed\n")
        module = types.ModuleType(subject.ARCHARM_SDK_MODULE)
        module.__file__ = str(self.path)
        owner = self

        class ArchArmSDK:
            def __init__(self, context, uid, gid):
                self.context, self.uid, self.gid = context, uid, gid
                self.image, self.platform, self.records = "tf-archarm-sdk:0123abcd", "linux/arm64", ()

            def client(self, mounts, probe_output):
                raise AssertionError("the client_cycle fake never opens a lease client")

        @contextmanager
        def acquire_sdk(*, host, workspace, context, uid, gid):
            owner.calls.append({"host": host, "workspace": workspace, "context": copy.deepcopy(context),
                                "uid": uid, "gid": gid, "environ": dict(os.environ)})
            lease = ArchArmSDK(copy.deepcopy(context), uid, gid)
            lease = mutate(lease) if mutate else lease
            owner.leases.append(lease)
            try:
                yield lease
            finally:
                owner.closed += 1
                if exit_error:
                    raise ContractError("CLEANUP_UNPROVEN", "inert fake cleanup failure")

        module.ArchArmSDK, module.acquire_sdk = ArchArmSDK, acquire_sdk
        self.module, self.lease_type = module, ArchArmSDK


class InertRunner:
    """Inner CommandRunner fake; returns synthetic receipts and records argv/environment."""

    def __init__(self):
        self.argv, self.environ = [], []

    def which(self, _name):
        return None

    def run(self, argv, *, cwd=None, env=None):
        self.argv.append(list(argv))
        self.environ.append(dict(os.environ))
        return CommandReceipt(list(argv), 0, b"", b"", tool_name=argv[0], executed=True)


class Forbidden:
    def __init__(self, name, result=None):
        self.name, self.result, self.calls = name, result, []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result


class _Temp(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))
        temp = tempfile.TemporaryDirectory(prefix="archarm-client-pure-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.gid = os.stat(self.base).st_gid  # new entries inherit this on both Linux and macOS here
        self.uid = os.getuid()


# --------------------------------------------------------------------------- lane contracts


class SixLaneContractTests(unittest.TestCase):
    def test_previous_five_lane_specs_unchanged_and_one_exact_arm_lane_added(self):
        self.assertEqual(tuple(subject.LANE_SPECS), SIX)
        for lane, expected in PREVIOUS_FIVE.items():
            self.assertEqual(tuple(getattr(subject.LANE_SPECS[lane], f) for f in
                                   ("lane", "family", "pin_family", "arch", "host_machine", "system", "platform")),
                             expected)
        self.assertEqual(subject.LANE_SPECS[ARM], subject.LaneSpec(
            ARM, "pacman", "pacman", "aarch64", "aarch64", "aarch64-linux", "linux/arm64"))

    def test_admission_lanes_and_required_job_set_name_six_clients(self):
        self.assertEqual(cai.ALLOWED_CLIENT_LANES, SIX)
        self.assertEqual(set(cai.ALLOWED_CLIENT_LANES), set(subject.LANE_SPECS))
        self.assertEqual(gh.QUALIFICATION.required_jobs, frozenset({"qualify-current-signer", *SIX}))
        self.assertEqual(gh.QUALIFICATION.workflow_file, "qualify-current-signer.yml")

    def test_workflow_matrix_runs_six_native_clients_without_signing_material(self):
        text = WORKFLOW.read_text()
        signer, client = text.split("\n  native-client:\n")
        pairs = re.findall(r"- lane: (\S+)\n\s+runner: (\S+)\n", client)
        self.assertEqual(pairs, [("apt-amd64", "ubuntu-24.04"), ("apt-arm64", "ubuntu-24.04-arm"),
                                 ("dnf-x86_64", "ubuntu-24.04"), ("dnf-aarch64", "ubuntu-24.04-arm"),
                                 ("pacman-x86_64", "ubuntu-24.04"), ("pacman-aarch64", "ubuntu-24.04-arm")])
        self.assertEqual({"qualify-current-signer", *(lane for lane, _ in pairs)}, gh.QUALIFICATION.required_jobs)
        self.assertEqual(re.findall(r"timeout-minutes: (\d+)", client), ["90"])
        self.assertIn("needs: qualify-current-signer", client)
        for forbidden in ("secrets.", "environment:", "PACKAGE_SIGNING", "PASSPHRASE", "qemu", "binfmt"):
            self.assertNotIn(forbidden, client)
        self.assertNotIn("qemu", text)
        # Signing secrets stay confined to the single protected signer job.
        self.assertEqual(text.count("secrets."), 2)
        self.assertEqual(signer.count("environment: github-pages"), 1)
        self.assertIn("timeout-minutes: 210", signer)
        self.assertTrue(text.startswith("name: Current Signer and Native Package Client Qualification\n"))
        self.assertIn("\npermissions: {}\n", text)

    def test_previous_lane_required_gates_unchanged(self):
        for lane in PREVIOUS_FIVE:
            names = subject.required_gate_names_for_lane(subject.LANE_SPECS[lane])
            self.assertFalse(any("probe-output-custody" in name for name in names))

    def test_arm_required_gates_are_pacman_shape_plus_custody(self):
        x86 = subject.required_gate_names_for_lane(subject.LANE_SPECS[X86])
        arm = subject.required_gate_names_for_lane(subject.LANE_SPECS[ARM])
        renamed = [name.replace(f"client.{X86}.", f"client.{ARM}.") for name in x86]
        custody = f"client.{ARM}.probe-output-custody"
        self.assertEqual([name for name in arm if name != custody], renamed)
        self.assertEqual(arm.count(custody), 1)
        self.assertEqual(arm[-2:], ["burst-native-addon-target", "burst-native-addon-load"])


class NativeHostTests(unittest.TestCase):
    def test_arm_lane_refused_on_x86_64_linux(self):
        with self.assertRaises(subject.PublicationError) as got:
            subject.verify_native_linux_host(ARM, uname_fn=lambda: _uname("Linux", "x86_64"))
        self.assertEqual(got.exception.code, "HOST_ARCHITECTURE_MISMATCH")

    def test_arm_lane_refused_off_linux_even_on_arm(self):
        for sysname in ("Darwin", "Windows", "FreeBSD"):
            with self.subTest(sysname=sysname), self.assertRaises(subject.PublicationError) as got:
                subject.verify_native_linux_host(ARM, uname_fn=lambda: _uname(sysname, "aarch64"))
            self.assertEqual(got.exception.code, "NON_LINUX_HOST_FORBIDDEN")

    def test_arm_lane_admitted_only_on_native_aarch64_linux(self):
        self.assertIs(subject.verify_native_linux_host(ARM, uname_fn=lambda: _uname("Linux", "aarch64")),
                      subject.LANE_SPECS[ARM])
        for machine in ("arm64", "armv7l", "x86_64"):
            with self.subTest(machine=machine), self.assertRaises(subject.PublicationError):
                subject.verify_native_linux_host(ARM, uname_fn=lambda: _uname("Linux", machine))

    def test_x86_pacman_still_refused_on_arm(self):
        with self.assertRaises(subject.PublicationError) as got:
            subject.verify_native_linux_host(X86, uname_fn=lambda: _uname("Linux", "aarch64"))
        self.assertEqual(got.exception.code, "HOST_ARCHITECTURE_MISMATCH")


# --------------------------------------------------------------------------- pacman spec


class PacmanSpecTests(_Temp):
    def setUp(self):
        super().setUp()
        self.keys = self.base / "keys"
        self.keys.mkdir()
        shutil.copyfile(ROOT / "keys" / subject.COMMITTED_PUBLIC_KEY_FILENAME,
                        self.keys / subject.COMMITTED_PUBLIC_KEY_FILENAME)

    def arm(self):
        return subject.build_production_client_spec(self.base, subject.LANE_SPECS[ARM])

    def test_x86_default_calls_r_without_architecture_keyword(self):
        seen = []

        def recorder(*args, **kwargs):
            seen.append(kwargs)
            return REAL_PACMAN_SPEC(*args, **kwargs)

        with mock.patch.object(hosted_deb, "pacman_spec", side_effect=recorder):
            patched = subject.build_production_client_spec(self.base, subject.LANE_SPECS[X86])
        unpatched = subject.build_production_client_spec(self.base, subject.LANE_SPECS[X86])
        self.assertEqual(seen, [{}])
        for key in ("family", "mounts", "configure", "refresh", "public_fingerprint", "expected_key_sha256"):
            self.assertEqual(patched[key], unpatched[key])
        self.assertIn(_printf_file(PACMAN_CONF, [
            "[options]", "Architecture = x86_64", "SigLevel = Required DatabaseRequired",
            "[knowledge-forge-ai]", f"Server = file://{SERVER_ROOT}/pacman/$arch"]), unpatched["configure"])

    def test_arm_spec_selects_signed_aarch64_tree_with_unchanged_trust(self):
        with mock.patch.object(hosted_deb, "pacman_spec", _pacman_spec_with_architecture(REAL_PACMAN_SPEC)):
            spec = self.arm()
        base = ["pacman", "--config", PACMAN_CONF]
        self.assertEqual(spec["configure"], [
            _printf_file(PACMAN_CONF, ["[options]", "Architecture = aarch64", "SigLevel = Required DatabaseRequired",
                                       "[knowledge-forge-ai]", f"Server = file://{SERVER_ROOT}/pacman/$arch"]),
            ["pacman-key", "--init"],
            ["pacman-key", "--add", f"{SERVER_ROOT}/keys/{subject.COMMITTED_PUBLIC_KEY_FILENAME}"],
            ["pacman-key", "--lsign-key", subject.PRODUCTION_PRIMARY_FINGERPRINT]])
        self.assertEqual(spec["mounts"], [(str(self.base / "arch"), f"{SERVER_ROOT}/pacman", False),
                                          (str(self.keys), f"{SERVER_ROOT}/keys", False)])
        self.assertEqual(spec["refresh"], [*base, "-Sy", "--noconfirm"])
        product = "theme-forge-stellar-burst"
        self.assertEqual(spec["install"](product), [*base, "-S", "--noconfirm", "--needed", "knowledge-forge-ai/" + product])
        self.assertEqual(spec["remove"](product), [*base, "-R", "--noconfirm", product])
        self.assertEqual(spec["query"](product), ["pacman", "-Q", product])
        self.assertEqual((spec["public_fingerprint"], spec["expected_key_sha256"]),
                         (subject.PRODUCTION_PRIMARY_FINGERPRINT, subject.COMMITTED_PUBLIC_KEY_SHA256))
        for flag in ("--nodeps", "-d", "--skipinteg", "--skippgpcheck", "--skipchecksums", "-A", "--ignorearch", "-Fy"):
            for command in (spec["refresh"], spec["install"](product), spec["remove"](product)):
                self.assertNotIn(flag, command)

    def test_arm_repository_uri_resolves_to_signer_aarch64_output_directory(self):
        import protected_signing_runtime as runtime_mod
        with mock.patch.object(hosted_deb, "pacman_spec", _pacman_spec_with_architecture(REAL_PACMAN_SPEC)):
            spec = self.arm()
        guest = PurePosixPath(f"{SERVER_ROOT}/pacman/aarch64/knowledge-forge-ai.db")
        source, target, writable = spec["mounts"][0]
        self.assertFalse(writable)
        host = Path(source) / str(guest.relative_to(target))
        (signed_dir,) = runtime_mod._pacman_output_directories(self.base, "aarch64", live=True)
        self.assertEqual(host.parent, signed_dir)

    def test_r_without_architecture_parameter_fails_closed(self):
        def legacy(pacman_dir, keys_dir, fingerprint):
            return REAL_PACMAN_SPEC(pacman_dir, keys_dir, fingerprint)
        with mock.patch.object(hosted_deb, "pacman_spec", legacy):
            with self.assertRaises(subject.PublicationError) as got:
                self.arm()
        self.assertEqual(got.exception.code, "PACMAN_SPEC_SHAPE_UNRECOGNIZED")

    def test_arm_shape_drift_refused(self):
        def drift(kind):
            inner = _pacman_spec_with_architecture(REAL_PACMAN_SPEC)

            def spec(*args, architecture="x86_64", **kwargs):
                value = inner(*args, architecture="x86_64" if kind == "ignored-arch" else architecture, **kwargs)
                base = ["pacman", "--config", PACMAN_CONF]
                if kind == "refresh":
                    value["refresh"] = [*base, "-Syy", "--noconfirm"]
                elif kind == "remove":
                    value["remove"] = lambda pkg: [*base, "-Rdd", "--noconfirm", pkg]
                elif kind == "query":
                    value["query"] = lambda pkg: ["true", pkg]
                elif kind == "install":
                    value["install"] = lambda pkg: [*base, "-S", "--noconfirm", "--nodeps", "rs9/" + pkg]
                return value
            return spec

        for kind in ("ignored-arch", "refresh", "remove", "query", "install"):
            with self.subTest(kind=kind), mock.patch.object(hosted_deb, "pacman_spec", drift(kind)):
                with self.assertRaises(subject.PublicationError) as got:
                    self.arm()
                self.assertEqual(got.exception.code, "PACMAN_SPEC_SHAPE_UNRECOGNIZED")

    def test_only_exact_arm_lane_selects_aarch64(self):
        arm = subject.LANE_SPECS[ARM]
        for changed in (replace(arm, platform="linux/amd64"), replace(arm, system="x86_64-linux"),
                        replace(arm, host_machine="x86_64"), replace(arm, lane=X86),
                        replace(arm, arch="armv7h", platform="linux/arm/v7")):
            with self.subTest(changed=changed), \
                    mock.patch.object(hosted_deb, "pacman_spec", _pacman_spec_with_architecture(REAL_PACMAN_SPEC)):
                with self.assertRaises(subject.PublicationError) as got:
                    subject.build_production_client_spec(self.base, changed)
                self.assertEqual(got.exception.code, "UNSUPPORTED_CLIENT_LANE")

    def test_unknown_architecture_parameter_refused_before_r(self):
        with mock.patch.object(hosted_deb, "pacman_spec", side_effect=AssertionError("reached R")):
            for arch in ("armv7h", "any", "", "x86_64 "):
                with self.subTest(arch=arch), self.assertRaises(subject.PublicationError) as got:
                    subject.adapt_production_pacman_spec(self.base / "arch", self.keys, architecture=arch)
                self.assertEqual(got.exception.code, "UNSUPPORTED_CLIENT_LANE")


# --------------------------------------------------------------------------- lease contract


class LeaseContextTests(unittest.TestCase):
    def test_exact_current_pacman_aarch64_context_with_source_identity(self):
        self.assertEqual(subject.archarm_lease_context(subject.LANE_SPECS[ARM], dict(SOURCE, lane=ARM)),
                         _expected_context())

    def test_wrong_lane_family_system_refused(self):
        arm = subject.LANE_SPECS[ARM]
        for changed in (subject.LANE_SPECS[X86], subject.LANE_SPECS["dnf-aarch64"], subject.LANE_SPECS["apt-arm64"],
                        replace(arm, family="dnf"), replace(arm, system="x86_64-linux"),
                        replace(arm, arch="x86_64"), replace(arm, platform="linux/amd64")):
            with self.subTest(changed=changed), self.assertRaises(subject.PublicationError) as got:
                subject.archarm_lease_context(changed, SOURCE)
            self.assertEqual(got.exception.code, "ARCHARM_LANE_CONTEXT")

    def test_source_identity_required(self):
        bad = [{k: v for k, v in SOURCE.items() if k != "r_tree"}, dict(SOURCE, rs9_run="4242"),
               dict(SOURCE, rs9_run=True), dict(SOURCE, rs9_run=0), dict(SOURCE, r_commit="C" * 40),
               dict(SOURCE, source_closure_sha256="e" * 63), dict(SOURCE, p_tree=None)]
        for admitted in bad:
            with self.subTest(admitted=admitted), self.assertRaises(subject.PublicationError) as got:
                subject.archarm_lease_context(subject.LANE_SPECS[ARM], admitted)
            self.assertEqual(got.exception.code, "ARCHARM_SOURCE_IDENTITY")

    def test_closed_sdk_context_is_joined_to_the_current_qualification_source(self):
        context = subject.archarm_lease_context(subject.LANE_SPECS[ARM], SOURCE)
        self.assertEqual(subject.archarm_sdk_context(context, 7),
                         {"generation": subject.gh.CURRENT_GENERATION, "runId":"7",
                          "runAttempt":1, "sourceSha":SOURCE["p_commit"]})
        for bad in (None, True, 0, "7"):
            with self.subTest(run=bad), self.assertRaises(subject.PublicationError):
                subject.archarm_sdk_context(context, bad)
        for field, value in (("generation","historical"), ("family","dnf"),
                             ("system","x86_64-linux"), ("lane",X86)):
            with self.subTest(field=field), self.assertRaises(subject.PublicationError):
                subject.archarm_sdk_context(dict(context, **{field:value}), 7)

    def test_runner_identity_is_actual_nonroot_numeric(self):
        self.assertEqual(subject.archarm_runner_identity(getuid=lambda: 1001, getgid=lambda: 118), (1001, 118))
        self.assertEqual(subject.archarm_runner_identity(getuid=lambda: 2147483647, getgid=lambda: 1),
                         (2147483647, 1))
        for uid, gid in ((0, 1000), (1000, 0), (2147483648, 1000), (1000, -1), (True, 1000), ("1000", 1000)):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(subject.PublicationError) as got:
                subject.archarm_runner_identity(getuid=lambda: uid, getgid=lambda: gid)
            self.assertEqual(got.exception.code, "ARCHARM_RUNNER_IDENTITY")


class SdkLoaderTests(_Temp):
    def load(self, sdk_module):
        with mock.patch.dict(sys.modules, {subject.ARCHARM_SDK_MODULE: sdk_module}):
            return subject.load_archarm_sdk(self.base)

    def refused(self, code, sdk_module):
        with self.assertRaises(subject.PublicationError) as got:
            self.load(sdk_module)
        self.assertEqual(got.exception.code, code)

    def test_loads_only_from_authenticated_r_checkout_file(self):
        sdk = FakeSdk(self.base)
        self.assertEqual(self.load(sdk.module), (sdk.module.acquire_sdk, sdk.lease_type))

    def test_missing_sdk_source_fails_closed(self):
        sdk = FakeSdk(self.base, write_file=False)
        self.refused("ARCHARM_SDK_UNAVAILABLE", sdk.module)

    def test_unimportable_sdk_fails_closed(self):
        FakeSdk(self.base)
        self.refused("ARCHARM_SDK_UNAVAILABLE", None)

    def test_module_from_elsewhere_refused(self):
        sdk = FakeSdk(self.base)
        other = self.base / "elsewhere" / "archarm_sdk.py"
        other.parent.mkdir()
        other.write_text("# inert\n")
        sdk.module.__file__ = str(other)
        self.refused("ARCHARM_SDK_IDENTITY", sdk.module)
        sdk.module.__file__ = None
        self.refused("ARCHARM_SDK_IDENTITY", sdk.module)

    def test_symlinked_sdk_source_refused(self):
        sdk = FakeSdk(self.base)
        real = self.base / "real_archarm_sdk.py"
        sdk.path.rename(real)
        os.symlink(real, sdk.path)
        self.refused("ARCHARM_SDK_IDENTITY", sdk.module)

    def test_incomplete_api_refused(self):
        for missing in ("acquire_sdk", "ArchArmSDK"):
            sdk = FakeSdk(self.base)
            delattr(sdk.module, missing)
            with self.subTest(missing=missing):
                self.refused("ARCHARM_SDK_API", sdk.module)


class LeaseVerificationTests(_Temp):
    def setUp(self):
        super().setUp()
        self.sdk = FakeSdk(self.base)
        self.context = _expected_context()

    def lease(self, **changes):
        lease = self.sdk.lease_type(copy.deepcopy(self.context), 1001, 118)
        for key, value in changes.items():
            setattr(lease, key, value)
        return lease

    def refused(self, code, lease):
        with self.assertRaises(subject.PublicationError) as got:
            subject.verify_archarm_lease(lease, self.sdk.lease_type, context=self.context, uid=1001, gid=118)
        self.assertEqual(got.exception.code, code)

    def test_exact_lease_accepted(self):
        self.assertIsNone(subject.verify_archarm_lease(self.lease(), self.sdk.lease_type,
                                                       context=self.context, uid=1001, gid=118))

    def test_forged_lease_shapes_refused(self):
        genuine = self.lease()
        subclass = type("Subclassed", (self.sdk.lease_type,), {})(copy.deepcopy(self.context), 1001, 118)
        for forged in (types.SimpleNamespace(**vars(genuine)), dict(vars(genuine)), subclass, None,
                       FakeSdk(self.base / "other").lease_type(copy.deepcopy(self.context), 1001, 118)):
            with self.subTest(forged=type(forged).__name__):
                self.refused("ARCHARM_LEASE_FORGED", forged)

    def test_wrong_generation_family_system_source_refused(self):
        for key, value in (("generation", "theme-forge-historical"), ("family", "dnf"),
                           ("system", "x86_64-linux"), ("architecture", "x86_64"), ("lane", X86),
                           ("source", dict(SOURCE, r_commit="f" * 40)), ("extra", "x")):
            with self.subTest(key=key):
                self.refused("ARCHARM_LEASE_CONTEXT", self.lease(context=dict(self.context, **{key: value})))
        for context in (None, [], {k: v for k, v in self.context.items() if k != "source"},
                        dict(self.context, rs9_run=object())):
            with self.subTest(context=type(context).__name__):
                self.refused("ARCHARM_LEASE_CONTEXT", self.lease(context=context))

    def test_platform_image_identity_refused(self):
        for changes in ({"platform": "linux/amd64"}, {"platform": None}, {"uid": 1002}, {"gid": 0},
                        {"uid": "1001"}, {"image": ""}, {"image": "-v /:/host"}, {"image": "tag with space"},
                        {"image": None}):
            with self.subTest(changes=changes):
                self.refused("ARCHARM_LEASE_IDENTITY", self.lease(**changes))

    def test_lease_without_client_refused(self):
        self.refused("ARCHARM_LEASE_API", self.lease(client=None))


# --------------------------------------------------------------------------- probe output custody


@unittest.skipUnless(NONROOT, "owned-output custody assertions require a nonroot uid")
class ProbeOutputCustodyTests(_Temp):
    def setUp(self):
        super().setUp()
        self.root = subject.create_probe_output_root(self.base, uid=self.uid, gid=self.gid)

    def verify(self, **kwargs):
        return subject.verify_probe_output_tree(self.root, uid=kwargs.get("uid", self.uid), gid=kwargs.get("gid", self.gid))

    def refused(self, code, **kwargs):
        with self.assertRaises(subject.PublicationError) as got:
            self.verify(**kwargs)
        self.assertEqual(got.exception.code, code)

    def test_fresh_exclusive_private_root(self):
        info = os.lstat(self.root)
        self.assertEqual((self.root.name, stat.S_IMODE(info.st_mode)), (subject.ARCHARM_PROBE_OUTPUT, 0o700))
        self.assertEqual(os.listdir(self.root), [])
        with self.assertRaises(subject.PublicationError) as got:
            subject.create_probe_output_root(self.base, uid=self.uid, gid=self.gid)
        self.assertEqual(got.exception.code, "PROBE_OUTPUT_ROOT")

    def test_owned_regular_tree_returns_counts_only(self):
        (self.root / "theme-forge-stellar-burst").mkdir(mode=0o755)
        (self.root / "theme-forge-stellar-burst" / "receipt.json").write_bytes(b"{}")
        self.assertEqual(self.verify(), {"directories": 1, "files": 1, "bytes": 2})

    def test_symlink_refused(self):
        os.symlink("/etc/passwd", self.root / "link")
        self.refused("PROBE_OUTPUT_SYMLINK")

    def test_world_writable_refused(self):
        child = self.root / "theme-forge-stellar-burst"
        child.mkdir()
        child.chmod(0o777)
        self.refused("PROBE_OUTPUT_WORLD_WRITABLE")

    def test_setuid_refused(self):
        path = self.root / "setid"
        path.write_bytes(b"x")
        path.chmod(0o4600)
        if not os.lstat(path).st_mode & stat.S_ISUID:
            self.skipTest("platform dropped the setuid bit")
        self.refused("PROBE_OUTPUT_SETID")

    def test_fifo_refused(self):
        os.mkfifo(self.root / "fifo", 0o600)
        self.refused("PROBE_OUTPUT_SPECIAL")

    def test_hard_link_refused(self):
        (self.root / "a").write_bytes(b"x")
        os.link(self.root / "a", self.root / "b")
        self.refused("PROBE_OUTPUT_LINKED")

    def test_unexpected_owner_refused(self):
        (self.root / "a").write_bytes(b"x")
        self.refused("PROBE_OUTPUT_OWNER", gid=self.gid + 1)
        self.refused("PROBE_OUTPUT_OWNER", uid=self.uid + 1)

    def test_depth_and_entry_bounds(self):
        (self.root / "a" / "b").mkdir(parents=True)
        with mock.patch.object(subject, "PROBE_OUTPUT_MAX_DEPTH", 1):
            self.refused("PROBE_OUTPUT_BOUNDS")
        for index in range(3):
            (self.root / f"f{index}").write_bytes(b"x")
        with mock.patch.object(subject, "PROBE_OUTPUT_MAX_ENTRIES", 2):
            self.refused("PROBE_OUTPUT_BOUNDS")

    def test_replaced_root_refused(self):
        shutil.rmtree(self.root)
        os.symlink(self.base, self.root)
        self.refused("PROBE_OUTPUT_ROOT")


# --------------------------------------------------------------------------- runner custody


class RunnerCustodyTests(unittest.TestCase):
    ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/inert-home",
           "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}

    def test_lease_mode_refuses_forced_and_pruning_removal_before_execution(self):
        inner = InertRunner()
        runner = subject.IsolatedClientRunner(inner, self.ENV, lease_custody=True)
        for argv in (["docker", "rm", "-f", "x"], ["docker", "rmi", "-f", "t"], ["docker", "rm", "--force", "x"],
                     ["docker", "container", "rm", "--force", "x"], ["docker", "image", "rm", "-f", "t"],
                     ["docker", "image", "prune", "-a"], ["docker", "container", "prune"],
                     ["docker", "system", "prune", "-a"], ["docker", "rmi", "--force=true", "t"]):
            with self.subTest(argv=argv), self.assertRaises(subject.PublicationError) as got:
                runner.run(argv)
            self.assertEqual(got.exception.code, "ARCHARM_FORCED_CLEANUP")
        self.assertEqual(inner.argv, [])

    def test_lease_mode_delegates_identity_bound_cleanup_without_tracking(self):
        inner = InertRunner()
        runner = subject.IsolatedClientRunner(inner, self.ENV, lease_custody=True)
        for argv in (["docker", "create", "--name", "c", "img"], ["docker", "run", "-d", "--name", "c2", "img"],
                     ["docker", "container", "stop", "--time", "10", "0" * 64],
                     ["docker", "container", "rm", "0" * 64], ["docker", "image", "rm", "--no-prune", "tag"]):
            runner.run(argv)
        self.assertEqual(len(inner.argv), 5)
        self.assertEqual(runner.retained_resources, set())

    def test_default_mode_custody_unchanged(self):
        inner = InertRunner()
        runner = subject.IsolatedClientRunner(inner, self.ENV)
        self.assertFalse(runner.lease_custody)
        runner.run(["docker", "run", "--name", "c", "img", "true"])
        self.assertEqual(runner.retained_resources, {("container", "c")})
        runner.run(["docker", "rm", "-f", "c"])
        self.assertEqual(runner.retained_resources, set())

    def test_signing_material_never_reaches_client_commands(self):
        for lease_custody in (False, True):
            runner = subject.IsolatedClientRunner(InertRunner(), self.ENV, lease_custody=lease_custody)
            for env in ({"PACKAGE_SIGNING_KEY": "x"}, {"PACKAGE_SIGNING_PASSPHRASE": "x"}, {"GNUPGHOME": "/h"},
                        {"GPG_TTY": "x"}, {"GH_TOKEN": "x"}, {"GITHUB_TOKEN": "x"}):
                with self.subTest(lease_custody=lease_custody, env=env), \
                        self.assertRaises(subject.PublicationError) as got:
                    runner.run(["docker", "version"], env=env)
                self.assertEqual(got.exception.code, "CLIENT_ENV_CREDENTIAL_LEAK")
        with self.assertRaises(subject.PublicationError):
            subject.IsolatedClientRunner(InertRunner(), dict(self.ENV, PACKAGE_SIGNING_KEY="x"), lease_custody=True)


# --------------------------------------------------------------------------- qualify_lane routing


@unittest.skipUnless(NONROOT, "lane routing assertions require a nonroot runner identity")
class QualifyLaneRouteTests(_Temp):
    def setUp(self):
        super().setUp()
        self.public = self.base / "public"
        (self.public / "keys").mkdir(parents=True)
        shutil.copyfile(ROOT / "keys" / subject.COMMITTED_PUBLIC_KEY_FILENAME,
                        self.public / "keys" / subject.COMMITTED_PUBLIC_KEY_FILENAME)
        self.r_root = self.base / "r"
        self.work = self.base / "work"
        self.work.mkdir(mode=0o700)
        self.cycles = []
        self.cycle_writer = None
        self.provisioners = {}

    def admitted(self, lane):
        return {"lane": lane, "destination": str(self.public), "inventory": {}, **SOURCE,
                "qualification_run_id": 7, "artifact_id": 8, "artifact_digest_sha256": "9" * 64,
                "public_inventory_sha256": "8" * 64, "public_file_count": 0}

    def fake_cycle(self, host, spec, **kwargs):
        self.cycles.append({"host": host, "spec": spec, "kwargs": kwargs,
                            "closed_at_call": self.sdk.closed if hasattr(self, "sdk") else None})
        if self.cycle_writer and "burst_scratch" in kwargs:
            self.cycle_writer(Path(kwargs["burst_scratch"]))
        return [{"name": kwargs["prefix"] + ".inert", "status": "pass"}], {}

    def run_lane(self, lane, machine, *, sdk=None, inner=None):
        inner = inner or InertRunner()
        gpg_sha256 = hashlib.sha256(b"K").hexdigest()
        bound = {"schema": subject.crb.BINDING_SCHEMA, "status": "bound", "r_command_contract_sha256": "3" * 64,
                 "p_command_contract_sha256": "2" * 64, "release_record_sha256": {}, "commands": [],
                 "native_client_execution": False, "publication_authority": False}
        for name, result in (("prepare_environment", {"image_ref": "inert"}),
                             ("provision_image", None), ("provision", {"image_ref": "inert/arch@sha256:" + "0" * 64,
                                                                       "preprovisioned_packages": ["base"]}),
                             ("resolve_targets", {}), ("prepare_client", {}), ("verify_client_image", "inert")):
            self.provisioners[name] = Forbidden(name, result)
        with ExitStack() as stack:
            enter = stack.enter_context
            enter(mock.patch.object(subject.rp, "verify_tree", lambda *a, **k: None))
            enter(mock.patch.object(subject, "authenticate_and_prepare_public_trust",
                                    lambda *a, **k: {"gpg_path": self.base / "inert.gpg", "gpg_sha256": gpg_sha256}))
            enter(mock.patch.object(subject, "derive_burst_record_from_p_contract",
                                    lambda *a, **k: (BURST_RECORD, "1" * 64)))
            enter(mock.patch.object(subject, "authenticate_p_command_contracts", lambda *a, **k: ({}, "2" * 64)))
            enter(mock.patch.object(subject, "_read_checked_json", lambda *a, **k: ({}, b"K")))
            enter(mock.patch.object(subject, "_read_checked_public_key", lambda *a, **k: b"K"))
            enter(mock.patch.object(subject, "_read_checked_raw", lambda *a, **k: b"K"))
            enter(mock.patch.object(subject, "archarm_runner_identity", lambda **k: (self.uid, self.gid)))
            enter(mock.patch.object(subject.crb, "bind_current_commands", lambda *a, **k: dict(bound)))
            enter(mock.patch.object(subject.crb, "_checked_contracts", lambda *a, **k: (None, "2" * 64, "3" * 64)))
            enter(mock.patch.object(hosted_deb, "pacman_spec", _pacman_spec_with_architecture(REAL_PACMAN_SPEC)))
            enter(mock.patch.object(hosted_deb, "client_cycle", self.fake_cycle))
            enter(mock.patch.object(hosted_deb, "prepare_environment", self.provisioners["prepare_environment"]))
            enter(mock.patch.object(hosted_deb, "provision_image", self.provisioners["provision_image"]))
            enter(mock.patch.object(hosted_native, "provision", self.provisioners["provision"]))
            enter(mock.patch.object(hosted_pins, "resolve_targets", self.provisioners["resolve_targets"]))
            enter(mock.patch.object(rpm_client_runtime, "prepare_client", self.provisioners["prepare_client"]))
            enter(mock.patch.object(rpm_client_runtime, "verify_client_image", self.provisioners["verify_client_image"]))
            enter(mock.patch.dict(sys.modules, {subject.ARCHARM_SDK_MODULE: sdk.module if sdk else None}))
            evidence = subject.qualify_lane(
                self.admitted(lane), p_root=ROOT, r_root=self.r_root, work_dir=self.work,
                recheck_fn=lambda: None, client=object(), inner_runner=inner,
                uname_fn=lambda: _uname("Linux", subject.LANE_SPECS[lane].host_machine if machine is None else machine))
        return evidence, inner

    def gate(self, evidence, name):
        rows = [row for row in evidence["gates"] if row["name"] == name]
        self.assertEqual(len(rows), 1, name)
        return rows[0]

    def old_provisioner_calls(self):
        return {name: fake.calls for name, fake in self.provisioners.items() if fake.calls}

    def write_probe_receipt(self, scratch):
        (scratch / "theme-forge-stellar-burst").mkdir(mode=0o755)
        (scratch / "theme-forge-stellar-burst" / "receipt.json").write_bytes(b"{}")

    def test_arm_route_passes_the_held_sdk_lease_not_the_old_provisioner(self):
        self.sdk = FakeSdk(self.r_root)
        self.cycle_writer = self.write_probe_receipt
        evidence, inner = self.run_lane(ARM, None, sdk=self.sdk)
        self.assertEqual(self.old_provisioner_calls(), {})
        self.assertEqual(len(self.sdk.calls), 1)
        call = self.sdk.calls[0]
        self.assertEqual(type(call["host"]).__name__, "RecordingRunner")
        self.assertIsInstance(call["host"].inner, subject.IsolatedClientRunner)
        self.assertTrue(call["host"].inner.lease_custody)
        self.assertEqual((call["workspace"], call["uid"], call["gid"]),
                         (self.work / subject.ARCHARM_SDK_WORKSPACE, self.uid, self.gid))
        self.assertEqual(call["context"], subject.archarm_sdk_context(_expected_context(), self.admitted(ARM)["qualification_run_id"]))
        (cycle,) = self.cycles
        (lease,) = self.sdk.leases
        self.assertIs(cycle["kwargs"]["sdk_lease"], lease)
        self.assertIs(type(cycle["kwargs"]["sdk_lease"]), self.sdk.lease_type)
        self.assertIs(cycle["host"], call["host"])
        self.assertEqual(cycle["kwargs"]["image"], lease.image)
        self.assertEqual(cycle["kwargs"]["platform"], "linux/arm64")
        self.assertEqual(cycle["kwargs"]["system"], "aarch64-linux")
        self.assertEqual(cycle["kwargs"]["generation"], gh.CURRENT_GENERATION)
        self.assertEqual(cycle["kwargs"]["prefix"], f"client.{ARM}")
        self.assertIsNone(cycle["kwargs"]["smoke"])
        self.assertEqual(cycle["kwargs"]["burst_scratch"], self.work / subject.ARCHARM_PROBE_OUTPUT)
        self.assertIn("Architecture = aarch64", cycle["spec"]["configure"][0][-1])
        self.assertEqual(cycle["closed_at_call"], 0)
        self.assertEqual(self.sdk.closed, 1)
        self.assertFalse(any(subject._forced_or_pruning_docker(argv) for argv in inner.argv))
        self.assertEqual(self.gate(evidence, f"client.{ARM}.probe-output-custody")["status"], "pass")
        self.assertEqual(evidence["archarm_sdk"], {
            "route": subject.ARCHARM_SDK_MODULE, "lease_verified": True, "lease_cleanup": "complete",
            "registry_provisioner_used": False, "probe_output_counts": {"directories": 1, "files": 1, "bytes": 2},
            "context": subject.archarm_sdk_context(_expected_context(), self.admitted(ARM)["qualification_run_id"])})
        self.assertEqual((evidence["cleanup_complete"], evidence["retained_custody_count"]), (True, 0))
        # Fakes never confer native authority.
        self.assertEqual((evidence["all_commands_executed"], evidence["overall_status"]), (False, "fail"))
        self.assertEqual((evidence["lane"], evidence["system"], evidence["platform"]),
                         (ARM, "aarch64-linux", "linux/arm64"))

    def test_x86_route_unchanged_and_never_touches_the_sdk(self):
        self.sdk = FakeSdk(self.r_root)
        evidence, inner = self.run_lane(X86, None, sdk=self.sdk)
        self.assertEqual(self.sdk.calls, [])
        provision = self.provisioners["provision"].calls
        self.assertEqual([args[:2] for args, _ in provision], [("pacman", "x86_64-linux")])
        (image_call,) = self.provisioners["provision_image"].calls
        self.assertEqual(image_call[0][1:4], ("pacman", "inert/arch@sha256:" + "0" * 64, "linux/amd64"))
        self.assertEqual(image_call[0][5], ["base", "python", "xorg-server-xvfb", "dbus"])
        (cycle,) = self.cycles
        self.assertEqual(set(cycle["kwargs"]), {"image", "platform", "products", "repository", "prefix", "smoke",
                                                "system", "burst_record", "burst_scratch", "generation"})
        self.assertEqual(cycle["kwargs"]["burst_scratch"], self.work / "burst-scratch")
        self.assertEqual(cycle["kwargs"]["platform"], "linux/amd64")
        self.assertIn("Architecture = x86_64", cycle["spec"]["configure"][0][-1])
        tag = image_call[0][4]
        self.assertTrue(tag.startswith(f"tf-client-{X86}:"))
        self.assertEqual(inner.argv, [["docker", "rmi", "-f", tag]])
        self.assertFalse((self.work / subject.ARCHARM_PROBE_OUTPUT).exists())
        self.assertNotIn("archarm_sdk", evidence)
        self.assertFalse(any("probe-output-custody" in row["name"] for row in evidence["gates"]))

    def test_arm_lane_on_x86_host_refused_before_any_work(self):
        self.sdk = FakeSdk(self.r_root)
        with self.assertRaises(subject.PublicationError) as got:
            self.run_lane(ARM, "x86_64", sdk=self.sdk)
        self.assertEqual(got.exception.code, "HOST_ARCHITECTURE_MISMATCH")
        self.assertEqual((self.sdk.calls, self.cycles, os.listdir(self.work)), ([], [], []))

    def assert_refused_setup(self, evidence, code):
        self.assertEqual(self.gate(evidence, f"client.{ARM}.setup"), {
            "name": f"client.{ARM}.setup", "status": "fail", "reason": code})
        self.assertEqual(self.cycles, [])
        self.assertEqual(self.old_provisioner_calls(), {})
        self.assertEqual(evidence["overall_status"], "fail")

    def test_forged_lease_from_sdk_refused_and_still_closed(self):
        self.sdk = FakeSdk(self.r_root, mutate=lambda lease: types.SimpleNamespace(**vars(lease)))
        evidence, _ = self.run_lane(ARM, None, sdk=self.sdk)
        self.assert_refused_setup(evidence, "ARCHARM_LEASE_FORGED")
        self.assertEqual(self.sdk.closed, 1)
        self.assertEqual(evidence["archarm_sdk"]["lease_verified"], False)
        self.assertEqual(self.gate(evidence, f"client.{ARM}.probe-output-custody")["reason"], "writers-not-quiesced")

    def test_wrong_generation_family_system_lease_refused(self):
        for key, value in (("generation", "theme-forge-historical"), ("family", "dnf"), ("system", "x86_64-linux")):
            def mutate(lease, key=key, value=value):
                lease.context = dict(lease.context, **{key: value})
                return lease
            with self.subTest(key=key):
                shutil.rmtree(self.work)
                self.work.mkdir(mode=0o700)
                self.cycles = []
                self.sdk = FakeSdk(self.r_root, mutate=mutate)
                evidence, _ = self.run_lane(ARM, None, sdk=self.sdk)
                self.assert_refused_setup(evidence, "ARCHARM_LEASE_CONTEXT")
                self.assertEqual(self.sdk.closed, 1)

    def test_missing_sdk_fails_closed_without_online_fallback(self):
        evidence, inner = self.run_lane(ARM, None, sdk=None)
        self.assert_refused_setup(evidence, "ARCHARM_SDK_UNAVAILABLE")
        self.assertEqual(inner.argv, [])

    def test_unproven_lease_close_is_retained_and_blocks_custody(self):
        self.sdk = FakeSdk(self.r_root, exit_error=True)
        self.cycle_writer = self.write_probe_receipt
        evidence, inner = self.run_lane(ARM, None, sdk=self.sdk)
        self.assertEqual(self.sdk.closed, 1)
        self.assertEqual(evidence["archarm_sdk"]["lease_cleanup"], "failed")
        self.assertEqual((evidence["cleanup_complete"], evidence["retained_custody_count"]), (False, 1))
        self.assertEqual(self.gate(evidence, f"client.{ARM}.probe-output-custody"),
                         {"name": f"client.{ARM}.probe-output-custody", "status": "fail",
                          "reason": "writers-not-quiesced"})
        self.assertEqual(inner.argv, [])  # P never force-removes lease resources

    def test_unsafe_probe_output_fails_custody_gate(self):
        def unsafe(scratch):
            os.symlink("/etc", scratch / "escape")
        self.sdk = FakeSdk(self.r_root)
        self.cycle_writer = unsafe
        evidence, _ = self.run_lane(ARM, None, sdk=self.sdk)
        self.assertEqual(self.gate(evidence, f"client.{ARM}.probe-output-custody"),
                         {"name": f"client.{ARM}.probe-output-custody", "status": "fail",
                          "reason": "PROBE_OUTPUT_SYMLINK"})
        self.assertIsNone(evidence["archarm_sdk"]["probe_output_counts"])

    def test_no_signing_or_token_environment_reaches_the_arm_client(self):
        self.sdk = FakeSdk(self.r_root)
        names = ("PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE", "GH_TOKEN", "GNUPGHOME")
        with mock.patch.dict(os.environ, {name: "inert-not-a-secret" for name in names}):
            self.run_lane(ARM, None, sdk=self.sdk)
            for name in names:
                self.assertEqual(os.environ[name], "inert-not-a-secret")
        (call,) = self.sdk.calls
        self.assertLessEqual(set(call["environ"]), set(cai.ALLOWED_CLIENT_ENV_KEYS))
        self.assertEqual(call["environ"]["HOME"], str(self.work / "client-home"))

    def test_caller_lease_knob_is_not_an_interface(self):
        import inspect
        params = set(inspect.signature(subject.qualify_lane).parameters)
        self.assertFalse({"sdk_lease", "lease", "sdk", "acquire_sdk"} & params)
        fields = {f.name for f in __import__("dataclasses").fields(cai.ClientInputOptions)}
        self.assertFalse({"sdk_lease", "lease", "sdk_image", "sdk_context"} & fields)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *remaining])
