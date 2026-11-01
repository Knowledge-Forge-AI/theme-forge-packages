"""Pure tests for the non-admitting lifecycle entrypoint.

All agent and platform seams are substituted.  No GnuPG, RPM, Docker, key,
secret, native process, or external workflow is used by this test module.
"""

from __future__ import annotations

import contextlib
from dataclasses import replace
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import types
from typing import Mapping
import unittest
from unittest.mock import patch

_MODULE_DIR = str(Path(__file__).resolve(strict=True).parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

import b3_fixture_entrypoint as entry
import b3_fixture_inputs as inputs
import b3_fixture_workspace as workspace


CANONICAL_COMMIT = "a" * 40
CANONICAL_SOURCE_SHA = "b" * 64
OWNED_SOURCE_SHA = "c" * 64


def _images() -> dict[str, str]:
    return entry._load_image_catalog()


def _current_images() -> dict[str, str]:
    return entry._load_image_catalog(entry.CURRENT_TOOLCHAIN_CATALOG_PATH, entry.CURRENT_TOOLCHAIN_CATALOG_SHA256)


def _spec() -> entry.FixtureSpec:
    return entry.FixtureSpec(
        canonical_commit=CANONICAL_COMMIT,
        canonical_source_bytes=106371,
        canonical_source_sha256=CANONICAL_SOURCE_SHA,
        option_table_lines="160-318",
        canonical_disposition_path=Path("/fixture/canonical.json"),
        owned_agent_source=Path("/fixture/owned_gpg_agent.py"),
        owned_agent_source_sha256=OWNED_SOURCE_SHA,
        target_gnupg_version="2.4.9",
        target_agent_mode="--supervised",
        target_rpm_version="6.0.2",
        images=_images(),
        image_catalog_path=entry.IMAGE_CATALOG_PATH,
        image_catalog_sha256=entry.IMAGE_CATALOG_SHA256,
    )


def _current_spec() -> entry.FixtureSpec:
    return replace(
        _spec(),
        images=_current_images(),
        image_catalog_path=entry.CURRENT_TOOLCHAIN_CATALOG_PATH,
        image_catalog_sha256=entry.CURRENT_TOOLCHAIN_CATALOG_SHA256,
    )


def _facts(mode: str = "fixture") -> dict[str, object]:
    return {
        "schema": entry.FACTS_SCHEMA,
        "execution_mode": mode,
        "tools": {
            name: {
                "path": path,
                "version_line": f"{name} (GnuPG) 2.4.9",
                "sha256": hashlib.sha256(f"fixture:{path}".encode("utf-8")).hexdigest(),
            }
            for name, path in entry.NATIVE_TOOLS.items()
        },
        "images": _images(),
    }


def _bind_inert_socket(directory: Path, name: str) -> None:
    cwd = os.getcwd()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.chdir(directory)
        sock.bind(name)
    finally:
        os.chdir(cwd)
        sock.close()


class _FakeAgent:
    instances: list["_FakeAgent"] = []
    start_error: BaseException | None = None
    close_error: BaseException | None = None

    def __init__(self, home: str | os.PathLike[str], job_root: str | os.PathLike[str]):
        self.home = Path(home)
        self.job = Path(job_root)
        self.events: list[str] = ["construct"]
        self.cleanup_confirmed = False
        type(self).instances.append(self)

    def start(self):
        self.events.append("start")
        if type(self).start_error is not None:
            raise type(self).start_error
        return self

    def require_live(self):
        self.events.append("require_live")

    def close(self):
        self.events.append("close")
        if type(self).close_error is not None:
            raise type(self).close_error
        self.cleanup_confirmed = True


def _fake_proc_preflight() -> None:
    return None


def _fake_preflight_external_paths(expected: object = None) -> types.SimpleNamespace:
    return types.SimpleNamespace(alias_target="/run", expected=expected)


def _fake_exe(pid: int) -> types.SimpleNamespace:
    if not isinstance(pid, int):
        raise TypeError("pid must be int")
    return types.SimpleNamespace(dev=1, ino=2, uid=0, mode=0o755, kind=stat.S_IFREG)


def _fake_trusted_tool(path: str) -> tuple[types.SimpleNamespace, str]:
    if not isinstance(path, str):
        raise TypeError("path must be str")
    return (
        types.SimpleNamespace(dev=1, ino=2, uid=0, mode=0o755, kind=stat.S_IFREG),
        hashlib.sha256(f"fixture:{path}".encode("utf-8")).hexdigest(),
    )


def _fake_bind_gpgconf_paths(
    records: Mapping[str, str], *, homedir: Path, job_root: Path
) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        homedir=homedir,
        job_root=job_root,
        socketdir=homedir,
        agent_socket=homedir / "S.gpg-agent",
    )


def _fake_module() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        OwnedGpgAgent=_FakeAgent,
        TARGET_GNUPG_VERSION="2.4.9",
        NATIVE_GPGCONF="/usr/bin/gpgconf",
        NATIVE_GPG_AGENT="/usr/bin/gpg-agent",
        NATIVE_GPG="/usr/bin/gpg",
        _proc_preflight=_fake_proc_preflight,
        _preflight_external_paths=_fake_preflight_external_paths,
        _exe=_fake_exe,
        _trusted_tool=_fake_trusted_tool,
        bind_gpgconf_paths=_fake_bind_gpgconf_paths,
    )


class _RootReplacementAgent(_FakeAgent):
    def close(self):
        super().close()
        original = self.job.with_name(self.job.name + "-original")
        self.job.rename(original)
        self.job.mkdir(mode=0o700)
        (self.job / "foreign").write_text("replacement", encoding="utf-8")


class _HomeReplacementAgent(_FakeAgent):
    def close(self):
        super().close()
        original = self.home.with_name("home-original")
        self.home.rename(original)
        self.home.mkdir(mode=0o700)
        (self.home / "foreign").write_text("replacement", encoding="utf-8")


class _ForeignEntryAgent(_FakeAgent):
    def close(self):
        super().close()
        (self.home / "foreign").write_text("unowned", encoding="utf-8")


class _ParentReplacementAgent(_FakeAgent):
    def close(self):
        super().close()
        parent = self.job.parent
        original = parent.with_name(parent.name + "-original")
        parent.rename(original)
        parent.mkdir(mode=0o700)
        (parent / "foreign").write_text("replacement", encoding="utf-8")


class _NativeReceiptShapeAgent(_FakeAgent):
    tool_digests: dict[str, str] | None = None

    def __init__(self, home: str | os.PathLike[str], job_root: str | os.PathLike[str]):
        super().__init__(home, job_root)
        self.receipt = types.SimpleNamespace(
            schema="tf.owned-gpg-agent-lifecycle.v3",
            status="owned-agent-running",
            evidence_class="native-unqualified",
            production_authority=False,
        )
        self.paths = types.SimpleNamespace(
            homedir=self.home,
            job_root=self.job,
            agent_socket=self.home / "S.gpg-agent",
            socketdir=self.home,
        )
        digests = type(self).tool_digests or {
            path: hashlib.sha256(f"fixture:{path}".encode("utf-8")).hexdigest()
            for path in entry.NATIVE_TOOLS.values()
        }
        self.retained_custody = types.SimpleNamespace(
            reaped=False,
            pidfd=123,
            tools={
                path: (
                    types.SimpleNamespace(dev=1, ino=2, uid=0, mode=0o755, kind=stat.S_IFREG),
                    digest,
                )
                for path, digest in digests.items()
            },
        )

    def close(self):
        super().close()
        self.retained_custody.reaped = True
        self.retained_custody.pidfd = None


def _fake_stage2_command_runner(argv: list[str]) -> tuple[int, str]:
    tool = Path(argv[0]).name
    if argv[-1] == "--version":
        if tool in {"gpgconf", "gpg-agent", "gpg"}:
            return 0, f"{tool} (GnuPG) 2.4.9"
        if tool in {"rpm", "rpmsign"}:
            return 0, "RPM version 6.0.2"
    if len(argv) >= 5 and argv[1] == "--homedir" and argv[3] == "--list-dirs":
        home = argv[2]
        field = argv[4]
        mapping = {
            "sysconfdir": "/etc/gnupg",
            "homedir": home,
            "socketdir": home,
            "agent-socket": f"{home}/S.gpg-agent",
        }
        return 0, mapping[field]
    return 1, ""


class FixtureEntrypointTests(unittest.TestCase):
    def setUp(self):
        _FakeAgent.instances.clear()
        _FakeAgent.start_error = None
        _FakeAgent.close_error = None
        _NativeReceiptShapeAgent.tool_digests = None
        self.parent = Path(tempfile.mkdtemp(prefix="tf-b3-test-"))
        self.parent.chmod(0o700)
        self.addCleanup(lambda: shutil.rmtree(self.parent, ignore_errors=True))

    def test_default_invocation_refuses_without_loading_or_executing(self):
        output = io.StringIO()
        with patch.object(entry, "load_manifest", side_effect=AssertionError("must refuse first")), contextlib.redirect_stdout(output):
            code = entry.main([])
        self.assertEqual(code, 2)
        value = json.loads(output.getvalue())
        self.assertEqual(value["error_code"], "NATIVE_EXECUTION_EXPLICIT_REQUIRED")
        self.assertFalse(value["production_authority"])

    def test_manifest_derives_canonical_identity_from_machine_json(self):
        canonical = {"canonicalCommit": CANONICAL_COMMIT, "canonicalAgentBytes": 106371,
                     "canonicalAgentSha256": CANONICAL_SOURCE_SHA, "optionTableVerifiedLines": "160-318"}
        manifest = {
            "schema": entry.SCHEMA,
            "production_authority": False,
            "canonical_disposition": {
                "path": "inputs/CANONICAL-C6-SUBSET.json",
                "sha256": entry.CANONICAL_SUBSET_SHA256,
            },
            "owned_agent": {"path": "inputs/owned_gpg_agent.py", "sha256": entry.REVIEWED_C6_SOURCE_SHA256},
            "image_catalog": {
                "path": "inputs/DIST1-VALIDATION-WORKFLOW-CONTRACT.json",
                "sha256": entry.IMAGE_CATALOG_SHA256,
                "selectors": dict(entry.IMAGE_CATALOG_SELECTORS),
            },
            "target": {"gnupg_version": "2.4.9", "agent_mode": "--supervised", "rpm_version": "6.0.2",
                       "images": _images()},
        }
        spec = entry.validate_manifest(manifest, canonical_data=canonical)
        self.assertEqual(spec.canonical_commit, CANONICAL_COMMIT)
        self.assertEqual(spec.canonical_source_sha256, CANONICAL_SOURCE_SHA)
        self.assertEqual(len(spec.canonical_commit), 40)

    def test_real_c6_source_loader_registers_module_without_starting_agent(self):
        manifest_path = Path(__file__).with_name("manifest.json")
        spec = entry.load_manifest(manifest_path)
        module = entry._load_owned_agent(spec)
        self.assertIs(sys.modules[module.__name__], module)
        self.assertEqual(module.OwnedGpgAgent.__module__, module.__name__)
        self.assertEqual(module.TARGET_GNUPG_VERSION, "2.4.9")

    def test_owned_source_hash_refusal_precedes_source_execution(self):
        real_spec = entry.load_manifest(Path(__file__).with_name("manifest.json"))
        with tempfile.TemporaryDirectory(prefix="tf-b3-tampered-") as raw_dir:
            tampered = Path(raw_dir) / "owned_gpg_agent.py"
            tampered.write_bytes(real_spec.owned_agent_source.read_bytes() + b"\n# tampered\n")
            with self.assertRaisesRegex(entry.FixtureError, "REVIEWED_SOURCE_REQUIRED"):
                entry._load_owned_agent(replace(real_spec, owned_agent_source=tampered))

    def test_manifest_rejects_caller_owned_source_hash_even_with_machine_fields(self):
        real_spec = entry.load_manifest(Path(__file__).with_name("manifest.json"))
        raw = json.loads(Path(__file__).with_name("manifest.json").read_text(encoding="utf-8"))
        raw["owned_agent"]["sha256"] = "0" * 64
        canonical = json.loads(real_spec.canonical_disposition_path.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(entry.FixtureError, "REVIEWED_SOURCE_REQUIRED"):
            entry.validate_manifest(raw, canonical_data=canonical)

    def test_manifest_rejects_absolute_or_traversal_input_roles(self):
        raw = json.loads(Path(__file__).with_name("manifest.json").read_text(encoding="utf-8"))
        raw["canonical_disposition"]["path"] = "../inputs/CANONICAL-C6-SUBSET.json"
        canonical = json.loads(entry.CANONICAL_SUBSET_PATH.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(entry.FixtureError, "PORTABLE_PATH"):
            entry.validate_manifest(raw, canonical_data=canonical)

    def test_bounded_json_read_refuses_oversized_input(self):
        with tempfile.TemporaryDirectory(prefix="tf-b3-json-cap-") as raw_dir:
            path = Path(raw_dir) / "oversized.json"
            path.write_bytes(b"{" + b"x" * inputs.MAX_JSON_BYTES + b"}")
            with self.assertRaisesRegex(entry.FixtureError, "TOO_LARGE"):
                inputs._read_json(path, "oversized input")

    def test_cleanup_failure_closes_wrapper_fds_but_retains_filesystem(self):
        binding = workspace._fresh_workspace(self.parent)
        (binding.home / "foreign").write_text("retained", encoding="utf-8")
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
            workspace._remove_fresh_workspace(binding)
        self.assertEqual(raised.exception.sanitized_detail, {
            "workspace_removed_confirmed": False, "unexpected_root_entry_count": 0, "unexpected_home_entry_count": 1,
            "home_diagnostics_status": "complete", "home_entries_inspected_count": 1, "home_entries_truncated": False,
            "home_entry_category_counts": {
                "private_keys_directory": 0, "random_seed": 0, "primary_socket": 0, "extra_socket": 0,
                "browser_socket": 0, "ssh_socket": 0, "common_config": 0, "other": 1,
            },
            "home_entry_type_counts": {
                "regular": 1, "directory": 0, "symlink": 0, "socket": 0, "other": 0, "vanished": 0, "unreadable": 0,
            },
            "private_keys_directory": {
                "present": False, "status": "absent", "identity_verified": False,
                "empty": False, "entry_count": 0, "truncated": False,
            },
        })
        for fd in (binding.parent_fd, binding.root_fd, binding.home_fd):
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertTrue(binding.root.is_dir())
        self.assertEqual((binding.home / "foreign").read_text(encoding="utf-8"), "retained")
        shutil.rmtree(binding.root)

    def test_facts_reject_wrong_image_or_tool_version_before_agent(self):
        facts = _facts()
        facts["images"] = {**_images(), "rpm": "foreign@sha256:" + "e" * 64}
        with self.assertRaisesRegex(entry.FixtureError, "FACTS_IMAGES"):
            entry.run_lifecycle(_spec(), facts, self.parent, module_loader=lambda _: self.fail("not loaded"),
                                support_checker=lambda: self.fail("not checked"), fixture_seam=True)

    def test_unsupported_platform_refuses_before_workspace_creation(self):
        with self.assertRaisesRegex(entry.FixtureError, "UNSUPPORTED_PLATFORM"):
            entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=lambda _: _fake_module(),
                                support_checker=lambda: (_ for _ in ()).throw(entry.FixtureError("UNSUPPORTED_PLATFORM")),
                                fixture_seam=True)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_successful_fixture_seam_uses_real_entrypoint_control_flow_and_is_nonadmitting(self):
        receipt = entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=lambda _: _fake_module(),
                                      support_checker=lambda: None, fixture_seam=True)
        self.assertEqual(receipt["evidence_class"], "fixture-only-substituted")
        self.assertFalse(receipt["native_execution_observed"])
        self.assertFalse(receipt["production_authority"])
        self.assertEqual(receipt["cleanup"]["held_process_cleanup_confirmed"], "not-observed")
        self.assertTrue(receipt["cleanup"]["workspace_removed_confirmed"])
        self.assertEqual(receipt["tool_facts"]["attestation"], "caller-declared-not-measured")
        self.assertEqual(_FakeAgent.instances[0].events, ["construct", "start", "require_live", "close"])
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_native_receipt_shape_derives_cleanup_and_binding_from_fake_state(self):
        receipt = entry.run_lifecycle(_spec(), _facts("hosted-native"), self.parent,
                                      module_loader=lambda _: types.SimpleNamespace(
                                          OwnedGpgAgent=_NativeReceiptShapeAgent),
                                      support_checker=lambda: None, fixture_seam=False)
        self.assertEqual(receipt["gpgconf_binding"]["status"], "bound")
        self.assertTrue(receipt["cleanup"]["held_process_cleanup_confirmed"])
        self.assertTrue(receipt["cleanup"]["socket_disappearance_confirmed"])
        self.assertTrue(receipt["cleanup"]["workspace_removed_confirmed"])
        self.assertEqual(receipt["tool_facts"]["attestation"], "caller-declared-not-measured")
        self.assertFalse(receipt["production_authority"])

    def test_start_failure_still_closes_and_removes_only_confirmed_workspace(self):
        _FakeAgent.start_error = RuntimeError("fixture start")
        with self.assertRaisesRegex(entry.FixtureError, "LIFECYCLE_FAILED"):
            entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=lambda _: _fake_module(),
                                support_checker=lambda: None, fixture_seam=True)
        self.assertEqual(_FakeAgent.instances[0].events, ["construct", "start", "close"])
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_cleanup_failure_retains_fresh_home_and_reports_custody(self):
        _FakeAgent.close_error = RuntimeError("fixture cleanup")
        with self.assertRaisesRegex(entry.FixtureError, "CUSTODY_RETAINED") as raised:
            entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=lambda _: _fake_module(),
                                support_checker=lambda: None, fixture_seam=True)
        self.assertTrue(raised.exception.retained_custody)
        self.assertIsNotNone(raised.exception.retained_root)
        retained = raised.exception.retained_root
        self.assertTrue(retained.is_dir())
        self.assertTrue((retained / "home").is_dir())
        shutil.rmtree(retained)

    def test_root_identity_replacement_retains_replacement_and_original(self):
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_IDENTITY_CHANGED") as raised:
            entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=lambda _: types.SimpleNamespace(
                OwnedGpgAgent=_RootReplacementAgent), support_checker=lambda: None, fixture_seam=True)
        retained = raised.exception.retained_root
        self.assertTrue(raised.exception.retained_custody)
        self.assertEqual((retained / "foreign").read_text(encoding="utf-8"), "replacement")
        self.assertTrue((retained.with_name(retained.name + "-original") / "home").is_dir())

    def test_home_identity_replacement_retains_replacement(self):
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_IDENTITY_CHANGED") as raised:
            entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=lambda _: types.SimpleNamespace(
                OwnedGpgAgent=_HomeReplacementAgent), support_checker=lambda: None, fixture_seam=True)
        retained = raised.exception.retained_root
        self.assertTrue(raised.exception.retained_custody)
        self.assertTrue(raised.exception.sanitized_detail["lifecycle_progress"]["closed_observation_returned"])
        self.assertEqual((retained / "home" / "foreign").read_text(encoding="utf-8"), "replacement")

    def test_parent_identity_replacement_retains_foreign_parent(self):
        original_parent = self.parent.with_name(self.parent.name + "-original")
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_IDENTITY_CHANGED") as raised:
            entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=lambda _: types.SimpleNamespace(
                OwnedGpgAgent=_ParentReplacementAgent), support_checker=lambda: None, fixture_seam=True)
        self.assertTrue(raised.exception.retained_custody)
        self.assertEqual((self.parent / "foreign").read_text(encoding="utf-8"), "replacement")
        self.assertTrue(any(original_parent.iterdir()))
        shutil.rmtree(original_parent)

    def test_foreign_entry_retains_exact_workspace_and_reports_custody(self):
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
            entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=lambda _: types.SimpleNamespace(
                OwnedGpgAgent=_ForeignEntryAgent), support_checker=lambda: None, fixture_seam=True)
        retained = raised.exception.retained_root
        self.assertTrue(raised.exception.retained_custody)
        self.assertEqual((retained / "home" / "foreign").read_text(encoding="utf-8"), "unowned")

    def test_native_facts_are_required_for_nonfixture_path(self):
        with self.assertRaisesRegex(entry.FixtureError, "NATIVE_FACTS_REQUIRED"):
            entry.run_lifecycle(_spec(), _facts("fixture"), self.parent, module_loader=lambda _: self.fail("not loaded"),
                                support_checker=lambda: None, fixture_seam=False)

    def test_entrypoint_contains_no_generic_gpgconf_kill_or_secret_argv_interface(self):
        source = Path(entry.__file__).read_text(encoding="utf-8")
        self.assertNotIn("--kill", source)
        self.assertNotIn("rmtree", source)
        for forbidden_flag in ("--passphrase", "--private-key", "--secret-key", "--key-file"):
            self.assertNotIn(forbidden_flag, source)

    def test_facts_with_secret_field_are_rejected_before_agent(self):
        facts = _facts()
        facts["passphrase"] = "must never be accepted"
        with self.assertRaisesRegex(entry.FixtureError, "FACTS_SECRET_FIELD"):
            entry.run_lifecycle(_spec(), facts, self.parent, module_loader=lambda _: self.fail("not loaded"),
                                support_checker=lambda: self.fail("not checked"), fixture_seam=True)

    def test_current_toolchain_catalog_distinguishes_bare_base_and_preserves_historical_catalog(self):
        catalog = inputs._load_current_toolchain_catalog()
        self.assertFalse(catalog["production_authority"])
        self.assertFalse(catalog["base_vs_provisioned"]["bare_base_is_fully_provisioned"])
        self.assertEqual(catalog["base_vs_provisioned"]["approved_package_subset"], ["gnupg2", "rpm-sign", "python3"])
        self.assertEqual(
            catalog["base_images"]["rpm"],
            "registry.fedoraproject.org/fedora@sha256:c5e15bd1e07c25904d0c5b9865fb7ee4589f8ca234e635742b0c1195838f4bfd",
        )
        self.assertFalse(catalog["historical_g_catalog"]["supplies_current_tools"])
        self.assertEqual(catalog["field_attestations"]["base_images"], "catalog-derived-not-measured")

    def test_facts_reject_catalog_derived_fields_attested_as_measured(self):
        bad_facts = _facts("hosted-native")
        bad_facts["images_attestation"] = "measured-in-container"
        with self.assertRaisesRegex(entry.FixtureError, "FACTS_CATALOG_ATTESTATION_INVALID"):
            inputs.validate_measured_facts(bad_facts, _spec())

    def test_stage2_metadata_shape_privacy_and_attestations_with_substituted_seams(self):
        spec = _current_spec()
        with patch.object(signal, "getsignal", return_value=signal.SIG_DFL):
            metadata, facts = entry.measure_stage2_metadata(
                spec,
                self.parent,
                module_loader=lambda _: _fake_module(),
                support_checker=lambda: None,
                command_runner=_fake_stage2_command_runner,
                env_map={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                uid_getter=lambda: (0, 0),
                task_lister=lambda: ["1"],
                python_resolver=lambda: "/usr/bin/python3.14",
            )
        self.assertEqual(metadata["status"], "stage2-metadata-verified")
        self.assertFalse(metadata["production_authority"])
        self.assertFalse(metadata["native_agent_started"])
        self.assertEqual(
            metadata["container_preconditions"]["python_sha256"],
            hashlib.sha256(b"fixture:/usr/bin/python3.14").hexdigest(),
        )
        self.assertEqual(
            metadata["container_preconditions"]["python_sha256_attestation"],
            "measured-in-container",
        )
        self.assertTrue(metadata["container_preconditions"]["python_exe_root_regular_verified"])
        self.assertEqual(metadata["catalog_bindings"]["images_attestation"], "catalog-derived-not-measured")
        self.assertFalse(metadata["catalog_bindings"]["bare_base_is_fully_provisioned"])
        for tool_name in entry.STAGE2_PROVISIONED_TOOLS:
            tool_entry = metadata["measured_tools"][tool_name]
            self.assertEqual(tool_entry["version_attestation"], "measured-in-container")
            self.assertEqual(tool_entry["sha256_attestation"], "measured-in-container")
        serialized = json.dumps(metadata, sort_keys=True)
        self.assertNotIn(str(self.parent), serialized)
        self.assertEqual(list(self.parent.iterdir()), [])

        receipt = entry.run_lifecycle(
            spec,
            facts,
            self.parent,
            module_loader=lambda _: types.SimpleNamespace(OwnedGpgAgent=_NativeReceiptShapeAgent),
            support_checker=lambda: None,
            fixture_seam=False,
        )
        self.assertEqual(receipt["status"], "native-lifecycle-complete")
        self.assertEqual(receipt["tool_facts"]["attestation"], "measured-in-container-stage2")
        self.assertEqual(receipt["tool_facts"]["images_attestation"], "catalog-derived-not-measured")
        self.assertTrue(receipt["cleanup"]["stage2_tool_digests_matched_c6_custody"])
        self.assertTrue(receipt["tool_facts"]["stage2_tool_digests_matched_c6_custody"])
        for tool_name in entry.NATIVE_TOOLS:
            self.assertEqual(receipt["tool_facts"]["tools"][tool_name]["sha256_attestation"], "measured-in-container")

    def test_fake_module_signatures_match_real_c6_functions(self):
        real_spec = entry.load_manifest(Path(__file__).with_name("manifest.json"))
        real_c6 = entry._load_owned_agent(real_spec)
        fake_c6 = _fake_module()
        for fn_name in (
            "_proc_preflight",
            "_preflight_external_paths",
            "_exe",
            "_trusted_tool",
            "bind_gpgconf_paths",
        ):
            real_sig = inspect.signature(getattr(real_c6, fn_name))
            fake_sig = inspect.signature(getattr(fake_c6, fn_name))
            real_params = [(p.name, p.kind, p.default) for p in real_sig.parameters.values()]
            fake_params = [(p.name, p.kind, p.default) for p in fake_sig.parameters.values()]
            self.assertEqual(fake_params, real_params, f"Signature mismatch for {fn_name}")
        real_init = inspect.signature(real_c6.OwnedGpgAgent.__init__)
        fake_init = inspect.signature(fake_c6.OwnedGpgAgent.__init__)
        self.assertEqual(
            [(p.name, p.kind) for p in fake_init.parameters.values()],
            [(p.name, p.kind) for p in real_init.parameters.values()],
        )

    def test_stage2_metadata_executes_real_c6_preflight_functions_and_rejects_python_exe_mismatch(self):
        real_spec = entry.load_manifest(Path(__file__).with_name("manifest.json"))
        real_c6 = entry._load_owned_agent(real_spec)
        expected_bin_sha = hashlib.sha256(b"synthetic-root-owned-regular-binary").hexdigest()

        dir_mode = stat.S_IFDIR | 0o755
        reg_mode = stat.S_IFREG | 0o755
        lnk_mode = stat.S_IFLNK | 0o777
        dir_paths = {"/", "/run", "/var", "/usr", "/usr/bin", "/etc", "/run/gnupg", "/run/gnupg/user", "/run/user"}
        tool_inodes = {
            "/usr/bin/python3.14": 100,
            "/usr/bin/gpgconf": 101,
            "/usr/bin/gpg-agent": 102,
            "/usr/bin/gpg": 103,
            "/usr/bin/rpm": 104,
            "/usr/bin/rpmsign": 105,
        }
        proc_exe_ino = [100]
        fd_to_ino: dict[int, int] = {}

        with tempfile.NamedTemporaryFile(prefix="tf-b3-bin-") as tmp_bin:
            tmp_bin.write(b"synthetic-root-owned-regular-binary")
            tmp_bin.flush()

            def fake_lstat(path, *args, **kwargs):
                if kwargs.get("dir_fd") is not None:
                    return os.lstat(path, *args, **kwargs)
                p = str(path)
                if p in dir_paths:
                    return types.SimpleNamespace(st_dev=1, st_ino=hash(p) & 0xFFFF, st_uid=0, st_mode=dir_mode)
                if p == "/var/run":
                    return types.SimpleNamespace(st_dev=1, st_ino=20, st_uid=0, st_mode=lnk_mode)
                if p in tool_inodes:
                    return types.SimpleNamespace(st_dev=1, st_ino=tool_inodes[p], st_uid=0, st_mode=reg_mode)
                if p.startswith(("/run/", "/var/run/", "/etc/gnupg", "/usr/bin/gpgconf.ctl")):
                    raise FileNotFoundError(p)
                return os.lstat(path, *args, **kwargs)

            def fake_stat(path, *args, **kwargs):
                p = str(path)
                if p.startswith("/proc/"):
                    if p.endswith("/ns/pid"):
                        return types.SimpleNamespace(st_dev=1, st_ino=2)
                    if p.endswith("/exe"):
                        return types.SimpleNamespace(st_dev=1, st_ino=proc_exe_ino[0], st_uid=0, st_mode=reg_mode)
                    if "/fd/" in p:
                        return types.SimpleNamespace(st_dev=9, st_ino=11)
                return os.stat(path, *args, **kwargs)

            def fake_listdir(path):
                if path == "/proc":
                    return ["1", "self", "net"]
                if isinstance(path, str) and path.startswith("/proc/") and path.endswith("/fd"):
                    return ["0"]
                return os.listdir(path)

            def fake_proc_text(path: str) -> str:
                if path == "/proc/self/mountinfo":
                    return "1 0 0:1 / /proc rw - proc proc rw\n"
                if path == "/proc/net/unix":
                    return "Num RefCount Protocol Flags Type St Inode Path\n"
                if path == "/proc/1/stat":
                    return "1 (init) S 0 1 1 0 0 0\n"
                raise FileNotFoundError(path)

            def fake_open(path, flags, *args, **kwargs):
                p = str(path)
                if p in tool_inodes:
                    fd = os.open(tmp_bin.name, os.O_RDONLY)
                    fd_to_ino[fd] = tool_inodes[p]
                    return fd
                return os.open(path, flags, *args, **kwargs)

            def fake_fstat(fd):
                if fd in fd_to_ino:
                    return types.SimpleNamespace(st_dev=1, st_ino=fd_to_ino[fd], st_uid=0, st_mode=reg_mode)
                return os.fstat(fd)

            c6_os = types.SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
            c6_os.lstat = fake_lstat
            c6_os.stat = fake_stat
            c6_os.readlink = lambda _path: "/run"
            c6_os.listdir = fake_listdir
            c6_os.open = fake_open
            c6_os.fstat = fake_fstat
            c6_os.listxattr = lambda _fd, ** _kw: []

            with (
                patch.object(signal, "getsignal", return_value=signal.SIG_DFL),
                patch.object(real_c6, "os", c6_os),
                patch.object(real_c6, "_proc_text", side_effect=fake_proc_text),
            ):
                metadata, facts = entry.measure_stage2_metadata(
                    real_spec,
                    self.parent,
                    module_loader=lambda _: real_c6,
                    support_checker=lambda: None,
                    command_runner=_fake_stage2_command_runner,
                    env_map={"PATH": "/usr/bin:/bin"},
                    uid_getter=lambda: (0, 0),
                    task_lister=lambda: ["1"],
                    python_resolver=lambda: "/usr/bin/python3.14",
                )
                self.assertEqual(metadata["status"], "stage2-metadata-verified")
                self.assertEqual(metadata["container_preconditions"]["python_sha256"], expected_bin_sha)
                self.assertTrue(metadata["container_preconditions"]["python_exe_root_regular_verified"])
                self.assertTrue(metadata["container_preconditions"]["var_run_alias_target_is_run"])
                for tool_name in entry.NATIVE_TOOLS:
                    self.assertEqual(facts["tools"][tool_name]["sha256"], expected_bin_sha)

                proc_exe_ino[0] = 999
                with self.assertRaisesRegex(entry.FixtureError, "TOOL_PREFLIGHT_FAILED"):
                    entry.measure_stage2_metadata(
                        real_spec,
                        self.parent,
                        module_loader=lambda _: real_c6,
                        support_checker=lambda: None,
                        command_runner=_fake_stage2_command_runner,
                        env_map={"PATH": "/usr/bin:/bin"},
                        uid_getter=lambda: (0, 0),
                        task_lister=lambda: ["1"],
                        python_resolver=lambda: "/usr/bin/python3.14",
                    )

    def test_stage3_refuses_when_c6_custody_tool_digest_drifts_from_stage2_facts(self):
        spec = _current_spec()
        facts = _facts("hosted-native")
        facts["images"] = _current_images()
        _NativeReceiptShapeAgent.tool_digests = {
            path: ("f" * 64 if name == "gpg-agent" else hashlib.sha256(f"fixture:{path}".encode("utf-8")).hexdigest())
            for name, path in entry.NATIVE_TOOLS.items()
        }
        with self.assertRaisesRegex(entry.FixtureError, "NATIVE_TOOL_DIGEST_DRIFT") as raised:
            entry.run_lifecycle(
                spec,
                facts,
                self.parent,
                module_loader=lambda _: types.SimpleNamespace(OwnedGpgAgent=_NativeReceiptShapeAgent),
                support_checker=lambda: None,
                fixture_seam=False,
            )
        self.assertTrue(raised.exception.retained_custody)
        self.assertIsNotNone(raised.exception.retained_root)
        shutil.rmtree(raised.exception.retained_root, ignore_errors=True)

    def test_stage2_refuses_credential_env_nonroot_uid_and_version_mismatch_before_agent(self):
        spec = _current_spec()
        with self.assertRaisesRegex(entry.FixtureError, "CREDENTIAL_ENV_FORBIDDEN"):
            entry.measure_stage2_metadata(
                spec,
                self.parent,
                module_loader=lambda _: self.fail("must refuse credential env first"),
                support_checker=lambda: None,
                command_runner=_fake_stage2_command_runner,
                env_map={"PACKAGE_SIGNING_KEY": "forbidden"},
                uid_getter=lambda: (0, 0),
                task_lister=lambda: ["1"],
            )
        with self.assertRaisesRegex(entry.FixtureError, "CONTAINER_ROOT_UID_REQUIRED"):
            entry.measure_stage2_metadata(
                spec,
                self.parent,
                module_loader=lambda _: self.fail("must refuse non-root UID first"),
                support_checker=lambda: None,
                command_runner=_fake_stage2_command_runner,
                env_map={"PATH": "/usr/bin:/bin"},
                uid_getter=lambda: (1000, 1000),
                task_lister=lambda: ["1"],
            )
        with patch.object(signal, "getsignal", return_value=signal.SIG_DFL):
            with self.assertRaisesRegex(entry.FixtureError, "TOOL_VERSION_MISMATCH"):
                entry.measure_stage2_metadata(
                    spec,
                    self.parent,
                    module_loader=lambda _: _fake_module(),
                    support_checker=lambda: None,
                    command_runner=lambda argv: (0, "gpgconf (GnuPG) 2.5.24"),
                    env_map={"PATH": "/usr/bin:/bin"},
                    uid_getter=lambda: (0, 0),
                    task_lister=lambda: ["1"],
                )
            with self.assertRaisesRegex(entry.FixtureError, "RPM_VERSION_MISMATCH"):
                entry.measure_stage2_metadata(
                    spec,
                    self.parent,
                    module_loader=lambda _: _fake_module(),
                    support_checker=lambda: None,
                    command_runner=lambda argv: (
                        (0, "RPM version 4.19.1")
                        if Path(argv[0]).name == "rpm"
                        else _fake_stage2_command_runner(argv)
                    ),
                    env_map={"PATH": "/usr/bin:/bin"},
                    uid_getter=lambda: (0, 0),
                    task_lister=lambda: ["1"],
                )

    def test_cli_isolated_mode_refusal_and_stage1_authentication_subprocess(self):
        entrypoint_path = Path(entry.__file__).resolve()
        manifest_path = entrypoint_path.with_name("manifest.json")
        refusal = subprocess.run(
            [sys.executable, "-I", "-B", str(entrypoint_path)],
            cwd=str(self.parent),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(refusal.returncode, 2, refusal.stderr)
        refusal_json = json.loads(refusal.stdout)
        self.assertEqual(refusal_json["error_code"], "NATIVE_EXECUTION_EXPLICIT_REQUIRED")
        self.assertFalse(refusal_json["production_authority"])

        stage1_out = self.parent / "b3-stage1-authentication.json"
        stage1 = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(entrypoint_path),
                "--authenticate-stage1",
                "--manifest",
                str(manifest_path),
                "--out",
                str(stage1_out),
            ],
            cwd=str(self.parent),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(stage1.returncode, 0, stage1.stderr)
        stage1_json = json.loads(stage1.stdout)
        self.assertEqual(stage1_json["status"], "stage1-authenticated")
        self.assertFalse(stage1_json["production_authority"])
        self.assertFalse(stage1_json["native_execution_observed"])
        self.assertEqual(stage1_json["owned_agent_sha256"], entry.REVIEWED_C6_SOURCE_SHA256)
        self.assertEqual(json.loads(stage1_out.read_text(encoding="utf-8")), stage1_json)

    def test_copied_root_relocation_preserves_manifest_and_stage1_authentication(self):
        source_root = Path(entry.__file__).resolve().parent
        relocated = self.parent / "relocated-b3-root"
        shutil.copytree(source_root, relocated)
        stage1 = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(relocated / "b3_fixture_entrypoint.py"),
                "--authenticate-stage1",
                "--manifest",
                str(relocated / "manifest.json"),
            ],
            cwd=str(self.parent),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(stage1.returncode, 0, stage1.stderr)
        payload = json.loads(stage1.stdout)
        self.assertEqual(payload["status"], "stage1-authenticated")
        self.assertEqual(payload["owned_agent_sha256"], entry.REVIEWED_C6_SOURCE_SHA256)

    def test_copied_c6_fixture_suite_passes_against_exact_c6_source(self):
        c6_source = entry.REVIEWED_C6_SOURCE_PATH
        c6_tests = entry.REVIEWED_C6_TESTS_PATH
        self.assertEqual(hashlib.sha256(c6_source.read_bytes()).hexdigest(), entry.REVIEWED_C6_SOURCE_SHA256)
        self.assertEqual(hashlib.sha256(c6_tests.read_bytes()).hexdigest(), entry.REVIEWED_C6_TESTS_SHA256)

        base_tmp = Path(os.environ.get("TMPDIR", "/tmp")).resolve()
        short_root = Path(tempfile.mkdtemp(prefix="c6-", dir=base_tmp))
        short_root.chmod(0o700)
        ws_dir = self.parent / "c6-ws"
        ws_dir.mkdir(mode=0o700)
        (ws_dir / "FIXTURE-ROOT.json").write_text(json.dumps({"path": str(short_root)}), encoding="utf-8")

        c6_dir = str(c6_source.parent)
        added = False
        if c6_dir not in sys.path:
            sys.path.insert(0, c6_dir)
            added = True
        try:
            spec = importlib.util.spec_from_file_location("b3_copied_test_owned_gpg_agent", c6_tests)
            self.assertIsNotNone(spec)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            assert spec.loader is not None
            spec.loader.exec_module(module)
            module._workspace = lambda: ws_dir
            suite = unittest.TestSuite()
            for case in unittest.defaultTestLoader.loadTestsFromTestCase(module.Tests):
                if case._testMethodName == "test_every_fixed_agent_option_is_present_in_pinned_upstream_option_table":
                    continue
                suite.addTest(case)
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
            self.assertTrue(result.wasSuccessful(), stream.getvalue())
            self.assertGreaterEqual(result.testsRun, 60)
        finally:
            sys.modules.pop("b3_copied_test_owned_gpg_agent", None)
            if added and c6_dir in sys.path:
                sys.path.remove(c6_dir)
            shutil.rmtree(short_root, ignore_errors=True)

    def test_cleanup_leftover_known_unknown_names_and_mixed_types_without_disclosure(self):
        binding = workspace._fresh_workspace(self.parent)
        outside = self.parent / "outside-secret.txt"
        outside.write_text("outside-target-secret", encoding="utf-8")
        (binding.home / "private-keys-v1.d").mkdir(mode=0o700)
        (binding.home / "random_seed").write_text("seed-bytes-secret", encoding="utf-8")
        (binding.home / "common.conf").write_text("no-autostart", encoding="utf-8")
        (binding.home / "secret-unknown.gpg").write_text("confidential-payload", encoding="utf-8")
        os.symlink(outside, binding.home / "outside-link")
        os.mkfifo(binding.home / "fifo-entry")
        for sock_name in ("S.gpg-agent", "S.gpg-agent.extra", "S.gpg-agent.browser", "S.gpg-agent.ssh"):
            _bind_inert_socket(binding.home, sock_name)
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
            workspace._remove_fresh_workspace(binding)
        detail = raised.exception.sanitized_detail
        self.assertEqual((detail["unexpected_home_entry_count"], detail["home_diagnostics_status"]), (10, "complete"))
        self.assertEqual(detail["home_entry_category_counts"], {
            "private_keys_directory": 1, "random_seed": 1, "primary_socket": 1, "extra_socket": 1,
            "browser_socket": 1, "ssh_socket": 1, "common_config": 1, "other": 3})
        self.assertEqual(detail["home_entry_type_counts"], {
            "regular": 3, "directory": 1, "symlink": 1, "socket": 4, "other": 1, "vanished": 0, "unreadable": 0})
        self.assertEqual(detail["private_keys_directory"], {
            "present": True, "status": "complete", "identity_verified": True,
            "empty": True, "entry_count": 0, "truncated": False})
        for token in ("private-keys-v1.d", "S.gpg-agent", "secret-unknown.gpg", "outside-link", "fifo-entry",
                      "seed-bytes-secret", "confidential-payload", "outside-target-secret"):
            self.assertNotIn(token, json.dumps(detail, sort_keys=True))
        self.assertEqual((outside.read_text(encoding="utf-8"), (binding.home / "secret-unknown.gpg").read_text(encoding="utf-8")),
                         ("outside-target-secret", "confidential-payload"))
        shutil.rmtree(binding.root, ignore_errors=True)

    def test_private_keys_directory_nonempty_symlink_and_identity_race_metadata(self):
        binding = workspace._fresh_workspace(self.parent)
        pk_dir = binding.home / "private-keys-v1.d"
        pk_dir.mkdir(mode=0o700)
        (pk_dir / "alpha.key").write_text("k1", encoding="utf-8")
        (pk_dir / "beta.key").write_text("k2", encoding="utf-8")
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
            workspace._remove_fresh_workspace(binding)
        detail = raised.exception.sanitized_detail
        self.assertEqual(detail["private_keys_directory"], {
            "present": True, "status": "complete", "identity_verified": True,
            "empty": False, "entry_count": 2, "truncated": False})
        self.assertNotIn("alpha.key", json.dumps(detail))
        self.assertEqual((pk_dir / "alpha.key").read_text(encoding="utf-8"), "k1")
        shutil.rmtree(binding.root, ignore_errors=True)
        binding2 = workspace._fresh_workspace(self.parent)
        ext_dir = self.parent / "ext-keys"
        ext_dir.mkdir(mode=0o700)
        (ext_dir / "ext.key").write_text("ext", encoding="utf-8")
        os.symlink(ext_dir, binding2.home / "private-keys-v1.d")
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised2:
            workspace._remove_fresh_workspace(binding2)
        self.assertEqual((raised2.exception.sanitized_detail["private_keys_directory"]["status"],
                          raised2.exception.sanitized_detail["home_entry_type_counts"]["symlink"]), ("not-directory", 1))
        shutil.rmtree(binding2.root, ignore_errors=True)
        binding3 = workspace._fresh_workspace(self.parent)
        (binding3.home / "private-keys-v1.d").mkdir(mode=0o700)
        orig_same_fd = workspace._same_fd_identity
        held_fds = {binding3.parent_fd, binding3.root_fd, binding3.home_fd}
        with patch.object(workspace, "_same_fd_identity",
                          side_effect=lambda fd, exp: orig_same_fd(fd, exp) if fd in held_fds else False), \
                self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised3:
            workspace._remove_fresh_workspace(binding3)
        self.assertEqual((raised3.exception.sanitized_detail["private_keys_directory"]["status"],
                          raised3.exception.sanitized_detail["home_diagnostics_status"]), ("identity-mismatch", "incomplete"))
        shutil.rmtree(binding3.root, ignore_errors=True)

    def test_cleanup_leftover_vanished_unreadable_and_entry_cap_truncation(self):
        binding = workspace._fresh_workspace(self.parent)
        (binding.home / "private-keys-v1.d").mkdir(mode=0o700)
        (binding.home / "ok").write_text("ok", encoding="utf-8")
        orig_lstat = os.lstat
        def fake_lstat(path, *args, **kwargs):
            if kwargs.get("dir_fd") == binding.home_fd and path in {"vanished-entry", "denied-entry"}:
                raise (FileNotFoundError if path == "vanished-entry" else PermissionError)(path)
            return orig_lstat(path, *args, **kwargs)
        home_list = ["vanished-entry", "denied-entry"] + ["ok"] * 62 + ["private-keys-v1.d"]
        root_list = ["home"] + [f"r-{i}" for i in range(65)]
        with patch.object(os, "listdir", side_effect=lambda fd: home_list if fd == binding.home_fd else root_list), \
                patch.object(os, "lstat", side_effect=fake_lstat), \
                patch.object(os, "open", side_effect=PermissionError("private-keys-v1.d")), \
                self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
            workspace._remove_fresh_workspace(binding)
        detail = raised.exception.sanitized_detail
        self.assertEqual(
            (detail["unexpected_root_entry_count"], detail["unexpected_home_entry_count"],
             detail["home_entries_truncated"], detail["home_diagnostics_status"],
             detail["home_entry_type_counts"]["vanished"], detail["home_entry_type_counts"]["unreadable"],
             detail["private_keys_directory"]["status"]),
            (65, 65, True, "incomplete", 1, 1, "unreadable"))
        self.assertNotIn("denied-entry", json.dumps(detail))
        shutil.rmtree(binding.root, ignore_errors=True)
        binding2 = workspace._fresh_workspace(self.parent)
        pk2 = binding2.home / "private-keys-v1.d"
        pk2.mkdir(mode=0o700)
        for idx in range(68):
            (pk2 / f"k-{idx:02d}").write_text("x", encoding="utf-8")
            (binding2.home / f"z-{idx:02d}").write_text("y", encoding="utf-8")
        with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised2:
            workspace._remove_fresh_workspace(binding2)
        detail2 = raised2.exception.sanitized_detail
        self.assertEqual((detail2["unexpected_home_entry_count"], detail2["home_entries_inspected_count"],
                          detail2["home_entries_truncated"], detail2["home_diagnostics_status"]), (69, 64, True, "truncated"))
        self.assertEqual(detail2["private_keys_directory"], {
            "present": True, "status": "truncated", "identity_verified": True,
            "empty": False, "entry_count": 64, "truncated": True})
        shutil.rmtree(binding2.root, ignore_errors=True)

    def test_lifecycle_progress_booleans_across_start_live_close_observation_and_cleanup(self):
        class _StepAgent(_NativeReceiptShapeAgent):
            step = ""
            leave_entry = True
            def _act(self, name: str, result: object = None) -> object:
                if type(self).step == name:
                    if type(self).leave_entry:
                        (self.home / "private-keys-v1.d").mkdir(mode=0o700)
                    raise RuntimeError(name)
                return result
            def __init__(self, home, job_root):
                super().__init__(home, job_root)
                self._act("ctor")
            def start(self):
                return self._act("start", super().start())
            def require_live(self):
                return self._act("live", super().require_live())
            def close(self):
                super().close()
                if type(self).step == "post_close":
                    (self.home / "random_seed").write_text("stale", encoding="utf-8")
                elif type(self).step == "stale_socket":
                    (self.home / "S.gpg-agent").write_text("stale", encoding="utf-8")
        loader = lambda _: types.SimpleNamespace(OwnedGpgAgent=_StepAgent)
        _StepAgent.step, _StepAgent.leave_entry = "live", False
        with self.assertRaisesRegex(entry.FixtureError, "LIFECYCLE_FAILED"):
            entry.run_lifecycle(_spec(), _facts(), self.parent, module_loader=loader,
                                support_checker=lambda: None, fixture_seam=True)
        _StepAgent.step, _StepAgent.leave_entry = "stale_socket", False
        with self.assertRaisesRegex(entry.FixtureError, "NATIVE_SOCKET_DISAPPEARANCE_UNCONFIRMED") as sock_err:
            entry.run_lifecycle(_spec(), _facts("hosted-native"), self.parent, module_loader=loader,
                                support_checker=lambda: None, fixture_seam=False)
        shutil.rmtree(sock_err.exception.retained_root, ignore_errors=True)
        for step_name, is_fixture, flags in (("ctor", True, (False, False, False, False, False)),
                                             ("start", True, (False, False, True, True, False)),
                                             ("live", True, (True, False, True, True, False)),
                                             ("post_close", False, (True, True, True, True, True))):
            _StepAgent.step, _StepAgent.leave_entry = step_name, True
            with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
                entry.run_lifecycle(_spec(), _facts("fixture" if is_fixture else "hosted-native"), self.parent,
                                    module_loader=loader, support_checker=lambda: None, fixture_seam=is_fixture)
            self.assertTrue(raised.exception.retained_custody)
            self.assertEqual(raised.exception.sanitized_detail["lifecycle_progress"], dict(zip(
                ("start_returned", "live_check_returned", "close_returned",
                 "cleanup_confirmed", "closed_observation_returned"), flags)))
            shutil.rmtree(raised.exception.retained_root, ignore_errors=True)


    def test_unexpected_metadata_error_counts_only_attempted_entries(self):
        binding = workspace._fresh_workspace(self.parent)
        for name in ("opaque-fixture-one", "opaque-fixture-two"):
            (binding.home / name).write_text("retained", encoding="utf-8")
        with patch.object(workspace, "_entry_type_key", side_effect=RuntimeError("withheld-fixture-detail")):
            with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
                workspace._remove_fresh_workspace(binding)
        detail = raised.exception.sanitized_detail
        self.assertEqual(detail["home_entries_inspected_count"], 1)
        self.assertEqual(detail["home_diagnostics_status"], "incomplete")
        self.assertEqual(detail["unexpected_home_entry_count"], 2)
        rendered = json.dumps(detail)
        self.assertNotIn("opaque-fixture", rendered)
        self.assertNotIn("withheld-fixture-detail", rendered)
        self.assertEqual((binding.home / "opaque-fixture-two").read_text(encoding="utf-8"), "retained")
        shutil.rmtree(binding.root)

    def _assert_fds_closed(self, descriptors: list[int]) -> None:
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_empty_owned_private_keys_dir_removed_only_after_confirmed_lifecycle(self):
        class _EmptyPkDirAgent(_NativeReceiptShapeAgent):
            def close(self):
                super().close()
                (self.home / "private-keys-v1.d").mkdir(mode=0o700)

        loader = lambda _: types.SimpleNamespace(OwnedGpgAgent=_EmptyPkDirAgent)
        for mode, seam in (("fixture", True), ("hosted-native", False)):
            receipt = entry.run_lifecycle(
                _spec(),
                _facts(mode),
                self.parent,
                module_loader=loader,
                support_checker=lambda: None,
                fixture_seam=seam,
            )
            self.assertTrue(receipt["cleanup"]["workspace_removed_confirmed"])
            self.assertEqual(list(self.parent.iterdir()), [])

        binding = workspace._fresh_workspace(self.parent)
        (binding.home / "private-keys-v1.d").mkdir(mode=0o700)
        opened_fds = [binding.parent_fd, binding.root_fd, binding.home_fd]
        closed_fds: list[int] = []
        orig_open, orig_close = os.open, os.close

        def tracking_open(path, flags, *args, **kwargs):
            fd = orig_open(path, flags, *args, **kwargs)
            opened_fds.append(fd)
            return fd

        def tracking_close(fd):
            closed_fds.append(fd)
            return orig_close(fd)

        with (
            patch.object(os, "open", side_effect=tracking_open),
            patch.object(os, "close", side_effect=tracking_close),
            patch.object(os, "unlink", side_effect=AssertionError("unlink forbidden")),
        ):
            workspace._remove_fresh_workspace(binding, allow_empty_private_keys_dir=True)
        self.assertEqual(len(opened_fds), 4)
        self.assertEqual(sorted(closed_fds), sorted(opened_fds))
        self._assert_fds_closed(opened_fds)
        self.assertEqual(list(self.parent.iterdir()), [])

        empty_binding = workspace._fresh_workspace(self.parent)
        empty_fds = [empty_binding.parent_fd, empty_binding.root_fd, empty_binding.home_fd]
        workspace._remove_fresh_workspace(empty_binding, allow_empty_private_keys_dir=True)
        self._assert_fds_closed(empty_fds)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_empty_private_keys_dir_refuses_by_default_nonliteral_true_and_failed_lifecycle(self):
        for bad_opt in (None, False, 1, "true", ["true"]):
            binding = workspace._fresh_workspace(self.parent)
            (binding.home / "private-keys-v1.d").mkdir(mode=0o700)
            fds = [binding.parent_fd, binding.root_fd, binding.home_fd]
            with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
                if bad_opt is None:
                    workspace._remove_fresh_workspace(binding)
                else:
                    workspace._remove_fresh_workspace(binding, allow_empty_private_keys_dir=bad_opt)
            self.assertTrue((binding.home / "private-keys-v1.d").is_dir())
            self.assertTrue(raised.exception.sanitized_detail["private_keys_directory"]["empty"])
            self._assert_fds_closed(fds)
            shutil.rmtree(binding.root, ignore_errors=True)

        all_true = {
            "start_returned": True,
            "live_check_returned": True,
            "close_returned": True,
            "cleanup_confirmed": True,
            "closed_observation_returned": True,
        }
        for key in all_true:
            for non_true in (False, 1):
                binding = workspace._fresh_workspace(self.parent)
                (binding.home / "private-keys-v1.d").mkdir(mode=0o700)
                progress = {**all_true, key: non_true}
                closed_obs = progress["closed_observation_returned"]
                with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED"):
                    entry._remove_lifecycle_workspace(
                        binding,
                        progress,
                        closed_observation_returned=closed_obs,
                        allow_empty_private_keys_dir=True,
                    )
                self.assertTrue((binding.home / "private-keys-v1.d").is_dir())
                shutil.rmtree(binding.root, ignore_errors=True)

    def test_empty_private_keys_dir_opt_in_retains_nonempty_symlink_file_and_extra_entries(self):
        binding = workspace._fresh_workspace(self.parent)
        pk_dir = binding.home / "private-keys-v1.d"
        pk_dir.mkdir(mode=0o700)
        child = pk_dir / "opaque-fixture.bin"
        child.write_text("opaque-synthetic-fixture", encoding="utf-8")
        orig_open = os.open

        def forbid_child_open(path, flags, *args, **kwargs):
            if "opaque-fixture" in str(path):
                raise AssertionError("child open forbidden")
            return orig_open(path, flags, *args, **kwargs)

        with (
            patch.object(os, "open", side_effect=forbid_child_open),
            patch.object(os, "unlink", side_effect=AssertionError("unlink forbidden")),
            self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised,
        ):
            workspace._remove_fresh_workspace(binding, allow_empty_private_keys_dir=True)
        detail = raised.exception.sanitized_detail
        self.assertEqual(detail["private_keys_directory"]["entry_count"], 1)
        self.assertFalse(detail["private_keys_directory"]["empty"])
        self.assertNotIn("opaque-fixture.bin", json.dumps(detail))
        self.assertEqual(child.read_text(encoding="utf-8"), "opaque-synthetic-fixture")
        shutil.rmtree(binding.root, ignore_errors=True)

        ext_dir = self.parent / "ext-empty-dir"
        ext_dir.mkdir(mode=0o700)
        for kind in ("symlink", "file", "extra_home", "extra_root"):
            ws = workspace._fresh_workspace(self.parent)
            target = ws.home / "private-keys-v1.d"
            if kind == "symlink":
                os.symlink(ext_dir, target)
            elif kind == "file":
                target.write_text("regular", encoding="utf-8")
                target.chmod(0o700)
            else:
                target.mkdir(mode=0o700)
                extra = (ws.home / "random_seed") if kind == "extra_home" else (ws.root / "extra-root")
                extra.write_text("retained", encoding="utf-8")
            with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED"):
                workspace._remove_fresh_workspace(ws, allow_empty_private_keys_dir=True)
            self.assertTrue(os.path.lexists(target))
            shutil.rmtree(ws.root, ignore_errors=True)
        self.assertTrue(ext_dir.is_dir())

    def test_empty_private_keys_dir_opt_in_retains_foreign_owner_and_wrong_mode(self):
        for bad_mode in (0o755, 0o750, 0o500):
            binding = workspace._fresh_workspace(self.parent)
            pk_dir = binding.home / "private-keys-v1.d"
            pk_dir.mkdir(mode=bad_mode)
            pk_dir.chmod(bad_mode)
            fds = [binding.parent_fd, binding.root_fd, binding.home_fd]
            with self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised:
                workspace._remove_fresh_workspace(binding, allow_empty_private_keys_dir=True)
            self.assertTrue(pk_dir.is_dir())
            self.assertTrue(raised.exception.retained_custody)
            self._assert_fds_closed(fds)
            pk_dir.chmod(0o700)
            shutil.rmtree(binding.root, ignore_errors=True)

        binding2 = workspace._fresh_workspace(self.parent)
        pk_dir2 = binding2.home / "private-keys-v1.d"
        pk_dir2.mkdir(mode=0o700)
        fds2 = [binding2.parent_fd, binding2.root_fd, binding2.home_fd]
        with (
            patch.object(os, "getuid", return_value=os.getuid() + 1),
            self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised2,
        ):
            workspace._remove_fresh_workspace(binding2, allow_empty_private_keys_dir=True)
        self.assertEqual(raised2.exception.sanitized_detail["private_keys_directory"]["status"], "identity-mismatch")
        self.assertTrue(pk_dir2.is_dir())
        self._assert_fds_closed(fds2)
        shutil.rmtree(binding2.root, ignore_errors=True)

    def test_empty_private_keys_dir_refuses_identity_swap_and_populate_before_rmdir_races(self):
        binding = workspace._fresh_workspace(self.parent)
        pk_dir = binding.home / "private-keys-v1.d"
        pk_dir.mkdir(mode=0o700)
        swapped_out = self.parent / "swapped-original-pk"
        held_fds = {binding.parent_fd, binding.root_fd, binding.home_fd}
        orig_listdir = os.listdir
        swapped = False

        def swap_on_pk_listdir(fd):
            nonlocal swapped
            items = orig_listdir(fd)
            if not swapped and fd not in held_fds:
                swapped = True
                pk_dir.rename(swapped_out)
                pk_dir.mkdir(mode=0o700)
            return items

        with (
            patch.object(os, "listdir", side_effect=swap_on_pk_listdir),
            patch.object(os, "rmdir", side_effect=AssertionError("must refuse before rmdir")),
            self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED"),
        ):
            workspace._remove_fresh_workspace(binding, allow_empty_private_keys_dir=True)
        self.assertTrue(swapped_out.is_dir())
        self.assertTrue(pk_dir.is_dir())
        self._assert_fds_closed(list(held_fds))
        shutil.rmtree(binding.root, ignore_errors=True)

        binding2 = workspace._fresh_workspace(self.parent)
        pk_dir2 = binding2.home / "private-keys-v1.d"
        pk_dir2.mkdir(mode=0o700)
        orig_rmdir = os.rmdir

        def populate_before_rmdir(path, *args, **kwargs):
            if path == "private-keys-v1.d":
                (pk_dir2 / "late-child.opaque").write_text("retained", encoding="utf-8")
            return orig_rmdir(path, *args, **kwargs)

        with (
            patch.object(os, "rmdir", side_effect=populate_before_rmdir),
            self.assertRaisesRegex(entry.FixtureError, "WORKSPACE_CLEANUP_UNCONFIRMED") as raised2,
        ):
            workspace._remove_fresh_workspace(binding2, allow_empty_private_keys_dir=True)
        detail2 = raised2.exception.sanitized_detail["private_keys_directory"]
        self.assertEqual((detail2["empty"], detail2["entry_count"]), (False, 1))
        self.assertEqual((pk_dir2 / "late-child.opaque").read_text(encoding="utf-8"), "retained")
        self._assert_fds_closed([binding2.parent_fd, binding2.root_fd, binding2.home_fd])
        shutil.rmtree(binding2.root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
