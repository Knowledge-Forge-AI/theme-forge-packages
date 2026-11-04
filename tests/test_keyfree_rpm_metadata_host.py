"""Ownership, context, and cleanup checks with explicit Docker replacement seams."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import types
import inspect
import unittest
from unittest.mock import patch

P_ROOT = Path(__file__).resolve().parents[1]
PROBE = P_ROOT / "tools/verification/rpm_metadata_probe"
spec = importlib.util.spec_from_file_location("rpm_probe_entry", PROBE / "entry.py")
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
PROFILE = entry.load_bundle(PROBE)
import tf_rpm_probe_host as host
import tf_rpm_probe_core as core

CID, IMAGE = "c" * 64, "sha256:" + "b" * 64
NAME, RUN = "tf-rpm-metadata-7", 7


def observations():
    result = []
    for arch in core.ARCHES:
        for kind in core.INPUT_CLASSES:
            result.append({"architecture": arch, "inputClass": kind, "stage": "DONE", "code": "NONE",
                           "toolExit": "ZERO", "stderrMarker": "NONE", "stdoutSize": "ZERO",
                           "stderrSize": "ZERO", "metadataAccepted": True})
    return {"schema": core.SCHEMA, "cases": result, "signingPerformed": False,
            "publicationAuthority": False, "privateKeyAccess": False,
            "tool": {"status": "MEASURED", "path": "/usr/bin/createrepo_c", "bytes": 100,
                     "sha256": "a" * 64, "versionObserved": False}}


class DockerStub:
    def __init__(self):
        self.calls, self.present = [], False
        self.row = {"Id": CID, "Name": "/" + NAME, "Image": IMAGE,
                    "Config": {"Labels": {host.OWNER_LABEL: str(RUN)}},
                    "State": {"Running": False, "Status": "created"}}
        self.payload = observations()
        self.create_result = CID.encode()
        self.corrupt_listing = False
        self.fail_list_after_rm = False

    def _run_bounded(self, label, argv):
        self.calls.append(argv)
        if argv[1:3] == ("container", "ls"):
            if self.fail_list_after_rm and not self.present and any(a[1:3] == ("container", "rm") for a in self.calls):
                return 1, b"", b"PRIVATE_CANARY", None
            rows = [{"ID": CID, "Names": NAME}] if self.present else []
            if self.corrupt_listing:
                rows = [{}]
            return 0, b"\n".join(json.dumps(r).encode() for r in rows), b"", None
        if argv[1] == "create":
            self.present = True
            return 0, self.create_result, b"", None
        if argv[1:3] == ("container", "inspect"):
            return 0, json.dumps([self.row]).encode(), b"", None
        if argv[1:3] == ("container", "start"):
            self.row["State"]["Status"] = "exited"
            return 0, json.dumps(self.payload).encode(), b"", None
        if argv[1:3] == ("container", "rm"):
            self.present = False
            return 0, CID.encode(), b"", None
        raise AssertionError("Unexpected Docker operation")


class OwnedContainerTests(unittest.TestCase):
    def setup_owner(self):
        engine = DockerStub()
        owner = host.OwnedContainer(engine, name=NAME, run_id=RUN, image=IMAGE)
        owner.create(("/usr/bin/docker", "create", "--name", NAME))
        return owner, engine

    def test_success_observes_all_cases_then_removes_only_held_id(self):
        owner, engine = self.setup_owner()
        self.assertEqual(len(owner.observe()["cases"]), 4)
        self.assertTrue(owner.cleanup())
        removals = [a for a in engine.calls if a[1:3] == ("container", "rm")]
        self.assertEqual(removals, [("/usr/bin/docker", "container", "rm", CID)])
        self.assertFalse(any("--force" in a or "-f" in a for a in engine.calls))

    def test_name_or_image_or_label_replacement_never_authorizes_removal(self):
        for field in ("Name", "Image", "label"):
            owner, engine = self.setup_owner()
            if field == "label":
                engine.row["Config"]["Labels"][host.OWNER_LABEL] = "foreign"
            else:
                engine.row[field] = "foreign"
            self.assertFalse(owner.cleanup())
            self.assertFalse(any(a[1:3] == ("container", "rm") for a in engine.calls))

    def test_unresolved_create_never_falls_back_to_name_removal(self):
        engine = DockerStub()
        engine.create_result = b"malformed"
        owner = host.OwnedContainer(engine, name=NAME, run_id=RUN, image=IMAGE)
        with self.assertRaises(ValueError):
            owner.create(("/usr/bin/docker", "create", "--name", NAME))
        self.assertFalse(owner.cleanup())
        self.assertFalse(any(a[1:3] == ("container", "rm") for a in engine.calls))

    def test_live_container_is_retained_until_hosted_vm_disposal(self):
        owner, engine = self.setup_owner()
        engine.row["State"] = {"Running": True, "Status": "running"}
        self.assertFalse(owner.cleanup())
        self.assertFalse(any(a[1:3] == ("container", "rm") for a in engine.calls))

    def test_absence_requires_successful_well_formed_complete_listing(self):
        owner, engine = self.setup_owner()
        engine.fail_list_after_rm = True
        self.assertFalse(owner.cleanup())
        engine = DockerStub();engine.corrupt_listing = True
        owner = host.OwnedContainer(engine, name=NAME, run_id=RUN, image=IMAGE)
        with self.assertRaises(ValueError):
            owner.create(("/usr/bin/docker", "create", "--name", NAME))

    def test_initial_name_collision_stops_before_create(self):
        engine = DockerStub();engine.present = True
        owner = host.OwnedContainer(engine, name=NAME, run_id=RUN, image=IMAGE)
        with self.assertRaises(ValueError):
            owner.create(("/usr/bin/docker", "create", "--name", NAME))
        self.assertFalse(any(a[1] == "create" for a in engine.calls))

    def test_truncated_success_or_continuable_failure_is_refused(self):
        owner, engine = self.setup_owner()
        engine.payload["cases"] = engine.payload["cases"][:1]
        with self.assertRaises(ValueError):
            owner.observe()
        engine.payload["cases"][0].update(stage="TOOL", code="COMMAND_FAILED",
                                          toolExit="NONZERO", metadataAccepted=False)
        with self.assertRaises(ValueError):
            owner.observe()

    def test_terminal_custody_code_allows_diagnostic_early_stop(self):
        owner, engine = self.setup_owner()
        engine.payload["cases"] = engine.payload["cases"][:1]
        engine.payload["cases"][0].update(stage="TOOL", code="COMMAND_CLEANUP",
                                          toolExit="NOT_RETURNED", metadataAccepted=False)
        self.assertEqual(owner.observe()["cases"][0]["code"], "COMMAND_CLEANUP")

    def test_terminal_case_cannot_be_followed_by_additional_observations(self):
        owner, engine = self.setup_owner()
        engine.payload["cases"][0].update(stage="METADATA", code="OUTPUT_INVENTORY",
                                          metadataAccepted=False)
        with self.assertRaises(ValueError):
            owner.observe()

    def test_claimed_authority_extra_fields_or_unknown_case_refuse(self):
        for mode in ("authority", "extra", "unknown"):
            owner, engine = self.setup_owner()
            if mode == "authority":
                engine.payload["publicationAuthority"] = True
            elif mode == "extra":
                engine.payload["privatePayload"] = "PRIVATE_CANARY"
            else:
                engine.payload["cases"][0]["code"] = "PRIVATE_CANARY"
            with self.assertRaises((ValueError, TypeError)):
                owner.observe()


class ContextTests(unittest.TestCase):
    def environment(self):
        return {
            "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Knowledge-Forge-AI/theme-forge-packages",
            "GITHUB_REPOSITORY_OWNER": "Knowledge-Forge-AI", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main", "GITHUB_REF_NAME": "main", "GITHUB_REF_TYPE": "branch",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW_REF": host.WORKFLOW_REF,
            "GITHUB_RUN_ID": "7", "GITHUB_SHA": "a" * 40, "RUNNER_ENVIRONMENT": "github-hosted",
        }

    def test_exact_original_hosted_context_is_required(self):
        linux = types.SimpleNamespace(sysname="Linux", machine="x86_64")
        with patch.object(host.os, "uname", return_value=linux):
            self.assertEqual(host.require_context(self.environment(), "a" * 40), 7)
            for key in self.environment():
                altered = {**self.environment(), key: "foreign"}
                with self.assertRaises(ValueError):
                    host.require_context(altered, "a" * 40)
            for key in ("GITHUB_HEAD_REF", "GITHUB_BASE_REF"):
                with self.assertRaises(ValueError):
                    host.require_context({**self.environment(), key: "fork"}, "a" * 40)

    def test_foreign_architecture_and_platform_are_refused(self):
        for system, machine in [("Darwin", "arm64"), ("Linux", "aarch64")]:
            with patch.object(host.os, "uname", return_value=types.SimpleNamespace(sysname=system, machine=machine)):
                with self.assertRaises(ValueError):
                    host.require_context(self.environment(), "a" * 40)

    def test_container_has_only_public_readonly_mounts_and_no_network_or_capabilities(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            argv = host.container_argv(NAME, RUN, IMAGE, {"p": root, "inputs": root}, "a" * 64)
        for pair in [("--network", "none"), ("--cap-drop", "ALL"),
                     ("--security-opt", "no-new-privileges"), ("--pull", "never")]:
            index = argv.index(pair[0]);self.assertEqual(argv[index + 1], pair[1])
        self.assertIn("--read-only", argv)
        self.assertNotIn("GH_TOKEN", " ".join(argv))
        self.assertNotIn("PACKAGE_SIGNING", " ".join(argv))
        self.assertEqual(argv.count("--mount"), 2)
        self.assertTrue(all(argv[i+1].endswith(",readonly") for i,a in enumerate(argv) if a == "--mount"))

    def test_zero_identity_or_invalid_image_or_mount_syntax_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(host.os, "getuid", return_value=0):
                with self.assertRaises(ValueError):
                    host.container_argv(NAME, RUN, IMAGE, {"p": root, "inputs": root}, "a" * 64)
            for path in [Path("relative"), Path("/public,secret"), Path("/public\nbad")]:
                with self.assertRaises(ValueError):
                    host.safe_mount_path(path)


class BootstrapTests(unittest.TestCase):
    def test_source_digest_mismatch_is_refused_before_loading(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "source.py"
            p.write_text('raise AssertionError("PRIVATE_CANARY_EXECUTED")')
            with self.assertRaises(ValueError):
                entry.hashed(p, "0" * 64)

    def test_preimported_module_cannot_replace_held_source(self):
        with self.assertRaises(ValueError):
            entry.install_held_modules({"json": (Path("unused"), b"raise AssertionError")})

    def test_bundle_member_tampering_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            manifest = (PROBE / "manifest.json").read_bytes()
            (directory / "manifest.json").write_bytes(manifest)
            first = next(iter(json.loads(manifest)["files"]))
            (directory / first).write_bytes(b"changed")
            with self.assertRaises((ValueError, FileNotFoundError)):
                entry.load_bundle(directory)


class OrchestrationTests(unittest.TestCase):
    def execute(self, *, cleanup=True, input_failure=False):
        events = []
        iso = types.SimpleNamespace()
        bridge = types.SimpleNamespace()
        token = "PRIVATE_CANARY_TOKEN"

        def pop(env):
            return env.pop("GH_TOKEN")

        def image(**kwargs):
            self.assertEqual(kwargs["token"], token)
            self.assertNotIn("GH_TOKEN", os.environ)
            events.append("image")
            raw = (P_ROOT / "tools/verification/current_signer/runtime-image-admission.json").read_bytes()
            return {"image_id": IMAGE, "container_python": "/usr/bin/python3",
                    "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                    "recipe_sha256": json.loads(raw)["recipe_sha256"]}

        def dispose(lease, mods):
            events.append("image-dispose")
            return {"confirmed": True}

        def prepare(*args):
            self.assertNotIn("GH_TOKEN", os.environ)
            events.append("inputs")
            if input_failure:
                raise ValueError("PRIVATE_CANARY")

        iso.prepare_runtime_image, iso.dispose_runtime_image = image, dispose
        iso.PINNED_LEAF_MANIFEST_SHA256 = entry.LEAF_SHA256
        bridge.pop_readonly_gh_token = pop
        bridge.require_key_free_bridge_env = lambda env, **kw: self.assertNotIn("GH_TOKEN", env)
        bridge._cleanup_owned_tree = lambda *args: events.append("work-cleanup") or True
        engine = types.SimpleNamespace(BoundedDockerSubprocessEngine=lambda **kw: object())
        mods = {"runtime_workflow_bridge": bridge, "signing_image_build": engine}
        args = types.SimpleNamespace(p_commit="a" * 40, expected_entry_sha256="b" * 64)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            context = host.HostContext(P_ROOT, root, root, "c" * 40, RUN, iso, mods)
            owner = types.SimpleNamespace(name=NAME, create=lambda argv: events.append("create"),
                                          observe=lambda: observations(),
                                          cleanup=lambda: events.append("container-cleanup") or cleanup)
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(host, "recheck", side_effect=lambda *a: None), \
                    patch.object(host, "public_session", return_value=object()), \
                    patch.object(host, "prepare_inputs", side_effect=prepare), \
                    patch.object(host, "OwnedContainer", return_value=owner):
                credential = {"GH_TOKEN": token}
                result = host.execute_observation(context, args, PROFILE, credential)
                self.assertEqual(credential, {})
        self.assertNotIn(token, json.dumps(result))
        return result, events

    def test_token_is_popped_before_image_and_never_sent_to_container(self):
        result, events = self.execute()
        self.assertEqual(result["status"], "diagnostic-complete")
        self.assertEqual(events, ["image", "inputs", "create", "container-cleanup",
                                  "image-dispose", "work-cleanup"])
        self.assertFalse(result["signingPerformed"])
        self.assertFalse(result["publicationAuthority"])

    def test_uncertain_container_blocks_image_and_work_disposal(self):
        result, events = self.execute(cleanup=False)
        self.assertEqual((result["status"], result["code"]), ("refused", "CLEANUP_UNCONFIRMED"))
        self.assertNotIn("image-dispose", events)
        self.assertNotIn("work-cleanup", events)

    def test_public_input_failure_disposes_owned_image_without_starting_container(self):
        result, events = self.execute(input_failure=True)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["stage"], "INPUTS")
        self.assertNotIn("create", events)
        self.assertIn("image-dispose", events)
        self.assertIn("work-cleanup", events)


class RealHelperContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.iso = host.load_isolation(P_ROOT)
        cls.mods = cls.iso.load_production_leaves(P_ROOT, cls.iso.HOST_LEAVES)

    def test_all_source_and_workflow_pins_match_executed_files(self):
        workflow = P_ROOT / ".github/workflows/probe-current-rpm-metadata.yml"
        entry_sha = hashlib.sha256((PROBE / "entry.py").read_bytes()).hexdigest()
        self.assertIn('EXPECTED_ENTRY_SHA256: "' + entry_sha + '"', workflow.read_text())
        self.assertEqual(entry.LEAF_SHA256, self.iso.PINNED_LEAF_MANIFEST_SHA256)
        self.assertEqual(host.WORKFLOW_REF, "Knowledge-Forge-AI/theme-forge-packages/"
                         + workflow.relative_to(P_ROOT).as_posix() + "@refs/heads/main")
        self.assertEqual(host.ISO_SHA256, hashlib.sha256(
            (P_ROOT / "tools/verification/isolation_probe/current_signer_isolation_probe.py").read_bytes()).hexdigest())
        self.assertIs(host.CONTINUABLE_CODES, core.CONTINUABLE_CODES)

    def test_real_bridge_removes_image_stage_root_before_outer_cleanup(self):
        bridge = self.mods["runtime_workflow_bridge"]
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "owned";work.mkdir(mode=0o700)
            image = work / "image";image.mkdir(mode=0o700)
            for name in ("transport", "quarantine", "build"):
                part = image / name;part.mkdir(mode=0o700)
                (part / "public").write_bytes(b"public")
            self.assertTrue(bridge._cleanup_owned_tree(image, {"transport", "quarantine", "build"}))
            self.assertFalse(image.exists())
            (work / "inputs").mkdir(mode=0o700)
            (work / "inputs/public.rpm").write_bytes(b"public")
            self.assertTrue(bridge._cleanup_owned_tree(work, {"inputs"}))
            self.assertFalse(work.exists())

    def test_real_leaf_callable_signatures_accept_the_exact_bridge_keywords(self):
        self.assertIn("source_closure", self.iso.HOST_LEAVES)
        bridge = self.mods["runtime_workflow_bridge"]
        inspect.signature(self.mods["source_closure"].authenticate_leaf_closure).bind(
            P_ROOT, expected_leaf_manifest_sha256=entry.LEAF_SHA256, require_unimported=False)
        inspect.signature(self.mods["signing_image_build"].BoundedDockerSubprocessEngine).bind(
            allow_native_execution=False, timeout_seconds=300)
        inspect.signature(self.iso.prepare_runtime_image).bind(
            p_dir=P_ROOT, work_dir=P_ROOT, run_suffix="7", token="public-canary",
            environ={}, mods=self.mods, recheck=lambda: None)
        holder = {"GH_TOKEN": "public-canary"}
        self.assertEqual(bridge.pop_readonly_gh_token(holder), "public-canary")
        self.assertEqual(holder, {})
        bridge.require_key_free_bridge_env({}, allow_gh_token=False)
        self.mods["source_closure"].authenticate_leaf_closure(
            P_ROOT, expected_leaf_manifest_sha256=entry.LEAF_SHA256, require_unimported=False)

    def test_real_admission_identity_uses_the_exact_raw_manifest_bytes(self):
        sib = self.mods["signing_image_build"]
        path = P_ROOT / "tools/verification/current_signer/runtime-image-admission.json"
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(digest, sib.ADMITTED_MANIFEST_SHA256)
        manifest, authenticated_raw = sib.authenticate_admission_manifest(
            path, expected_manifest_sha256=digest)
        self.assertEqual(authenticated_raw, raw)
        self.assertEqual(manifest.manifest_sha256, digest)
        self.assertIn("createrepo_c", json.loads(raw)["roots"])

    def test_real_engine_private_callable_accepts_the_exact_container_contract(self):
        sib = self.mods["signing_image_build"]
        inspect.signature(sib.BoundedDockerSubprocessEngine._run_bounded).bind(
            object(), "rpm-keyfree-container", ("/usr/bin/docker", "container", "ls"))
        self.assertGreaterEqual(sib.MAX_ENGINE_STREAM_BYTES, 16384)

    def test_real_image_preparation_authenticates_sources_before_transport(self):
        self.iso.verify_production_pins(P_ROOT)
        calls = []
        def refuse_transport(token, directory):
            calls.append("transport")
            raise RuntimeError("FIXED_TEST_STOP")
        def forbidden_engine():
            raise AssertionError("Native execution must not be reached")
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "image"
            with self.assertRaises(self.iso.ProbeRefusal) as caught:
                self.iso.prepare_runtime_image(
                    p_dir=P_ROOT, work_dir=work, run_suffix="7", token="public-canary",
                    environ={}, mods=self.mods, recheck=lambda: None,
                    transport_factory=refuse_transport, engine_factory=forbidden_engine)
            self.assertEqual(caught.exception.stage, "INTAKE")
            self.assertTrue(caught.exception.probe_lease["work_root_cleaned"])
            self.assertFalse(work.exists())
        self.assertEqual(calls, ["transport"])

    def test_generic_clean_checkout_helper_accepts_exact_r_coordinates(self):
        bridge = self.mods["runtime_workflow_bridge"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);(root / ".git").mkdir()
            def git(argv, directory, env):
                self.assertEqual(directory, root)
                self.assertNotIn("GH_TOKEN", env)
                value = (host.R_COMMIT if argv[1:] == ("rev-parse", "HEAD") else
                         host.R_TREE if argv[1] == "rev-parse" else "")
                return 0, (value + "\n").encode() if value else b"", b""
            _, tree = bridge.verify_clean_p_checkout_and_resolve_tree(root, host.R_COMMIT, git_runner=git)
            self.assertEqual(tree, host.R_TREE)

    def test_real_r_transport_public_api_and_import_origin(self):
        import sys
        r_root = Path(os.environ.get("TF_RPM_R_SOURCE", P_ROOT.parent / "r"))
        self.assertTrue((r_root / "src/rs9/public_release_transport.py").is_file())
        sys.path.insert(0, str(r_root / "src"))
        import rs9.public_release_transport as transport
        self.assertEqual(Path(transport.__file__), r_root / "src/rs9/public_release_transport.py")
        inspect.signature(transport.PublicReleaseTransport.prepare).bind(
            object(), PROFILE["artifacts"], commit=host.R_COMMIT,
            run_id=PROFILE["RRun"], generation="current")
        inspect.signature(transport.PublicRelaySession.download).bind(
            object(), {}, Path("public.zip"), total_tracker=[0])


if __name__ == "__main__":
    unittest.main()

