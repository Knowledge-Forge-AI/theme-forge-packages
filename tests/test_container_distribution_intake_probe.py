"""Pure contracts; no Docker, network, image build or native execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("container_probe", ROOT / "tools/verification/probe_container_distribution_intake.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def arguments():
    return dict(image="sha256:" + "a" * 64, python="/usr/bin/python3", p_root="/fixture/p", r_root="/fixture/r", observer_file="/fixture/probe.py", export_root="/fixture/export", name="tf-intake-1234-" + "b" * 32, owner="c" * 64, uid=1001, gid=1001)


def observation():
    names = ("classificationQualified", "generationCurrent", "scopeMatches", "sourceCommitBound", "runIdBound", "currentDistributionQualificationTrue", "fullLive1False", "publishedReadyFalse", "productionFalse", "publicationFalse")
    return dict(schema="tf.keyfree-current-distribution-intake.v1", status="observed-pass", phase="COMPLETE", sourceRun=41935969366, sourceCommit="42942b2d0f60059102c3baf43c5045e1ff42da7e", signingOrPublicationAuthority=False, signerContainerExercised=False, nativeFailureCauseProved=False, verifiedContextPassed=True, exceptionCode="NONE", collectionCleanupConfirmed=True, probeFault=False, packetState="AVAILABLE", hostedSummaryPresent=True,
                packet=dict(validationStatus="pass", validationReasons=[], artifactCollectionReasons=[], artifactFailureCodes=[], verifiedArtifacts=12, failedArtifacts=0, expiredArtifacts=0, expectedArtifactCount=True, packetPredicates={name: True for name in names}, summaryBinding="verified"))


class Commands(unittest.TestCase):
    def test_hardening_and_noninit_inspection(self):
        args = probe.docker_argv(**arguments())
        self.assertEqual(args[:4], ["/usr/bin/docker", "run", "--rm", "-i"])
        self.assertEqual(args[args.index("--network") + 1], "bridge")
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        self.assertEqual(args[args.index("--security-opt") + 1], "no-new-privileges")
        self.assertEqual(args[args.index("--tmpfs") + 1], "/work/workspace:rw,exec,nosuid,nodev,mode=0700,uid=1001,gid=1001")
        self.assertEqual(args[-6:], ["--", "/usr/bin/python3", "-I", "-B", "-c", probe.CONTAINER_CODE])
        self.assertNotIn("--current-signer-worker", args)
        self.assertNotIn("--privileged", args)
        self.assertEqual(sum(item.endswith(",readonly") for item in args), 3)

    def test_only_selected_env_and_no_home_override(self):
        args = probe.docker_argv(**arguments())
        names = [args[i + 1] for i, value in enumerate(args) if value == "-e"]
        self.assertEqual(names, ["GH_TOKEN", *probe.CONTEXT_KEYS])
        self.assertNotIn("HOME", names)
        self.assertNotIn("/var/run/docker.sock", " ".join(args))
        self.assertFalse(any("PACKAGE_SIGNING" in value for value in args))

    def test_invalid_identity_or_path_refused(self):
        for key, value in [("image", "mutable:latest"), ("python", "/other/python"), ("uid", 0), ("gid", 0), ("name", "foreign"), ("owner", "bad"), ("p_root", "relative"), ("observer_file", "/bad,readonly")]:
            data = arguments()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(probe.Refusal):
                probe.docker_argv(**data)


class Lifecycle(unittest.TestCase):
    def exercise(self, responses):
        calls = []
        def run(args, env, **options):
            calls.append(args)
            result = responses.pop(0)
            if isinstance(result, BaseException):
                raise result
            return types.SimpleNamespace(returncode=result[0], stdout=result[1])
        result = probe.run_owned_container(["/fixture/run"], arguments()["name"], {}, run)
        return result, calls

    def test_success_confirms_absence(self):
        result, calls = self.exercise([(0, b""), (0, b""), (0, b"")])
        self.assertEqual(result, dict(attempted=True, exit="ZERO", absenceConfirmed=True))
        self.assertEqual(len(calls), 3)
        self.assertIn("name=" + arguments()["name"], calls[0])
        self.assertIn("name=" + arguments()["name"], calls[-1])

    def test_existing_or_uncertain_name_never_starts(self):
        for response in [(0, b"foreign-fixture-id"), (1, b"")]:
            result, calls = self.exercise([response])
            self.assertFalse(result["attempted"])
            self.assertEqual(len(calls), 1)

    def test_nonzero_still_checks_removal(self):
        result, _ = self.exercise([(0, b""), (1, b""), (0, b"")])
        self.assertEqual(result["exit"], "NONZERO")
        self.assertTrue(result["absenceConfirmed"])

    def test_timeout_retains_without_cleanup_mutation(self):
        result, calls = self.exercise([(0, b""), subprocess.TimeoutExpired("fixture", 1), (0, b"owned-fixture-id")])
        self.assertEqual(result["exit"], "INTERRUPTED_OR_TIMEOUT")
        self.assertFalse(result["absenceConfirmed"])
        self.assertFalse(any("rm" in args or "kill" in args or "stop" in args for args in calls))

    def test_uncertain_postquery_does_not_expose_error(self):
        result, _ = self.exercise([(0, b""), (0, b""), OSError("fixture-private-sentinel")])
        self.assertFalse(result["absenceConfirmed"])
        self.assertNotIn("fixture-private-sentinel", json.dumps(result))

    def test_absence_query_receives_no_token(self):
        seen = []
        def run(args, env, **kwargs):
            seen.append(dict(env))
            return types.SimpleNamespace(returncode=0, stdout=b"")
        self.assertTrue(probe.absent(arguments()["name"], {"PATH": "/usr/bin:/bin", "GH_TOKEN": "fixture-token"}, run))
        self.assertEqual(seen, [{"PATH": "/usr/bin:/bin"}])


class Disclosure(unittest.TestCase):
    def test_source_run_and_scope_require_exact_types(self):
        for key, value in [("sourceRun", 41935969366.0), ("signerContainerExercised", "fixture-private-sentinel")]:
            doc = observation()
            doc[key] = value
            with self.subTest(key=key), self.assertRaises(probe.Refusal):
                probe.closed_observation(doc, frozenset())

    def test_packet_availability_must_match_content(self):
        doc = observation()
        doc["packetState"] = "UNAVAILABLE"
        with self.assertRaises(probe.Refusal):
            probe.closed_observation(doc, frozenset())

    def test_nonfinite_and_duplicate_json_refused(self):
        for raw in ['{"count":NaN}', '{"count":Infinity}', '{"count":-Infinity}', '{"count":0,"count":1}']:
            with self.subTest(raw=raw), self.assertRaises(probe.Refusal):
                probe.strict_json(raw)
    def test_valid_success_excludes_host_scope_flag(self):
        result = probe.closed_observation(observation(), frozenset())
        self.assertEqual(result["status"], "observed-pass")
        self.assertNotIn("signerContainerExercised", result)

    def test_unknown_values_refused(self):
        for location in ("extra", "code", "packetCode", "source"):
            doc = observation()
            if location == "extra":
                doc["fixture-private-sentinel"] = "fixture-private-sentinel"
            elif location == "code":
                doc["exceptionCode"] = "fixture-private-sentinel"
            elif location == "packetCode":
                doc["packet"]["validationReasons"] = ["fixture-private-sentinel"]
            else:
                doc["sourceCommit"] = "fixture-private-sentinel"
            with self.subTest(location=location), self.assertRaises(probe.Refusal):
                probe.closed_observation(doc, frozenset())

    def test_inconsistent_success_refused(self):
        for key, value in [("verifiedContextPassed", False), ("probeFault", True), ("collectionCleanupConfirmed", False), ("hostedSummaryPresent", False)]:
            doc = observation()
            doc[key] = value
            with self.subTest(key=key), self.assertRaises(probe.Refusal):
                probe.closed_observation(doc, frozenset())
        for key, value in [("expiredArtifacts", 1), ("verifiedArtifacts", 11), ("expectedArtifactCount", False)]:
            doc = observation()
            doc["packet"][key] = value
            with self.subTest(key=key), self.assertRaises(probe.Refusal):
                probe.closed_observation(doc, frozenset())

    def test_early_refusal_survives_unavailable_packet(self):
        doc = observation()
        doc.update(status="refused", phase="IMPORT", verifiedContextPassed=False, exceptionCode="PROBE_REFUSED", packet=None, collectionCleanupConfirmed=False, probeFault=True)
        doc.pop("packetState")
        doc.pop("hostedSummaryPresent")
        result = probe.closed_observation(doc, frozenset())
        self.assertEqual(result["exceptionCode"], "PROBE_REFUSED")
        self.assertEqual(result["packetState"], "UNAVAILABLE")

    def test_observed_failure_preserves_source_code(self):
        doc = observation()
        doc.update(status="observed-fail", verifiedContextPassed=False, exceptionCode="DISTRIBUTION_NOT_QUALIFIED")
        result = probe.closed_observation(doc, {"DISTRIBUTION_NOT_QUALIFIED"})
        self.assertEqual(result["exceptionCode"], "DISTRIBUTION_NOT_QUALIFIED")


class HeldSource(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_exact_bytes_load(self):
        path = self.root / "source.py"
        raw = b"VALUE = 42\n"
        path.write_bytes(raw)
        module = probe.load_held(path, hashlib.sha256(raw).hexdigest(), "_fixture_held_probe")
        self.assertEqual(module.VALUE, 42)

    def test_mismatch_never_executes(self):
        path = self.root / "source.py"
        path.write_bytes(b"raise AssertionError('must not execute')\n")
        with self.assertRaises(probe.Refusal):
            probe.load_held(path, "a" * 64, "_fixture_bad_probe")

    def test_links_refused(self):
        path = self.root / "source.py"
        raw = b"VALUE = 42\n"
        path.write_bytes(raw)
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            probe.load_held(link, hashlib.sha256(raw).hexdigest(), "_fixture_link_probe")
        hardlink = self.root / "hardlink"
        os.link(path, hardlink)
        with self.assertRaises(probe.Refusal):
            probe.load_held(hardlink, hashlib.sha256(raw).hexdigest(), "_fixture_hardlink_probe")


class Orchestration(unittest.TestCase):
    def exercise(self, *, absent=True, disposal=True, corrupt=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            p_root, r_root, caller = [root / name for name in ("p", "r", "caller")]
            for path in (p_root, r_root, caller):
                path.mkdir()
            export = root / "export"
            disposed, environments = [], []
            def held(path, limit=None):
                if Path(path).name == "probe_current_distribution_intake.py":
                    return (ROOT / probe.OBSERVER_REL).read_bytes()
                return Path(path).read_bytes()
            observer = types.SimpleNamespace(authenticate_context=lambda env: "1234", physical_directory=lambda path: path,
                clean_git=lambda *args: None, closed_codes=lambda path: frozenset(), held_bytes=held,
                P_COMMIT="a" * 40, P_TREE="b" * 40, R_COMMIT="c" * 40, R_TREE="d" * 40)
            bridge = types.SimpleNamespace(pop_readonly_gh_token=lambda env: env.pop("GH_TOKEN"), require_key_free_bridge_env=lambda *args, **kwargs: None)
            modules = {"runtime_workflow_bridge": bridge, "source_closure": types.SimpleNamespace(authenticate_leaf_closure=lambda *args, **kwargs: None)}
            lease = dict(image_id="sha256:" + "a" * 64, container_python="/usr/bin/python3", manifest_sha256="b" * 64, recipe_sha256="c" * 64)
            def prepare(**kwargs):
                self.assertEqual(kwargs["token"], "fixture-read-token")
                self.assertNotIn("GH_TOKEN", kwargs["environ"])
                kwargs["recheck"]()
                return lease
            def dispose(received, mods):
                self.assertIs(received, lease)
                disposed.append(True)
                return {"confirmed": disposal}
            iso = types.SimpleNamespace(verify_production_pins=lambda root: None, load_production_leaves=lambda *args: modules,
                HOST_LEAVES=(), PINNED_LEAF_MANIFEST_SHA256="d" * 64, prepare_runtime_image=prepare,
                dispose_runtime_image=dispose, ProbeRefusal=type("FixtureRefusal", (Exception,), {}), IMAGE_STAGES=())
            def container(args, name, env):
                environments.append(dict(env))
                raw = "fixture-private-sentinel" if corrupt else json.dumps(observation())
                (export / "RESULT.json").write_text(raw)
                return {"attempted": True, "exit": "ZERO", "absenceConfirmed": absent}
            fake_command = lambda *args, **kwargs: types.SimpleNamespace(returncode=0, stdout=b"f" * 40 + b"\n")
            with patch.dict(os.environ, {"GH_TOKEN": "fixture-read-token", "GITHUB_SHA": "e" * 40}), patch.object(probe.sys, "platform", "linux"), patch.object(probe, "load_held", side_effect=[observer, iso]), patch.object(probe, "run_owned_container", side_effect=container), patch.object(probe, "command", side_effect=fake_command):
                result = probe.execute(p_root, r_root, caller, root / "image", export)
            return result, disposed, environments, export.exists()

    def test_success_disposes_exact_lease_and_only_forwards_read_token(self):
        result, disposed, envs, export_exists = self.exercise()
        self.assertEqual(result["status"], "observed-pass")
        self.assertTrue(result["imageRuntimeExercised"])
        self.assertTrue(result["imageDisposalConfirmed"])
        self.assertEqual(len(disposed), 1)
        self.assertEqual(envs[0]["GH_TOKEN"], "fixture-read-token")
        self.assertTrue(set(envs[0]) <= {"PATH", "HOME", "LANG", "LC_ALL", "GH_TOKEN", *probe.CONTEXT_KEYS})
        self.assertNotIn("fixture-read-token", json.dumps(result))
        self.assertFalse(export_exists)

    def test_uncertain_container_holds_lease(self):
        result, disposed, _, export_exists = self.exercise(absent=False)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["refusal"], "CONTAINER_CUSTODY_UNCONFIRMED")
        self.assertEqual(disposed, [])
        self.assertIsNone(result["observation"])
        self.assertTrue(export_exists)

    def test_failed_image_disposal_overrides_observation_success(self):
        result, disposed, _, _ = self.exercise(disposal=False)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["refusal"], "IMAGE_CUSTODY_UNCONFIRMED")
        self.assertEqual(len(disposed), 1)

    def test_corrupt_result_is_withheld_and_lease_disposed(self):
        result, disposed, _, export_exists = self.exercise(corrupt=True)
        self.assertEqual(result["status"], "refused")
        self.assertNotIn("fixture-private-sentinel", json.dumps(result))
        self.assertIsNone(result["observation"])
        self.assertEqual(len(disposed), 1)
        self.assertTrue(export_exists)


if __name__ == "__main__":
    unittest.main()
