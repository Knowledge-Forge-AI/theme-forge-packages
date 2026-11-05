"""Pure contract checks; no GitHub, collector, product or signing execution."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("intake_probe", ROOT / "tools/verification/probe_current_distribution_intake.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def context():
    return {"GITHUB_REPOSITORY": probe.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW_REF": probe.WORKFLOW_REF, "GITHUB_RUN_ID": "1234", "GITHUB_SHA": "a" * 40, "GH_TOKEN": "fixture-read-token"}


def packet():
    return {"validation": {"status": "pass", "reasons": []}, "artifacts": [{"collection": "verified"} for _ in range(12)],
            "classification": "qualified-current-distribution-candidate", "generation": "theme-forge-current-202610",
            "qualification_scope": "current-distribution-only", "source_commit": probe.R_COMMIT, "run_id": probe.R_RUN,
            "production_enabled": False, "publication_authority": False,
            "diagnostic_scope": {"summary_binding": "verified", "current_distribution_qualification": True,
                                 "full_live1_qualification": False, "published_linux_nix_ready": False}}


class Disclosure(unittest.TestCase):
    def test_exact_success_view(self):
        view = probe.packet_view(packet(), frozenset())
        self.assertEqual(view["validationStatus"], "pass")
        self.assertEqual(view["validationReasons"], [])
        self.assertEqual(view["verifiedArtifacts"], 12)
        self.assertEqual(view["expiredArtifacts"], 0)
        self.assertTrue(view["expectedArtifactCount"])
        self.assertTrue(all(view["packetPredicates"].values()))

    def test_unknown_values_do_not_escape(self):
        doc = packet()
        doc.update(private="fixture-private-sentinel", artifact_collection_reasons=["fixture-private-sentinel"])
        doc["validation"] = {"status": "fixture-private-sentinel", "reasons": ["fixture-private-sentinel"]}
        doc["artifacts"][0] = {"collection": "failed", "reason": "fixture-private-sentinel", "path": "fixture-private-sentinel"}
        doc["diagnostic_scope"]["summary_binding"] = "fixture-private-sentinel"
        raw = json.dumps(probe.packet_view(doc, {"HOSTED_COLLECTION_FAILED"}))
        self.assertNotIn("fixture-private-sentinel", raw)
        self.assertNotIn("path", raw)
        self.assertIn("UNLISTED_CODE", raw)

    def test_known_refusal_is_retained_and_deduplicated(self):
        doc = packet()
        doc["validation"] = {"status": "fail", "reasons": ["HOSTED_API", "HOSTED_API"]}
        doc["artifacts"][0] = {"collection": "failed", "reason": "HOSTED_API"}
        view = probe.packet_view(doc, {"HOSTED_API"})
        self.assertEqual(view["validationReasons"], ["HOSTED_API"])
        self.assertEqual(view["artifactFailureCodes"], ["HOSTED_API"])
        self.assertEqual(view["failedArtifacts"], 1)
        self.assertEqual(view["verifiedArtifacts"], 11)

    def test_malformed_packet_refused(self):
        for doc in [None, [], {}, {**packet(), "artifacts": [None]}, {**packet(), "artifacts": [{}] * 129}, {**packet(), "validation": []}, {**packet(), "diagnostic_scope": None}]:
            with self.subTest(doc=type(doc).__name__), self.assertRaises(probe.Refusal):
                probe.packet_view(doc, frozenset())

    def test_labels_are_bounded(self):
        doc = packet()
        labels = ["CODE_" + str(i) for i in range(20)]
        doc["validation"]["reasons"] = labels
        self.assertEqual(len(probe.packet_view(doc, set(labels))["validationReasons"]), 8)

    def test_wrong_reason_type_is_closed(self):
        doc = packet()
        doc["validation"]["reasons"] = "fixture-private-sentinel"
        self.assertEqual(probe.packet_view(doc, frozenset())["validationReasons"], ["UNLISTED_CODE"])

    def test_each_packet_predicate_flips_independently(self):
        cases = [("classification", "bad", "classificationQualified"), ("generation", "bad", "generationCurrent"),
                 ("qualification_scope", "bad", "scopeMatches"), ("source_commit", "bad", "sourceCommitBound"),
                 ("run_id", True, "runIdBound"), ("production_enabled", True, "productionFalse"),
                 ("publication_authority", True, "publicationFalse")]
        scoped = [("current_distribution_qualification", False, "currentDistributionQualificationTrue"),
                  ("full_live1_qualification", True, "fullLive1False"), ("published_linux_nix_ready", True, "publishedReadyFalse")]
        for key, value, expected in cases + scoped:
            doc = packet()
            (doc["diagnostic_scope"] if (key, value, expected) in scoped else doc)[key] = value
            predicates = probe.packet_view(doc, frozenset())["packetPredicates"]
            self.assertEqual([key for key, passed in predicates.items() if not passed], [expected])

    def test_additional_and_expired_artifacts_remain_observable(self):
        doc = packet()
        doc["artifacts"].append({"expired": True})
        view = probe.packet_view(doc, frozenset())
        self.assertFalse(view["expectedArtifactCount"])
        self.assertEqual(view["expiredArtifacts"], 1)


class CollectionObservation(unittest.TestCase):
    class ContractError(Exception):
        def __init__(self, code):
            self.code = code

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def call(self, verifier):
        return probe.collection_observation(None, self.root, verifier, self.ContractError, {"DISTRIBUTION_NOT_QUALIFIED", "DISTRIBUTION_SOURCE"})

    def test_precollect_code_survives_missing_packet(self):
        def fail(*args, **kwargs):
            raise self.ContractError("DISTRIBUTION_SOURCE")
        result = self.call(fail)
        self.assertEqual(result["exceptionCode"], "DISTRIBUTION_SOURCE")
        self.assertEqual(result["packetState"], "UNAVAILABLE")
        self.assertFalse(result["verifiedContextPassed"])

    def test_code_survives_malformed_packet(self):
        (self.root / "manager-packet.json").write_text("fixture-private-sentinel")
        def fail(*args, **kwargs):
            raise self.ContractError("DISTRIBUTION_NOT_QUALIFIED")
        result = self.call(fail)
        self.assertEqual(result["exceptionCode"], "DISTRIBUTION_NOT_QUALIFIED")
        self.assertNotIn("fixture-private-sentinel", json.dumps(result))

    def test_noncontract_outcome_still_reads_packet(self):
        (self.root / "manager-packet.json").write_text(json.dumps(packet()))
        def fail(*args, **kwargs):
            raise OSError("fixture-private-sentinel")
        result = self.call(fail)
        self.assertEqual(result["exceptionCode"], "NON_CONTRACT_OSERROR")
        self.assertEqual(result["packetState"], "AVAILABLE")
        self.assertTrue(all(result["packet"]["packetPredicates"].values()))
        self.assertNotIn("fixture-private-sentinel", json.dumps(result))

    def test_success_and_owned_summary(self):
        (self.root / "manager-packet.json").write_text(json.dumps(packet()))
        (self.root / "hosted-summary").mkdir()
        (self.root / "hosted-summary/hosted-summary.json").write_text("{}")
        result = self.call(lambda *args, **kwargs: None)
        self.assertTrue(result["verifiedContextPassed"])
        self.assertTrue(result["hostedSummaryPresent"])
        self.assertFalse(result["probeFault"])

    def test_inherited_and_python_output_are_discarded(self):
        read_fd, write_fd = os.pipe()
        saved = [os.dup(1), os.dup(2)]
        try:
            os.dup2(write_fd, 1)
            os.dup2(write_fd, 2)
            def noisy(*args, **kwargs):
                os.write(1, b"fixture-private-sentinel")
                os.write(2, b"fixture-private-sentinel")
                print("fixture-private-sentinel")
                raise self.ContractError("DISTRIBUTION_SOURCE")
            result = self.call(noisy)
        finally:
            os.dup2(saved[0], 1)
            os.dup2(saved[1], 2)
            for fd in [write_fd, *saved]:
                os.close(fd)
        try:
            self.assertEqual(os.read(read_fd, 4096), b"")
        finally:
            os.close(read_fd)
        self.assertEqual(result["exceptionCode"], "DISTRIBUTION_SOURCE")


class Context(unittest.TestCase):
    def test_selected_original_context(self):
        self.assertEqual(probe.authenticate_context(context()), "1234")

    def test_forged_context_refused(self):
        for key, value in [("GITHUB_REPOSITORY", "other/repository"), ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", "refs/heads/staging"), ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_WORKFLOW_REF", "wrong"), ("GITHUB_RUN_ID", "0"), ("GITHUB_SHA", "not-a-commit"), ("GH_TOKEN", "")]:
            env = context()
            env[key] = value
            with self.subTest(key=key), self.assertRaises(probe.Refusal):
                probe.authenticate_context(env)

    def test_signing_and_foreign_credentials_refused(self):
        for name in ("PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE", "CUSTOM_PRIVATE_KEY", "GNUPGHOME", "SSH_AUTH_SOCK", "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
            env = context()
            env[name] = "fixture-private-sentinel"
            with self.subTest(name=name), self.assertRaises(probe.Refusal):
                probe.authenticate_context(env)

    def test_context_failure_has_no_effect_or_raw_output(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch.object(probe.sys, "platform", "linux"), patch.object(probe, "clean_git", side_effect=AssertionError("must not reach Git")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = probe.observe("/unopened-p", "/unopened-r")
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["phase"], "CONTEXT")
        self.assertEqual(result["exceptionCode"], "PROBE_REFUSED")
        self.assertEqual(out.getvalue() + err.getvalue(), "")
        self.assertFalse(result["verifiedContextPassed"])


class Filesystem(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def leaf(self):
        path = self.root / "collection"
        path.mkdir(mode=0o700)
        return path, (path.stat().st_dev, path.stat().st_ino)

    def test_held_file_read_and_limits(self):
        path = self.root / "record"
        path.write_bytes(b"abc")
        self.assertEqual(probe.held_bytes(path, 3), b"abc")
        with self.assertRaises(probe.Refusal):
            probe.held_bytes(path, 2)

    def test_symlink_and_hardlink_reads_refused(self):
        original = self.root / "original"
        original.write_bytes(b"public-fixture")
        symlink = self.root / "symlink"
        symlink.symlink_to(original)
        with self.assertRaises(OSError):
            probe.held_bytes(symlink)
        hardlink = self.root / "hardlink"
        os.link(original, hardlink)
        with self.assertRaises(probe.Refusal):
            probe.held_bytes(hardlink)

    def test_owned_public_tree_removed(self):
        path, identity = self.leaf()
        (path / "subdir").mkdir()
        (path / "subdir/member").write_bytes(b"public-fixture")
        self.assertTrue(probe.remove_collection(path, identity))
        self.assertFalse(path.exists())

    def test_symlink_cleanup_refused_and_target_preserved(self):
        path, identity = self.leaf()
        target = self.root / "preserve"
        target.write_bytes(b"keep")
        (path / "link").symlink_to(target)
        self.assertFalse(probe.remove_collection(path, identity))
        self.assertEqual(target.read_bytes(), b"keep")
        self.assertTrue(path.is_dir())

    def test_replaced_root_not_deleted(self):
        path, identity = self.leaf()
        path.rename(self.root / "original")
        path.mkdir()
        self.assertFalse(probe.remove_collection(path, identity))
        self.assertTrue(path.exists())

    def test_hardlink_cleanup_refused(self):
        path, identity = self.leaf()
        original = self.root / "preserve"
        original.write_bytes(b"keep")
        os.link(original, path / "member")
        self.assertFalse(probe.remove_collection(path, identity))
        self.assertEqual(original.read_bytes(), b"keep")

    def test_normal_home_unchanged_and_exclusive_collection(self):
        before = os.environ.get("HOME")
        with patch.object(probe.Path, "home", return_value=self.root):
            path, identity = probe.fresh_collection("1234")
            with self.assertRaises(FileExistsError):
                probe.fresh_collection("1234")
            self.assertEqual(os.environ.get("HOME"), before)
            self.assertTrue(probe.remove_collection(path, identity))

    def test_physical_directory_rejects_symlink(self):
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(probe.Refusal):
            probe.physical_directory(link)

    def test_closed_labels_come_from_pinned_public_source(self):
        source = self.root / "src/rs9"
        source.mkdir(parents=True)
        (source / "codes.py").write_text('CODE = "HOSTED_API"\nOTHER = "fixture-private-sentinel"\n')
        self.assertEqual(probe.closed_codes(self.root), frozenset({"HOSTED_API"}))


if __name__ == "__main__":
    unittest.main()
