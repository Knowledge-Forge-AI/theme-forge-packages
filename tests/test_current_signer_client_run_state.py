"""Pure current-client admission regressions; no API, GPG or package clients run."""
import copy
import json
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/verification/current_signer"))
import client_artifact_input as subject
import publication_github_api as gh

RUN, WORKFLOW, COMMIT = 777, 55, "a" * 40
LANES = subject.ALLOWED_CLIENT_LANES


class Api:
    """Exact-path in-memory metadata fixture; never executes a transport."""
    def __init__(self, status="in_progress"):
        self.workflow = {"id": WORKFLOW, "path": subject.QUALIFY_WORKFLOW_PATH}
        self.run = {
            "id": RUN, "workflow_id": WORKFLOW, "path": subject.QUALIFY_WORKFLOW_PATH,
            "event": "workflow_dispatch", "head_branch": "main", "run_attempt": 1,
            "previous_attempt_url": None, "status": status, "conclusion": None,
            "head_sha": COMMIT, "repository": {"full_name": gh.REPOSITORY},
            "head_repository": {"full_name": gh.REPOSITORY},
        }
        self.jobs = [
            {"id": i + 10, "name": name, "run_id": RUN, "run_attempt": 1,
             "head_sha": COMMIT, "head_branch": "main",
             "status": "completed" if name == subject.SIGNER_JOB_NAME else "in_progress",
             "conclusion": "success" if name == subject.SIGNER_JOB_NAME else None}
            for i, name in enumerate((subject.SIGNER_JOB_NAME, *LANES))
        ]

    def get(self, path):
        base = f"repos/{gh.REPOSITORY}/actions"
        if path == base + "/workflows/qualify-current-signer.yml":
            value = self.workflow
        elif path == base + f"/runs/{RUN}":
            value = self.run
        elif path == base + f"/runs/{RUN}/attempts/1/jobs?per_page=100&page=1":
            value = {"total_count": len(self.jobs), "jobs": self.jobs}
        else:
            raise AssertionError("Unexpected fixture metadata path")
        return json.dumps(value).encode()


class ClientRunStateTests(unittest.TestCase):
    def refused(self, api, code, lane=LANES[0]):
        with self.assertRaises(gh.PublicationError) as caught:
            subject.admit_in_progress_qualification_run(api, RUN, COMMIT, lane)
        self.assertEqual(caught.exception.code, code)

    def test_queued_and_in_progress_admit_every_active_lane(self):
        for status in ("queued", "in_progress"):
            for lane in LANES:
                with self.subTest(status=status, lane=lane):
                    result = subject.admit_in_progress_qualification_run(Api(status), RUN, COMMIT, lane)
                    self.assertEqual(set(result), {"run_id", "workflow_id", "signer_job_id", "lane_job_id"})
                    self.assertEqual(result["run_id"], RUN)
                    self.assertEqual(result["signer_job_id"], 10)

    def test_all_other_statuses_have_fixed_refusals(self):
        states = {
            "completed": "COMPLETED", "waiting": "WAITING", "pending": "PENDING",
            "requested": "REQUESTED", "action_required": "ACTION_REQUIRED",
        }
        for state, label in states.items():
            for lane in LANES:
                with self.subTest(state=state, lane=lane):
                    self.refused(Api(state), "QUALIFICATION_RUN_STATUS_" + label, lane)

    def test_unknown_malformed_and_missing_status_never_echo_values(self):
        for value in ("untrusted-status-canary", None, False, 7, [], {}):
            with self.subTest(type=type(value).__name__):
                self.refused(Api(value), "QUALIFICATION_RUN_STATUS_OTHER")
        api = Api()
        del api.run["status"]
        self.refused(api, "QUALIFICATION_RUN_STATUS_OTHER")

    def test_explicit_null_conclusion_required(self):
        for state in ("queued", "in_progress"):
            for conclusion in ("success", "failure", "cancelled", "unknown", False, 0, []):
                with self.subTest(state=state, conclusion=conclusion):
                    api = Api(state)
                    api.run["conclusion"] = conclusion
                    self.refused(api, "QUALIFICATION_RUN_CONCLUSION_NON_NULL")
            api = Api(state)
            del api.run["conclusion"]
            self.refused(api, "QUALIFICATION_RUN_CONCLUSION_ABSENT")

    def test_completed_never_admitted_even_with_null_or_success_conclusion(self):
        for value in (None, "success", "failure", "cancelled"):
            api = Api("completed")
            api.run["conclusion"] = value
            self.refused(api, "QUALIFICATION_RUN_STATUS_COMPLETED")

    def test_queued_status_does_not_bypass_any_run_identity_field(self):
        mutations = {
            "id": RUN + 1, "workflow_id": WORKFLOW + 1, "path": "other.yml",
            "event": "pull_request", "head_branch": "topic", "run_attempt": 2,
            "previous_attempt_url": "https://example.invalid/attempt/1", "head_sha": "b" * 40,
            "repository": {"full_name": "untrusted/fork"},
            "head_repository": {"full_name": "untrusted/fork"},
        }
        for key, value in mutations.items():
            for lane in LANES:
                with self.subTest(field=key, lane=lane):
                    api = Api("queued")
                    api.run[key] = value
                    self.refused(api, "QUALIFICATION_RUN_MISMATCH", lane)

    def test_workflow_identity_remains_required(self):
        for key, value in (("id", None), ("path", "other.yml")):
            api = Api("queued")
            api.workflow[key] = value
            self.refused(api, "QUALIFICATION_WORKFLOW")

    def test_signer_must_exist_and_have_completed_successfully(self):
        for state, conclusion in (("queued", None), ("in_progress", None),
                                  ("completed", "failure"), ("completed", "cancelled"),
                                  ("completed", "skipped"), ("completed", None)):
            api = Api("queued")
            api.jobs[0].update(status=state, conclusion=conclusion)
            self.refused(api, "SIGNER_JOB_NOT_SUCCESSFUL")
        api = Api("queued")
        api.jobs.pop(0)
        self.refused(api, "SIGNER_JOB_NOT_SUCCESSFUL")

    def test_each_caller_lane_must_be_active_and_nonterminal(self):
        for lane in LANES:
            for status, conclusion in (("completed", "success"), ("completed", "failure"),
                                        ("waiting", None), ("in_progress", "failure")):
                api = Api("queued")
                next(j for j in api.jobs if j["name"] == lane).update(status=status, conclusion=conclusion)
                self.refused(api, "CLIENT_LANE_JOB_STATE", lane)
            api = Api("queued")
            api.jobs = [j for j in api.jobs if j["name"] != lane]
            self.refused(api, "CLIENT_LANE_JOB_STATE", lane)

    def test_existing_queued_lane_metadata_is_still_accepted(self):
        for state in ("queued", "in_progress"):
            for lane in LANES:
                api = Api(state)
                next(j for j in api.jobs if j["name"] == lane)["status"] = "queued"
                subject.admit_in_progress_qualification_run(api, RUN, COMMIT, lane)

    def test_foreign_caller_lane_is_rejected(self):
        self.refused(Api("queued"), "QUALIFICATION_RUN_REFERENCE", "foreign-client")

    def test_aggregate_status_flip_preserves_intake_and_pre_action_recheck(self):
        # Actual run admission and snapshot comparisons; checkout, archive staging
        # and artifact selection are explicit unit seams, not native evidence.
        class ChangingApi(Api):
            def __init__(self, directory):
                super().__init__("queued")
                self.directory, self.states = directory, []

            def get(self, path):
                if path.endswith(f"/runs/{RUN}"):
                    self.run["status"] = "queued" if not self.states else "in_progress"
                    self.states.append(self.run["status"])
                return super().get(path)

            def download_zip(self, artifact_id, size):
                fd = os.open(self.directory / "inert-archive", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, b"fixture")
                return fd

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            api = ChangingApi(root)
            digest = hashlib.sha256(b"fixture").hexdigest()
            artifact = gh.ArtifactRef(999, gh.ARTIFACT_PREFIX + "4242", 7, digest)
            options = subject.ClientInputOptions(
                LANES[0], gh.REPOSITORY, str(root / "p"), str(root / "r"), COMMIT,
                "b" * 40, str(RUN), "999", digest, "c" * 64, str(root / "work"),
                str(root / "public"), str(root / "audit.json"))
            environ = {
                "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": gh.REPOSITORY,
                "GITHUB_REPOSITORY_OWNER": "Knowledge-Forge-AI", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REF": "refs/heads/main", "GITHUB_REF_NAME": "main", "GITHUB_REF_TYPE": "branch",
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": str(RUN), "GITHUB_SHA": COMMIT,
                "GITHUB_WORKFLOW_REF": f"{gh.REPOSITORY}/{subject.QUALIFY_WORKFLOW_PATH}@refs/heads/main",
            }
            source = ({"run_id": 4242}, "d" * 64, {"p_commit": COMMIT})
            staged = {"inventory": {"inert": {"bytes": 7, "sha256": digest}}, "receipt_sha256": "e" * 64}
            with mock.patch.object(subject, "authenticate_checkouts_and_descriptor", return_value=source), \
                    mock.patch.object(gh, "select_artifact", return_value=artifact), \
                    mock.patch.object(subject.rp, "admit_archive", return_value=staged), \
                    mock.patch.object(subject.rp, "verify_tree") as verify_tree:
                audit, recheck = subject.admit_client_artifact_input(options, api, environ=environ)
                recheck()
            self.assertEqual(api.states, ["queued", "in_progress", "in_progress"])
            self.assertFalse(audit["published"])
            self.assertFalse(audit["signing_performed"])
            self.assertTrue(audit["final_native_authority_requires_all_client_jobs"])
            verify_tree.assert_called_once_with(options.destination, staged["inventory"])

    def test_all_job_origins_remain_bound(self):
        for key, value in (("run_id", RUN + 1), ("run_attempt", 2),
                           ("head_sha", "b" * 40), ("head_branch", "topic")):
            for position in range(len(Api().jobs)):
                with self.subTest(field=key, job=position):
                    api = Api("queued")
                    api.jobs[position][key] = value
                    self.refused(api, "QUALIFICATION_JOB_STATE")

    def test_duplicate_or_foreign_jobs_remain_refused(self):
        api = Api("queued")
        api.jobs.append(copy.deepcopy(api.jobs[0]))
        api.jobs[-1]["id"] = 900
        self.refused(api, "QUALIFICATION_JOB_SET")
        api = Api("queued")
        api.jobs[1]["name"] = "foreign-client"
        self.refused(api, "QUALIFICATION_JOB_SET")

    def test_final_publication_still_requires_all_seven_completed_successful_jobs(self):
        api = Api("completed")
        api.run["conclusion"] = "success"
        for j in api.jobs:
            j.update(status="completed", conclusion="success")
        self.assertEqual(set(gh.admit_run(api, RUN, gh.QUALIFICATION, COMMIT)["jobs"]),
                         gh.QUALIFICATION.required_jobs)
        for missing in range(len(api.jobs)):
            incomplete = copy.deepcopy(api)
            incomplete.jobs.pop(missing)
            with self.assertRaises(gh.PublicationError) as caught:
                gh.admit_run(incomplete, RUN, gh.QUALIFICATION, COMMIT)
            self.assertEqual(caught.exception.code, "QUALIFICATION_JOB_SET")
        for status in ("queued", "in_progress"):
            incomplete = copy.deepcopy(api)
            incomplete.run.update(status=status, conclusion=None)
            with self.assertRaises(gh.PublicationError) as caught:
                gh.admit_run(incomplete, RUN, gh.QUALIFICATION, COMMIT)
            self.assertEqual(caught.exception.code, "QUALIFICATION_RUN_MISMATCH")


if __name__ == "__main__":
    unittest.main()
