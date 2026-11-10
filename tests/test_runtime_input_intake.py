"""Pure contract tests for the fixed runtime-input release relay.

Tests bind synthetic values only inside a context manager, and fake the
network and subprocess boundaries without bypassing the validators or
materializer. The unbound-state check explicitly restores the closed sentinel.
"""

from __future__ import annotations

from contextlib import ExitStack
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

_SOURCE = Path(__file__).resolve().parents[1] / "tools" / "verification" / "current_signer"
sys.path.insert(0, str(_SOURCE))
import publication_github_api as gh  # noqa: E402
import runtime_input_intake as intake  # noqa: E402
import signing_image_build as image  # noqa: E402


RPM_BODY = b"synthetic-rpm"
QUARANTINE_BODY = b"{\"schema\":\"synthetic\"}\n"


def _run_document() -> dict:
    return {
        "id": intake.SOURCE_RUN,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "workflow_id": intake.SOURCE_WORKFLOW_ID,
        "path": intake.SOURCE_WORKFLOW,
        "head_sha": intake.SOURCE_COMMIT,
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "repository": {"id": intake.REPOSITORY_ID, "full_name": gh.REPOSITORY},
        "head_repository": {"id": intake.REPOSITORY_ID, "full_name": gh.REPOSITORY},
        "download_count": 1,
        "updated_at": "2026-11-09T00:00:00Z",
        "html_url": "https://example.invalid/run",
    }


def _archive_bytes() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("demo-1.rpm", RPM_BODY)
        archive.writestr("QUARANTINE.json", QUARANTINE_BODY)
    return stream.getvalue()


class RelayTransport:
    """Network-boundary fake; all validation remains in runtime_input_intake."""

    def __init__(self, documents: dict[str, dict], archive: bytes, archive_path: Path):
        self.documents = documents
        self.archive = archive
        self.archive_path = archive_path
        self.paths: list[str] = []
        self.download_asset_calls: list[int] = []
        self.download_zip_calls: list[tuple[int, int]] = []

    def get(self, path: str) -> bytes:
        self.paths.append(path)
        if path not in self.documents:
            raise AssertionError(f"unexpected path: {path}")
        return json.dumps(self.documents[path], sort_keys=True).encode("utf-8")

    def download_original_asset(self, asset_id: int) -> int:
        self.download_asset_calls.append(asset_id)
        return os.open(self.archive_path, os.O_RDONLY | os.O_CLOEXEC)

    def download_zip(self, artifact_id: int, size: int) -> int:
        self.download_zip_calls.append((artifact_id, size))
        raise AssertionError("legacy Actions download used by relay route")


class RuntimeRelayTests(unittest.TestCase):
    def setUp(self):
        self.archive = _archive_bytes()
        self.archive_sha256 = hashlib.sha256(self.archive).hexdigest()
        self.quarantine_sha256 = hashlib.sha256(QUARANTINE_BODY).hexdigest()
        self.rpm_sha256 = hashlib.sha256(RPM_BODY).hexdigest()

    def synthetic_binding(self, stack: ExitStack):
        values = {
            "RUNTIME_INPUT_ROUTE": intake.ORIGINAL_PUBLIC_RELEASE_ROUTE,
            "RELAY_RELEASE_ID": 9001,
            "RELAY_RUNTIME_ASSET_ID": 9002,
            "RELAY_SOURCE_ASSET_ID": 9003,
            "RELAY_NOTICES_ASSET_ID": 9004,
            "RELAY_RUNTIME_ASSET_BYTES": len(self.archive),
            "RELAY_SOURCE_ASSET_BYTES": 17,
            "RELAY_NOTICES_ASSET_BYTES": 13,
            "RELAY_RUNTIME_ASSET_SHA256": self.archive_sha256,
            "RELAY_SOURCE_ASSET_SHA256": "1" * 64,
            "RELAY_NOTICES_ASSET_SHA256": "2" * 64,
            "ARCHIVE_BYTES": len(self.archive),
            "ARCHIVE_SHA256": self.archive_sha256,
        }
        for name, value in values.items():
            stack.enter_context(mock.patch.object(intake, name, value))
        stack.enter_context(mock.patch.object(image, "QUARANTINE_ARCHIVES", {
            "demo-1.rpm": (len(RPM_BODY), self.rpm_sha256),
        }))
        stack.enter_context(mock.patch.object(image, "QUARANTINE_SHA256", self.quarantine_sha256))
        return values

    def documents(self):
        specs = intake._relay_asset_specs()
        asset_rows = []
        docs = {intake.RUN_PATH: _run_document()}
        release = {
            "id": intake.RELAY_RELEASE_ID,
            "tag_name": intake.RELAY_TAG,
            "draft": False,
            "prerelease": False,
            "download_count": 2,
            "updated_at": "2026-11-09T00:00:00Z",
            "html_url": "https://example.invalid/release",
            "uploader": {"login": "ignored"},
        }
        docs[intake.RELAY_TAG_PATH] = copy.deepcopy(release)
        docs[intake.RELAY_TAG_REF_PATH] = {
            "ref": f"refs/tags/{intake.RELAY_TAG}",
            "object": {"type": "commit", "sha": intake.SOURCE_COMMIT},
            "url": "https://example.invalid/ref",
        }
        docs[intake._relay_release_path()] = copy.deepcopy(release)
        for spec in specs:
            row = {
                "id": spec["id"], "name": spec["name"], "size": spec["bytes"],
                "state": "uploaded", "digest": "sha256:" + spec["sha256"],
                "download_count": 3, "updated_at": "2026-11-09T00:00:00Z",
                "browser_download_url": "https://example.invalid/asset",
            }
            asset_rows.append(copy.deepcopy(row))
            docs[intake._relay_asset_path(spec["id"])] = copy.deepcopy(row)
        docs[intake._relay_asset_list_path()] = asset_rows
        return docs

    def with_transport(self, stack: ExitStack, documents=None):
        root = Path(tempfile.mkdtemp(prefix="runtime-intake-", dir=Path(__file__).parent))
        stack.callback(lambda: self._remove_tree(root))
        archive_path = root / "archive.zip"
        archive_path.write_bytes(self.archive)
        transport = RelayTransport(documents or self.documents(), self.archive, archive_path)
        return root, transport

    @staticmethod
    def _remove_tree(root: Path):
        for child in sorted(root.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        root.rmdir()

    def test_source_closed_binding_refuses_before_any_relay_get(self):
        class NoNetwork:
            def get(self, path):
                raise AssertionError("source-closed binding attempted network")

        with mock.patch.object(intake, "RELAY_RELEASE_ID", intake.SOURCE_CLOSED_RELEASE_ID):
            with self.assertRaises(intake.IntakeError) as raised:
                intake.prepare_pinned_runtime_inputs(NoNetwork(), "/never-created", environ={})
        self.assertIn(raised.exception.code, {
            "RUNTIME_INTAKE_RELAY_METADATA", "RUNTIME_INTAKE_RELAY_ASSET_SET",
        })

    def test_complete_relay_happy_path_never_uses_old_artifact(self):
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            root, transport = self.with_transport(stack)
            destination = root / "quarantine"
            result = intake.prepare_pinned_runtime_inputs(transport, destination, environ={})
            materialized = {
                "rpm": (destination / "demo-1.rpm").read_bytes(),
                "quarantine": (destination / "QUARANTINE.json").read_bytes(),
            }
            expected_paths = {
                intake.RUN_PATH, intake.RELAY_TAG_PATH, intake.RELAY_TAG_REF_PATH,
                intake._relay_release_path(), intake._relay_asset_list_path(),
                *(intake._relay_asset_path(spec["id"]) for spec in intake._relay_asset_specs()),
            }
        self.assertEqual(result["relay_release_id"], 9001)
        self.assertEqual(result["relay_asset_id"], 9002)
        self.assertEqual(result["relay_asset_bytes"], len(self.archive))
        self.assertEqual(result["relay_asset_sha256"], self.archive_sha256)
        self.assertEqual(result["schema"], "tf.current-signer-runtime-input-intake.v1")
        self.assertEqual(result["artifact_id"], intake.ARCHIVE_ID)
        self.assertEqual(result["artifact_bytes"], len(self.archive))
        self.assertEqual(result["artifact_sha256"], self.archive_sha256)
        self.assertEqual(transport.download_asset_calls, [9002])
        self.assertEqual(transport.download_zip_calls, [])
        self.assertNotIn(intake.ARTIFACTS_PATH, transport.paths)
        self.assertEqual({path for path in transport.paths}, expected_paths)
        self.assertEqual(materialized["rpm"], RPM_BODY)
        self.assertEqual(materialized["quarantine"], QUARANTINE_BODY)

    def test_legacy_empty_artifact_list_still_refuses_and_never_touches_relay(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(intake, "RUNTIME_INPUT_ROUTE",
                                                   intake.LEGACY_ACTIONS_ARTIFACT_ROUTE))
            root, transport = self.with_transport(stack, {
                intake.RUN_PATH: _run_document(),
                intake.ARTIFACTS_PATH: {"total_count": 0, "artifacts": []},
            })
            with self.assertRaises(intake.IntakeError) as raised:
                intake.prepare_pinned_runtime_inputs(transport, root / "quarantine", environ={})
        self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_ARTIFACT_LIST")
        self.assertEqual(transport.paths, [intake.RUN_PATH, intake.ARTIFACTS_PATH])
        self.assertEqual(transport.download_asset_calls, [])

    def test_original_run_predicate_checks_all_identity_and_strict_types(self):
        valid = _run_document()
        admitted = intake.admit_original_run(valid)
        self.assertEqual(admitted["run_id"], intake.SOURCE_RUN)
        self.assertEqual(admitted["ref"], intake.DERIVED_SOURCE_REF)
        for key, bad in {
            "id": True, "run_attempt": "1", "workflow_id": float(intake.SOURCE_WORKFLOW_ID),
            "event": "push", "head_sha": "0" * 40, "head_branch": "trunk",
            "status": "in_progress", "conclusion": "failure",
            "path": ".github/workflows/other.yml",
        }.items():
            candidate = copy.deepcopy(valid)
            candidate[key] = bad
            with self.subTest(key=key), self.assertRaises(intake.IntakeError) as raised:
                intake.admit_original_run(candidate)
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_ORIGINAL_RUN")
        observed_ref = copy.deepcopy(valid)
        observed_ref["ref"] = "refs/heads/not-used-by-the-original-predicate"
        self.assertEqual(intake.admit_original_run(observed_ref)["ref"], intake.DERIVED_SOURCE_REF)
        for key in ("repository", "head_repository"):
            candidate = copy.deepcopy(valid)
            candidate[key]["id"] = str(intake.REPOSITORY_ID)
            with self.subTest(key=key), self.assertRaises(intake.IntakeError) as raised:
                intake.admit_original_run(candidate)
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_ORIGINAL_REPOSITORY")

    def test_original_legacy_predicate_accepts_valid_artifact_and_rejects_empty(self):
        artifact = {
            "id": intake.ARCHIVE_ID,
            "name": intake.ARCHIVE_NAME,
            "size_in_bytes": intake.ARCHIVE_BYTES,
            "digest": "sha256:" + intake.ARCHIVE_SHA256,
            "expired": False,
            "workflow_run": {
                "id": intake.SOURCE_RUN, "repository_id": intake.REPOSITORY_ID,
                "head_repository_id": intake.REPOSITORY_ID, "head_branch": "main",
                "head_sha": intake.SOURCE_COMMIT,
            },
        }
        self.assertEqual(intake.admit_original_provenance(_run_document(), [artifact])["artifact_id"],
                         intake.ARCHIVE_ID)
        with self.assertRaises(intake.IntakeError) as raised:
            intake.admit_original_provenance(_run_document(), [])
        self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_ARTIFACT_LIST")

    def test_relay_metadata_rejects_release_tag_ref_status_digest_and_sizes(self):
        cases = [
            (intake.RELAY_TAG_PATH, "id", 9999, "RUNTIME_INTAKE_RELAY_METADATA"),
            (intake.RELAY_TAG_PATH, "draft", True, "RUNTIME_INTAKE_RELAY_METADATA"),
            (intake.RELAY_TAG_REF_PATH, "object",
             {"type": "tag", "sha": intake.SOURCE_COMMIT}, "RUNTIME_INTAKE_RELAY_METADATA"),
        ]
        for path, key, value, code in cases:
            with self.subTest(path=path, key=key), ExitStack() as stack:
                self.synthetic_binding(stack)
                docs = self.documents()
                docs[path][key] = value
                with self.assertRaises(intake.IntakeError) as raised:
                    intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
                self.assertEqual(raised.exception.code, code)
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            docs = self.documents()
            docs[intake._relay_asset_list_path()][0]["digest"] = None
            with self.assertRaises(intake.IntakeError) as raised:
                intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_METADATA")

    def test_duplicate_key_and_nonfinite_metadata_are_closed_refusals(self):
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            docs = self.documents()
            transport = RelayTransport(docs, self.archive, Path("/dev/null"))
            original_get = transport.get
            transport.get = lambda path: (
                b'{"id":9001,"id":9001}' if path == intake.RELAY_TAG_PATH else original_get(path)
            )
            with self.assertRaises(intake.IntakeError) as raised:
                intake._relay_snapshot(transport)
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_METADATA")

    def test_asset_list_object_envelope_is_rejected_in_favor_of_real_array_shape(self):
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            docs = self.documents()
            rows = docs[intake._relay_asset_list_path()]
            docs[intake._relay_asset_list_path()] = {"total_count": 3, "assets": rows}
            with self.assertRaises(intake.IntakeError) as raised:
                intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
        self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_ASSET_SET")
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            docs = self.documents()
            transport = RelayTransport(docs, self.archive, Path("/dev/null"))
            original_get = transport.get
            transport.get = lambda path: (
                b'{"id":9001,"tag_name":"current-signer-runtime-inputs-41549016980-attempt-1",'
                b'"draft":NaN,"prerelease":false}' if path == intake.RELAY_TAG_PATH else original_get(path)
            )
            with self.assertRaises(intake.IntakeError) as raised:
                intake._relay_snapshot(transport)
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_METADATA")
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            docs = self.documents()
            docs[intake._relay_asset_list_path()][0]["size"] += 1
            with self.assertRaises(intake.IntakeError) as raised:
                intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_METADATA")
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            docs = self.documents()
            docs[intake._relay_asset_list_path()][0]["state"] = "new"
            with self.assertRaises(intake.IntakeError) as raised:
                intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_METADATA")
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            docs = self.documents()
            docs[intake._relay_asset_path(9002)]["id"] = 9003
            with self.assertRaises(intake.IntakeError) as raised:
                intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_ASSET_SET")

    def test_relay_asset_set_rejects_duplicates_extra_and_wrong_id_name_pairs(self):
        mutations = []
        mutations.append(lambda rows: rows.__setitem__(2, copy.deepcopy(rows[1])))
        mutations.append(lambda rows: rows.__setitem__(2, {
            "id": 9010, "name": "extra.zip", "size": 1, "state": "uploaded", "digest": "sha256:" + "3" * 64,
        }))
        mutations.append(lambda rows: rows[0].update(id=9003))
        mutations.append(lambda rows: rows[0].update(name=intake.RELAY_SOURCE_ASSET_NAME))
        for mutate in mutations:
            with self.subTest(mutate=mutate), ExitStack() as stack:
                self.synthetic_binding(stack)
                docs = self.documents()
                mutate(docs[intake._relay_asset_list_path()])
                with self.assertRaises(intake.IntakeError) as raised:
                    intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
                self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_ASSET_SET")

    def test_mutable_release_and_asset_fields_do_not_change_closed_identity(self):
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            docs = self.documents()
            for document in docs.values():
                if isinstance(document, dict):
                    document["download_count"] = 101
                    document["updated_at"] = "2026-11-10T00:00:00Z"
                    document["html_url"] = "https://example.invalid/changed"
                    document["uploader"] = {"login": "changed"}
                else:
                    for row in document:
                        row["download_count"] = 101
                        row["updated_at"] = "2026-11-10T00:00:00Z"
                        row["browser_download_url"] = "https://example.invalid/changed"
            first = intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
            second = intake._relay_snapshot(RelayTransport(docs, self.archive, Path("/dev/null")))
        self.assertEqual(first["identity"], second["identity"])

    def test_metadata_race_on_accepted_path_variant_is_identity_refusal(self):
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            root, transport = self.with_transport(stack)
            original_get = transport.get
            changed = {"done": False}

            def get(path):
                body = original_get(path)
                if changed["done"] and path == intake.RUN_PATH:
                    document = json.loads(body)
                    document["path"] = intake.SOURCE_WORKFLOW + "@refs/heads/main"
                    return json.dumps(document).encode()
                return body

            transport.get = get
            original_download = transport.download_original_asset

            def download(asset_id):
                changed["done"] = True
                return original_download(asset_id)

            transport.download_original_asset = download
            with self.assertRaises(intake.IntakeError) as raised:
                intake.prepare_pinned_runtime_inputs(transport, root / "quarantine", environ={})
        self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_IDENTITY")
        self.assertFalse((root / "quarantine").exists())

    def test_transport_route_paths_and_octet_stream_limits_are_exact(self):
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            transport = object.__new__(intake.RuntimeInputTransport)
            output = Path(tempfile.mkstemp(prefix="runtime-output-", dir=Path(__file__).parent)[1])
            stack.callback(output.unlink)
            seen = {}

            def new_output(kind):
                return os.open(output, os.O_RDWR | os.O_TRUNC)

            def run(argv, fd, limit, timeout):
                seen.update(argv=argv, limit=limit, timeout=timeout)
                os.write(fd, self.archive)

            transport._new_output = new_output
            transport._run = run
            fd = transport.download_original_asset(9002)
            os.close(fd)
        self.assertEqual(seen["argv"], (
            gh.GH_BINARY, "api", "--method", "GET", "-H", "Accept: application/octet-stream",
            "-H", gh.API_VERSION_HEADER, "repos/Knowledge-Forge-AI/theme-forge-packages/releases/assets/9002",
        ))
        self.assertEqual(seen["limit"], len(self.archive))
        self.assertEqual(seen["timeout"], gh.DOWNLOAD_TIMEOUT_SECONDS)

    def test_metadata_get_uses_exact_json_header_path_and_bound(self):
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            transport = object.__new__(intake.RuntimeInputTransport)
            output = Path(tempfile.mkstemp(prefix="runtime-metadata-", dir=Path(__file__).parent)[1])
            stack.callback(output.unlink)
            seen = {}

            transport._new_output = lambda kind: os.open(output, os.O_RDWR | os.O_TRUNC)

            def run(argv, fd, limit, timeout):
                seen.update(argv=argv, limit=limit, timeout=timeout)
                os.write(fd, b"{}")

            transport._run = run
            self.assertEqual(transport.get(intake.RELAY_TAG_PATH), b"{}")
        self.assertEqual(seen["argv"], gh.GhApiTransport.argv(intake.RELAY_TAG_PATH))
        self.assertEqual(seen["limit"], gh.MAX_METADATA_BYTES)
        self.assertEqual(seen["timeout"], gh.METADATA_TIMEOUT_SECONDS)

    def test_relay_rejects_artifact_list_and_inherited_download_structurally(self):
        transport = object.__new__(intake.RuntimeInputTransport)
        with self.assertRaises(intake.IntakeError) as raised:
            transport.get(intake.ARTIFACTS_PATH)
        self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_PATH")
        with self.assertRaises(intake.IntakeError) as raised:
            transport.download_zip(intake.ARCHIVE_ID, intake.ARCHIVE_BYTES)
        self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_RELAY_PATH")
        with mock.patch.object(intake, "RUNTIME_INPUT_ROUTE", intake.LEGACY_ACTIONS_ARTIFACT_ROUTE):
            with self.assertRaises(intake.IntakeError) as raised:
                transport.get(intake.RELAY_TAG_PATH)
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_API_PATH")

    def test_key_free_child_environment_and_secret_refusal(self):
        transport = object.__new__(intake.RuntimeInputTransport)
        transport._token = "read-token"
        transport._config = "/private/config"
        self.assertEqual(transport.child_env(), {
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/private/config",
            "GH_CONFIG_DIR": "/private/config", "GH_HOST": "github.com", "GH_TOKEN": "read-token",
            "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1",
        })
        for env in ({"SIGNING_KEY": "secret"}, {"GPG_AGENT_INFO": "secret"}, {"PASSPHRASE_X": "secret"}):
            with self.subTest(env=env), self.assertRaises(intake.IntakeError) as raised:
                intake.require_key_free_environment(env)
            self.assertEqual(raised.exception.code, "RUNTIME_INTAKE_CREDENTIAL_ENVIRONMENT")

    def test_bad_oversized_truncated_and_corrupt_bytes_fail_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="runtime-bytes-", dir=Path(__file__).parent) as raw_dir:
            path = Path(raw_dir) / "archive.bin"
            path.write_bytes(self.archive)
            fd = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaises(intake.IntakeError):
                    intake._fd_bytes(fd, len(self.archive) + 1, self.archive_sha256)
                with self.assertRaises(intake.IntakeError):
                    intake._fd_bytes(fd, intake.MAX_ZIP_BYTES + 1, self.archive_sha256)
                with self.assertRaises(intake.IntakeError):
                    intake._fd_bytes(fd, len(self.archive), "0" * 64)
            finally:
                os.close(fd)
        with tempfile.TemporaryDirectory(prefix="runtime-cleanup-", dir=Path(__file__).parent) as raw_dir:
            path = Path(raw_dir) / "archive.bin"
            path.write_bytes(self.archive)
            fd = os.open(path, os.O_RDONLY)
            destination = Path(raw_dir) / "quarantine"
            with self.assertRaises(intake.IntakeError):
                intake.materialize_closed_zip(
                    fd, destination, expected_size=len(self.archive), expected_sha256=self.archive_sha256,
                    expected_archives={"demo-1.rpm": {"bytes": len(RPM_BODY), "sha256": "f" * 64}},
                    expected_quarantine_sha256=self.quarantine_sha256,
                )
            os.close(fd)
            self.assertFalse(destination.exists())

    def test_download_failure_closes_owned_fd_without_retaining_child(self):
        with ExitStack() as stack:
            self.synthetic_binding(stack)
            transport = object.__new__(intake.RuntimeInputTransport)
            output = Path(tempfile.mkstemp(prefix="runtime-failure-", dir=Path(__file__).parent)[1])
            stack.callback(output.unlink)
            opened = []

            def new_output(kind):
                fd = os.open(output, os.O_RDWR | os.O_TRUNC)
                opened.append(fd)
                return fd

            transport._new_output = new_output
            transport._run = lambda *args: (_ for _ in ()).throw(gh.PublicationError("TRANSPORT_EXIT"))
            with self.assertRaises(gh.PublicationError):
                transport.download_original_asset(9002)
            with self.assertRaises(OSError):
                os.fstat(opened[0])

    def test_only_four_new_relay_labels_are_present(self):
        source = (_SOURCE / "runtime_input_intake.py").read_text()
        labels = set(re.findall(r"RUNTIME_INTAKE_RELAY_[A-Z_]+", source))
        self.assertEqual(labels, {
            "RUNTIME_INTAKE_RELAY_IDENTITY", "RUNTIME_INTAKE_RELAY_ASSET_SET",
            "RUNTIME_INTAKE_RELAY_METADATA", "RUNTIME_INTAKE_RELAY_PATH",
        })


if __name__ == "__main__":
    unittest.main()
