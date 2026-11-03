"""Closed, key-free intake of the original qualified runtime RPM quarantine.

Only exact GitHub GET metadata and the pinned original artifact ZIP are accepted.
No install, package execution, engine invocation, signing or publication occurs.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping
import zipfile
import zlib
import publication_github_api as gh
import signing_image_build as image

SOURCE_RUN = 41549016980
SOURCE_COMMIT = "b5e30ed31249a6088d183e16ec052879deb7e920"
SOURCE_WORKFLOW = ".github/workflows/prepare-current-signing-inputs.yml"
SOURCE_WORKFLOW_ID = 405100637
REPOSITORY_ID = 1400852482
ARCHIVE_ID = 13189473693
ARCHIVE_NAME = "current-signer-quarantine-41549016980"
ARCHIVE_BYTES = 34054202
ARCHIVE_SHA256 = "80e03010b83b97b40959b2eb5d31249e7b966f5dcb1a4a818210b3d5084e3cc3"
RUN_PATH = f"repos/{gh.REPOSITORY}/actions/runs/{SOURCE_RUN}"
ARTIFACTS_PATH = RUN_PATH + "/artifacts?per_page=100&page=1"
MAX_ZIP_BYTES = 64 * 1024 * 1024
MAX_QUARANTINE_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_RPM_NAME = re.compile(r"[A-Za-z0-9+_][A-Za-z0-9+_.-]{0,159}\.rpm")
_SHA256 = re.compile(r"[0-9a-f]{64}")

class IntakeError(RuntimeError):
    """Fixed error category; never contains credential, API body or raw diagnostics."""
    def __init__(self, code: str, *, custody_retained: bool = False):
        self.code = code
        self.custody_retained = custody_retained
        super().__init__(code)

def require_key_free_environment(environ: Mapping[str, str]) -> None:
    if gh.signing_secret_names_present(environ) or any(
        key.startswith(("GPG_", "GNUPG")) for key in environ
    ):
        raise IntakeError("RUNTIME_INTAKE_CREDENTIAL_ENVIRONMENT")

class RuntimeInputTransport(gh.GhApiTransport):
    """Existing bounded CLI transport, narrowed to two exact original-run GETs."""
    def get(self, path: str) -> bytes:
        if path not in (RUN_PATH, ARTIFACTS_PATH):
            raise IntakeError("RUNTIME_INTAKE_API_PATH")
        fd = self._new_output("metadata")
        try:
            self._run(self.argv(path), fd, gh.MAX_METADATA_BYTES, gh.METADATA_TIMEOUT_SECONDS)
            return self._read_back(fd)
        finally:
            os.close(fd)

def admit_original_provenance(run: dict, artifacts: list) -> dict:
    if not isinstance(run, dict) or any(run.get(key) != expected for key, expected in {
        "id": SOURCE_RUN, "run_attempt": 1, "event": "workflow_dispatch",
        "workflow_id": SOURCE_WORKFLOW_ID,
        "head_sha": SOURCE_COMMIT, "head_branch": "main",
        "status": "completed", "conclusion": "success",
    }.items()) or run.get("path") not in (SOURCE_WORKFLOW, SOURCE_WORKFLOW + "@refs/heads/main") or type(run.get("run_attempt")) is not int:
        raise IntakeError("RUNTIME_INTAKE_ORIGINAL_RUN")
    if any(type(run.get(key)) is not int for key in ("id", "workflow_id")):
        raise IntakeError("RUNTIME_INTAKE_ORIGINAL_RUN")
    for key in ("repository", "head_repository"):
        repo = run.get(key)
        if not isinstance(repo, dict) or type(repo.get("id")) is not int or repo.get("id") != REPOSITORY_ID or repo.get("full_name") != gh.REPOSITORY:
            raise IntakeError("RUNTIME_INTAKE_ORIGINAL_REPOSITORY")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 100:
        raise IntakeError("RUNTIME_INTAKE_ARTIFACT_LIST")
    selected = [row for row in artifacts if isinstance(row, dict) and row.get("id") == ARCHIVE_ID]
    if len(selected) != 1:
        raise IntakeError("RUNTIME_INTAKE_ORIGINAL_ARTIFACT")
    artifact = selected[0]
    if type(artifact.get("id")) is not int or type(artifact.get("size_in_bytes")) is not int:
        raise IntakeError("RUNTIME_INTAKE_ORIGINAL_ARTIFACT")
    if any(artifact.get(key) != expected for key, expected in {
        "name": ARCHIVE_NAME, "size_in_bytes": ARCHIVE_BYTES,
        "digest": "sha256:" + ARCHIVE_SHA256, "expired": False,
    }.items()) or artifact.get("expired") is not False:
        raise IntakeError("RUNTIME_INTAKE_ORIGINAL_ARTIFACT")
    origin = artifact.get("workflow_run")
    if not isinstance(origin, dict) or any(origin.get(key) != expected for key, expected in {
        "id": SOURCE_RUN, "repository_id": REPOSITORY_ID, "head_repository_id": REPOSITORY_ID,
        "head_branch": "main", "head_sha": SOURCE_COMMIT,
    }.items()):
        raise IntakeError("RUNTIME_INTAKE_ARTIFACT_ORIGIN")
    if any(type(origin.get(key)) is not int for key in ("id", "repository_id", "head_repository_id")):
        raise IntakeError("RUNTIME_INTAKE_ARTIFACT_ORIGIN")
    return {"run": SOURCE_RUN, "commit": SOURCE_COMMIT, "artifact_id": ARCHIVE_ID,
            "artifact_bytes": ARCHIVE_BYTES, "artifact_sha256": ARCHIVE_SHA256}

def _fd_bytes(fd: int, size: int, digest: str) -> bytes:
    before = os.fstat(fd)
    if (type(size) is not int or not 0 < size <= MAX_ZIP_BYTES
        or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
        or not stat.S_ISREG(before.st_mode) or before.st_nlink > 1 or before.st_size != size):
        raise IntakeError("RUNTIME_INTAKE_ZIP_IDENTITY")
    blocks = []
    offset = 0
    while offset <= size:
        body = os.pread(fd, min(1024 * 1024, size + 1 - offset), offset)
        if not body:
            break
        blocks.append(body); offset += len(body)
    after = os.fstat(fd)
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_nlink,
                            row.st_mtime_ns, row.st_ctime_ns, row.st_mode)
    raw = b"".join(blocks)
    if identity(before) != identity(after) or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise IntakeError("RUNTIME_INTAKE_ZIP_IDENTITY")
    return raw

def _validate_expected_inventory(expected: Mapping[str, dict]) -> dict:
    if not isinstance(expected, Mapping) or not 1 <= len(expected) <= 60:
        raise IntakeError("RUNTIME_INTAKE_EXPECTED_INVENTORY")
    result = {}
    for name, row in expected.items():
        if (not isinstance(name, str) or not _RPM_NAME.fullmatch(name)
            or not isinstance(row, dict) or set(row) != {"bytes", "sha256"}
            or type(row["bytes"]) is not int or not 0 < row["bytes"] <= image.MAX_ARCHIVE_FILE_BYTES
            or not isinstance(row["sha256"], str) or not _SHA256.fullmatch(row["sha256"])):
            raise IntakeError("RUNTIME_INTAKE_EXPECTED_INVENTORY")
        result[name] = dict(row)
    if sum(row["bytes"] for row in result.values()) > MAX_OUTPUT_BYTES:
        raise IntakeError("RUNTIME_INTAKE_EXPECTED_INVENTORY")
    return result

def _validated_zip_bodies(raw: bytes, expected: Mapping[str, dict], quarantine_sha256: str) -> dict[str, bytes]:
    expected = _validate_expected_inventory(expected)
    if not isinstance(quarantine_sha256, str) or not _SHA256.fullmatch(quarantine_sha256):
        raise IntakeError("RUNTIME_INTAKE_QUARANTINE_PIN")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if len(names) != len(set(names)) or set(names) != set(expected) | {"QUARANTINE.json"}:
                raise IntakeError("RUNTIME_INTAKE_ZIP_MEMBERS")
            bodies = {}
            for member in members:
                mode = stat.S_IFMT(member.external_attr >> 16)
                if (member.is_dir() or member.flag_bits & 1 or mode not in (0, stat.S_IFREG)
                    or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    raise IntakeError("RUNTIME_INTAKE_ZIP_TYPE")
                maximum = expected[member.filename]["bytes"] if member.filename in expected else MAX_QUARANTINE_BYTES
                if not 0 < member.file_size <= maximum:
                    raise IntakeError("RUNTIME_INTAKE_ZIP_MEMBER_SIZE")
                if member.filename in expected and member.file_size != maximum:
                    raise IntakeError("RUNTIME_INTAKE_ZIP_MEMBER_SIZE")
                body = archive.read(member)
                pin = expected.get(member.filename)
                digest = hashlib.sha256(body).hexdigest()
                if (pin and (len(body) != pin["bytes"] or digest != pin["sha256"])
                    or not pin and digest != quarantine_sha256):
                    raise IntakeError("RUNTIME_INTAKE_MEMBER_DIGEST")
                bodies[member.filename] = body
            return bodies
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, ValueError, zlib.error) as error:
        if isinstance(error, IntakeError):
            raise
        raise IntakeError("RUNTIME_INTAKE_ZIP_INVALID") from None

def _file_identity(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_gid

def _write_exclusive(root_fd: int, name: str, body: bytes, created: dict) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=root_fd)
    created[name] = (fd, None)
    created[name] = (fd, _file_identity(os.fstat(fd)))
    with os.fdopen(fd, "wb", closefd=False) as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(body); stream.flush()

def _directory_identity(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid

def materialize_closed_zip(
    fd: int, destination: str | Path, *, expected_size: int, expected_sha256: str,
    expected_archives: Mapping[str, dict], expected_quarantine_sha256: str,
) -> dict:
    raw = _fd_bytes(fd, expected_size, expected_sha256)
    bodies = _validated_zip_bodies(raw, expected_archives, expected_quarantine_sha256)
    destination = Path(destination)
    try:
        image.physical_dir(destination.parent)
    except image.ImageBuildError:
        raise IntakeError("RUNTIME_INTAKE_DESTINATION") from None
    if destination.name in ("", ".", ".."):
        raise IntakeError("RUNTIME_INTAKE_DESTINATION")
    try:
        os.mkdir(destination, 0o700)
    except OSError:
        raise IntakeError("RUNTIME_INTAKE_DESTINATION") from None
    root_fd = None
    identity = None
    created = {}
    try:
        birth = os.lstat(destination)
        root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if birth.st_uid != os.geteuid() or _directory_identity(birth) != _directory_identity(os.fstat(root_fd)):
            raise IntakeError("RUNTIME_INTAKE_DESTINATION_CHANGED")
        os.fchmod(root_fd, 0o700)
        identity = _directory_identity(os.fstat(root_fd))
        for name, body in sorted(bodies.items()):
            _write_exclusive(root_fd, name, body, created)
        if set(os.listdir(root_fd)) != set(bodies) or _directory_identity(os.lstat(destination)) != identity:
            raise IntakeError("RUNTIME_INTAKE_DESTINATION_CHANGED")
        for name, body in bodies.items():
            physical = destination / name
            measured = image.held_unaliased_bytes(physical)
            current = os.lstat(physical)
            owned_fd, expected_identity = created[name]
            held = os.fstat(owned_fd)
            if (measured != body or stat.S_IMODE(current.st_mode) != 0o600
                or _file_identity(current) != expected_identity or _file_identity(held) != expected_identity
                or current.st_nlink != 1 or held.st_nlink != 1):
                raise IntakeError("RUNTIME_INTAKE_MATERIALIZED_BYTES")
    except BaseException as error:
        safe = root_fd is not None and identity is not None
        try:
            if not safe or _directory_identity(os.lstat(destination)) != identity:
                raise ValueError("unverified directory")
            names = sorted(os.listdir(root_fd))
            if not set(names) <= set(created):
                raise ValueError("foreign entry")
            for name in names:
                info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                held_fd, expected_identity = created[name]
                held = os.fstat(held_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or held.st_nlink != 1
                    or _file_identity(info) != expected_identity or _file_identity(held) != expected_identity):
                    raise ValueError("unsafe entry")
            for name in names:
                os.unlink(name, dir_fd=root_fd)
                if os.fstat(created[name][0]).st_nlink != 0:
                    raise ValueError("owned unlink not confirmed")
            if os.listdir(root_fd) or _directory_identity(os.lstat(destination)) != identity:
                raise ValueError("directory changed")
            os.rmdir(destination)
        except BaseException:
            safe = False
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            error.custody_retained = not safe
            raise
        code = error.code if isinstance(error, IntakeError) else "RUNTIME_INTAKE_WRITE_FAILED"
        raise IntakeError(code, custody_retained=not safe) from None
    finally:
        close_failed = False
        for owned_fd in [*(row[0] for row in created.values()), *([root_fd] if root_fd is not None else [])]:
            try:
                os.close(owned_fd)
            except OSError:
                close_failed = True
        if close_failed:
            raise IntakeError("RUNTIME_INTAKE_DESCRIPTOR_RELEASE_FAILED", custody_retained=True)
    return {"archive_count": len(expected_archives),
            "archive_bytes": sum(row["bytes"] for row in expected_archives.values()),
            "zip_sha256": expected_sha256, "quarantine_sha256": expected_quarantine_sha256,
            "candidate_tools_executed": False, "image_class_admitted": False}

def prepare_pinned_runtime_inputs(transport: RuntimeInputTransport, destination: str | Path,
                                  *, environ: Mapping[str, str]) -> dict:
    require_key_free_environment(os.environ)
    require_key_free_environment(environ)
    if gh._RETAINED_CHILDREN:
        raise IntakeError("RUNTIME_INTAKE_TRANSPORT_CUSTODY", custody_retained=True)
    def snapshot() -> dict:
        run = gh.parse_json(transport.get(RUN_PATH), "RUNTIME_INTAKE_RUN_JSON")
        artifacts = gh.parse_json(transport.get(ARTIFACTS_PATH), "RUNTIME_INTAKE_ARTIFACT_JSON")
        if not isinstance(artifacts, dict) or type(artifacts.get("total_count")) is not int:
            raise IntakeError("RUNTIME_INTAKE_ARTIFACT_LIST")
        rows = artifacts.get("artifacts")
        if not isinstance(rows, list) or artifacts["total_count"] != len(rows):
            raise IntakeError("RUNTIME_INTAKE_ARTIFACT_LIST")
        return admit_original_provenance(run, rows)
    try:
        admitted = snapshot()
        fd = transport.download_zip(ARCHIVE_ID, ARCHIVE_BYTES)
        try:
            if snapshot() != admitted:
                raise IntakeError("RUNTIME_INTAKE_PROVENANCE_CHANGED")
            expected = {name: {"bytes": row[0], "sha256": row[1]}
                        for name, row in image.QUARANTINE_ARCHIVES.items()}
            result = materialize_closed_zip(fd, destination,
                expected_size=ARCHIVE_BYTES, expected_sha256=ARCHIVE_SHA256,
                expected_archives=expected, expected_quarantine_sha256=image.QUARANTINE_SHA256)
        finally:
            os.close(fd)
        if gh._RETAINED_CHILDREN:
            raise IntakeError("RUNTIME_INTAKE_TRANSPORT_CUSTODY", custody_retained=True)
        return {"schema": "tf.current-signer-runtime-input-intake.v1", **admitted, **result,
                "image_build_performed": False, "signing_authority": False, "publication_authority": False}
    except IntakeError as error:
        error.custody_retained = error.custody_retained or bool(gh._RETAINED_CHILDREN)
        raise
    except gh.PublicationError:
        raise IntakeError("RUNTIME_INTAKE_TRANSPORT_FAILED",
                          custody_retained=bool(gh._RETAINED_CHILDREN)) from None
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            error.custody_retained = bool(getattr(error, "custody_retained", False)) or bool(gh._RETAINED_CHILDREN)
            raise
        raise IntakeError("RUNTIME_INTAKE_TRANSPORT_FAILED",
                          custody_retained=bool(gh._RETAINED_CHILDREN)) from None
