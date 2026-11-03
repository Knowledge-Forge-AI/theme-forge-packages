"""Read-only GitHub Actions admission and source-claim binding for retained publication.

Only closed GET paths are admitted, executed through the fixed /usr/bin/gh with
an allowlisted child environment. Also authenticates the P-checkout RS9
descriptor and the non-publishing worker receipt. Never signs, uploads,
dispatches, reruns or mutates anything. Errors are fixed codes: no API body,
stderr, token, local path or ephemeral URL is retained or printed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import time

GH_BINARY = "/usr/bin/gh"
REPOSITORY = "Knowledge-Forge-AI/theme-forge-packages"
API_VERSION_HEADER = "X-GitHub-Api-Version: 2022-11-28"
ARTIFACT_PREFIX = "qualified-public-repository-"
DESCRIPTOR_REL_PATH = "tools/verification/current-rs9-inputs.json"
DESCRIPTOR_SCHEMA = "theme-forge.current-rs9-input-source.v1"
CURRENT_GENERATION = "theme-forge-current-202610"
RS9_REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
WORKER_RECEIPT_SCHEMA = "tf.current-signer-worker-receipt.v1"
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024
MAX_DEPTH, MAX_PATH_CHARS = 16, 512
PER_PAGE, MAX_PAGES = 100, 5
METADATA_TIMEOUT_SECONDS, DOWNLOAD_TIMEOUT_SECONDS, REAP_TIMEOUT_SECONDS = 60.0, 1800.0, 10.0
POLL_SECONDS = 0.05
MIN_ARTIFACT_LIFETIME = timedelta(minutes=30)
SIGNING_SECRET_NAMES = frozenset({
    "PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE", "SIGNING_KEY", "SIGNING_PASSPHRASE",
})

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_TIMESTAMP = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.[0-9]{1,9})?Z")
_COMPONENT = re.compile(r"[A-Za-z0-9._+~@=,:-]{1,128}")
_FORBIDDEN_COMPONENTS = frozenset({".", "..", ".git", ".github", ".protected-work"})
_ID = r"[1-9][0-9]{0,19}"
_REPO = re.escape(REPOSITORY)
_PAGE = rf"\?per_page={PER_PAGE}&page=[1-{MAX_PAGES}]"
_METADATA_PATHS = (
    re.compile(rf"repos/{_REPO}/actions/workflows/(?:qualify-current-signer|validate)\.yml"),
    re.compile(rf"repos/{_REPO}/actions/runs/{_ID}"),
    re.compile(rf"repos/{_REPO}/actions/runs/{_ID}/attempts/1/jobs{_PAGE}"),
    re.compile(rf"repos/{_REPO}/actions/runs/{_ID}/artifacts{_PAGE}"),
)
_ZIP_PATH = re.compile(rf"repos/{_REPO}/actions/artifacts/{_ID}/zip")
_RS9_HASH_KEYS = ("workflow_sha256", "contract_sha256", "builder_source_sha256",
                  "configuration_sha256", "release_ingestion_sha256")
_RS9_KEYS = frozenset(_RS9_HASH_KEYS) | frozenset({
    "repository", "source_commit", "source_tree", "run_id", "not_before", "workflow_path",
    "generation", "qualification_scope", "event", "ref", "attempt",
})
# Literals mirror signer_worker._write_worker_receipt and the frozen runtime's
# ExecutionResult(status="observed") for native execution.
_RECEIPT_EXACT = {
    "schema": WORKER_RECEIPT_SCHEMA, "status": "pass", "evidence_class": "native-unqualified",
    "same_pid_verified": True, "native_signing_execution": True, "signing_status": "observed",
    "c6_agent_and_private_work_cleanup_confirmed": True, "lease_closed_confirmed": True,
    "stage_snapshot_joined_to_fresh_admission": True, "public_verification_status": "pass",
    "public_native_crypto_verified": True, "container_signing_credential_free_at_start": True,
    "custody_retained": False, "publication_authority": False, "native_client_qualification": False,
}
_RECEIPT_KEYS = frozenset(_RECEIPT_EXACT) | frozenset({
    "worker_pid", "lease_owner_pid", "source_binding", "descriptor_sha256",
    "online_intake_token_present", "container_totally_credential_free_at_start",
    "online_token_removed_from_future_child_env", "env_removal_erases_kernel_or_memory_copies",
    "custody_model", "signed_package_rows", "signed_store_records", "exported_file_count", "exported_files",
})

# Process-local custody for children whose termination could not be confirmed.
# Never serialized, retried or broadened into a wider kill.
_RETAINED_CHILDREN: list = []


class PublicationError(RuntimeError):
    """Fixed refusal code only."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def refuse(code: str):
    raise PublicationError(code)


@dataclass(frozen=True)
class RunSpec:
    code: str
    workflow_file: str
    required_jobs: frozenset


QUALIFICATION = RunSpec("QUALIFICATION", "qualify-current-signer.yml", frozenset({
    "qualify-current-signer", "apt-amd64", "apt-arm64", "dnf-x86_64", "dnf-aarch64", "pacman-x86_64",
}))
GUI_VALIDATION = RunSpec("GUI", "validate.yml", frozenset({
    "P native Nix x86_64-linux (candidate only)",
    "P native Nix aarch64-linux (candidate only)",
    "P native Nix aarch64-darwin (candidate only)",
}))


@dataclass(frozen=True)
class ArtifactRef:
    artifact_id: int
    name: str
    size: int
    sha256: str


def positive_int(value) -> bool:
    return type(value) is int and 0 < value < 2 ** 63


def parse_json(raw: bytes, code: str):
    """Strict UTF-8 JSON: no duplicate keys, no NaN/Infinity, no BOM."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                refuse(code)
            result[key] = value
        return result

    try:
        return json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _name: refuse(code))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PublicationError(code) from None


def signing_secret_names_present(environ) -> list:
    return sorted(n for n in environ if n in SIGNING_SECRET_NAMES or "SIGNING" in n.upper()
                  or "PASSPHRASE" in n.upper())


def safe_relative(rel) -> str:
    """ASCII-only relative POSIX path; no traversal, control, unicode or dropped components."""
    if type(rel) is not str or not 0 < len(rel) <= MAX_PATH_CHARS:
        refuse("PATH_POLICY")
    parts = rel.split("/")
    if len(parts) > MAX_DEPTH or any(p in _FORBIDDEN_COMPONENTS or not _COMPONENT.fullmatch(p) for p in parts):
        refuse("PATH_POLICY")
    return rel


def read_small_regular(path: str, code: str, limit: int = MAX_SOURCE_BYTES) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise PublicationError(code) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            refuse(code)
        chunks, total = [], 0
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - total)):
            total += len(chunk)
            if total > limit:
                refuse(code)
            chunks.append(chunk)
        if total != info.st_size:
            refuse(code)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _new_private_dir(path: str) -> str:
    if type(path) is not str or not os.path.isabs(path) or os.path.normpath(path) != path:
        refuse("TRANSPORT_WORKDIR")
    try:
        os.mkdir(path, 0o700)
    except OSError:
        raise PublicationError("TRANSPORT_WORKDIR") from None
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        refuse("TRANSPORT_WORKDIR")
    os.chmod(path, 0o700)
    return path


class GhApiTransport:
    """Bounded owner of short-lived `gh api` GET children; one child at a time."""

    def __init__(self, token: str, work_dir: str, *, popen=subprocess.Popen, killpg=os.killpg,
                 clock=time.monotonic, sleep=time.sleep):
        if (type(token) is not str or not 1 <= len(token) <= 1024 or not token.isascii()
                or not token.isprintable() or " " in token):
            refuse("TOKEN_FORMAT")
        self._token = token
        self._dir = _new_private_dir(work_dir)
        self._config = _new_private_dir(os.path.join(self._dir, "gh-config"))
        self._disable_telemetry()
        self._popen, self._killpg, self._clock, self._sleep = popen, killpg, clock, sleep
        self._sequence = 0

    def _disable_telemetry(self) -> None:
        # gh2.103+ otherwise creates nested device-ID state below this fresh HOME.
        # Keep transport state flat and non-telemetric without broadening cleanup.
        data = b"telemetry: disabled\n"
        try:
            fd = os.open(os.path.join(self._config, "config.yml"),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or before.st_uid != os.geteuid()):
                    refuse("TRANSPORT_CONFIG_FILE")
                os.fchmod(fd, 0o600)
                remaining = memoryview(data)
                while remaining:
                    count = os.write(fd, remaining)
                    if not 0 < count <= len(remaining):
                        refuse("TRANSPORT_CONFIG_WRITE")
                    remaining = remaining[count:]
                after = os.fstat(fd)
                if ((after.st_dev, after.st_ino, after.st_uid, after.st_nlink)
                        != (before.st_dev, before.st_ino, before.st_uid, 1)
                        or not stat.S_ISREG(after.st_mode) or stat.S_IMODE(after.st_mode) != 0o600
                        or after.st_size != len(data)):
                    refuse("TRANSPORT_CONFIG_FILE")
            finally:
                os.close(fd)
        except OSError:
            raise PublicationError("TRANSPORT_CONFIG_WRITE") from None

    def child_env(self) -> dict:
        # Allowlist only: never forwards signing secrets or ambient credentials.
        return {
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": self._config,
            "GH_CONFIG_DIR": self._config, "GH_HOST": "github.com", "GH_TOKEN": self._token,
            "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1",
        }

    @staticmethod
    def argv(path: str, *, json_accept: bool = True) -> tuple:
        accept = ("-H", "Accept: application/vnd.github+json") if json_accept else ()
        return (GH_BINARY, "api", "--method", "GET") + accept + ("-H", API_VERSION_HEADER, path)

    def get(self, path: str) -> bytes:
        if type(path) is not str or not any(p.fullmatch(path) for p in _METADATA_PATHS):
            refuse("API_PATH_NOT_ADMITTED")
        fd = self._new_output("metadata")
        try:
            self._run(self.argv(path), fd, MAX_METADATA_BYTES, METADATA_TIMEOUT_SECONDS)
            return self._read_back(fd)
        finally:
            os.close(fd)

    def _read_back(self, fd: int) -> bytes:
        size = os.fstat(fd).st_size
        if size > MAX_METADATA_BYTES:
            refuse("TRANSPORT_OUTPUT_BOUND")
        data = os.pread(fd, size + 1, 0)
        if len(data) != size:
            refuse("TRANSPORT_OUTPUT_UNSTABLE")
        return data

    def download_zip(self, artifact_id: int, size: int) -> int:
        """Return an owned read/write fd of the downloaded archive; caller closes it."""
        path = f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"
        if not positive_int(artifact_id) or not positive_int(size) or size > MAX_ARCHIVE_BYTES \
                or not _ZIP_PATH.fullmatch(path):
            refuse("ARTIFACT_REFERENCE")
        fd = self._new_output("archive")
        try:
            self._run(self.argv(path, json_accept=False), fd, size, DOWNLOAD_TIMEOUT_SECONDS)
        except BaseException:
            os.close(fd)  # partial bytes stay on disk: never wiped, never retried
            raise
        return fd

    def _new_output(self, kind: str) -> int:
        self._sequence += 1
        name = os.path.join(self._dir, f"{kind}-{self._sequence:04d}.bin")
        return os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)

    def _run(self, argv: tuple, out_fd: int, limit: int, timeout: float) -> None:
        try:
            proc = self._popen(argv, stdin=subprocess.DEVNULL, stdout=out_fd, stderr=subprocess.DEVNULL,
                               env=self.child_env(), cwd=self._dir, close_fds=True, start_new_session=True)
        except OSError:
            raise PublicationError("TRANSPORT_SPAWN") from None
        try:
            deadline = self._clock() + timeout
            while True:
                code = proc.poll()
                if os.fstat(out_fd).st_size > limit:
                    refuse("TRANSPORT_OUTPUT_BOUND")
                if code is not None:
                    break
                if self._clock() > deadline:
                    refuse("TRANSPORT_DEADLINE")
                self._sleep(POLL_SECONDS)
        except BaseException as error:
            self._abort(proc, error)
            raise
        if code != 0:
            refuse("TRANSPORT_EXIT")

    def _abort(self, proc, error: BaseException) -> None:
        """Kill only this child's own new session while it is still unreaped."""
        try:
            if proc.returncode is None and proc.poll() is None:
                try:
                    self._killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=REAP_TIMEOUT_SECONDS)
        except BaseException as cleanup_error:
            _RETAINED_CHILDREN.append({"process": proc, "error": error, "cleanup_error": cleanup_error})
            return
        if proc.returncode is None:
            _RETAINED_CHILDREN.append({"process": proc, "error": error, "cleanup_error": None})


def _get_object(api, path: str, code: str) -> dict:
    doc = parse_json(api.get(path), code)
    return doc if isinstance(doc, dict) else refuse(code)


def _collect_pages(api, base: str, key: str, code: str) -> list:
    """Bounded pagination; incomplete, inconsistent or duplicated pages refuse."""
    items, ids, total = [], set(), None
    for page in range(1, MAX_PAGES + 1):
        doc = _get_object(api, f"{base}?per_page={PER_PAGE}&page={page}", code)
        count, batch = doc.get("total_count"), doc.get(key)
        if type(count) is not int or count < 0 or not isinstance(batch, list) or len(batch) > PER_PAGE:
            refuse(code)
        if total is not None and count != total:
            refuse(code + "_PAGINATION")
        total = count
        for item in batch:
            if not isinstance(item, dict) or not positive_int(item.get("id")) or item["id"] in ids:
                refuse(code + "_DUPLICATE")
            ids.add(item["id"])
            items.append(item)
        if len(items) >= total or not batch:
            break
    if len(items) != total:
        refuse(code + "_PAGINATION")
    return items


def _full_name(value) -> object:
    return value.get("full_name") if isinstance(value, dict) else None


def admit_run(api, run_id: int, spec: RunSpec, p_commit: str) -> dict:
    """Original workflow_dispatch/main/attempt-1 run, completed success at exact P commit."""
    if not positive_int(run_id) or type(p_commit) is not str or not HEX40.fullmatch(p_commit):
        refuse(spec.code + "_RUN_REFERENCE")
    base, path = f"repos/{REPOSITORY}/actions", ".github/workflows/" + spec.workflow_file
    workflow = _get_object(api, f"{base}/workflows/{spec.workflow_file}", spec.code + "_WORKFLOW")
    if not positive_int(workflow.get("id")) or workflow.get("path") != path:
        refuse(spec.code + "_WORKFLOW")
    run = _get_object(api, f"{base}/runs/{run_id}", spec.code + "_RUN")
    if not (run.get("id") == run_id and run.get("workflow_id") == workflow["id"]
            and run.get("path") in (path, path + "@refs/heads/main")
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
            and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and run.get("previous_attempt_url") is None
            and run.get("status") == "completed" and run.get("conclusion") == "success"
            and run.get("head_sha") == p_commit and _full_name(run.get("repository")) == REPOSITORY
            and _full_name(run.get("head_repository")) == REPOSITORY):
        refuse(spec.code + "_RUN_MISMATCH")
    jobs = _collect_pages(api, f"{base}/runs/{run_id}/attempts/1/jobs", "jobs", spec.code + "_JOBS")
    for job in jobs:
        if not (type(job.get("name")) is str and job.get("run_id") == run_id
                and type(job.get("run_attempt")) is int and job["run_attempt"] == 1
                and job.get("head_sha") == p_commit and job.get("head_branch") == "main"
                and job.get("status") == "completed" and job.get("conclusion") == "success"):
            refuse(spec.code + "_JOB_NOT_SUCCESSFUL")
    names = [job["name"] for job in jobs]
    if len(names) != len(set(names)) or set(names) != spec.required_jobs:
        refuse(spec.code + "_JOB_SET")
    return {"run_id": run_id, "workflow_id": workflow["id"], "jobs": tuple(sorted(names))}


def select_artifact(api, run_id: int, p_commit: str, expected_name: str, now: datetime) -> ArtifactRef:
    """Exactly one unexpired, digest-bearing artifact of the exact name from the exact run."""
    artifacts = _collect_pages(api, f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts",
                               "artifacts", "ARTIFACTS")
    related = [a for a in artifacts if type(a.get("name")) is str and a["name"].startswith(ARTIFACT_PREFIX)]
    if len(related) != 1 or related[0].get("name") != expected_name:
        refuse("ARTIFACT_SELECTION")
    item, origin = related[0], related[0].get("workflow_run")
    digest = _DIGEST.fullmatch(item["digest"]) if type(item.get("digest")) is str else None
    size = item.get("size_in_bytes")
    if not (positive_int(size) and size <= MAX_ARCHIVE_BYTES and item.get("expired") is False
            and digest is not None and isinstance(origin, dict) and origin.get("id") == run_id
            and origin.get("head_sha") == p_commit and origin.get("head_branch") == "main"):
        refuse("ARTIFACT_METADATA")
    stamp = _TIMESTAMP.fullmatch(item["expires_at"]) if type(item.get("expires_at")) is str else None
    if stamp is None:
        refuse("ARTIFACT_METADATA")
    try:
        expires = datetime.strptime(stamp.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        raise PublicationError("ARTIFACT_METADATA") from None
    if expires <= now + MIN_ARTIFACT_LIFETIME:
        refuse("ARTIFACT_EXPIRING")
    return ArtifactRef(item["id"], expected_name, size, digest.group(1))


def authenticate_descriptor(p_root: str) -> tuple:
    """Required binding only: the qualification run performed the fresh live admission."""
    raw = read_small_regular(os.path.join(p_root, DESCRIPTOR_REL_PATH), "DESCRIPTOR_ABSENT")
    doc = parse_json(raw, "DESCRIPTOR_SCHEMA")
    if (not isinstance(doc, dict)
            or set(doc) != {"schema", "generation", "status", "production_enabled", "publication_authority", "rs9"}
            or doc["schema"] != DESCRIPTOR_SCHEMA or doc["generation"] != CURRENT_GENERATION
            or doc["production_enabled"] is not False or doc["publication_authority"] is not False):
        refuse("DESCRIPTOR_SCHEMA")
    rs9 = doc["rs9"]
    if doc["status"] != "qualified-original-run-inputs" or not isinstance(rs9, dict):
        refuse("DESCRIPTOR_UNADMITTED")
    if (set(rs9) != _RS9_KEYS or rs9["repository"] != RS9_REPOSITORY
            or any(type(rs9[k]) is not str or not HEX40.fullmatch(rs9[k]) for k in ("source_commit", "source_tree"))
            or not positive_int(rs9["run_id"]) or rs9["event"] != "push" or rs9["ref"] != "refs/heads/main"
            or type(rs9["attempt"]) is not int or rs9["attempt"] != 1 or rs9["generation"] != CURRENT_GENERATION
            or any(type(rs9[k]) is not str or not HEX64.fullmatch(rs9[k]) for k in _RS9_HASH_KEYS)):
        refuse("DESCRIPTOR_BINDING")
    return rs9, hashlib.sha256(raw).hexdigest()


def check_receipt(raw: bytes, binding: dict, descriptor_sha256: str) -> dict:
    """Worker receipt = NON-publishing source proof; returns its exported inventory."""
    receipt = parse_json(raw, "RECEIPT_SCHEMA")
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS:
        refuse("RECEIPT_SCHEMA")
    if any(type(receipt[k]) is not type(v) or receipt[k] != v for k, v in _RECEIPT_EXACT.items()):
        refuse("RECEIPT_INVARIANT")
    source = receipt["source_binding"]
    if (not isinstance(source, dict) or set(source) != set(binding)
            or any(type(source[k]) is not type(v) or source[k] != v for k, v in binding.items())
            or receipt["descriptor_sha256"] != descriptor_sha256):
        refuse("RECEIPT_BINDING")
    if (not positive_int(receipt["worker_pid"]) or type(receipt["lease_owner_pid"]) is not int
            or receipt["lease_owner_pid"] != receipt["worker_pid"] or not positive_int(receipt["signed_package_rows"])):
        refuse("RECEIPT_INVARIANT")
    files = receipt["exported_files"]
    if (not isinstance(files, dict) or type(receipt["exported_file_count"]) is not int
            or receipt["exported_file_count"] != len(files)):
        refuse("RECEIPT_INVENTORY")
    for rel, entry in files.items():
        safe_relative(rel)
        if (not isinstance(entry, dict) or set(entry) != {"bytes", "sha256"} or type(entry["bytes"]) is not int
                or not 0 <= entry["bytes"] <= MAX_FILE_BYTES or type(entry["sha256"]) is not str
                or not HEX64.fullmatch(entry["sha256"])):
            refuse("RECEIPT_INVENTORY")
    return files
