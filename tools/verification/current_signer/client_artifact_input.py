"""Authenticate and stage the signed public-repository artifact for native client qualification.

Client qualification jobs execute downstream WITHIN the running
`.github/workflows/qualify-current-signer.yml` workflow (`workflow_dispatch`,
`refs/heads/main`, `run_attempt == 1`, exact `github.sha`). Unlike final Pages
publication (`publication_github_api.admit_run`), the enclosing workflow run is
still `in_progress` with `conclusion is None` while client jobs execute.
"""
from __future__ import annotations

import os
import sys

if __name__ == "__main__":  # explicit sibling bootstrap under python3 -I -B
    _HERE = os.path.dirname(os.path.realpath(__file__))
    if sys.path[:1] != [_HERE]:
        sys.path.insert(0, _HERE)

import argparse  # noqa: E402
import base64  # noqa: E402
from dataclasses import dataclass, fields  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
from typing import Any, Callable, Mapping, MutableMapping  # noqa: E402

import publication_github_api as gh  # noqa: E402
from publication_github_api import PublicationError, refuse  # noqa: E402
import retained_publication as rp  # noqa: E402
import source_closure as sc  # noqa: E402

CLIENT_INPUT_SCHEMA = "tf.current-signer-client-artifact-input.v1"
QUALIFY_WORKFLOW_FILE = "qualify-current-signer.yml"
QUALIFY_WORKFLOW_PATH = ".github/workflows/qualify-current-signer.yml"
SIGNER_JOB_NAME = "qualify-current-signer"
ALLOWED_CLIENT_LANES = ("apt-amd64", "apt-arm64", "dnf-x86_64", "dnf-aarch64", "pacman-x86_64", "pacman-aarch64")
PRODUCTION_PRIMARY_FINGERPRINT = "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF"
PRODUCTION_SIGNING_SUBKEY = "C021E00EE3D37C459B0E1CB3199F8028126E8A8C"
COMMITTED_PUBLIC_KEY_REL_PATH = "keys/knowledge-forge-ai-packages.asc"
COMMITTED_PUBLIC_KEY_GPG_REL_PATH = "keys/knowledge-forge-ai-packages.gpg"
COMMITTED_PUBLIC_KEY_FILENAME = "knowledge-forge-ai-packages.asc"
COMMITTED_PUBLIC_KEY_SHA256 = "6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95"
ALLOWED_CLIENT_ENV_KEYS = frozenset({
    "PATH", "LANG", "LC_ALL", "HOME", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE",
})
_NUMERIC_ID = re.compile(r"[1-9][0-9]{0,19}")
_OPTIONAL_SHA256_PREFIX = re.compile(r"(?:sha256:)?([0-9a-f]{64})")
_TOKEN_ENV_NAMES = frozenset({
    "GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
})
_SIGNING_ENV_PREFIXES = ("TF_GPG_", "GPG_", "GNUPG", "SIGNING_")
_NEW_AUDIT_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class ClientInputOptions:
    lane: str; repository: str; p_root: str; r_root: str; p_commit: str; p_tree: str
    qualification_run_id: str; expected_artifact_id: str; expected_artifact_sha256: str
    leaf_manifest_sha256: str; work_root: str; destination: str; audit_out: str


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_regular_fd(fd: int, expected_size: int, code: str = "ARCHIVE_SIZE") -> str:
    """Hash an open regular-file descriptor of exact expected size."""
    digest, offset = hashlib.sha256(), 0
    while chunk := os.pread(fd, rp.CHUNK, offset):
        offset += len(chunk)
        if offset > expected_size:
            refuse(code)
        digest.update(chunk)
    if offset != expected_size or os.fstat(fd).st_size != expected_size:
        refuse(code)
    return digest.hexdigest()


def write_exclusive_json(path: str, payload: Mapping[str, Any], code: str = "AUDIT_PATH") -> None:
    """Write a canonical JSON audit/evidence file exclusively with mode 0644."""
    if not isinstance(path, str) or not os.path.isabs(path) or os.path.normpath(path) != path:
        refuse(code)
    try:
        fd = os.open(path, _NEW_AUDIT_FLAGS, 0o600)
    except OSError:
        raise PublicationError(code) from None
    try:
        os.fchmod(fd, 0o644)
        view = memoryview((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        while view:
            written = os.write(fd, view)
            view = view[written:] if written > 0 else refuse(code)
    finally:
        os.close(fd)


def signing_or_gpg_env_present(environ: Mapping[str, str]) -> bool:
    """Return True if any signing secret, passphrase, or GPG variable is present."""
    return bool(gh.signing_secret_names_present(environ)) or any(
        name.upper().startswith(_SIGNING_ENV_PREFIXES) for name in environ
    )


def _crc24_openpgp(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
        crc &= 0xFFFFFF
    return crc


def _openpgp_v4_fingerprints(packet_bytes: bytes) -> dict[int, list[str]]:
    """Parse OpenPGP binary packet stream and compute v4 SHA-1 fingerprints for tags 6 and 14."""
    offset, total, found = 0, len(packet_bytes), {6: [], 14: []}
    while offset < total:
        ctb = packet_bytes[offset]
        if not (ctb & 0x80):
            refuse("PUBLIC_KEY_PACKET_FORMAT")
        offset += 1
        if ctb & 0x40:
            tag = ctb & 0x3F
            if offset >= total:
                refuse("PUBLIC_KEY_PACKET_FORMAT")
            first, offset = packet_bytes[offset], offset + 1
            if first < 192:
                length = first
            elif first < 224 and offset < total:
                length, offset = ((first - 192) << 8) + packet_bytes[offset] + 192, offset + 1
            elif first == 255 and offset + 4 <= total:
                length, offset = int.from_bytes(packet_bytes[offset : offset + 4], "big"), offset + 4
            else:
                refuse("PUBLIC_KEY_PACKET_FORMAT")
        else:
            tag, len_type = (ctb >> 2) & 0x0F, ctb & 0x03
            n_bytes = (1, 2, 4)[len_type] if len_type < 3 else refuse("PUBLIC_KEY_PACKET_FORMAT")
            if offset + n_bytes > total:
                refuse("PUBLIC_KEY_PACKET_FORMAT")
            length, offset = int.from_bytes(packet_bytes[offset : offset + n_bytes], "big"), offset + n_bytes
        if offset + length > total:
            refuse("PUBLIC_KEY_PACKET_FORMAT")
        body, offset = packet_bytes[offset : offset + length], offset + length
        if tag in (6, 14):
            if not body or body[0] != 4:
                refuse("PUBLIC_KEY_VERSION_UNSUPPORTED")
            prefix = bytes((0x99, (length >> 8) & 0xFF, length & 0xFF))
            found[tag].append(hashlib.sha1(prefix + body).hexdigest().upper())
    return found


def dearmor_and_verify_public_key(armored: bytes) -> bytes:
    """Strictly dearmor committed ASCII public key and verify SHA-256, CRC24, and v4 fingerprints."""
    if _sha256_hex(armored) != COMMITTED_PUBLIC_KEY_SHA256:
        refuse("PUBLIC_KEY_SHA256_MISMATCH")
    try:
        lines = armored.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise PublicationError("PUBLIC_KEY_ARMOR_FORMAT") from None
    if (len(lines) < 5 or lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----" or lines[1] != ""
            or lines[-1] != "-----END PGP PUBLIC KEY BLOCK-----"
            or not lines[-2].startswith("=") or len(lines[-2]) != 5):
        refuse("PUBLIC_KEY_ARMOR_FORMAT")
    try:
        payload = base64.b64decode("".join(lines[2:-2]), validate=True)
        crc_bytes = base64.b64decode(lines[-2][1:], validate=True)
    except ValueError:
        raise PublicationError("PUBLIC_KEY_ARMOR_FORMAT") from None
    if len(crc_bytes) != 3 or int.from_bytes(crc_bytes, "big") != _crc24_openpgp(payload):
        refuse("PUBLIC_KEY_CRC24_MISMATCH")
    fps = _openpgp_v4_fingerprints(payload)
    if fps.get(6) != [PRODUCTION_PRIMARY_FINGERPRINT] or PRODUCTION_SIGNING_SUBKEY not in fps.get(14, []):
        refuse("PUBLIC_KEY_FINGERPRINT_MISMATCH")
    return payload


def normalize_artifact_sha256(value: str) -> str:
    if type(value) is not str or (match := _OPTIONAL_SHA256_PREFIX.fullmatch(value)) is None:
        refuse("OPTIONS")
    return match.group(1)


def validate_options(options: ClientInputOptions) -> tuple[int, int, str]:
    if (options.lane not in ALLOWED_CLIENT_LANES or options.repository != gh.REPOSITORY
            or not os.path.isabs(options.p_root) or not os.path.isabs(options.r_root)
            or not gh.HEX40.fullmatch(options.p_commit) or not gh.HEX40.fullmatch(options.p_tree)
            or not gh.HEX64.fullmatch(options.leaf_manifest_sha256)
            or not _NUMERIC_ID.fullmatch(options.qualification_run_id)
            or not _NUMERIC_ID.fullmatch(options.expected_artifact_id)
            or not os.path.isabs(options.work_root) or not os.path.isabs(options.destination)
            or not os.path.isabs(options.audit_out)):
        refuse("OPTIONS")
    return (int(options.qualification_run_id), int(options.expected_artifact_id),
            normalize_artifact_sha256(options.expected_artifact_sha256))


def authenticate_caller_environ(options: ClientInputOptions, environ: Mapping[str, str]) -> None:
    """Bind options to trusted GitHub Actions context; reject secrets, forks, reruns, non-main."""
    if signing_or_gpg_env_present(environ):
        refuse("SIGNING_SECRET_IN_ENVIRONMENT")
    if environ.get("GITHUB_HEAD_REF") or environ.get("GITHUB_BASE_REF"):
        refuse("CALLER_FORK_OR_PR_CONTEXT")
    if (environ.get("GITHUB_ACTIONS") != "true" or environ.get("GITHUB_REPOSITORY") != gh.REPOSITORY
            or environ.get("GITHUB_REPOSITORY_OWNER") != "Knowledge-Forge-AI"
            or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or environ.get("GITHUB_REF") != "refs/heads/main" or environ.get("GITHUB_REF_NAME") != "main"
            or environ.get("GITHUB_REF_TYPE") != "branch"
            or environ.get("GITHUB_RUN_ATTEMPT") != "1"
            or environ.get("GITHUB_RUN_ID") != options.qualification_run_id
            or environ.get("GITHUB_SHA") != options.p_commit):
        refuse("CALLER_GITHUB_CONTEXT")
    if environ.get("GITHUB_WORKFLOW_REF") != f"{gh.REPOSITORY}/{QUALIFY_WORKFLOW_PATH}@refs/heads/main":
        refuse("CALLER_WORKFLOW_REF")


def pop_intake_token(environ: MutableMapping[str, str]) -> str:
    """Extract read-only GH_TOKEN for GhApiTransport and scrub tokens/GIT_* from mutable env."""
    token = environ.get("GH_TOKEN")
    for name in list(environ):
        if name in _TOKEN_ENV_NAMES or name.startswith("GIT_"):
            del environ[name]
    if not token:
        refuse("TOKEN_ABSENT")
    return token


def sanitized_client_env(home_dir: str) -> dict[str, str]:
    """Allowlisted child environment for native client tooling; never leaks GH_TOKEN or secrets."""
    if not os.path.isabs(home_dir) or os.path.normpath(home_dir) != home_dir:
        refuse("CLIENT_ENV_HOME")
    return {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": home_dir,
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
    }


def authenticate_checkouts_and_descriptor(
    options: ClientInputOptions, *, git_runner: Callable[..., tuple[int, bytes, bytes]] | None = None,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    """Verify the complete pinned leaf closure, descriptor and clean P/R checkouts."""
    leaf_raw = gh.read_small_regular(os.path.join(options.p_root, rp.LEAF_MANIFEST_REL_PATH), "LEAF_MANIFEST_ABSENT")
    if _sha256_hex(leaf_raw) != options.leaf_manifest_sha256:
        refuse("LEAF_MANIFEST_DIGEST")
    try:
        # The root launcher authenticates held source bytes before imports. Recheck
        # all physical leaves and the executing entry modules before API/native I/O.
        sc.authenticate_leaf_closure(options.p_root,
            expected_leaf_manifest_sha256=options.leaf_manifest_sha256, require_unimported=False)
    except sc.ClosureError as error:
        raise PublicationError(error.code) from None
    rs9, descriptor_sha256 = gh.authenticate_descriptor(options.p_root)
    try:
        sc.authenticate_rs9_descriptor(options.p_root, expected_r_commit=rs9["source_commit"],
                                       expected_r_tree=rs9["source_tree"], expected_rs9_run=rs9["run_id"])
        git_env = sc.scoped_git_env(options.p_root, options.r_root)
        sc.verify_clean_git_checkout(options.p_root, options.p_commit, options.p_tree, git_env=git_env, git_runner=git_runner)
        sc.verify_clean_git_checkout(options.r_root, rs9["source_commit"], rs9["source_tree"], git_env=git_env, git_runner=git_runner)
    except sc.ClosureError as error:
        raise PublicationError(error.code) from None
    binding = {
        "p_commit": options.p_commit, "p_tree": options.p_tree, "r_commit": rs9["source_commit"],
        "r_tree": rs9["source_tree"], "source_closure_sha256": options.leaf_manifest_sha256, "rs9_run": rs9["run_id"],
    }
    return rs9, descriptor_sha256, binding


def admit_in_progress_qualification_run(api: gh.GhApiTransport, run_id: int, p_commit: str, lane: str) -> dict[str, Any]:
    """Authenticate in-progress qualification workflow run and completed upstream signer job."""
    if not gh.positive_int(run_id) or type(p_commit) is not str or not gh.HEX40.fullmatch(p_commit) or lane not in ALLOWED_CLIENT_LANES:
        refuse("QUALIFICATION_RUN_REFERENCE")
    base = f"repos/{gh.REPOSITORY}/actions"
    workflow = gh._get_object(api, f"{base}/workflows/{QUALIFY_WORKFLOW_FILE}", "QUALIFICATION_WORKFLOW")
    if not gh.positive_int(workflow.get("id")) or workflow.get("path") != QUALIFY_WORKFLOW_PATH:
        refuse("QUALIFICATION_WORKFLOW")
    run = gh._get_object(api, f"{base}/runs/{run_id}", "QUALIFICATION_RUN")
    if not (run.get("id") == run_id and run.get("workflow_id") == workflow["id"]
            and run.get("path") in (QUALIFY_WORKFLOW_PATH, QUALIFY_WORKFLOW_PATH + "@refs/heads/main")
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
            and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and run.get("previous_attempt_url") is None
            and run.get("status") == "in_progress" and run.get("conclusion") is None
            and run.get("head_sha") == p_commit
            and gh._full_name(run.get("repository")) == gh.REPOSITORY
            and gh._full_name(run.get("head_repository")) == gh.REPOSITORY):
        refuse("QUALIFICATION_RUN_MISMATCH")
    jobs = gh._collect_pages(api, f"{base}/runs/{run_id}/attempts/1/jobs", "jobs", "QUALIFICATION_JOBS")
    names = [job.get("name") for job in jobs]
    if any(type(name) is not str for name in names) or len(names) != len(set(names)) or not set(names).issubset(gh.QUALIFICATION.required_jobs):
        refuse("QUALIFICATION_JOB_SET")
    for job in jobs:
        if not (job.get("run_id") == run_id and type(job.get("run_attempt")) is int
                and job["run_attempt"] == 1 and job.get("head_sha") == p_commit and job.get("head_branch") == "main"):
            refuse("QUALIFICATION_JOB_STATE")
    by_name = {job["name"]: job for job in jobs}
    signer_job = by_name.get(SIGNER_JOB_NAME)
    if signer_job is None or not (signer_job.get("status") == "completed" and signer_job.get("conclusion") == "success"):
        refuse("SIGNER_JOB_NOT_SUCCESSFUL")
    lane_job = by_name.get(lane)
    if lane_job is None or not (lane_job.get("status") in ("in_progress", "queued") and lane_job.get("conclusion") is None):
        refuse("CLIENT_LANE_JOB_STATE")
    return {"run_id": run_id, "workflow_id": workflow["id"], "signer_job_id": signer_job["id"], "lane_job_id": lane_job["id"]}


def admit_client_artifact_input(
    options: ClientInputOptions, api: gh.GhApiTransport, *,
    now: datetime | None = None, environ: Mapping[str, str] | None = None,
    git_runner: Callable[..., tuple[int, bytes, bytes]] | None = None,
) -> tuple[dict[str, Any], Callable[[], None]]:
    """Authenticate run/source/artifact, stage verified public tree, and return (audit, recheck_fn)."""
    authenticate_caller_environ(options, os.environ if environ is None else environ)
    now_utc = datetime.now(timezone.utc) if now is None else now
    qual_id, expected_art_id, expected_art_sha256 = validate_options(options)
    rs9, descriptor_sha256, binding = authenticate_checkouts_and_descriptor(options, git_runner=git_runner)
    expected_name = gh.ARTIFACT_PREFIX + str(rs9["run_id"])

    def admitted_snapshot() -> tuple[dict[str, Any], gh.ArtifactRef]:
        run_state = admit_in_progress_qualification_run(api, qual_id, options.p_commit, options.lane)
        artifact_ref = gh.select_artifact(api, qual_id, options.p_commit, expected_name, now_utc)
        if artifact_ref.artifact_id != expected_art_id or artifact_ref.sha256 != expected_art_sha256:
            refuse("ARTIFACT_SIGNER_OUTPUT_MISMATCH")
        return run_state, artifact_ref

    run_state, artifact = admitted_snapshot()
    fd = api.download_zip(artifact.artifact_id, artifact.size)
    try:
        held = os.fstat(fd)
        if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or held.st_size != artifact.size:
            refuse("ARCHIVE_SIZE")
        if hash_regular_fd(fd, artifact.size, "ARCHIVE_SIZE") != artifact.sha256:
            refuse("ARCHIVE_DIGEST")
        staged = rp.admit_archive(fd, artifact.size, binding=binding, descriptor_sha256=descriptor_sha256, destination=options.destination)
    finally:
        os.close(fd)
    if admitted_snapshot() != (run_state, artifact):
        refuse("API_STATE_CHANGED")

    def recheck_before_native_action() -> None:
        if admitted_snapshot() != (run_state, artifact):
            refuse("API_STATE_CHANGED")
        if authenticate_checkouts_and_descriptor(options, git_runner=git_runner) != (
            rs9, descriptor_sha256, binding
        ):
            refuse("CLIENT_SOURCE_CHANGED")
        rp.verify_tree(options.destination, staged["inventory"])

    inventory = staged["inventory"]
    audit = dict(
        binding, schema=CLIENT_INPUT_SCHEMA, status="admitted-for-native-client-qualification",
        lane=options.lane, repository=gh.REPOSITORY, descriptor_sha256=descriptor_sha256,
        qualification_run_id=qual_id, qualification_workflow_id=run_state["workflow_id"],
        signer_job_id=run_state["signer_job_id"], lane_job_id=run_state["lane_job_id"],
        artifact_id=artifact.artifact_id, artifact_name=artifact.name,
        artifact_digest_sha256=artifact.sha256, archive_bytes=artifact.size,
        receipt_sha256=staged["receipt_sha256"], destination=options.destination, inventory=inventory,
        public_file_count=len(inventory), public_total_bytes=sum(e["bytes"] for e in inventory.values()),
        public_inventory_sha256=_sha256_hex(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")),
        worker_receipt_role="non-publishing-source-proof", worker_receipt_publication_authority=False,
        worker_receipt_native_client_qualification=False,
        final_native_authority_requires_all_client_jobs=True, signing_performed=False, published=False,
    )
    write_exclusive_json(options.audit_out, {k: v for k, v in audit.items() if k not in {"destination", "inventory"}})
    return audit, recheck_before_native_action


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for field in fields(ClientInputOptions):
        parser.add_argument("--" + field.name.replace("_", "-"), dest=field.name, required=True)
    args = parser.parse_args(argv)
    try:
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            refuse("PYTHON_ISOLATION_FLAGS")
        here = os.path.dirname(os.path.realpath(__file__))
        if any(os.path.dirname(os.path.realpath(m.__file__)) != here for m in (gh, rp, sc)):
            refuse("IMPORT_IDENTITY")
        options = ClientInputOptions(**{f.name: getattr(args, f.name) for f in fields(ClientInputOptions)})
        authenticate_caller_environ(options, os.environ)
        token = pop_intake_token(os.environ)
        api = gh.GhApiTransport(token, options.work_root)
        audit, recheck = admit_client_artifact_input(options, api, environ=os.environ)
        recheck()
    except (PublicationError, sc.ClosureError) as error:
        print(f"REFUSED {error.code}", file=sys.stderr)
        if gh._RETAINED_CHILDREN:
            print("TRANSPORT_CHILD_RETAINED", file=sys.stderr)
        return 2
    except Exception:
        print("REFUSED INTERNAL", file=sys.stderr)
        if gh._RETAINED_CHILDREN:
            print("TRANSPORT_CHILD_RETAINED", file=sys.stderr)
        return 2
    if gh._RETAINED_CHILDREN:
        print("TRANSPORT_CHILD_RETAINED", file=sys.stderr)
        return 2
    print(f"ADMITTED lane={audit['lane']} artifact_id={audit['artifact_id']} public_file_count={audit['public_file_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
