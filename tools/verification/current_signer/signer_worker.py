"""Single-PID foreground container worker for Theme Forge full-signer preparation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading
from typing import Any, Callable, Mapping

from source_closure import (
    WORKER_RECEIPT_SCHEMA, apply_process_git_scope, authenticate_leaf_closure,
    authenticate_rs9_descriptor, configure_worker_sys_path, held_regular_bytes,
    parse_strict_json, physical_dir, sha256_hex, verify_clean_git_checkout, zero_bytes,
)

_SIGNING_SECRET_TOKENS = ("SECRET", "PASSWORD", "PASSPHRASE", "PRIVATE_KEY", "SIGNING_KEY", "CREDENTIAL")
_ONLINE_INTAKE_TOKENS = ("GH_TOKEN", "GITHUB_TOKEN")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RETAINED_WORKER_CUSTODIES: list[dict[str, Any]] = []


class WorkerError(RuntimeError):
    """Fixed-code worker refusal; never embeds secret or raw payload text."""
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")

@dataclass(frozen=True)
class WorkerConfig:
    p_root: Path
    r_root: Path
    workspace_root: Path
    export_root: Path
    p_commit: str
    p_tree: str
    r_commit: str
    r_tree: str
    source_closure_sha256: str
    rs9_run: int
    challenge_nonce: str
    expected_gpg_sha256: str
    expected_rpm_sha256: str
    release_date: str
    zip_transport: str = "actions"
    intake_timeout: int = 7200
    allow_online_intake_token: bool = True
    require_native_signing: bool = True
    require_isolated_python_flags: bool = True
    require_unimported_leaves: bool = True

@dataclass(frozen=True)
class WorkerHooks:
    streams: Any | None = None
    git_runner: Callable[..., tuple[int, bytes, bytes]] | None = None
    isolation_prover: Callable[[], None] | None = None
    runtime_factory: Callable[[], Any] | None = None
    public_verifier: Callable[..., dict[str, Any]] | None = None

def _check_online_env(allow_intake_token: bool) -> bool:
    intake_present = False
    for key, value in os.environ.items():
        if not value:
            continue
        upper = key.upper()
        if any(tok in upper for tok in _SIGNING_SECRET_TOKENS):
            raise WorkerError("SIGNING_SECRET_ENV_FORBIDDEN", "Signing secret environment variable forbidden")
        if "TOKEN" in upper:
            if allow_intake_token and key in _ONLINE_INTAKE_TOKENS:
                intake_present = True
            else:
                raise WorkerError("UNEXPECTED_TOKEN_ENV", "Unexpected token in worker environment")
    return intake_present

def _strip_online_tokens_and_require_clean() -> None:
    for key in _ONLINE_INTAKE_TOKENS:
        os.environ.pop(key, None)
    for key, value in os.environ.items():
        if value and any(tok in key.upper() for tok in (*_SIGNING_SECRET_TOKENS, "TOKEN")):
            raise WorkerError("CREDENTIAL_ENV_FORBIDDEN", "Credential environment variable present in private phase")

def _require_serial_preconditions(expected_pid: int, lease: Any | None = None) -> None:
    if os.getpid() != expected_pid:
        raise WorkerError("WORKER_PID_CHANGED", "Worker PID changed across phase boundary")
    if lease is not None and (getattr(lease, "_pid", None) != expected_pid or getattr(lease, "state", None) != "active"):
        raise WorkerError("LEASE_PID_OR_STATE", "Lease is not active in the same worker PID")
    if (
        threading.current_thread() is not threading.main_thread()
        or threading.active_count() != 1 or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
    ):
        raise WorkerError("SIGCHLD_OR_THREAD_PRECONDITION", "Dedicated serial main thread and default SIGCHLD required")

def _mkdir_0700(path: Path, label: str) -> Path:
    os.mkdir(path, 0o700)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise WorkerError("WORKSPACE_CUSTODY", f"Fresh {label} custody invalid")
    return path


def _prepare_workspace_dirs(workspace_root: Path, p_root: Path, r_root: Path, export_root: Path) -> dict[str, Path]:
    ws, exp = physical_dir(workspace_root, "worker workspace"), physical_dir(export_root, "export root")
    if os.listdir(ws) or os.listdir(exp):
        raise WorkerError("WORKSPACE_NOT_EMPTY", "Worker workspace and export root must be empty")
    roots = (ws, p_root, r_root, exp)
    if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(roots) for b in roots[i + 1:]):
        raise WorkerError("ROOT_OVERLAP", "Worker workspace, source roots, and export root must be disjoint")
    ws_info = os.lstat(ws)
    if ws_info.st_uid != os.getuid() or stat.S_IMODE(ws_info.st_mode) != 0o700:
        raise WorkerError("WORKSPACE_CUSTODY", "Worker workspace must be owned mode 0700")
    home = curr = _mkdir_0700(ws / "container-home", "container home")
    for part in ("Documents", "agent", "outbox", "release-starport-9_dev", "collection"):
        curr = _mkdir_0700(curr / part, f"outbox {part}")
    return {
        "home": home, "collection": curr, "stage": _mkdir_0700(ws / "stage", "unsigned stage"),
        "lease_dest": ws / "lease-inputs", "signing_output": ws / "signed-output",
        "public_work": _mkdir_0700(ws / "public-verify-work", "public verification work"),
        "public_deploy": _mkdir_0700(ws / "public-deploy", "public deployment staging"),
    }


def _authenticate_worker_sources(config: WorkerConfig, hooks: WorkerHooks) -> dict[str, Any]:
    for pin_name, pin_val in (("expected_gpg_sha256", config.expected_gpg_sha256), ("expected_rpm_sha256", config.expected_rpm_sha256)):
        if not isinstance(pin_val, str) or not _HEX64.fullmatch(pin_val):
            raise WorkerError("BINARY_PIN_FORMAT", f"{pin_name} must be 64-hex")
    p_root, r_root = physical_dir(config.p_root, "P source root"), physical_dir(config.r_root, "R source root")
    git_env = apply_process_git_scope(p_root, r_root)
    verify_clean_git_checkout(p_root, config.p_commit, config.p_tree, git_env=git_env, git_runner=hooks.git_runner)
    verify_clean_git_checkout(r_root, config.r_commit, config.r_tree, git_env=git_env, git_runner=hooks.git_runner)
    desc_info = authenticate_rs9_descriptor(
        p_root, expected_r_commit=config.r_commit, expected_r_tree=config.r_tree, expected_rs9_run=config.rs9_run,
    )
    authenticate_leaf_closure(
        p_root, expected_leaf_manifest_sha256=config.source_closure_sha256, require_unimported=config.require_unimported_leaves,
    )
    configure_worker_sys_path(p_root, r_root, require_isolated_flags=config.require_isolated_python_flags)
    return desc_info


def _collect_and_snapshot(
    config: WorkerConfig, descriptor_doc: Mapping[str, Any], dirs: Mapping[str, Path], worker_pid: int,
) -> tuple[Any, Any, int]:
    import current_import_routing as routing_mod
    import public_repository_files as pub_files_mod
    from rs9.qualified_distribution_inputs import SourceBoundConfiguration

    rs9_block = descriptor_doc["rs9"]
    rs9_cfg = SourceBoundConfiguration(
        repository=config.r_root, source_commit=config.r_commit, source_tree=config.r_tree,
        run_id=config.rs9_run, not_before=datetime.fromisoformat(rs9_block["not_before"].replace("Z", "+00:00")),
        workflow_sha256=rs9_block["workflow_sha256"], contract_sha256=rs9_block["contract_sha256"],
        builder_source_sha256=rs9_block["builder_source_sha256"],
        configuration_sha256=rs9_block["configuration_sha256"],
        release_ingestion_sha256=rs9_block["release_ingestion_sha256"],
    )
    p_files = {rel: sha256_hex(held_regular_bytes(config.p_root / rel)) for rel in routing_mod.SOURCE_FILES}
    prod_src = routing_mod.ProductionSource(config.p_root, config.p_commit, config.p_tree, p_files)
    with routing_mod.fresh_signing_inputs(
        rs9_cfg, prod_src, dirs["collection"], dirs["stage"],
        release_date=config.release_date, zip_transport=config.zip_transport, timeout=config.intake_timeout,
    ) as handle:
        lease = routing_mod.transfer_signing_inputs(handle, dirs["lease_dest"])
        _require_serial_preconditions(worker_pid, lease)
        lease_pid = int(getattr(lease, "_pid", -1))
        before_sign_stage = pub_files_mod.snapshot(dirs["stage"])
    routing_raw = before_sign_stage.members.get("unsigned-routing.json")
    if routing_raw is None or routing_raw != lease._record.get("routing_bytes"):
        raise WorkerError("STAGE_ROUTING_MISMATCH", "Stage snapshot routing bytes differ from held lease")
    routing_doc = parse_strict_json(routing_raw, "STAGE_ROUTING_SCHEMA")
    if (
        routing_doc.get("p_source", {}).get("commit") != config.p_commit
        or routing_doc.get("p_source", {}).get("tree") != config.p_tree
        or routing_doc.get("rs9_original", {}).get("source_commit") != config.r_commit
        or routing_doc.get("rs9_original", {}).get("source_tree") != config.r_tree
        or routing_doc.get("rs9_original", {}).get("run_id") != config.rs9_run
    ):
        raise WorkerError("STAGE_SOURCE_JOIN_MISMATCH", "Stage routing source coordinates differ from binding")
    return lease, before_sign_stage, lease_pid


def _sign_and_verify_public(
    config: WorkerConfig, dirs: Mapping[str, Path], stage_state: tuple[Any, Any], streams: Any, hooks: WorkerHooks, *, worker_pid: int,
) -> tuple[Any, Any, dict[str, Any], Any]:
    import protected_signing_runtime as runtime_mod
    import public_repository_files as pub_files_mod
    import public_repository_verifier as pub_verifier_mod
    from signer_protocol_io import read_secret_frame

    lease, before_sign_stage = stage_state
    key_buf, phrase_buf = read_secret_frame(streams, WorkerError)
    try:
        _require_serial_preconditions(worker_pid, lease)
        active_runtime = hooks.runtime_factory() if hooks.runtime_factory is not None else runtime_mod.ProtectedSigningRuntime()
        try:
            execution = active_runtime.execute_live_lease(
                lease, output_root=dirs["signing_output"],
                public_key_bytes=held_regular_bytes(config.p_root / "keys/knowledge-forge-ai-packages.asc"),
                private_key_bytes=key_buf, passphrase=phrase_buf,
            )
        except BaseException as error:
            error.runtime = active_runtime
            raise
    finally:
        zero_bytes(key_buf)
        zero_bytes(phrase_buf)
    if (
        active_runtime.retained_custody is not None or getattr(active_runtime, "_agent", None) is not None
        or getattr(lease, "state", None) != "closed" or (dirs["signing_output"] / ".protected-work").exists()
    ):
        err = WorkerError("PRIVATE_CLEANUP_UNCONFIRMED", "Private runtime or lease cleanup is unconfirmed")
        err.runtime = active_runtime  # type: ignore[attr-defined]
        raise err
    pub_verifier_mod.require_all_custody_closed()
    if config.require_native_signing:
        if getattr(execution, "native_execution", None) is not True or getattr(execution, "status", None) != "observed":
            raise WorkerError("SIGNING_NATIVE_EXECUTION_REQUIRED", "Native signing execution and observed status required")
    elif getattr(execution, "native_execution", None) is not False or getattr(execution, "status", None) != "test-only":
        raise WorkerError("SIGNING_FIXTURE_STATE_INVALID", "Control-plane fixture must not claim native execution")
    pub_files_mod.unchanged(before_sign_stage)
    verifier_fn = hooks.public_verifier or pub_verifier_mod.verify_and_assemble
    pub_result = verifier_fn(
        unsigned_stage=dirs["stage"], signed_output=dirs["signing_output"],
        public_key=config.p_root / "keys/knowledge-forge-ai-packages.asc",
        work_root=dirs["public_work"], deployment_root=dirs["public_deploy"],
        expected_gpg_sha256=config.expected_gpg_sha256, expected_rpm_sha256=config.expected_rpm_sha256,
    )
    if not isinstance(pub_result, dict) or pub_result.get("status") != "pass" or pub_result.get("native_crypto_verified") is not config.require_native_signing:
        raise WorkerError("PUBLIC_VERIFICATION_FAILED", "Public repository verification did not pass")
    pub_files_mod.unchanged(before_sign_stage)
    pub_verifier_mod.require_all_custody_closed()
    verified_deploy = pub_files_mod.snapshot(dirs["public_deploy"])
    export_repo = config.export_root / "public-repository"
    os.mkdir(export_repo, 0o755)
    pub_files_mod.write_new(export_repo, verified_deploy.members)
    exported_snap = pub_files_mod.snapshot(export_repo)
    if exported_snap.members != verified_deploy.members:
        raise WorkerError("EXPORT_INVENTORY_MISMATCH", "Exported public repository differs from verified deploy")
    return active_runtime, execution, pub_result, exported_snap


def _write_worker_receipt(
    export_root: Path, binding_rec: dict[str, object], desc_sha: str,
    run_meta: tuple[int, int, bool], results: tuple[Any, dict[str, Any], Any],
) -> dict[str, Any]:
    import public_repository_files as pub_files_mod

    worker_pid, lease_pid, online_token_present = run_meta
    execution, pub_result, exported_snap = results
    native_exec = bool(execution.native_execution)
    receipt = {
        "schema": WORKER_RECEIPT_SCHEMA, "status": "pass",
        "evidence_class": "native-unqualified" if native_exec else "control-plane-fixture-only",
        "worker_pid": worker_pid, "lease_owner_pid": lease_pid,
        "same_pid_verified": os.getpid() == worker_pid == lease_pid, "source_binding": binding_rec,
        "descriptor_sha256": desc_sha, "online_intake_token_present": online_token_present,
        "container_signing_credential_free_at_start": True,
        "container_totally_credential_free_at_start": not online_token_present,
        "online_token_removed_from_future_child_env": True, "env_removal_erases_kernel_or_memory_copies": False,
        "custody_model": {
            "pr_checkout_files_verified_by_identity_and_hash_not_held_open_by_s1": True,
            "s1_lease_holds_collection_stage_roots_and_staged_artifact_files": True,
        },
        "native_signing_execution": native_exec, "signing_status": execution.status,
        "signed_package_rows": len(execution.objects), "c6_agent_and_private_work_cleanup_confirmed": True,
        "lease_closed_confirmed": True, "stage_snapshot_joined_to_fresh_admission": True,
        "public_verification_status": pub_result["status"], "public_native_crypto_verified": pub_result["native_crypto_verified"],
        "signed_store_records": pub_result.get("signed_store_records", 0),
        "exported_file_count": len(exported_snap.members),
        "exported_files": pub_files_mod.inventory(exported_snap.members),
        "custody_retained": False, "publication_authority": False, "native_client_qualification": False,
    }
    (export_root / "outer-controller-receipt.json").write_bytes((json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return receipt


def _retain_worker_failure(
    worker_pid: int, lease: Any, active_runtime: Any, active_streams: Any, error: BaseException,
) -> None:
    runtime = active_runtime or getattr(error, "runtime", None)
    if (
        runtime is None and getattr(error, "code", None) != "PRIVATE_CLEANUP_UNCONFIRMED"
        and lease is not None and getattr(lease, "state", None) == "active"
    ):
        try:
            lease._close_confirmed()
        except BaseException:
            pass
    if active_streams is not None:
        try:
            active_streams.close_all()
        except BaseException:
            pass
    if (
        (runtime is not None and getattr(runtime, "retained_custody", None) is not None)
        or (lease is not None and getattr(lease, "state", None) != "closed")
        or bool(active_streams is not None and active_streams.close_errors)
    ):
        _RETAINED_WORKER_CUSTODIES.append({
            "pid": worker_pid, "lease": lease, "runtime": runtime, "streams": active_streams, "error": error,
        })


def execute_worker_flow(config: WorkerConfig, *, hooks: WorkerHooks | None = None) -> dict[str, Any]:
    hk = hooks or WorkerHooks()
    worker_pid = os.getpid()
    _require_serial_preconditions(worker_pid)
    online_token_present = _check_online_env(config.allow_online_intake_token)
    lease = active_runtime = active_streams = None
    saved_home = os.environ.get("HOME")
    try:
        desc_info = _authenticate_worker_sources(config, hk)
        from signer_protocol_io import ProtocolStreams
        import signing_linux_isolation as isolation_mod
        from signing_network_gate import SourceBinding, encode_message, worker_acknowledgement

        active_streams = hk.streams if hk.streams is not None else ProtocolStreams.detach_stdio(WorkerError)
        binding = SourceBinding(
            config.p_commit, config.p_tree, config.r_commit, config.r_tree, config.source_closure_sha256, config.rs9_run,
        )
        binding.record()
        dirs = _prepare_workspace_dirs(config.workspace_root, config.p_root, config.r_root, config.export_root)
        os.environ["HOME"] = str(dirs["home"])
        lease, before_sign_stage, lease_pid = _collect_and_snapshot(config, desc_info["descriptor"], dirs, worker_pid)
        _strip_online_tokens_and_require_clean()
        _require_serial_preconditions(worker_pid, lease)
        active_streams.write_line(encode_message("ready", binding, config.challenge_nonce, worker_pid=worker_pid))
        prover = hk.isolation_prover or isolation_mod.prove_linux_isolation
        ack_line = worker_acknowledgement(
            active_streams.read_line(), binding, config.challenge_nonce,
            lambda: (_require_serial_preconditions(worker_pid, lease), _strip_online_tokens_and_require_clean(), prover())[2],
            worker_pid=worker_pid,
        )
        active_streams.write_line(ack_line)
        active_streams.close_out()
        active_runtime, execution, pub_result, exported_snap = _sign_and_verify_public(
            config, dirs, (lease, before_sign_stage), active_streams, hk, worker_pid=worker_pid,
        )
        return _write_worker_receipt(
            config.export_root, binding.record(), desc_info["descriptor_sha256"],
            (worker_pid, lease_pid, online_token_present), (execution, pub_result, exported_snap),
        )
    except BaseException as error:
        _retain_worker_failure(worker_pid, lease, active_runtime, active_streams, error)
        raise
    finally:
        if saved_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = saved_home
        if active_streams is not None:
            try:
                active_streams.close_all()
            except BaseException:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Theme Forge single-PID full-signer container worker")
    for flag in ("--p-root", "--r-root", "--workspace-root", "--export-root"):
        parser.add_argument(flag, type=Path, required=True)
    for flag in (
        "--p-commit", "--p-tree", "--r-commit", "--r-tree", "--source-closure-sha256",
        "--challenge-nonce", "--expected-gpg-sha256", "--expected-rpm-sha256", "--release-date",
    ):
        parser.add_argument(flag, required=True)
    parser.add_argument("--rs9-run", type=int, required=True)
    parser.add_argument("--zip-transport", choices=("actions", "public-release-relay"), default="actions")
    parser.add_argument("--intake-timeout", type=int, default=7200)
    parser.add_argument("--no-online-token", action="store_true")
    args = parser.parse_args(argv)
    cfg = WorkerConfig(
        p_root=args.p_root, r_root=args.r_root, workspace_root=args.workspace_root, export_root=args.export_root,
        p_commit=args.p_commit, p_tree=args.p_tree, r_commit=args.r_commit, r_tree=args.r_tree,
        source_closure_sha256=args.source_closure_sha256, rs9_run=args.rs9_run,
        challenge_nonce=args.challenge_nonce, expected_gpg_sha256=args.expected_gpg_sha256,
        expected_rpm_sha256=args.expected_rpm_sha256, release_date=args.release_date,
        zip_transport=args.zip_transport, intake_timeout=args.intake_timeout,
        allow_online_intake_token=not args.no_online_token,
    )
    try:
        execute_worker_flow(cfg)
    except Exception as error:
        code = getattr(error, "code", None) or (
            error.args[0] if error.args and isinstance(error.args[0], str) and re.fullmatch(r"[A-Z0-9_]{3,64}", error.args[0])
            else "WORKER_EXECUTION_FAILED"
        )
        print(json.dumps({
            "schema": WORKER_RECEIPT_SCHEMA, "status": "failed-closed", "error_code": code,
            "custody_retained": bool(_RETAINED_WORKER_CUSTODIES),
            "publication_authority": False, "native_client_qualification": False,
        }, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
