"""Host outer controller for Theme Forge full-signer container orchestration."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

from source_closure import (
    MAX_FRAME_SECRET_BYTES, REQUIRED_B3_LEAVES, WORKER_RECEIPT_SCHEMA, apply_process_git_scope,
    authenticate_leaf_closure, authenticate_rs9_descriptor, configure_worker_sys_path,
    held_regular_bytes, parse_strict_json, physical_dir, scoped_git_env,
    sha256_hex, verify_clean_git_checkout, zero_bytes,
)

DOCKER_BINARY = "/usr/bin/docker"
HOST_SUMMARY_SCHEMA = "tf.current-signer-host-controller.v1"
_FORBIDDEN_DOCKER_FLAGS = ("-t", "--tty", "-d", "--detach", "--privileged", "--net=host", "--network=host")
_FORBIDDEN_UPPER_SUBSTRINGS = (
    "--PRIVILEGED", "NET_ADMIN", "SYS_ADMIN", "DOCKER.SOCK",
    "SECRET", "PASSWORD", "PASSPHRASE", "PRIVATE_KEY", "SIGNING_KEY",
    "CREDENTIAL", "GPG_KEY", "TOKEN=", "KEY=",
)
_RUN_SUFFIX_RE = re.compile(r"^[0-9]{1,20}$")
_IMAGE_DIGEST_RE = re.compile(r"^(?:[A-Za-z0-9._/:+-]+@)?sha256:[0-9a-f]{64}$")
_UID_GID_RE = re.compile(r"^[0-9]+:[0-9]+$")
_RETAINED_HOST_SESSIONS: list[dict[str, Any]] = []
_RETAINED_FRAME_AVAILABILITY_DIRS: list[dict[str, Any]] = []


class HostControllerError(RuntimeError):
    """Fixed-code host controller refusal; never embeds secret payloads."""
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")

@dataclass(frozen=True)
class HostControllerConfig:
    p_root: Path
    r_root: Path
    export_root: Path
    p_commit: str
    p_tree: str
    r_commit: str
    r_tree: str
    source_closure_sha256: str
    rs9_run: int
    challenge_nonce: str
    run_id_suffix: str
    container_image: str
    container_python: str
    expected_gpg_sha256: str
    expected_rpm_sha256: str
    release_date: str
    zip_transport: str = "actions"
    pass_online_github_token: bool = True
    timeout_seconds: float = 7500.0
    require_native_signing: bool = True
    require_isolated_python_flags: bool = True
    require_unimported_leaves: bool = True

@dataclass(frozen=True)
class HostControllerHooks:
    git_runner: Callable[..., tuple[int, bytes, bytes]] | None = None
    docker_cmd_runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]] | None = None
    worker_spawner: Callable[[tuple[str, ...], Mapping[str, str]], Any] | None = None
    frame_emitter: Callable[[], bytearray] | None = None

def build_docker_run_argv(config: HostControllerConfig, network_name: str, container_name: str) -> tuple[str, ...]:
    if not _IMAGE_DIGEST_RE.fullmatch(config.container_image):
        raise HostControllerError("CONTAINER_IMAGE_PIN", "Container image must be an immutable repository digest or local content ID")
    if not config.container_python.startswith("/") or "\x00" in config.container_python:
        raise HostControllerError("CONTAINER_PYTHON_PATH", "Container Python must be an absolute path")
    p_dir, r_dir = physical_dir(config.p_root, "P source root"), physical_dir(config.r_root, "R source root")
    exp_dir = physical_dir(config.export_root, "export root")
    uid, gid = os.getuid(), os.getgid()
    env_args = ("-e", "GH_TOKEN") if config.pass_online_github_token else ()
    worker_flags = ("--no-online-token",) if not config.pass_online_github_token else ()
    argv = (
        DOCKER_BINARY, "run", "--rm", "-i", "--pull", "never", "--name", container_name, "--network", network_name,
        "--user", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--mount", f"type=bind,src={p_dir},dst=/work/p,readonly",
        "--mount", f"type=bind,src={r_dir},dst=/work/r,readonly",
        "--mount", f"type=bind,src={exp_dir},dst=/work/export",
        "--tmpfs", f"/work/workspace:rw,exec,nosuid,nodev,mode=0700,uid={uid},gid={gid}",
        *env_args, config.container_image,
        config.container_python, "-I", "-B", "/work/p/tools/verification/current_import_routing.py", "--current-signer-worker",
        "--p-root", "/work/p", "--r-root", "/work/r", "--workspace-root", "/work/workspace", "--export-root", "/work/export",
        "--p-commit", config.p_commit, "--p-tree", config.p_tree, "--r-commit", config.r_commit, "--r-tree", config.r_tree,
        "--source-closure-sha256", config.source_closure_sha256, "--rs9-run", str(config.rs9_run),
        "--challenge-nonce", config.challenge_nonce, "--expected-gpg-sha256", config.expected_gpg_sha256,
        "--expected-rpm-sha256", config.expected_rpm_sha256, "--release-date", config.release_date,
        "--zip-transport", config.zip_transport, *worker_flags,
    )
    validate_docker_run_argv(argv)
    return argv


def validate_docker_run_argv(argv: Sequence[str]) -> None:
    if tuple(argv[:4]) != (DOCKER_BINARY, "run", "--rm", "-i"):
        raise HostControllerError("DOCKER_RUN_PREFIX", "Docker run must start with /usr/bin/docker run --rm -i")
    for idx, token in enumerate(argv):
        if not isinstance(token, str) or not token or "\x00" in token:
            raise HostControllerError("DOCKER_RUN_TOKEN", "Invalid token in docker run argv")
        if token in _FORBIDDEN_DOCKER_FLAGS or token.startswith("-v"):
            raise HostControllerError("DOCKER_RUN_FORBIDDEN_FLAG", f"Forbidden docker run flag: {token}")
        if token in {"--network", "--net"} and idx + 1 < len(argv) and argv[idx + 1] == "host":
            raise HostControllerError("DOCKER_RUN_FORBIDDEN_FLAG", "Host network mode is forbidden")
        upper = token.upper()
        if any(bad in upper for bad in _FORBIDDEN_UPPER_SUBSTRINGS):
            raise HostControllerError("DOCKER_RUN_FORBIDDEN_CONTENT", "Forbidden capability, socket, or secret in argv")
        if "TOKEN" in upper and token not in {"GH_TOKEN", "--no-online-token"}:
            raise HostControllerError("DOCKER_RUN_FORBIDDEN_CONTENT", "Unexpected token argument in docker run argv")
    if (
        "--user" not in argv or not _UID_GID_RE.fullmatch(argv[argv.index("--user") + 1])
        or "--cap-drop" not in argv or argv[argv.index("--cap-drop") + 1] != "ALL"
        or "--security-opt" not in argv or argv[argv.index("--security-opt") + 1] != "no-new-privileges"
        or not any(t.endswith(",dst=/work/p,readonly") for t in argv)
        or not any(t.endswith(",dst=/work/r,readonly") for t in argv)
        or not any(t.startswith("/work/workspace:") and "mode=0700,uid=" in t for t in argv)
    ):
        raise HostControllerError("DOCKER_RUN_HARDENING", "Missing user, mount readonly, tmpfs uid, or capability hardening")


def _default_docker_runner(argv: tuple[str, ...], timeout: float) -> tuple[int, bytes, bytes]:
    completed = subprocess.run(
        argv, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr

def _default_worker_spawner(argv: tuple[str, ...], env: Mapping[str, str]) -> Any:
    return subprocess.Popen(
        argv, env=dict(env), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True, close_fds=True,
    )

def _availability_identity(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)

def _release_availability_dir(tmp_dir: str, expected_identity: tuple) -> bool:
    """Remove only the known nonsecret availability leaf and its original empty directory."""
    import stat
    fd = None
    try:
        fd = os.open(tmp_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if _availability_identity(os.fstat(fd)) != expected_identity:
            raise ValueError("AVAILABILITY_DIRECTORY_CHANGED")
        names = set(os.listdir(fd))
        if not names <= {"availability.json"}:
            raise ValueError("AVAILABILITY_UNKNOWN_ENTRY")
        if names:
            info = os.stat("availability.json", dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or info.st_size > 65536):
                raise ValueError("AVAILABILITY_ENTRY_CHANGED")
            os.unlink("availability.json", dir_fd=fd)
        if os.listdir(fd) or _availability_identity(os.lstat(tmp_dir)) != expected_identity:
            raise ValueError("AVAILABILITY_DIRECTORY_CHANGED")
        os.rmdir(tmp_dir)
    except BaseException as error:
        if not any(row["path"] == tmp_dir for row in _RETAINED_FRAME_AVAILABILITY_DIRS):
            _RETAINED_FRAME_AVAILABILITY_DIRS.append({"path": tmp_dir, "identity": expected_identity})
        if not isinstance(error, Exception):
            raise
        return False
    finally:
        if fd is not None:
            os.close(fd)
    return True

def _frame_custody_retained() -> bool:
    module = sys.modules.get("secret_frame_transport")
    return bool(_RETAINED_FRAME_AVAILABILITY_DIRS) or bool(
        module is not None and module.retained_custody_available()
    )

def _default_frame_emitter(p_root: Path, verified_leaves: Mapping[str, str]) -> bytearray:
    # Deferred until host source authentication and the detached-worker acknowledgement.
    from secret_frame_transport import FrameTransportError, capture_frame, retained_custody_available
    probe_script = p_root / "tools/verification/b3/probe_current_signer_c6_gpg.py"
    for rel in REQUIRED_B3_LEAVES:
        expected = verified_leaves.get(rel)
        if expected is None or sha256_hex(held_regular_bytes(p_root / rel)) != expected:
            raise HostControllerError("FRAME_SOURCE_CHANGED", "Authenticated producer source changed")
    probe_sha = verified_leaves["tools/verification/b3/probe_current_signer_c6_gpg.py"]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
    for key in ("PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE", "HOME", "USER", "LOGNAME"):
        if key in os.environ:
            env[key] = os.environ[key]
    tmp_dir = tempfile.mkdtemp(prefix="tf-frame-avail-")
    os.chmod(tmp_dir, 0o700)
    identity = _availability_identity(os.lstat(tmp_dir))
    out_buf, clear, removed = bytearray(), True, False
    try:
        avail_path = Path(tmp_dir) / "availability.json"
        clear = False
        try:
            out_buf = capture_frame(
                (sys.executable, "-I", "-B", str(probe_script), "--emit-stdin-frame",
                 "--expected-probe-sha256", probe_sha, "--availability-out", str(avail_path)),
                str(p_root), env, timeout=60.0, max_stdout=MAX_FRAME_SECRET_BYTES * 2 + 16,
            )
        except BaseException as error:
            clear = not retained_custody_available()
            if isinstance(error, FrameTransportError):
                raise HostControllerError(error.code, "Existing frame producer capture failed") from None
            raise
        clear = True
        if parse_strict_json(held_regular_bytes(avail_path, max_bytes=65536), "AVAILABILITY_SCHEMA").get("status") != "pass":
            raise HostControllerError("FRAME_EMITTER_FAILED", "Existing frame producer availability refused")
        if not _release_availability_dir(tmp_dir, identity):
            raise HostControllerError("FRAME_AVAILABILITY_RETAINED", "Availability cleanup uncertain")
        removed = True
    except BaseException:
        zero_bytes(out_buf)
        if not removed and not any(row["path"] == tmp_dir for row in _RETAINED_FRAME_AVAILABILITY_DIRS):
            if clear:
                _release_availability_dir(tmp_dir, identity)
            else:
                _RETAINED_FRAME_AVAILABILITY_DIRS.append({"path": tmp_dir, "identity": identity})
        raise
    return out_buf

def _verify_exported_artifacts(
    export_root: Path, expected_binding: Mapping[str, object], *, expected_worker_pid: int, require_native_signing: bool = True,
) -> dict[str, Any]:
    import public_repository_files as pub_files_mod
    if set(os.listdir(export_root)) != {"public-repository", "outer-controller-receipt.json"}:
        raise HostControllerError("EXPORT_ROOT_POLLUTED", "Export root must contain only public-repository and receipt")
    receipt = parse_strict_json(held_regular_bytes(export_root / "outer-controller-receipt.json"), "RECEIPT_SCHEMA")
    expected_native, expected_status = (True, "observed") if require_native_signing else (False, "test-only")
    if (
        receipt.get("schema") != WORKER_RECEIPT_SCHEMA or receipt.get("status") != "pass"
        or receipt.get("source_binding") != dict(expected_binding)
        or type(receipt.get("worker_pid")) is not int or receipt["worker_pid"] <= 0
        or receipt.get("worker_pid") != expected_worker_pid
        or receipt.get("lease_owner_pid") != receipt.get("worker_pid") or receipt.get("same_pid_verified") is not True
        or receipt.get("native_signing_execution") is not expected_native or receipt.get("signing_status") != expected_status
        or receipt.get("c6_agent_and_private_work_cleanup_confirmed") is not True
        or receipt.get("lease_closed_confirmed") is not True or receipt.get("stage_snapshot_joined_to_fresh_admission") is not True
        or receipt.get("public_verification_status") != "pass" or receipt.get("public_native_crypto_verified") is not expected_native
        or receipt.get("custody_retained") is not False or receipt.get("publication_authority") is not False
        or receipt.get("native_client_qualification") is not False
    ):
        raise HostControllerError("WORKER_RECEIPT_INVALID", "Worker receipt failed required invariants")
    snap = pub_files_mod.snapshot(export_root / "public-repository")
    if pub_files_mod.inventory(snap.members) != receipt.get("exported_files"):
        raise HostControllerError("EXPORT_INVENTORY_MISMATCH", "Exported public repository does not match worker receipt")
    return receipt

def _authenticate_host_sources(config: HostControllerConfig, hooks: HostControllerHooks) -> tuple[Path, Path, Path, dict[str, str]]:
    if not _RUN_SUFFIX_RE.fullmatch(config.run_id_suffix):
        raise HostControllerError("RUN_SUFFIX_INVALID", "run_id_suffix must be 1..20 ASCII digits")
    p_root, r_root = physical_dir(config.p_root, "P source root"), physical_dir(config.r_root, "R source root")
    exp_root = physical_dir(config.export_root, "export root")
    if os.listdir(exp_root):
        raise HostControllerError("EXPORT_ROOT_NOT_EMPTY", "Export root must be empty before run")
    git_env = apply_process_git_scope(p_root, r_root)
    verify_clean_git_checkout(p_root, config.p_commit, config.p_tree, git_env=git_env, git_runner=hooks.git_runner)
    verify_clean_git_checkout(r_root, config.r_commit, config.r_tree, git_env=git_env, git_runner=hooks.git_runner)
    authenticate_rs9_descriptor(p_root, expected_r_commit=config.r_commit, expected_r_tree=config.r_tree, expected_rs9_run=config.rs9_run)
    verified_leaves = authenticate_leaf_closure(p_root, expected_leaf_manifest_sha256=config.source_closure_sha256, require_unimported=config.require_unimported_leaves)
    configure_worker_sys_path(p_root, r_root, require_isolated_flags=config.require_isolated_python_flags)
    return p_root, r_root, exp_root, verified_leaves


def _run_gate_session(
    gate: Any, session: Any, gate_cmds: tuple[tuple[str, ...], tuple[str, ...]],
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], emitter: Callable[[], bytearray],
) -> str:
    from signer_protocol_io import validate_frame_bytes

    disconnect_cmd, inspect_cmd = gate_cmds

    def _disconnect() -> None:
        if runner(disconnect_cmd, 30.0)[0] != 0:
            raise HostControllerError("DOCKER_NETWORK_DISCONNECT", "Failed to disconnect worker network")

    def _inspect() -> bytes:
        rc, out, _ = runner(inspect_cmd, 30.0)
        if rc != 0:
            raise HostControllerError("DOCKER_NETWORK_INSPECT", "Failed to inspect worker networks")
        return out

    def _exchange(challenge: bytes) -> bytes:
        session.write_stdin(challenge, close_after=False)
        ack = session.read_protocol_line()
        session.require_no_extra_stdout()
        return ack

    def _emit_frame() -> None:
        frame_buf = emitter()
        try:
            validate_frame_bytes(frame_buf, HostControllerError)
            session.write_stdin(frame_buf, close_after=True)
        finally:
            zero_bytes(frame_buf)

    gate.release_frame(
        ready=session.read_protocol_line(), disconnect=_disconnect, inspect_networks=_inspect,
        exchange_challenge=_exchange, emit_existing_frame_and_eof=_emit_frame,
    )
    return str(gate.state)


def _teardown_host_session(
    session: Any | None, resources: tuple[str, str], remove_net_cmd: tuple[str, ...],
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], *, succeeded: bool,
) -> tuple[dict[str, Any], BaseException | None]:
    network_name, container_name = resources
    interrupt = None
    session_uncertain = False
    if session is not None:
        try:
            session.terminate_and_close()
        except BaseException as error:
            session_uncertain = True
            if not isinstance(error, Exception):
                interrupt = error
        session_uncertain = session_uncertain or session.cleanup_uncertain
    force_remove_attempted = not succeeded or session_uncertain
    container_force_removed = network_removed = container_absent = False
    if force_remove_attempted:
        try:
            container_force_removed = runner((DOCKER_BINARY, "rm", "-f", container_name), 30.0)[0] == 0
        except BaseException as error:
            if not isinstance(error, Exception) and interrupt is None:
                interrupt = error
    try:
        rc, out, _err = runner(
            (DOCKER_BINARY, "container", "ls", "--all", "--quiet", "--filter", f"name=^/{container_name}$"), 30.0)
        container_absent = rc == 0 and not out.strip()
    except BaseException as error:
        if not isinstance(error, Exception) and interrupt is None:
            interrupt = error
    try:
        network_removed = runner(remove_net_cmd, 30.0)[0] == 0
    except BaseException as error:
        if not isinstance(error, Exception) and interrupt is None:
            interrupt = error
    return {
        "network": network_name, "container": container_name,
        "container_force_remove_attempted": force_remove_attempted,
        "container_force_removed": container_force_removed, "container_absence_confirmed": container_absent,
        "network_removed": network_removed, "session_cleanup_uncertain": bool(session_uncertain),
        "teardown_interrupted": interrupt is not None, "teardown_is_not_c6_cleanup": True,
    }, interrupt


def execute_host_controller(config: HostControllerConfig, *, hooks: HostControllerHooks | None = None) -> dict[str, Any]:
    hk = hooks or HostControllerHooks()
    p_root, r_root, exp_root, verified_leaves = _authenticate_host_sources(config, hk)
    from signer_protocol_io import ForegroundContainerSession
    from signing_network_gate import HostGate, SourceBinding, docker_gate_commands

    binding = SourceBinding(
        config.p_commit, config.p_tree, config.r_commit, config.r_tree, config.source_closure_sha256, config.rs9_run,
    )
    gate = HostGate(binding, config.challenge_nonce)
    network_name = f"tf-current-signer-{config.run_id_suffix}-1"
    container_name = f"tf-current-signer-{config.run_id_suffix}-2"
    gate_cmds = docker_gate_commands(network_name, container_name)
    create_net_cmd = (DOCKER_BINARY, "network", "create", "--driver", "bridge", network_name)
    remove_net_cmd = (DOCKER_BINARY, "network", "rm", network_name)
    docker_run_argv = build_docker_run_argv(config, network_name, container_name)
    runner = hk.docker_cmd_runner or _default_docker_runner
    spawner = hk.worker_spawner or _default_worker_spawner
    emitter = hk.frame_emitter or (lambda: _default_frame_emitter(p_root, verified_leaves))

    if runner(create_net_cmd, 30.0)[0] != 0:
        raise HostControllerError("DOCKER_NETWORK_CREATE", "Failed to create fresh Docker bridge network")
    session: ForegroundContainerSession | None = None
    caught_error: BaseException | None = None
    run_succeeded = False
    try:
        spawn_env = dict(scoped_git_env(p_root, r_root))
        if config.pass_online_github_token and "GH_TOKEN" in os.environ:
            spawn_env["GH_TOKEN"] = os.environ["GH_TOKEN"]
        session = ForegroundContainerSession(
            spawner(docker_run_argv, spawn_env), time.monotonic() + config.timeout_seconds, HostControllerError,
        )
        gate_state = _run_gate_session(gate, session, gate_cmds, runner, emitter)
        exit_code = session.wait_for_exit()
        session.require_stdout_clean_eof()
        if exit_code != 0:
            raise HostControllerError("WORKER_NONZERO_EXIT", f"Worker container exited with status {exit_code}")
        worker_receipt = _verify_exported_artifacts(
            exp_root, binding.record(), expected_worker_pid=gate.worker_pid, require_native_signing=config.require_native_signing,
        )
        run_succeeded = True
    except BaseException as error:
        caught_error = error
        raise
    finally:
        teardown, teardown_interrupt = _teardown_host_session(
            session, (network_name, container_name), remove_net_cmd, runner, succeeded=run_succeeded,
        )
        teardown["frame_capture_custody_retained"] = _frame_custody_retained()
        uncertain = (
            teardown["session_cleanup_uncertain"] or not teardown["container_absence_confirmed"]
            or not teardown["network_removed"] or teardown["frame_capture_custody_retained"]
            or (teardown["container_force_remove_attempted"] and not teardown["container_force_removed"])
            or teardown_interrupt is not None
        )
        if caught_error is not None:
            caught_error.host_teardown = teardown
            if teardown_interrupt is not None:
                caught_error.teardown_interrupt = teardown_interrupt
        if uncertain:
            _RETAINED_HOST_SESSIONS.append({
                "container": container_name, "session": session, "teardown": teardown, "error": caught_error,
            })
            if caught_error is None:
                if teardown_interrupt is not None:
                    teardown_interrupt.host_teardown = teardown
                    raise teardown_interrupt
                error = HostControllerError("HOST_TEARDOWN_UNCONFIRMED", "Owned host teardown unconfirmed")
                error.host_teardown = teardown
                _RETAINED_HOST_SESSIONS[-1]["error"] = error
                raise error
    return {
        "schema": HOST_SUMMARY_SCHEMA, "status": "pass", "gate_state": gate_state, "worker_receipt": worker_receipt,
        "host_container_and_network_teardown": teardown,
        "c6_agent_and_private_work_cleanup_confirmed": worker_receipt["c6_agent_and_private_work_cleanup_confirmed"],
        "publication_authority": False, "native_client_qualification": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Theme Forge full-signer host controller")
    for flag in ("--p-root", "--r-root", "--export-root"):
        parser.add_argument(flag, type=Path, required=True)
    for flag in (
        "--p-commit", "--p-tree", "--r-commit", "--r-tree", "--source-closure-sha256",
        "--challenge-nonce", "--run-id-suffix", "--container-image", "--container-python",
        "--expected-gpg-sha256", "--expected-rpm-sha256", "--release-date",
    ):
        parser.add_argument(flag, required=True)
    parser.add_argument("--rs9-run", type=int, required=True)
    parser.add_argument("--zip-transport", choices=("actions", "public-release-relay"), default="actions")
    parser.add_argument("--no-online-token", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=7500.0)
    args = parser.parse_args(argv)
    cfg = HostControllerConfig(
        p_root=args.p_root, r_root=args.r_root, export_root=args.export_root,
        p_commit=args.p_commit, p_tree=args.p_tree, r_commit=args.r_commit, r_tree=args.r_tree,
        source_closure_sha256=args.source_closure_sha256, rs9_run=args.rs9_run,
        challenge_nonce=args.challenge_nonce, run_id_suffix=args.run_id_suffix,
        container_image=args.container_image, container_python=args.container_python,
        expected_gpg_sha256=args.expected_gpg_sha256, expected_rpm_sha256=args.expected_rpm_sha256,
        release_date=args.release_date, zip_transport=args.zip_transport,
        pass_online_github_token=not args.no_online_token, timeout_seconds=args.timeout_seconds,
    )
    try:
        execute_host_controller(cfg)
    except Exception as error:
        code = getattr(error, "code", None) or (
            error.args[0] if error.args and isinstance(error.args[0], str) and re.fullmatch(r"[A-Z0-9_]{3,64}", error.args[0])
            else "HOST_EXECUTION_FAILED"
        )
        print(json.dumps({
            "schema": HOST_SUMMARY_SCHEMA, "status": "failed-closed", "error_code": code,
            "custody_retained": bool(_RETAINED_HOST_SESSIONS) or _frame_custody_retained(),
            "host_container_and_network_teardown": getattr(error, "host_teardown", None),
            "publication_authority": False, "native_client_qualification": False,
        }, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
