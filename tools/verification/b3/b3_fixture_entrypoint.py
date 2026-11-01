"""Private non-admitting lifecycle CLI; native execution is explicit and unqualified."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
from typing import Any, Callable, Mapping

_MODULE_DIR = str(Path(__file__).resolve(strict=True).parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from b3_fixture_inputs import (
    _absolute_path,
    _load_current_toolchain_catalog,
    _load_image_catalog,
    _load_owned_agent,
    _read_json,
    _sha256_bytes,
    authenticate_stage1,
    load_manifest,
    validate_manifest,
    validate_measured_facts,
)
from b3_fixture_types import (
    CANONICAL_SUBSET_PATH,
    CANONICAL_SUBSET_SHA256,
    CURRENT_IMAGE_CATALOG_SELECTORS,
    CURRENT_TOOLCHAIN_CATALOG_PATH,
    CURRENT_TOOLCHAIN_CATALOG_SHA256,
    FACTS_SCHEMA,
    IMAGE_CATALOG_PATH,
    IMAGE_CATALOG_SELECTORS,
    IMAGE_CATALOG_SHA256,
    NATIVE_TOOLS,
    RECEIPT_SCHEMA,
    REVIEWED_C6_SOURCE_PATH,
    REVIEWED_C6_SOURCE_SHA256,
    REVIEWED_C6_TESTS_PATH,
    REVIEWED_C6_TESTS_SHA256,
    SCHEMA,
    STAGE1_AUTH_SCHEMA,
    STAGE2_METADATA_SCHEMA,
    STAGE2_PROVISIONED_TOOLS,
    TARGET_AGENT_MODE,
    TARGET_GNUPG_VERSION,
    TARGET_RPM_VERSION,
    FixtureError,
    FixtureSpec,
    WorkspaceBinding,
)
from b3_fixture_workspace import (
    _close_workspace_binding,
    _fresh_workspace,
    _remove_fresh_workspace,
    _validate_job_parent,
)

_FORBIDDEN_ENV_TOKENS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSPHRASE",
    "PRIVATE_KEY",
    "SIGNING_KEY",
    "CREDENTIAL",
)


def check_native_support() -> None:
    if sys.platform != "linux" or sys.version_info < (3, 11):
        raise FixtureError("UNSUPPORTED_PLATFORM")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise FixtureError("UNSUPPORTED_PIDFD")


def _path_absent(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _check_credential_free_env(env_map: Mapping[str, str] | None = None) -> None:
    env = os.environ if env_map is None else env_map
    for key, value in env.items():
        upper = key.upper()
        if value and any(token in upper for token in _FORBIDDEN_ENV_TOKENS):
            raise FixtureError("CREDENTIAL_ENV_FORBIDDEN")


def _default_command_runner(argv: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise FixtureError("STAGE2_COMMAND_EXEC_FAILED") from error
    try:
        text = completed.stdout.decode("utf-8")
    except UnicodeError as error:
        raise FixtureError("STAGE2_COMMAND_OUTPUT_ENCODING") from error
    if "\x00" in text:
        raise FixtureError("STAGE2_COMMAND_OUTPUT_NUL")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    first_line = lines[0][:128] if lines else ""
    return completed.returncode, first_line


def measure_stage2_metadata(
    spec: FixtureSpec,
    job_parent: Path,
    *,
    module_loader: Callable[[FixtureSpec], Any] = _load_owned_agent,
    support_checker: Callable[[], None] = check_native_support,
    command_runner: Callable[[list[str]], tuple[int, str]] = _default_command_runner,
    env_map: Mapping[str, str] | None = None,
    uid_getter: Callable[[], tuple[int, int]] = lambda: (os.getuid(), os.geteuid()),
    task_lister: Callable[[], list[str]] = lambda: os.listdir("/proc/self/task"),
    python_resolver: Callable[[], str] = lambda: str(Path(sys.executable).resolve(strict=True)),
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Measure container tool paths/versions/digests and C6 preconditions before any agent start."""
    _check_credential_free_env(env_map)
    support_checker()
    uid, euid = uid_getter()
    if uid != 0 or euid != 0:
        raise FixtureError("CONTAINER_ROOT_UID_REQUIRED")
    try:
        tasks = task_lister()
    except OSError as error:
        raise FixtureError("PROC_TASK_UNAVAILABLE") from error
    if (
        threading.current_thread() is not threading.main_thread()
        or threading.active_count() != 1
        or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
        or len(tasks) != 1
    ):
        raise FixtureError("SIGCHLD_PRECONDITION")

    module = module_loader(spec)
    try:
        module._proc_preflight()
        layout = module._preflight_external_paths()
        python_path = python_resolver()
        python_ident, python_digest = module._trusted_tool(python_path)
        proc_exe_ident = module._exe(os.getpid())
    except Exception as error:
        code = getattr(error, "code", None)
        raise FixtureError(str(code) if isinstance(code, str) and code else "C6_PREFLIGHT_FAILED") from error
    if proc_exe_ident != python_ident:
        raise FixtureError("TOOL_PREFLIGHT_FAILED")

    measured_tools: dict[str, dict[str, Any]] = {}
    for name, path in STAGE2_PROVISIONED_TOOLS.items():
        try:
            _, digest = module._trusted_tool(path)
        except Exception as error:
            code = getattr(error, "code", None)
            raise FixtureError(str(code) if isinstance(code, str) and code else "TOOL_PREFLIGHT_FAILED") from error
        rc, first_line = command_runner([path, "--version"])
        if rc != 0 or not first_line:
            raise FixtureError("TOOL_VERSION_QUERY_FAILED")
        if name in NATIVE_TOOLS:
            expected_line = f"{name} (GnuPG) {spec.target_gnupg_version}"
            if first_line != expected_line:
                raise FixtureError("TOOL_VERSION_MISMATCH")
        else:
            expected_line = f"RPM version {spec.target_rpm_version}"
            if first_line != expected_line:
                raise FixtureError("RPM_VERSION_MISMATCH")
        measured_tools[name] = {
            "path": path,
            "version_line": first_line,
            "version_attestation": "measured-in-container",
            "sha256": digest,
            "sha256_attestation": "measured-in-container",
            "root_owned_regular_executable": True,
        }

    probe_ws = _fresh_workspace(job_parent)
    try:
        if os.listdir(probe_ws.home_fd):
            raise FixtureError("HOME_NOT_EMPTY", retained_custody=True, retained_root=probe_ws.root)
        records: dict[str, str] = {}
        for field in ("sysconfdir", "homedir", "socketdir", "agent-socket"):
            rc, line = command_runner([
                STAGE2_PROVISIONED_TOOLS["gpgconf"],
                "--homedir",
                str(probe_ws.home),
                "--list-dirs",
                field,
            ])
            if rc != 0 or not line:
                raise FixtureError("GPGCONF_QUERY_FAILED")
            records[field] = line
        try:
            bound = module.bind_gpgconf_paths(records, homedir=probe_ws.home, job_root=probe_ws.root)
        except Exception as error:
            code = getattr(error, "code", None)
            raise FixtureError(str(code) if isinstance(code, str) and code else "GPGCONF_BIND_FAILED") from error
        post_query_home_empty = len(os.listdir(probe_ws.home_fd)) == 0
        if not post_query_home_empty:
            raise FixtureError("HOME_NOT_EMPTY", retained_custody=True, retained_root=probe_ws.root)
    except FixtureError:
        try:
            _remove_fresh_workspace(probe_ws)
        except FixtureError:
            raise
        raise
    _remove_fresh_workspace(probe_ws)

    facts_payload: dict[str, Any] = {
        "schema": FACTS_SCHEMA,
        "execution_mode": "hosted-native",
        "attestation": "measured-in-container-stage2",
        "images_attestation": "catalog-derived-not-measured",
        "tools": {
            name: {
                "path": measured_tools[name]["path"],
                "version_line": measured_tools[name]["version_line"],
                "sha256": measured_tools[name]["sha256"],
                "sha256_attestation": "measured-in-container",
            }
            for name in NATIVE_TOOLS
        },
        "images": dict(spec.images),
    }
    validate_measured_facts(facts_payload, spec)

    python_version = f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    metadata_receipt: dict[str, Any] = {
        "schema": STAGE2_METADATA_SCHEMA,
        "status": "stage2-metadata-verified",
        "production_authority": False,
        "native_agent_started": False,
        "canonical_commit": spec.canonical_commit,
        "owned_agent_sha256": spec.owned_agent_source_sha256,
        "container_preconditions": {
            "platform_linux": True,
            "python_version": python_version,
            "python_version_attestation": "measured-in-container",
            "python_sha256": python_digest,
            "python_sha256_attestation": "measured-in-container",
            "python_exe_root_regular_verified": proc_exe_ident == python_ident,
            "fixed_root_uid_confirmed": True,
            "pidfd_primitives_available": True,
            "main_thread_single_task_confirmed": True,
            "sigchld_default_confirmed": True,
            "c6_proc_preflight_confirmed": True,
            "c6_external_paths_preflight_confirmed": True,
            "var_run_alias_target_is_run": getattr(layout, "alias_target", None) == "/run",
            "credential_environment_absent": True,
        },
        "gpgconf_probe": {
            "single_name_queries_verified": True,
            "homedir_matches_fresh_home": bound.homedir == probe_ws.home,
            "job_root_matches_fresh_root": bound.job_root == probe_ws.root,
            "socketdir_bound": isinstance(bound.socketdir, Path),
            "agent_socket_bound": isinstance(bound.agent_socket, Path),
            "post_query_home_empty": True,
            "probe_workspace_removed_confirmed": True,
        },
        "measured_tools": measured_tools,
        "catalog_bindings": {
            "images": dict(spec.images),
            "images_attestation": "catalog-derived-not-measured",
            "image_catalog_sha256": spec.image_catalog_sha256,
            "bare_base_is_fully_provisioned": False,
            "approved_package_subset": ["gnupg2", "rpm-sign", "python3"],
        },
    }
    return metadata_receipt, facts_payload


def _closed_agent_observation(
    agent: Any,
    workspace: WorkspaceBinding,
    fixture_seam: bool,
    facts_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build evidence from closed agent state; substituted seams stay explicit."""
    if fixture_seam:
        return {
            "gpgconf_binding": {"status": "fixture-only-substituted", "source": "fake-agent-seam"},
            "cleanup": {
                "status": "fixture-only-substituted",
                "agent_cleanup_confirmed": bool(getattr(agent, "cleanup_confirmed", False)),
                "held_process_cleanup_confirmed": "not-observed",
                "socket_disappearance_confirmed": "not-observed",
                "stage2_tool_digests_matched_c6_custody": "not-observed",
            },
        }
    try:
        agent_receipt = agent.receipt
        paths = agent.paths
        custody = agent.retained_custody
    except Exception as error:
        raise FixtureError("NATIVE_LIFECYCLE_RECEIPT_UNAVAILABLE", retained_custody=True,
                            retained_root=workspace.root) from error
    if paths.homedir != workspace.home or paths.job_root != workspace.root:
        raise FixtureError("NATIVE_PATH_BINDING_SCOPE", retained_custody=True, retained_root=workspace.root)
    socket_absent = _path_absent(paths.agent_socket)
    held_process_closed = bool(
        getattr(agent, "cleanup_confirmed", False)
        and getattr(custody, "reaped", False)
        and getattr(custody, "pidfd", None) is None
    )
    if not held_process_closed:
        raise FixtureError("NATIVE_PROCESS_CLEANUP_UNCONFIRMED", retained_custody=True, retained_root=workspace.root)
    if not socket_absent:
        raise FixtureError("NATIVE_SOCKET_DISAPPEARANCE_UNCONFIRMED", retained_custody=True, retained_root=workspace.root)
    custody_tools = getattr(custody, "tools", None)
    expected_tools = (facts_summary or {}).get("tools")
    if not isinstance(custody_tools, Mapping) or not isinstance(expected_tools, Mapping):
        raise FixtureError("NATIVE_TOOL_DIGEST_UNAVAILABLE", retained_custody=True, retained_root=workspace.root)
    for tool_name, tool_path in NATIVE_TOOLS.items():
        recorded_entry = custody_tools.get(tool_path)
        expected_entry = expected_tools.get(tool_name)
        if (
            not isinstance(recorded_entry, tuple)
            or len(recorded_entry) != 2
            or not isinstance(expected_entry, Mapping)
            or recorded_entry[1] != expected_entry.get("sha256")
        ):
            raise FixtureError("NATIVE_TOOL_DIGEST_DRIFT", retained_custody=True, retained_root=workspace.root)
    return {
        "gpgconf_binding": {
            "status": "bound",
            "source": "OwnedGpgAgent.paths",
            "homedir_matches_fresh_home": paths.homedir == workspace.home,
            "job_root_matches_fresh_root": paths.job_root == workspace.root,
            "agent_socket_bound": isinstance(paths.agent_socket, Path),
            "socketdir_bound": isinstance(paths.socketdir, Path),
            "query_protocol": "C6-single-name-source-bound; not independently remeasured",
        },
        "cleanup": {
            "status": "closed-state-derived",
            "agent_receipt": {
                "schema": getattr(agent_receipt, "schema", None),
                "status": getattr(agent_receipt, "status", None),
                "evidence_class": getattr(agent_receipt, "evidence_class", None),
                "production_authority": getattr(agent_receipt, "production_authority", None),
            },
            "agent_cleanup_confirmed": bool(getattr(agent, "cleanup_confirmed", False)),
            "held_process_cleanup_confirmed": held_process_closed,
            "socket_disappearance_confirmed": socket_absent,
            "stage2_tool_digests_matched_c6_custody": True,
        },
    }


_LIFECYCLE_PROGRESS_FIELDS = (
    "start_returned",
    "live_check_returned",
    "close_returned",
    "cleanup_confirmed",
    "closed_observation_returned",
)


def _new_lifecycle_progress() -> dict[str, bool]:
    return dict.fromkeys(_LIFECYCLE_PROGRESS_FIELDS, False)


def _lifecycle_cleanup_confirmed(progress: Mapping[str, object]) -> bool:
    return all(progress.get(field) is True for field in _LIFECYCLE_PROGRESS_FIELDS)


def _remove_lifecycle_workspace(
    workspace: WorkspaceBinding,
    progress: Mapping[str, bool],
    *,
    closed_observation_returned: bool = False,
    allow_empty_private_keys_dir: bool = False,
) -> None:
    lifecycle_progress = {
        **progress,
        "closed_observation_returned": closed_observation_returned,
    }
    allow_private_keys_cleanup = (
        allow_empty_private_keys_dir is True
        and _lifecycle_cleanup_confirmed(lifecycle_progress)
    )
    try:
        _remove_fresh_workspace(
            workspace,
            allow_empty_private_keys_dir=allow_private_keys_cleanup,
        )
    except FixtureError as error:
        detail = dict(error.sanitized_detail) if error.sanitized_detail is not None else {}
        detail["lifecycle_progress"] = lifecycle_progress
        raise FixtureError(
            error.code,
            retained_custody=error.retained_custody,
            retained_root=error.retained_root,
            sanitized_detail=detail,
        ) from error


def run_lifecycle(
    spec: FixtureSpec,
    facts: dict[str, Any],
    job_parent: Path,
    *,
    module_loader: Callable[[FixtureSpec], Any] = _load_owned_agent,
    support_checker: Callable[[], None] = check_native_support,
    fixture_seam: bool = False,
) -> dict[str, Any]:
    """Run only the owned-agent lifetime; fixture substitutions never admit."""
    facts_summary = validate_measured_facts(facts, spec)
    if not fixture_seam and facts.get("execution_mode") != "hosted-native":
        raise FixtureError("NATIVE_FACTS_REQUIRED")
    support_checker()
    module = module_loader(spec)
    workspace = _fresh_workspace(job_parent)
    progress = _new_lifecycle_progress()
    try:
        agent = module.OwnedGpgAgent(workspace.home, workspace.root)
    except BaseException as error:
        _remove_lifecycle_workspace(workspace, progress)
        raise FixtureError("AGENT_CONSTRUCTOR_FAILED") from error

    primary: BaseException | None = None
    cleanup: BaseException | None = None
    try:
        agent.start()
        progress["start_returned"] = True
        agent.require_live()
        progress["live_check_returned"] = True
    except BaseException as error:
        primary = error
    finally:
        try:
            agent.close()
            progress["close_returned"] = True
        except BaseException as error:
            cleanup = error

    progress["cleanup_confirmed"] = getattr(agent, "cleanup_confirmed", False) is True
    if cleanup is not None or not progress["cleanup_confirmed"]:
        _close_workspace_binding(workspace)
        raise FixtureError("CUSTODY_RETAINED", retained_custody=True, retained_root=workspace.root) from cleanup or primary
    if primary is not None:
        _remove_lifecycle_workspace(workspace, progress)
        raise FixtureError("LIFECYCLE_FAILED") from primary
    try:
        observation = _closed_agent_observation(agent, workspace, fixture_seam, facts_summary)
    except FixtureError:
        _close_workspace_binding(workspace)
        raise
    _remove_lifecycle_workspace(
        workspace,
        progress,
        closed_observation_returned=True,
        allow_empty_private_keys_dir=_lifecycle_cleanup_confirmed(
            {**progress, "closed_observation_returned": True}
        ),
    )
    observation["cleanup"]["workspace_removed_confirmed"] = True
    tool_facts_out = dict(facts_summary)
    tool_facts_out["stage2_tool_digests_matched_c6_custody"] = (
        "not-observed" if fixture_seam else observation["cleanup"]["stage2_tool_digests_matched_c6_custody"]
    )
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "fixture-substituted-complete" if fixture_seam else "native-lifecycle-complete",
        "evidence_class": "fixture-only-substituted" if fixture_seam else "native-unqualified",
        "native_execution_observed": not fixture_seam,
        "production_authority": False,
        "canonical_commit": spec.canonical_commit,
        "target": {
            "gnupg_version": spec.target_gnupg_version,
            "agent_mode": spec.target_agent_mode,
            "rpm_version": spec.target_rpm_version,
        },
        "gpgconf_binding": observation["gpgconf_binding"],
        "cleanup": observation["cleanup"],
        "tool_facts": tool_facts_out,
        "key_material": "not-used",
        "rpm_slice": "not-exercised",
    }


def _write_json_output(path_str: str | None, payload: Mapping[str, Any], label: str) -> None:
    if not path_str:
        return
    target = _absolute_path(path_str, label)
    try:
        target.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except OSError as error:
        raise FixtureError(f"{label.upper().replace(' ', '_')}_WRITE") from error


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authenticate-stage1", action="store_true", help="authenticate Stage 1 source, catalogs, and manifest without native execution")
    parser.add_argument("--measure-stage2", action="store_true", help="measure Stage 2 container tool facts and C6 preconditions before any agent start")
    parser.add_argument("--execute-native", action="store_true", help="explicit parent-authorized native lifecycle option")
    parser.add_argument("--manifest", default=str(Path(__file__).with_name("manifest.json")))
    parser.add_argument("--facts", default=None, help="supplied non-secret tool/image facts JSON")
    parser.add_argument("--job-parent", default=None, help="existing private mode-0700 parent for one fresh job root")
    parser.add_argument("--out", default=None, help="optional absolute output path for Stage 1 authentication JSON")
    parser.add_argument("--metadata-out", default=None, help="optional absolute output path for Stage 2 metadata JSON")
    parser.add_argument("--facts-out", default=None, help="optional absolute output path for Stage 2 measured facts JSON")
    parser.add_argument("--receipt-out", default=None, help="optional absolute output path for lifecycle receipt JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    selected_modes = int(bool(args.authenticate_stage1)) + int(bool(args.measure_stage2)) + int(bool(args.execute_native))
    if selected_modes == 0:
        print(json.dumps({"schema": RECEIPT_SCHEMA, "status": "refused",
                          "error_code": "NATIVE_EXECUTION_EXPLICIT_REQUIRED", "production_authority": False}, sort_keys=True))
        return 2
    if selected_modes > 1:
        print(json.dumps({"schema": RECEIPT_SCHEMA, "status": "refused",
                          "error_code": "MUTUALLY_EXCLUSIVE_MODE_FLAGS", "production_authority": False}, sort_keys=True))
        return 2

    if args.authenticate_stage1:
        try:
            stage1_receipt = authenticate_stage1(args.manifest)
            _write_json_output(args.out, stage1_receipt, "stage1 out")
        except FixtureError as error:
            failure = {"schema": STAGE1_AUTH_SCHEMA, "status": "failed-closed", "error_code": error.code,
                       "production_authority": False, "native_execution_observed": False}
            try:
                _write_json_output(args.out, failure, "stage1 out")
            except FixtureError:
                pass
            print(json.dumps(failure, sort_keys=True))
            return 2
        except Exception:
            failure = {"schema": STAGE1_AUTH_SCHEMA, "status": "failed-closed", "error_code": "STAGE1_AUTH_FAILED",
                       "production_authority": False, "native_execution_observed": False}
            print(json.dumps(failure, sort_keys=True))
            return 2
        print(json.dumps(stage1_receipt, sort_keys=True))
        return 0

    if args.measure_stage2:
        if not args.job_parent:
            print(json.dumps({"schema": STAGE2_METADATA_SCHEMA, "status": "refused",
                              "error_code": "STAGE2_JOB_PARENT_REQUIRED", "production_authority": False}, sort_keys=True))
            return 2
        try:
            spec = load_manifest(args.manifest)
            parent = _validate_job_parent(args.job_parent)
            metadata_receipt, facts_payload = measure_stage2_metadata(spec, parent)
            _write_json_output(args.facts_out, facts_payload, "facts out")
            _write_json_output(args.metadata_out, metadata_receipt, "metadata out")
        except FixtureError as error:
            failure = {"schema": STAGE2_METADATA_SCHEMA, "status": "failed-closed", "error_code": error.code,
                       "production_authority": False, "native_agent_started": False,
                       "custody_retained": error.retained_custody}
            if error.sanitized_detail is not None:
                failure["sanitized_cleanup"] = error.sanitized_detail
            try:
                _write_json_output(args.metadata_out, failure, "metadata out")
            except FixtureError:
                pass
            print(json.dumps(failure, sort_keys=True))
            return 2
        except Exception:
            failure = {"schema": STAGE2_METADATA_SCHEMA, "status": "failed-closed",
                       "error_code": "STAGE2_METADATA_FAILED", "production_authority": False,
                       "native_agent_started": False, "custody_retained": True}
            print(json.dumps(failure, sort_keys=True))
            return 2
        print(json.dumps(metadata_receipt, sort_keys=True))
        return 0

    if not args.facts or not args.job_parent:
        print(json.dumps({"schema": RECEIPT_SCHEMA, "status": "refused",
                          "error_code": "NATIVE_INPUTS_REQUIRED", "production_authority": False}, sort_keys=True))
        return 2
    try:
        spec = load_manifest(args.manifest)
        facts = _read_json(_absolute_path(args.facts, "facts"), "facts")
        check_native_support()
        parent = _validate_job_parent(args.job_parent)
        receipt = run_lifecycle(spec, dict(facts), parent)
        _write_json_output(args.receipt_out, receipt, "receipt out")
    except FixtureError as error:
        failure = {"schema": RECEIPT_SCHEMA, "status": "failed-closed", "error_code": error.code,
                   "production_authority": False, "custody_retained": error.retained_custody}
        if error.sanitized_detail is not None:
            failure["sanitized_cleanup"] = error.sanitized_detail
        try:
            _write_json_output(args.receipt_out, failure, "receipt out")
        except FixtureError:
            pass
        print(json.dumps(failure, sort_keys=True))
        return 2
    except Exception:
        failure = {"schema": RECEIPT_SCHEMA, "status": "failed-closed",
                   "error_code": "FIXTURE_PREPARATION_FAILED", "production_authority": False,
                   "custody_retained": True}
        print(json.dumps(failure, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
