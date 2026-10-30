"""Closed Linux GUI controller derived from the reviewed P predicate helper.

This controller is preparation-only.  It never accepts a caller-selected
application PID or a numeric signal target.  The Node owner binds the monitor
and the Python controller keeps pidfds, executable descriptors and the P3
watchdog lease until the transaction is complete.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time
from typing import Any


SCHEMA = "theme-forge.p-native-gui-controller.v1"
LIMIT = 65_536
SIGNAL_TRANSACTION_BUDGET_SECONDS = 35
RECEIPT_LIMIT = 4 * 1024 * 1024
HEX64 = set("0123456789abcdef")
HEX32 = set("0123456789abcdef")
PREDICATE_SOURCE_HASH = "5c642cc3eed380324d3109a9a428be020ed529774f5c4f5877bb2bb1b93ac93f"
TARGETS = {
    ("linux-arm64", "B"): "aarch64-unknown-linux-gnu",
    ("linux-x64", "C"): "x86_64-unknown-linux-gnu",
    ("linux-x64", "C-signal"): "x86_64-unknown-linux-gnu",
}


class Refusal(RuntimeError):
    """A closed contract or observed process predicate was not satisfied."""


def require(value: Any, reason: str) -> None:
    if not value:
        raise Refusal(reason)


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value}")


def parse_json(raw: bytes, label: str, maximum: int = LIMIT) -> Any:
    require(len(raw) <= maximum, f"{label} exceeds bound")
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise Refusal(f"invalid {label}") from error


def _text(value: Any, label: str) -> str:
    require(isinstance(value, str) and value and "\x00" not in value, f"{label} must be nonempty text")
    require(all(ord(char) >= 0x20 and ord(char) != 0x7F for char in value), f"{label} contains control text")
    return value


def _hex(value: Any, label: str) -> str:
    value = _text(value, label)
    require(len(value) == 64 and set(value) <= HEX64, f"{label} must be SHA-256")
    return value


def _nonce(value: Any, label: str = "nonce") -> str:
    value = _text(value, label)
    require(len(value) == 32 and set(value) <= HEX32, f"{label} must be 128-bit lowercase hex")
    return value


def _path(value: Any, label: str) -> str:
    value = _text(value, label)
    require(value.startswith("/") and "/../" not in value and not value.endswith("/.."), f"{label} path")
    return value


def _positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be positive integer")
    return value


def _identity(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"}, f"{label} fields")
    return {"path": _path(value["path"], f"{label}.path"),
            "sha256": _hex(value["sha256"], f"{label}.sha256"),
            "size": _positive_int(value["size"], f"{label}.size")}


def validate_bind_message(message: Any) -> dict[str, Any]:
    """Validate the only caller-to-controller bind message."""
    require(isinstance(message, dict), "bind message object")
    fields = {"schema", "op", "nonce", "nodePid", "monitorPid", "monitor", "application",
              "predicateHelper", "source", "platform", "scenario", "receiptPath", "launchBindingSha256"}
    require(set(message) == fields, "bind message fields")
    require(message["schema"] == SCHEMA and message["op"] == "bind", "bind message schema")
    nonce = _nonce(message["nonce"])
    node_pid = _positive_int(message["nodePid"], "nodePid")
    monitor_pid = _positive_int(message["monitorPid"], "monitorPid")
    monitor = message["monitor"]
    require(isinstance(monitor, dict) and set(monitor) == {"executable", "argv"}, "monitor fields")
    monitor_executable = _identity(monitor["executable"], "monitor.executable")
    argv = monitor["argv"]
    require(isinstance(argv, list) and 0 < len(argv) <= 8192, "monitor argv")
    argv = [_text(value, "monitor argv item") for value in argv]
    application = _identity(message["application"], "application")
    predicate = _identity(message["predicateHelper"], "predicate helper")
    source = message["source"]
    require(isinstance(source, dict) and set(source) == {"pCommit", "pTree", "nebularCommit", "nebularTree"}, "source fields")
    for key in source:
        value = _text(source[key], key)
        require(len(value) == 40 and set(value) <= HEX64, f"{key} must be Git SHA")
    platform = _text(message["platform"], "platform")
    scenario = _text(message["scenario"], "scenario")
    require((platform, scenario) in TARGETS, "Linux GUI scenario/platform")
    receipt_path = _path(message["receiptPath"], "receiptPath")
    launch_binding = _hex(message["launchBindingSha256"], "launchBindingSha256")
    return {"schema": SCHEMA, "op": "bind", "nonce": nonce, "nodePid": node_pid, "monitorPid": monitor_pid,
            "monitor": {"executable": monitor_executable, "argv": argv},
            "application": application, "predicateHelper": predicate, "source": dict(source),
            "platform": platform, "scenario": scenario, "receiptPath": receipt_path,
            "launchBindingSha256": launch_binding}


def validate_command(message: Any, operation: str, expected_nonce: str | None = None) -> dict[str, Any]:
    require(isinstance(message, dict) and message.get("schema") == SCHEMA and message.get("op") == operation,
            f"{operation} message schema")
    nonce = _nonce(message.get("nonce"))
    if expected_nonce is not None:
        require(nonce == expected_nonce, "controller nonce changed")
    if operation == "terminate":
        require(set(message) == {"schema", "op", "nonce", "scenario"}, "terminate fields")
        return {"schema": SCHEMA, "op": operation, "nonce": nonce, "scenario": _text(message["scenario"], "scenario")}
    if operation == "finalize":
        require(set(message) == {"schema", "op", "nonce", "monitorExit"}, "finalize fields")
        exit_value = message["monitorExit"]
        require(isinstance(exit_value, dict) and set(exit_value) == {"code", "signal"}, "monitor exit fields")
        code = exit_value["code"]
        sig = exit_value["signal"]
        require(code is None or type(code) is int, "monitor exit code")
        require(sig is None or isinstance(sig, str), "monitor exit signal")
        return {"schema": SCHEMA, "op": operation, "nonce": nonce,
                "monitorExit": {"code": code, "signal": sig}}
    raise Refusal("unsupported controller operation")


def _regular_digest(path: Path) -> tuple[dict[str, Any], bytes]:
    """Read a bounded held sibling without following a symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "predicate helper is not a regular file")
        require(info.st_size <= LIMIT * 8, "predicate helper exceeds bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(LIMIT, LIMIT * 8 - total + 1))
            if not chunk:
                break
            total += len(chunk)
            require(total <= LIMIT * 8, "predicate helper read exceeds bound")
            chunks.append(chunk)
        data = b"".join(chunks)
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}, data
    finally:
        os.close(fd)


def _stable_module(expected: dict[str, Any]) -> Any:
    """Load the exact P3 helper copied beside this derived controller."""
    sibling = Path(__file__).with_name("p-process-predicate-probe.py")
    require(sibling.is_file() and not sibling.is_symlink(), "predicate helper sibling is missing")
    helper = sibling.resolve()
    actual, data = _regular_digest(helper)
    require(expected == actual, "predicate helper binding changed")
    require(hashlib.sha256(data).hexdigest() == expected["sha256"], "predicate helper digest")
    spec = importlib.util.spec_from_file_location("p_process_predicate_probe", helper)
    require(spec is not None and spec.loader is not None, "verified predicate helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(getattr(module, "SOURCE_HASH", None) == PREDICATE_SOURCE_HASH, "predicate helper runtime contract")
    return module


def _read_regular_receipt(path: str) -> tuple[bytes, int]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "receipt is not a private regular file")
        require(info.st_size <= RECEIPT_LIMIT, "receipt exceeds bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(LIMIT, RECEIPT_LIMIT - total + 1))
            if not chunk:
                break
            total += len(chunk)
            require(total <= RECEIPT_LIMIT, "receipt read exceeds bound")
            chunks.append(chunk)
        return b"".join(chunks), info.st_mode & 0o777
    finally:
        os.close(fd)


def _receipt(path: str, scenario: str, target: str, app_pid: int, app_sha: str) -> dict[str, Any]:
    data, mode = _read_regular_receipt(path)
    require(mode == 0o600, "receipt mode")
    value = parse_json(data, "application receipt", RECEIPT_LIMIT)
    require(isinstance(value, dict), "receipt object")
    require(value.get("schema") == "nebular.release-smoke-receipt-v1", "receipt schema")
    require(value.get("scenario") == scenario and value.get("target") == target, "receipt target/scenario")
    require(value.get("pid") == app_pid, "receipt PID is not the independently bound application")
    require(isinstance(value.get("executable"), dict) and value["executable"].get("sha256") == app_sha,
            "receipt executable identity")
    require(value.get("awaitingSignal") is True, "C-signal receipt readiness")
    return value


class GuiSession:
    """One owned monitor/application identity and optional C-signal witness."""

    def __init__(self, config: dict[str, Any], stable: Any):
        self.config = config
        self.stable = stable
        self.view = stable.ProcView()
        self.handles: list[int] = []
        self.monitor: dict[str, Any] | None = None
        self.application: dict[str, Any] | None = None
        self.monitor_fd: int | None = None
        self.application_fd: int | None = None
        self.monitor_executable_fd: int | None = None
        self.application_executable_fd: int | None = None
        self.credentials: dict[str, Any] | None = None
        self.lease: Any = None
        self.witness: dict[str, Any] | None = None
        self.completed = False
        self.finalization_deadline = None

    def _monitor_ready(self) -> bool:
        """Poll the same owned process through the wrapper-to-Bubblewrap exec."""
        pid = self.monitor["pid"]
        current = self.stable.assert_fixed(self.view, self.monitor)
        require(current["ppid"] == self.config["nodePid"], "monitor parent changed before exec")
        expected = self.config["monitor"]["executable"]
        actual, fd = self.view.executable(pid)
        try:
            if actual["size"] != expected["size"] or actual["sha256"] != expected["sha256"]:
                return False
            observed_path = os.readlink("exe", dir_fd=self.view.directory(pid))
            if os.path.realpath(observed_path) != os.path.realpath(expected["path"]):
                return False
            expected_cmdline = b"\0".join(os.fsencode(item) for item in self.config["monitor"]["argv"]) + b"\0"
            if self.view.read(pid, "cmdline") != expected_cmdline:
                return False
            require(self.stable.assert_fixed(self.view, self.monitor)["ppid"] == self.config["nodePid"],
                    "monitor changed during exec bind")
            self.monitor_executable_fd = fd
            self.handles.append(fd)
            fd = None
            return True
        finally:
            if fd is not None:
                os.close(fd)

    def _direct_children(self, pid: int) -> list[int]:
        parent_fd = self.view.directory(pid)
        task_fd = os.open("task", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            leader_fd = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=task_fd)
            try:
                child_fd = os.open("children", os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=leader_fd)
                try:
                    raw = os.read(child_fd, 4097)
                finally:
                    os.close(child_fd)
            finally:
                os.close(leader_fd)
        finally:
            os.close(task_fd)
        require(len(raw) <= LIMIT, "direct child list bound")
        values = raw.decode("ascii").split()
        require(len(values) <= 32 and all(item.isdigit() for item in values), "direct child list framing")
        return [int(item) for item in values]

    def _discover_application(self) -> dict[str, Any] | None:
        expected = self.config["application"]
        matches = []
        for pid in self._direct_children(self.monitor["pid"]):
            scan = self.stable.ProcView(self.view.root)
            try:
                snapshot = scan.snapshot(pid)
                actual, fd = scan.executable(pid)
                try:
                    if actual["size"] != expected["size"] or actual["sha256"] != expected["sha256"]:
                        continue
                finally:
                    os.close(fd)
                status = scan.status(pid)
                require(status["Uid"] == self.credentials["Uid"] and status["Gid"] == self.credentials["Gid"], "application credentials changed")
                require(scan.namespace(pid) == self.view.namespace(self.monitor["pid"]), "application namespace changed")
                matches.append((snapshot, scan.threads(pid)))
            except (FileNotFoundError, ProcessLookupError):
                continue
            finally:
                scan.close()
        require(len(matches) <= 1, "ambiguous raw GUI application child")
        return matches[0][0] if matches and matches[0][1] >= 2 else None

    def _live_executable_matches(self, process: dict[str, Any], held_fd: int, snapshot: dict[str, Any]) -> None:
        if snapshot["state"] == "Z":
            # An exited group leader has no /proc exe. Its held pidfd death
            # and stable start identity, rather than an executable reopen,
            # are the relevant witness at this point.
            selected = self.application_fd if process is self.application else self.monitor_fd
            require(bool(select.select([selected], [], [], 0)[0]), "zombie pidfd not readable")
            return
        actual, live_fd = self.view.executable(process["pid"])
        try:
            require(actual == self.stable.opened_identity(held_fd), "live executable identity changed")
            self.stable.assert_fixed(self.view, process)
        finally:
            os.close(live_fd)

    def _revalidate_handles(self, *, require_app: bool = True) -> None:
        require(self.monitor_fd is not None and self.monitor is not None and self.monitor_executable_fd is not None, "monitor handle missing")
        self.stable.pidfd_target(self.view, self.monitor_fd, self.monitor["pid"])
        monitor_state = self.stable.assert_fixed(self.view, self.monitor)
        self._live_executable_matches(self.monitor, self.monitor_executable_fd, monitor_state)
        monitor = self.stable.opened_identity(self.monitor_executable_fd)
        expected_monitor = self.config["monitor"]["executable"]
        require(monitor["size"] == expected_monitor["size"] and monitor["sha256"] == expected_monitor["sha256"], "monitor bytes changed")
        if require_app:
            require(self.application_fd is not None and self.application is not None and self.application_executable_fd is not None, "application handle missing")
            self.stable.pidfd_target(self.view, self.application_fd, self.application["pid"])
            application_state = self.stable.assert_fixed(self.view, self.application)
            self._live_executable_matches(self.application, self.application_executable_fd, application_state)
            application = self.stable.opened_identity(self.application_executable_fd)
            expected_app = self.config["application"]
            require(application["size"] == expected_app["size"] and application["sha256"] == expected_app["sha256"], "application bytes changed")

    def _response(self, operation: str, **fields: Any) -> dict[str, Any]:
        return {"op": operation, "schema": SCHEMA, "nonce": self.config["nonce"], "accepted": True,
                "application": self._process(self.application, self.application_executable_fd),
                "monitor": self._process(self.monitor, self.monitor_executable_fd),
                "source": self.config["source"], "launchBindingSha256": self.config["launchBindingSha256"],
                "target": TARGETS[(self.config["platform"], self.config["scenario"])], **fields}

    def heartbeat(self) -> None:
        if self.lease is None:
            require(self.witness is None and self.finalization_deadline is None, "unarmed watchdog state")
            return
        if self.lease.write is None:
            require(self.witness is not None and self.finalization_deadline is not None,
                    "unexpected disarmed watchdog state")
            require(time.monotonic() < self.finalization_deadline, "finalization deadline")
        else:
            self.lease.pulse()

    def _lease_proof(self) -> dict[str, Any] | None:
        if self.lease is None:
            require(self.config["scenario"] != "C-signal", "signal watchdog lease missing")
            return None
        return {"acknowledgements": list(self.lease.acknowledgements), "nonceSha256": hashlib.sha256(self.lease.nonce.encode()).hexdigest(), "rescue": False}

    def _process(self, process: dict[str, Any], executable_fd: int) -> dict[str, Any]:
        return {"pid": process["pid"], "start": process["start"], "executable": self.stable.opened_identity(executable_fd)}

    def bind(self) -> dict[str, Any]:
        config = self.config
        require(os.getppid() == config["nodePid"], "controller is not Node's sibling")
        snapshot = self.view.snapshot(config["monitorPid"])
        require(snapshot["ppid"] == config["nodePid"], "monitor parent is not Node")
        self.monitor = {"pid": snapshot["pid"], "start": snapshot["start"]}
        monitor_fd = os.pidfd_open(config["monitorPid"])
        self.handles.append(monitor_fd)
        self.stable.pidfd_target(self.view, monitor_fd, self.monitor["pid"])
        self.stable.wait_until(self._monitor_ready, time.monotonic() + 10)
        self.monitor_fd = monitor_fd
        self.credentials = self.view.status(self.monitor["pid"])
        require(self.credentials["Uid"] == (os.getuid(),) * 4 and self.credentials["Gid"] == (os.getgid(),) * 4, "monitor credentials")
        require(self.view.threads(self.monitor["pid"]) == 1, "monitor must be single-threaded")
        require(self.view.namespace(self.monitor["pid"]) == self.view.namespace(os.getpid()), "monitor PID namespace")
        expected_cmdline = b"\0".join(os.fsencode(item) for item in config["monitor"]["argv"]) + b"\0"
        require(self.view.read(self.monitor["pid"], "cmdline") == expected_cmdline, "monitor argv identity")
        require(self.stable.assert_fixed(self.view, self.monitor)["ppid"] == config["nodePid"], "monitor changed during bind")
        self.application = self.stable.wait_until(self._discover_application, time.monotonic() + 10)
        self.application_fd = os.pidfd_open(self.application["pid"])
        self.handles.append(self.application_fd)
        self.stable.pidfd_target(self.view, self.application_fd, self.application["pid"])
        live, self.application_executable_fd = self.view.executable(self.application["pid"])
        self.handles.append(self.application_executable_fd)
        expected = config["application"]
        require(live["size"] == expected["size"] and live["sha256"] == expected["sha256"], "live GUI bytes changed")
        require(self.stable.assert_fixed(self.view, self.application)["ppid"] == self.monitor["pid"], "application parent changed")
        self._revalidate_handles()
        require(self.lease is None, "bind must not arm a signal watchdog")
        self.bound = True
        return self._response("BOUND")

    def terminate(self) -> dict[str, Any]:
        operation_epoch = time.monotonic()
        require(self.bound and self.config["scenario"] == "C-signal", "C-signal binding required")
        _receipt(self.config["receiptPath"], self.config["scenario"], TARGETS[(self.config["platform"], self.config["scenario"])], self.application["pid"], self.config["application"]["sha256"])
        require(self.lease is None, "signal watchdog already armed")
        self._revalidate_handles()
        lease_epoch = time.monotonic()
        self.lease = self.stable.Lease(sys.executable, self.config["predicateHelper"]["path"], self.view,
            self.monitor_fd, self.monitor, lease_epoch,
            cleanup=(self.application_fd, {"pid": self.application["pid"], "start": self.application["start"]}))
        require(self.lease.acknowledgements and self.lease.acknowledgements[0]["op"] == "ARMED",
                "watchdog did not acknowledge before stop")
        epoch = time.monotonic()
        self.stable.send(self.view, self.monitor_fd, self.monitor, signal.SIGSTOP)
        self.stable.wait_until(lambda: self.stable.assert_fixed(self.view, self.monitor)["state"] == "T", epoch + 2, self.lease.pulse)
        self.stable.recheck_stopped_identity(self.view, self.monitor, self.application, self.config["nodePid"], self.credentials)
        t0 = time.monotonic()
        require(t0 < epoch + 2, "STOP prephase budget")
        self._revalidate_handles()
        self.stable.send(self.view, self.application_fd, self.application, signal.SIGTERM)
        self.stable.wait_until(lambda: bool(select.select([self.application_fd], [], [], 0)[0]), t0 + 24, self.lease.pulse)
        before = self.stable.assert_fixed(self.view, self.monitor)
        first = self.stable.assert_fixed(self.view, self.application)
        second = self.stable.assert_fixed(self.view, self.application)
        after = self.stable.assert_fixed(self.view, self.monitor)
        self.witness = self.stable.zombie_witness(before, first, second, after, self.application, self.monitor)
        cont_deadline = min(t0 + 29, time.monotonic() + 4)
        self._revalidate_handles(require_app=False)
        self.stable.send(self.view, self.monitor_fd, self.monitor, signal.SIGCONT)
        self.stable.wait_until(lambda: self.stable.resumed_or_exited(self.view, self.monitor_fd, self.monitor), cont_deadline, self.lease.pulse)
        self.stable.wait_until(lambda: bool(select.select([self.monitor_fd], [], [], 0)[0]), cont_deadline, self.lease.pulse)
        self.lease.disarm(self.witness, "exited")
        self.finalization_deadline = time.monotonic() + 5
        require(time.monotonic() < t0 + 30, "composed signal budget")
        require(time.monotonic() < lease_epoch + 35, "watchdog transaction budget")
        response = self._response("TERMINATED", witness=self.witness, watchdog=self._lease_proof())
        self.heartbeat()
        require(time.monotonic() < operation_epoch + SIGNAL_TRANSACTION_BUDGET_SECONDS, "complete signal transaction budget")
        return response

    def finalize(self, monitor_exit: dict[str, Any]) -> dict[str, Any]:
        require(self.bound, "GUI session not bound")
        scenario = self.config["scenario"]
        self.heartbeat()
        if scenario == "C-signal":
            require(self.witness is not None and monitor_exit == {"code": 143, "signal": None}, "C-signal finalization")
        else:
            require(monitor_exit == {"code": 0, "signal": None}, "ordinary finalization")
        require(bool(select.select([self.application_fd], [], [], 0)[0]), "application did not exit")
        if scenario != "C-signal":
            require(self.lease is None, "ordinary scenario unexpectedly armed a watchdog")
        response = self._response("FINALIZED", monitorExit=monitor_exit,
                              witness=self.witness if scenario == "C-signal" else None,
                              watchdog=self._lease_proof(),
                              cleanup={"application": "exited", "controller": "closed", "monitor": "node-waited"})
        self.heartbeat()
        self.completed = True
        return response

    def close(self) -> None:
        errors = []
        if not self.completed:
            identity_valid = False
            try:
                self._revalidate_handles(require_app=True)
                identity_valid = True
            except Exception as error:
                errors.append(type(error).__name__)
            if identity_valid:
                try:
                    errors.extend(self.stable.cleanup_bound(self.monitor_fd, self.application_fd, self.lease, False))
                except Exception as error:
                    errors.append(type(error).__name__)
            elif self.lease is not None and self.lease.write is not None:
                # Never issue direct cleanup signals after role revalidation failed.
                # Closing the existing lease invokes the qualified watchdog's
                # fail-only rescue on its inherited handles and fixed identities.
                # The identity failure remains fatal regardless of rescue.
                try:
                    self.lease.fail()
                except Exception as error:
                    errors.append(type(error).__name__)
        elif self.lease is not None and self.lease.write is not None:
            errors.append("UndisarmedLease")
        for fd in reversed(self.handles):
            try:
                os.close(fd)
            except OSError as error:
                errors.append(type(error).__name__)
        try:
            self.view.close()
        except OSError as error:
            errors.append(type(error).__name__)
        require(not errors, "exact GUI cleanup failed")


def _write(stream_out, response: dict[str, Any]) -> None:
    stream_out.write(json.dumps(response, separators=(",", ":")) + "\n")
    stream_out.flush()


def run_controller(stream_in, stream_out) -> int:
    raw = stream_in.buffer.readline(LIMIT + 1)
    require(raw and len(raw) <= LIMIT and raw.endswith(b"\n"), "bind framing")
    config = validate_bind_message(parse_json(raw, "bind message"))
    stable = _stable_module(config["predicateHelper"])
    session = GuiSession(config, stable)
    fd = stream_in.buffer.fileno()
    try:
        _write(stream_out, session.bind())
        while True:
            session.heartbeat()
            if not select.select([fd], [], [], 0.25)[0]:
                continue
            raw = stream_in.buffer.readline(LIMIT + 1)
            require(raw and len(raw) <= LIMIT and raw.endswith(b"\n"), "controller framing/EOF")
            message = parse_json(raw, "controller command")
            operation = message.get("op") if isinstance(message, dict) else None
            if operation == "terminate":
                command = validate_command(message, "terminate", config["nonce"])
                require(command["scenario"] == config["scenario"], "terminate scenario changed")
                _write(stream_out, session.terminate())
            elif operation == "finalize":
                normalized = validate_command(message, "finalize", config["nonce"])
                _write(stream_out, session.finalize(normalized["monitorExit"]))
                return 0
            else:
                raise Refusal("unexpected controller operation")
    finally:
        session.close()


if __name__ == "__main__":
    if sys.argv[1:2] != ["controller"]:
        raise SystemExit("controller mode required")
    try:
        raise SystemExit(run_controller(sys.stdin, sys.stdout))
    except (Refusal, OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        sys.stderr.write(f"P GUI controller refused: {type(error).__name__}\n")
        raise SystemExit(1)
