"""PENDING test policy: Linux monitor/application predicate, never GUI acceptance.

Local tests inject ProcView and pidfd operations. Only the hosted `run` mode may
observe real procfs or signal native processes. There is no numeric-kill fallback.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import threading
import time

LIMIT = 65536
SOURCE_HASH = "5c642cc3eed380324d3109a9a428be020ed529774f5c4f5877bb2bb1b93ac93f"
FIELDS = {"ARM": {"op", "nonce", "seq", "epoch", "deadline"},
          "HEARTBEAT": {"op", "nonce", "seq"},
          "DISARM": {"op", "nonce", "seq", "identity", "witnessDigest", "resumeObservation"}}


class Refusal(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_stat(raw):
    """Linux proc_pid_stat(5), including embedded spaces and parentheses in comm."""
    require(len(raw) <= LIMIT and raw.endswith(b"\n"), "stat framing")
    left, right = raw.find(b" ("), raw.rfind(b") ")
    require(left > 0 and right > left, "stat comm framing")
    pid = int(raw[:left])
    tail = raw[right + 2:].split()
    require(len(tail) >= 50, "stat lacks field 52")
    state = tail[0].decode("ascii")
    require(len(state) == 1, "stat state")
    return {"pid": pid, "state": state, "ppid": int(tail[1]),
            "start": int(tail[19]), "exit_code": int(tail[49])}


def parse_status(raw):
    require(len(raw) <= LIMIT, "status bound")
    result = {}
    for row in raw.decode("ascii").splitlines():
        key, _, value = row.partition(":")
        if key in {"Tgid", "Pid", "TracerPid", "Uid", "Gid"}:
            require(key not in result, "duplicate status field")
            result[key] = tuple(int(x) for x in value.split())
    require(set(result) == {"Tgid", "Pid", "TracerPid", "Uid", "Gid"}, "status fields")
    require(all(len(result[k]) == 1 for k in ("Tgid", "Pid", "TracerPid")), "status arity")
    require(len(result["Uid"]) == len(result["Gid"]) == 4, "credential arity")
    require(result["Tgid"] == result["Pid"] and result["TracerPid"] == (0,), "leader/untraced required")
    return result


def parse_pidfd(raw):
    rows = [r.split(b":", 1)[1].strip() for r in raw.splitlines() if r.startswith(b"Pid:")]
    require(len(rows) == 1, "pidfd target field")
    return int(rows[0])


def stable_zombie_bracket(before, first, second, after, app, monitor):
    require(before["state"] == after["state"] == "T", "ordinary monitor STOP required")
    require(before["pid"] == after["pid"] == monitor["pid"] and
            before["start"] == after["start"] == monitor["start"], "monitor changed")
    keys = ("pid", "state", "ppid", "start", "exit_code")
    require(tuple(first[k] for k in keys) == tuple(second[k] for k in keys), "unstable zombie")
    require(first["state"] == "Z" and first["pid"] == app["pid"] and
            first["start"] == app["start"] and first["ppid"] == monitor["pid"], "wrong group-leader zombie")
    return {k: first[k] for k in keys}


def exact_sigterm(status):
    require(status == 15 and os.WIFSIGNALED(status) and os.WTERMSIG(status) == 15 and
            not os.WCOREDUMP(status), "not exact non-core SIGTERM 15")


def zombie_witness(before, first, second, after, app, monitor):
    witness = stable_zombie_bracket(before, first, second, after, app, monitor)
    exact_sigterm(witness["exit_code"])
    return witness


class Protocol:
    def __init__(self, nonce):
        self.nonce, self.seq, self.armed, self.closed = nonce, 0, False, False

    def receive(self, raw, now):
        require(not self.closed and len(raw) <= 4096 and raw.endswith(b"\n"), "protocol framing/closed")
        def pairs(values):
            out = {}
            for k, v in values:
                require(k not in out, "duplicate JSON field")
                out[k] = v
            return out
        item = json.loads(raw, object_pairs_hook=pairs)
        require(isinstance(item, dict) and item.get("op") in FIELDS, "unknown operation")
        require(set(item) == FIELDS[item["op"]], "closed protocol fields")
        require(item["nonce"] == self.nonce and type(item["seq"]) is int and item["seq"] == self.seq + 1, "nonce/sequence")
        require((not self.armed and item["op"] == "ARM") or
                (self.armed and item["op"] in {"HEARTBEAT", "DISARM"}), "protocol order")
        if item["op"] == "ARM":
            require(isinstance(item["epoch"], (int, float)) and item["deadline"] == item["epoch"] + 40 and
                    0 <= now - item["epoch"] < 2, "immutable lease")
            self.armed = True
        elif item["op"] == "DISARM":
            require(isinstance(item["identity"], dict) and set(item["identity"]) == {"pid", "start"}, "disarm identity")
            require(isinstance(item["witnessDigest"], str) and len(item["witnessDigest"]) == 64 and
                    item["resumeObservation"] in {"resumed", "exited"}, "disarm proof")
            self.closed = True
        self.seq += 1
        return item


class ProcView:
    """One opened proc directory per fixed identity; bounded relative reads only."""
    def __init__(self, root="/proc"):
        self.root = Path(root)
        self.fds = {}

    def close(self):
        for fd in self.fds.values():
            os.close(fd)
        self.fds.clear()

    def directory(self, pid):
        if pid not in self.fds:
            self.fds[pid] = os.open(self.root / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        return self.fds[pid]

    def read(self, pid, member):
        decimal_fdinfo = member.startswith("fdinfo/") and bool(member[7:]) and all("0" <= c <= "9" for c in member[7:])
        require(member in {"stat", "status", "cmdline", "task"} or decimal_fdinfo, "unsupported proc read")
        fd = os.open(member, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.directory(pid))
        try:
            data = os.read(fd, LIMIT + 1)
            require(len(data) <= LIMIT, "proc read bound")
            return data
        finally:
            os.close(fd)

    def snapshot(self, pid):
        return parse_stat(self.read(pid, "stat"))

    def status(self, pid):
        return parse_status(self.read(pid, "status"))

    def threads(self, pid):
        fd = os.open("task", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=self.directory(pid))
        try:
            entries = os.listdir(fd)
            require(len(entries) <= 1024 and all(x.isdigit() for x in entries), "task entries")
            return len(entries)
        finally:
            os.close(fd)

    def namespace(self, pid):
        return os.readlink("ns/pid", dir_fd=self.directory(pid))

    def executable(self, pid):
        fd = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=self.directory(pid))
        return opened_identity(fd), fd


def opened_identity(fd):
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode), "executable not regular")
    h = hashlib.sha256()
    offset = 0
    while True:
        data = os.pread(fd, 65536, offset)
        if not data:
            break
        h.update(data)
        offset += len(data)
        require(offset < 256 * 1024 * 1024, "exe size bound")
    return {"dev": st.st_dev, "ino": st.st_ino, "size": st.st_size, "sha256": h.hexdigest()}


def open_expected(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    return opened_identity(fd), fd


def assert_fixed(view, identity):
    now = view.snapshot(identity["pid"])
    require(now["pid"] == identity["pid"] and now["start"] == identity["start"], "fixed identity changed")
    return now


def pidfd_target(view, fd, pid):
    require(parse_pidfd(view.read(os.getpid(), "fdinfo/" + str(fd))) == pid, "inherited pidfd target mismatch")


def send(view, fd, identity, sig):
    assert_fixed(view, identity)
    pidfd_target(view, fd, identity["pid"])
    signal.pidfd_send_signal(fd, sig)


def resumed_or_exited(view, fd, identity):
    # Node owns wait/reaping. A readable original pidfd remains authoritative
    # after Node reaps the monitor and procfs/fdinfo no longer exposes its PID.
    try:
        return assert_fixed(view, identity)["state"] not in {"T", "t"}
    except (FileNotFoundError, ProcessLookupError):
        require(bool(select.select([fd], [], [], 0)[0]) and
                parse_pidfd(view.read(os.getpid(), "fdinfo/"+str(fd))) == -1,
                "monitor disappeared without held pidfd death")
        return True


def wait_until(check, deadline, pulse=lambda: None):
    while time.monotonic() < deadline:
        value = check()
        if value:
            require(time.monotonic() <= deadline, "bounded phase observation crossed deadline")
            return value
        pulse()
        time.sleep(.01)
    raise Refusal("bounded phase deadline")


def bounded_line(fd, deadline, maximum=4096):
    buf = b""
    while time.monotonic() < deadline:
        require(select.select([fd], [], [], max(0, deadline-time.monotonic()))[0], "FD response deadline")
        data = os.read(fd, maximum + 1 - len(buf))
        require(data, "FD response EOF")
        buf += data
        require(len(buf) <= maximum, "FD response bound")
        if b"\n" in buf:
            require(buf.endswith(b"\n") and buf.count(b"\n") == 1, "FD response framing")
            return buf
    raise Refusal("FD response deadline")


def watchdog(fd, life, nonce, identity, cleanup=None):
    os.set_inheritable(fd, False)
    os.set_inheritable(life, False)
    view, protocol, buf = ProcView(), Protocol(nonce), b""
    deadline, beat, armed = time.monotonic() + 2, time.monotonic(), False
    try:
        pidfd_target(view, fd, identity["pid"])
        assert_fixed(view, identity)
        if cleanup is not None:
            cleanupfd, application = cleanup
            os.set_inheritable(cleanupfd, False)
            pidfd_target(view, cleanupfd, application["pid"])
            require(assert_fixed(view, application)["ppid"] == identity["pid"], "cleanup app parent changed")
        while True:
            now = time.monotonic()
            require(now < deadline and now - beat < 2, "watchdog lease/heartbeat")
            if select.select([life], [], [], .05)[0]:
                data = os.read(life, 4097)
                require(data and len(buf) + len(data) <= 4096, "lifetime EOF/overflow")
                buf += data
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    item = protocol.receive(raw + b"\n", time.monotonic())
                    beat = time.monotonic()
                    if item["op"] == "ARM":
                        deadline, armed = item["deadline"], True
                        print(json.dumps({"op": "ARMED", "seq": item["seq"]}), flush=True)
                    elif item["op"] == "DISARM":
                        require(item["identity"] == identity, "disarm target changed")
                        require(resumed_or_exited(view, fd, identity), "monitor remains stopped")
                        print(json.dumps({"op": "DISARMED", "seq": item["seq"]}), flush=True)
                        return 0
    except (Refusal, OSError, ValueError, TypeError):
        # Fail-only rescue on the original inherited handle. Never reopen by PID.
        try:
            pidfd_target(view, fd, identity["pid"])
            signal.pidfd_send_signal(fd, signal.SIGCONT)
        except (OSError, Refusal):
            pass
        if cleanup is not None:
            # Controller-death negative exercise only: retain the original
            # application pidfd for bounded cleanup after monitor rescue.
            try:
                send(view, cleanup[0], cleanup[1], signal.SIGKILL)
            except (OSError, Refusal):
                pass
        print(json.dumps({"op": "RESCUED", "armed": armed}), flush=True)
        return 1
    finally:
        view.close()
        os.close(fd)
        os.close(life)
        if cleanup is not None:
            os.close(cleanup[0])


class Lease:
    def __init__(self, python, script, view, fd, identity, epoch, cleanup=None):
        self.view, self.fd, self.identity = view, fd, identity
        self.nonce, self.seq, self.last = os.urandom(24).hex(), 0, 0
        self.acknowledgements = []
        read, self.write = os.pipe()
        os.set_inheritable(read, False)
        os.set_inheritable(self.write, False)
        duplicate = os.dup(fd)
        cleanup_duplicate = os.dup(cleanup[0]) if cleanup is not None else None
        extra = ([str(cleanup_duplicate), str(cleanup[1]["pid"]), str(cleanup[1]["start"])]
                 if cleanup is not None else [])
        try:
            self.child = subprocess.Popen([python, "-I", "-S", script, "watchdog", str(duplicate), str(read),
                                           self.nonce, str(identity["pid"]), str(identity["start"]), *extra],
                                          pass_fds=(duplicate, read) + ((cleanup_duplicate,) if cleanup is not None else ()), stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                          close_fds=True, start_new_session=True)
        finally:
            os.close(duplicate)
            os.close(read)
            if cleanup_duplicate is not None:
                os.close(cleanup_duplicate)
        self.message("ARM", epoch=epoch, deadline=epoch + 40)
        self.ack("ARMED", time.monotonic() + 1)

    def message(self, op, **fields):
        self.seq += 1
        os.write(self.write, (json.dumps(dict(op=op, nonce=self.nonce, seq=self.seq, **fields)) + "\n").encode())
        self.last = time.monotonic()

    def pulse(self):
        require(self.child.poll() is None, "watchdog exited/rescued")
        if time.monotonic() - self.last > .25:
            self.message("HEARTBEAT")

    def ack(self, op, deadline):
        line = bounded_line(self.child.stdout.fileno(), deadline)
        require(json.loads(line) == {"op": op, "seq": self.seq}, "watchdog ack")
        self.acknowledgements.append(json.loads(line))

    def disarm(self, witness, resume):
        self.message("DISARM", identity=self.identity, witnessDigest=digest(json.dumps(witness, sort_keys=True).encode()),
                     resumeObservation=resume)
        self.ack("DISARMED", time.monotonic() + 1)
        os.close(self.write)
        self.write = None
        require(self.child.wait(timeout=1) == 0, "watchdog rescue invalidates pass")

    def fail(self):
        if self.write is not None:
            os.close(self.write)
            self.write = None
        self.child.wait(timeout=3)


def surrogate_thread():
    ready, stop = threading.Event(), threading.Event()
    def wait():
        ready.set()
        stop.wait()
    thread = threading.Thread(target=wait, daemon=True)
    thread.start()
    require(ready.wait(timeout=1), "surrogate worker readiness")
    return thread, stop


def surrogate(case):
    require(case in {"term", "normal143"}, "surrogate case")
    if case == "normal143":
        signal.signal(signal.SIGTERM, lambda *_: os._exit(143))
    surrogate_thread()
    while True:
        signal.pause()


def recheck_stopped_identity(view, monitor, app, node_pid, credentials):
    stopped = assert_fixed(view, monitor)
    require(stopped["state"] == "T" and stopped["ppid"] == node_pid and view.threads(monitor["pid"]) == 1,
            "stopped monitor identity/thread changed")
    require(assert_fixed(view, app)["ppid"] == monitor["pid"], "stopped application parent changed")
    status = view.status(app["pid"])  # parse_status independently rejects tracing and non-leaders.
    require(status["Uid"] == credentials["Uid"] and status["Gid"] == credentials["Gid"], "stopped application credentials changed")
    require(view.namespace(app["pid"]) == view.namespace(monitor["pid"]) == view.namespace(os.getpid()),
            "stopped application namespace changed")


def cleanup_bound(monfd, appfd, lease, completed):
    """Attempt every exact-handle step; callers re-raise only after closing FDs."""
    errors = []
    def attempt(action):
        try:
            action()
        except ProcessLookupError:
            pass
        except Exception as error:
            errors.append(type(error).__name__)
    if monfd is not None:
        attempt(lambda: signal.pidfd_send_signal(monfd, signal.SIGCONT))
    if lease is not None and lease.write is not None:
        attempt(lease.fail)
    if not completed:
        for fd in (appfd, monfd):
            if fd is not None:
                attempt(lambda fd=fd: signal.pidfd_send_signal(fd, signal.SIGKILL))
    return errors


def control_case(config):
    require(set(config) == {"argv", "bwrap", "pythonObject", "python", "script", "case", "nodePid", "monitorPid"},
            "closed controller contract fields")
    argv, expected_bwrap, expected_python = config["argv"], config["bwrap"], config["pythonObject"]
    python, script, case = config["python"], config["script"], config["case"]
    node_pid, monitor_pid = config["nodePid"], config["monitorPid"]
    require(type(node_pid) is int and type(monitor_pid) is int and node_pid > 1 and monitor_pid > 1,
            "controller identity types")
    require(case in {"term", "normal143", "controller-death"}, "closed controller case")
    require(os.getppid() == node_pid, "controller is not a Node sibling child")
    view, handles, lease, appfd = ProcView(), [], None, None
    monfd, app, monitor, completed = None, None, None, False
    try:
        epoch_discovery = time.monotonic()
        snapshot = view.snapshot(monitor_pid)
        require(snapshot["ppid"] == node_pid, "monitor/controller do not share Node parent")
        monitor = {k: snapshot[k] for k in ("pid", "start")}
        candidate_monitor_fd = os.pidfd_open(monitor_pid)
        handles.append(candidate_monitor_fd)
        pidfd_target(view, candidate_monitor_fd, monitor_pid)
        def monitor_ready():
            ident, fd = view.executable(monitor_pid)
            os.close(fd)
            return ident == expected_bwrap
        wait_until(monitor_ready, epoch_discovery + 10)
        credentials = view.status(monitor_pid)
        require(credentials["Uid"] == (os.getuid(),)*4 and credentials["Gid"] == (os.getgid(),)*4,
                "monitor credential mismatch")
        require(view.threads(monitor_pid) == 1 and view.namespace(monitor_pid) == view.namespace(os.getpid()), "monitor threads/namespace")
        require(view.read(monitor_pid, "cmdline") == b"\0".join(os.fsencode(x) for x in argv + ["normal143" if case == "normal143" else "term"]) + b"\0", "sealed monitor argv")
        require(assert_fixed(view, monitor)["ppid"] == node_pid, "monitor changed during bind")
        monfd = candidate_monitor_fd  # Only validated owned handles may control/cleanup.
        def discover():
            matches = []
            for entry in os.listdir(view.root):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                scan = ProcView(view.root)
                try:
                    snap = scan.snapshot(pid)
                    if snap["ppid"] != monitor_pid:
                        continue
                    actual, fd = scan.executable(pid)
                    os.close(fd)
                    if actual == expected_python:
                        require(scan.status(pid)["Uid"] == credentials["Uid"] and
                                scan.status(pid)["Gid"] == credentials["Gid"] and
                                scan.namespace(pid) == view.namespace(monitor_pid), "application credentials/namespace")
                        if scan.threads(pid) >= 2:
                            matches.append(snap)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                finally:
                    scan.close()
            require(len(matches) <= 1, "ambiguous direct application child")
            return matches[0] if matches else None
        app = wait_until(discover, epoch_discovery + 10)
        candidate_application_fd = os.pidfd_open(app["pid"])
        handles.append(candidate_application_fd)
        pidfd_target(view, candidate_application_fd, app["pid"])
        # Live executable is bound before death; no zombie exe read is required.
        live, livefd = view.executable(app["pid"])
        handles.append(livefd)
        require(live == expected_python, "live application exe changed")
        require(assert_fixed(view, app)["ppid"] == monitor_pid and
                view.status(app["pid"])["Uid"] == credentials["Uid"] and
                view.status(app["pid"])["Gid"] == credentials["Gid"] and
                view.namespace(app["pid"]) == view.namespace(monitor_pid), "application changed during bind")
        appfd = candidate_application_fd
        epoch = time.monotonic()
        lease = Lease(python, script, view, monfd, monitor, epoch,
                      cleanup=(appfd, {k: app[k] for k in ("pid", "start")}) if case == "controller-death" else None)
        send(view, monfd, monitor, signal.SIGSTOP)
        wait_until(lambda: assert_fixed(view, monitor)["state"] == "T", epoch + 2, lease.pulse)
        recheck_stopped_identity(view, monitor, app, node_pid, credentials)
        if case == "controller-death":
            # Node remains the monitor's parent. Only this sibling controller
            # dies; sole lifetime writer closes. Watchdog CONT then exact-app
            # cleanup makes the failed transaction observable to Node.
            print(json.dumps({"phase":"stopped-before-controller-death", "ownerNodePid":node_pid,
                              "monitor":monitor,"controllerPid":os.getpid(),"siblingParentBound":True,
                              "application":{k:app[k] for k in ("pid","ppid","start")},
                              "watchdogArmed":lease.acknowledgements}),flush=True)
            os._exit(73)
        t0 = time.monotonic()
        require(t0 < epoch + 2, "STOP prephase budget")
        send(view, appfd, app, signal.SIGTERM)
        wait_until(lambda: bool(select.select([appfd], [], [], 0)[0]), t0 + 24, lease.pulse)
        witness_deadline = min(time.monotonic() + 1, t0 + 25)
        before = assert_fixed(view, monitor)
        first, second = assert_fixed(view, app), assert_fixed(view, app)
        after = assert_fixed(view, monitor)
        require(before["ppid"] == after["ppid"] == node_pid, "monitor Node parent changed")
        require(time.monotonic() <= witness_deadline, "witness deadline")
        if case == "term":
            witness = zombie_witness(before, first, second, after, app, monitor)
        else:
            bracket = stable_zombie_bracket(before, first, second, after, app, monitor)
            require(bracket["exit_code"] == 143 << 8,
                    "negative fixture did not produce ordinary exit143")
            try:
                exact_sigterm(bracket["exit_code"])
            except Refusal:
                witness = {"negativeRejected": True, "exit_code": first["exit_code"], "stableBracket": bracket}
            else:
                raise Refusal("ordinary143 accepted")
        cont_deadline = min(t0 + 29, time.monotonic() + 4)
        send(view, monfd, monitor, signal.SIGCONT)
        wait_until(lambda: resumed_or_exited(view, monfd, monitor), cont_deadline, lease.pulse)
        wait_until(lambda: bool(select.select([monfd], [], [], 0)[0]), cont_deadline, lease.pulse)
        lease.disarm(witness, "exited")
        require(time.monotonic() < t0 + 30, "composed30 budget")
        completed = True
        return {"case": case, "witness": witness, "elapsed": time.monotonic()-t0,
                "monitor": monitor, "application": {k: app[k] for k in ("pid", "start")},
                "ownerNodePid": node_pid, "controllerPid": os.getpid(),
                "siblingParentBound": True, "monitorWaitStatusOwner": "Node",
                "watchdogRescue": False, "watchdogAcknowledgements": lease.acknowledgements,
                "watchdogNonceSha256": digest(lease.nonce.encode()),
                "credentialFieldsSha256": digest(json.dumps(credentials,sort_keys=True).encode()),
                "sharedPidNamespace": view.namespace(os.getpid())}

    finally:
        # CONT always precedes failure-only exact-handle cleanup. No process groups.
        errors = cleanup_bound(monfd, appfd, lease, completed)
        for fd in handles:
            try:
                os.close(fd)
            except OSError as error:
                errors.append(type(error).__name__)
        try:
            view.close()
        except OSError as error:
            errors.append(type(error).__name__)
        require(not errors, "bounded exact-handle cleanup failed")


if __name__ == "__main__":
    if sys.argv[1:2] == ["surrogate"]:
        surrogate(sys.argv[2])
    elif sys.argv[1:2] == ["watchdog"]:
        cleanup = (int(sys.argv[7]), {"pid": int(sys.argv[8]), "start": int(sys.argv[9])}) if len(sys.argv) == 10 else None
        sys.exit(watchdog(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4],
                          {"pid": int(sys.argv[5]), "start": int(sys.argv[6])}, cleanup=cleanup))
    elif sys.argv[1:2] == ["controller"]:
        raw = sys.stdin.buffer.read(LIMIT+1)
        require(len(raw) <= LIMIT, "controller contract bound")
        result = control_case(json.loads(raw))
        print(json.dumps(result, sort_keys=True), flush=True)
    else:
        raise SystemExit("use the authenticated predicate driver; no arbitrary PID/command mode")
