"""Read public RPM metadata from one fixed, network-isolated signing base.

This is a key-free admission aid. It neither installs packages nor grants
runtime, signing, native-client, or publication acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid

BASE_IMAGE = "registry.fedoraproject.org/fedora@sha256:c5e15bd1e07c25904d0c5b9865fb7ee4589f8ca234e635742b0c1195838f4bfd"
REPOSITORY = "Knowledge-Forge-AI/theme-forge-packages"
BYTE_LIMIT = 16 * 1024 * 1024
QUERY_SECONDS = 90
SCRIPT_SCALARS = ("PREIN", "POSTIN", "PREUN", "POSTUN", "PRETRANS", "POSTTRANS", "PREUNTRANS", "POSTUNTRANS", "VERIFYSCRIPT")
SCRIPT_ARRAYS = ("PREINPROG", "POSTINPROG", "PREUNPROG", "POSTUNPROG", "PRETRANSPROG", "POSTTRANSPROG", "PREUNTRANSPROG", "POSTUNTRANSPROG", "VERIFYSCRIPTPROG", "TRIGGERSCRIPTS", "TRIGGERSCRIPTPROG", "FILETRIGGERSCRIPTS", "FILETRIGGERSCRIPTPROG", "TRANSFILETRIGGERSCRIPTS", "TRANSFILETRIGGERSCRIPTPROG", "TRIGGERNAME", "TRIGGERFLAGS", "TRIGGERVERSION", "TRIGGERINDEX", "FILETRIGGERNAME", "FILETRIGGERFLAGS", "FILETRIGGERVERSION", "FILETRIGGERINDEX", "TRANSFILETRIGGERNAME", "TRANSFILETRIGGERFLAGS", "TRANSFILETRIGGERVERSION", "TRANSFILETRIGGERINDEX")
SCRIPT_SCALARS += ("PREINFLAGS", "POSTINFLAGS", "PREUNFLAGS", "POSTUNFLAGS", "PRETRANSFLAGS", "POSTTRANSFLAGS", "VERIFYSCRIPTFLAGS", "PREUNTRANSFLAGS", "POSTUNTRANSFLAGS")
SCRIPT_ARRAYS += ("TRIGGERSCRIPTFLAGS", "FILETRIGGERSCRIPTFLAGS", "TRANSFILETRIGGERSCRIPTFLAGS", "FILETRIGGERPRIORITIES", "TRANSFILETRIGGERPRIORITIES")
IDENTITY = "%{=NAME}\\t%{=EPOCHNUM}\\t%{=VERSION}\\t%{=RELEASE}\\t%{=ARCH}\\t"
QUERY_FORMATS = {
    "packages": "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\t%{LICENSE}\\n",
    "members": "[" + IDENTITY + "%{FILENAMES}\\t%{FILEMODES}\\t%{LONGFILESIZES}\\t%{FILEDIGESTS}\\t%{=FILEDIGESTALGO}\\t%{FILEUSERNAME}\\t%{FILEGROUPNAME}\\t%{FILEFLAGS}\\t%{FILELINKTOS}\\t%{FILESTATES}\\n]",
    "provides": "%|PROVIDENAME?{[" + IDENTITY + "%{PROVIDENAME}\\t%{PROVIDEFLAGS}\\t%{PROVIDEVERSION}\\n]}:{}|",
    "requires": "%|REQUIRENAME?{[" + IDENTITY + "%{REQUIRENAME}\\t%{REQUIREFLAGS}\\t%{REQUIREVERSION}\\n]}:{}|",
    "conflicts": "%|CONFLICTNAME?{[" + IDENTITY + "%{CONFLICTNAME}\\t%{CONFLICTFLAGS}\\t%{CONFLICTVERSION}\\n]}:{}|",
    "obsoletes": "%|OBSOLETENAME?{[" + IDENTITY + "%{OBSOLETENAME}\\t%{OBSOLETEFLAGS}\\t%{OBSOLETEVERSION}\\n]}:{}|",
    "scripts": r"\n".join(["%|" + tag + "?{" + IDENTITY + tag + "\\t%{" + tag + ":json}\\n}:{}|" for tag in SCRIPT_SCALARS]
    + ["%|" + tag + "?{[" + IDENTITY + tag + "\\t%{" + tag + ":json}\\n]}:{}|" for tag in SCRIPT_ARRAYS]),
}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,199}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.~^-]{0,299}\Z")
NUMBER = re.compile(r"[0-9]+\Z")


class Refusal(Exception):
    def __init__(self, code, line=None):
        super().__init__(code)
        self.line = line


def child_env(home: Path) -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def bounded(argv: list[str], *, env: dict[str, str], seconds: int = QUERY_SECONDS, limit: int = BYTE_LIMIT) -> tuple[int, bytes, bytes]:
    """Bound both pipes and lifetime; reap the command's own process group."""
    out, err = bytearray(), bytearray()
    deadline = time.monotonic() + seconds
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, start_new_session=True)
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, target in ((child.stdout, out), (child.stderr, err)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, target)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refusal("COMMAND_TIMEOUT")
                for key, _ in selector.select(min(remaining, 0.25)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if chunk:
                        key.data.extend(chunk)
                        if len(key.data) > limit:
                            raise Refusal("COMMAND_OUTPUT_LIMIT")
                    else:
                        selector.unregister(key.fileobj)
            try:
                code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise Refusal("COMMAND_TIMEOUT") from error
        return code, bytes(out), bytes(err)
    finally:
        # A descendant may outlive its parent even after closing both pipes.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=10)
        child.stdout.close()
        child.stderr.close()


def query_argv(kind: str, container: str) -> list[str]:
    return ["docker", "run", "--name", container, "--pull=never", "--platform=linux/amd64",
            "--read-only", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user=65534:65534", "--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--ipc=none", "--cpus=1",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777", "--env=HOME=/tmp",
            "--env=LANG=C.UTF-8", "--env=LC_ALL=C.UTF-8", "--entrypoint=/usr/bin/rpm", BASE_IMAGE,
            "--noplugins", "--query", "--all", "--queryformat", QUERY_FORMATS[kind]]


def parse_rows(kind: str, raw: bytes) -> list[list]:
    if kind in ("scripts", "provides", "requires", "conflicts", "obsoletes") and raw == b"":
        return []
    if not raw or len(raw) > BYTE_LIMIT or not raw.endswith(b"\n"):
        raise Refusal("QUERY_OUTPUT_SHAPE")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise Refusal("QUERY_OUTPUT_ENCODING") from error
    lines = text[:-1].split("\n")
    if any(ord(c) < 32 and c not in "\n\t" for c in text) or len(lines) > 100000:
        raise Refusal("QUERY_OUTPUT_SHAPE")
    expected = {"packages": 7, "members": 15, "provides": 8, "requires": 8, "conflicts": 8, "obsoletes": 8, "scripts": 7}[kind]
    rows = []
    for line_number, line in enumerate(lines, 1):
        # A literal separator resets RPM6 destructive parsing between conditionals.
        if kind == "scripts" and line == "":
            continue
        row = line.split("\t")
        if len(row) != expected:
            raise Refusal("QUERY_FIELD_COUNT", line_number)
        if (not NAME.fullmatch(row[0]) or not NUMBER.fullmatch(row[1])
                or not VERSION.fullmatch(row[2]) or not VERSION.fullmatch(row[3])
                or not (NAME.fullmatch(row[4]) or row[0] == "gpg-pubkey" and row[4] == "(none)")):
            raise Refusal("QUERY_IDENTITY_SHAPE", line_number)
        if kind == "scripts":
            if row[5] not in (*SCRIPT_SCALARS, *SCRIPT_ARRAYS):
                raise Refusal("SCRIPT_TAG_SHAPE", line_number)
            try:
                value = json.loads(row[6])
            except (ValueError, TypeError) as error:
                raise Refusal("SCRIPT_JSON_SHAPE", line_number) from error
            if not isinstance(value, (str, int)) or isinstance(value, bool):
                raise Refusal("SCRIPT_VALUE_SHAPE", line_number)
            row[6] = value
        elif kind == "packages":
            if not (VERSION.fullmatch(row[5]) or row[0] == "gpg-pubkey" and row[5] == "(none)") or not row[6]:
                raise Refusal("QUERY_OUTPUT_SHAPE", line_number)
        elif kind == "members":
            if (not row[5].startswith("/") or ".." in row[5].split("/")
                    or not all(NUMBER.fullmatch(row[i]) for i in (6, 7, 12, 14))
                    or row[9] != "(none)" and not NUMBER.fullmatch(row[9])
                    or row[8] and not re.fullmatch(r"[0-9a-f]+", row[8])):
                raise Refusal("QUERY_OUTPUT_SHAPE", line_number)
        elif not row[5] or not NUMBER.fullmatch(row[6]):
            raise Refusal("QUERY_OUTPUT_SHAPE", line_number)
        rows.append(row)
    return rows


def package_join(kind, rows, package_keys):
    keys = [tuple(row[:5]) for row in rows]
    if kind == "packages":
        if len(set(keys)) != len(keys):
            raise Refusal("DUPLICATE_PACKAGE_KEY")
        return set(keys)
    if any(key not in package_keys for key in keys):
        raise Refusal("UNKNOWN_PACKAGE_KEY")
    return package_keys


def check_context(env: dict[str, str]) -> None:
    exact = {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REPOSITORY_OWNER": "Knowledge-Forge-AI",
             "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
             "GITHUB_REF_TYPE": "branch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true"}
    if (any(env.get(k) != v for k, v in exact.items()) or not env.get("GITHUB_RUN_ID", "").isdigit()
            or not re.fullmatch("[0-9a-f]{40}", env.get("GITHUB_SHA", ""))):
        raise Refusal("CALLER_CONTEXT")


def write_json(path: Path, doc: dict) -> None:
    with path.open("x", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(doc, handle, indent=2, sort_keys=True)
        handle.write("\n")


def inspect_base(output: Path, *, execute=bounded, environ=None) -> dict:
    caller = dict(os.environ if environ is None else environ)
    check_context(caller)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    home = output / "docker-home"
    home.mkdir(mode=0o700)
    env = child_env(home)
    active, enrolled, uncertain, outputs, query_facts = set(), set(), set(), {}, {}
    package_keys = set()
    error_code, failure_phase = None, "pull"
    try:
        code, _, _ = execute(["docker", "pull", "--platform=linux/amd64", BASE_IMAGE], env=env, seconds=180)
        if code:
            raise Refusal("BASE_PULL_FAILED")
        for kind in QUERY_FORMATS:
            failure_phase = kind
            name = "tf-signing-base-" + uuid.uuid4().hex
            active.add(name)  # docker may create a container before reporting failure.
            enrolled.add(name)
            try:
                code, raw, stderr = execute(query_argv(kind, name), env=env)
            except Exception:
                uncertain.add(name)
                raise
            query_facts[kind] = {"exit_code": code, "stdout_bytes": len(raw), "stdout_sha256": hashlib.sha256(raw).hexdigest(),
                                 "stderr_bytes": len(stderr), "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
            if code:
                raise Refusal("QUERY_COMMAND_FAILED")
            rows = parse_rows(kind, raw)
            package_keys = package_join(kind, rows, package_keys)
            with (output / (kind + ".tsv")).open("xb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(raw)
            outputs[kind] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "rows": len(rows)}
            code, _, _ = execute(["docker", "rm", "-f", name], env=env, seconds=20)
            if code:
                raise Refusal("CONTAINER_REMOVAL_FAILED")
            active.remove(name)
    except Refusal as error:
        error_code = str(error)
        if failure_phase in query_facts:
            query_facts[failure_phase]["first_rejected_line"] = error.line
    except Exception:
        error_code = "INTERNAL"
    finally:
        for name in tuple(active):
            try:
                code, _, _ = execute(["docker", "rm", "-f", name], env=env, seconds=20)
                if code == 0:
                    active.remove(name)
            except Exception:
                pass
    # Exact-name list must be empty too; successful rm is not the sole absence check.
    absence = False
    try:
        code, raw, _ = execute(["docker", "ps", "--all", "--no-trunc", "--format", "{{.Names}}"], env=env, seconds=20)
        listed = raw.decode("ascii", errors="strict").splitlines()
        absence = code == 0 and not (enrolled & {name.lstrip("/") for name in listed})
    except Exception:
        pass
    cleanup_ok = absence and not (active | uncertain)
    if not cleanup_ok and error_code is None:
        error_code, failure_phase = "CLEANUP_UNCONFIRMED", "cleanup"
    result = {"schema": "tf.current-signing-base-metadata.v1", "base_image": BASE_IMAGE,
              "source_commit": caller["GITHUB_SHA"], "source_run": int(caller["GITHUB_RUN_ID"]),
              "status": "pass" if error_code is None and cleanup_ok else "fail",
              "error_code": error_code, "failure_phase": failure_phase if error_code else None,
              "container_cleanup_confirmed": cleanup_ok, "retained_container_count": len(active | uncertain),
              "uncertain_creation_count": len(uncertain), "cleanup_scope": "point-in-time; disposable-host teardown required after uncertain create",
              "outputs": outputs, "query_facts": query_facts, "candidate_packages_installed": False,
              "signing_credentials_accessed": False, "production_acceptance": False}
    write_json(output / "RESULT.json", result)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = inspect_base(args.output)
    except Refusal as error:
        print("REFUSED " + str(error), file=sys.stderr)
        return 2
    except Exception:
        print("REFUSED INTERNAL", file=sys.stderr)
        return 2
    print("BASE_METADATA_" + result["status"].upper())
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
