"""Credential-free reproduction of the existing RPM metadata boundary.

Only the exact createrepo command runs. Production signing and output validators
are imported from authenticated source; no signing runtime instance or key exists.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace

SCHEMA = "tf.keyfree-rpm-metadata-observation.v1"
ARCHES = ("x86_64", "aarch64")
INPUT_CLASSES = ("unsigned", "public-fixture-signed")
STAGES = frozenset({"SETUP", "TOOL", "SNAPSHOT", "PRESERVATION", "METADATA", "DONE"})
CODES = frozenset({
    "NONE", "COMMAND_FAILED", "COMMAND_TIMEOUT", "COMMAND_OUTPUT_LIMIT",
    "COMMAND_POLICY", "COMMAND_CLEANUP", "OUTPUT_INVENTORY", "PACKAGE_MUTATED",
    "REPOSITORY_METADATA", "PATH_IO", "FILE_CHANGED", "REGULAR_FILE_REQUIRED",
    "SIZE_LIMIT", "READ_DESCRIPTOR_CLEANUP", "INPUT_REFUSED", "INTERNAL",
})
ERROR_MARKERS = {
    "RPM_SIGNATURE_POLICY": (b"signature", b"public key", b"keyring"),
    "SHARED_LIBRARY": (b"error while loading shared libraries", b"cannot open shared object"),
    "PERMISSION": (b"permission denied", b"read-only file system"),
    "OPTION": (b"unknown option", b"argument parsing failed", b"unrecognized option"),
    "LOCK": (b"lock already exists", b"cannot create lock", b"cannot obtain lock"),
}
MARKERS = frozenset(ERROR_MARKERS) | {"NONE", "UNCLASSIFIED"}
CONTINUABLE_CODES = frozenset({"NONE", "COMMAND_FAILED", "REPOSITORY_METADATA"})
_HEX = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\.rpm")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("JSON_REFUSED")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("JSON_REFUSED")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def held_file(path: Path, maximum: int) -> bytes:
    before = os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= maximum):
        raise ValueError("INPUT_REFUSED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        body = bytearray()
        while len(body) <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - len(body)))
            if not block:
                break
            body.extend(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid,
                          st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if (identity(before) != identity(opened) or identity(opened) != identity(after)
            or identity(after) != identity(os.lstat(path)) or len(body) != before.st_size):
        raise ValueError("INPUT_REFUSED")
    return bytes(body)


def binary_identity() -> dict:
    path = Path("/usr/bin/createrepo_c")
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        raise ValueError("TOOL_IDENTITY_REFUSED")
    body = held_file(path, 32 * 1024 * 1024)
    if not body.startswith(b"\x7fELF"):
        raise ValueError("TOOL_IDENTITY_REFUSED")
    return {"status": "MEASURED", "path": str(path), "bytes": len(body), "sha256": sha(body),
            "versionObserved": False}


def validate_tool(tool: dict) -> dict:
    if (type(tool) is not dict or set(tool) != {"status", "path", "bytes", "sha256", "versionObserved"}
            or type(tool["bytes"]) is not int
            or tool["path"] != "/usr/bin/createrepo_c" or tool["versionObserved"] is not False):
        raise ValueError("TOOL_IDENTITY_REFUSED")
    if tool["status"] == "REFUSED" and tool["bytes"] == 0 and tool["sha256"] is None:
        return tool
    if (tool["status"] != "MEASURED" or type(tool["bytes"]) is not int
            or not 0 < tool["bytes"] <= 32 * 1024 * 1024 or type(tool["sha256"]) is not str
            or not _HEX.fullmatch(tool["sha256"])):
        raise ValueError("TOOL_IDENTITY_REFUSED")
    return tool


def diagnostic_code(error: BaseException) -> str:
    code = getattr(error, "code", None)
    return code if type(code) is str and code in CODES else "INTERNAL"


def marker(stderr: bytes, exit_code: int) -> str:
    if exit_code == 0:
        return "NONE"
    lowered = stderr.lower()
    found = [name for name, tokens in ERROR_MARKERS.items()
             if any(token in lowered for token in tokens)]
    return found[0] if len(found) == 1 else "UNCLASSIFIED"


def size_bucket(size: int) -> str:
    if size == 0:
        return "ZERO"
    if size <= 4096:
        return "UP_TO_4K"
    if size <= 65536:
        return "UP_TO_64K"
    return "UP_TO_256K"


def public_packages(case: dict, inputs: Path) -> dict[str, bytes]:
    if case["architecture"] not in ARCHES or case["inputClass"] not in INPUT_CLASSES:
        raise ValueError("INPUT_REFUSED")
    result = {}
    for item in case["packages"]:
        name, digest, size = item["name"], item["sha256"], item["bytes"]
        if (not _NAME.fullmatch(name) or not _HEX.fullmatch(digest)
                or type(size) is not int or not 0 < size <= 512 * 1024 * 1024
                or name in result):
            raise ValueError("INPUT_REFUSED")
        body = held_file(inputs / (digest + ".rpm"), size)
        if len(body) != size or sha(body) != digest:
            raise ValueError("INPUT_REFUSED")
        result[name] = body
    if not result or len(result) > 16:
        raise ValueError("INPUT_REFUSED")
    return result


def run_one(case: dict, packages: dict[str, bytes], workspace: Path, rt, meta, runner) -> dict:
    """Test seam is explicit; the container entry constructs only the genuine runner."""
    arch, input_class = case["architecture"], case["inputClass"]
    result = {"architecture": arch, "stage": "SETUP", "code": "INTERNAL",
              "toolExit": "NOT_RETURNED", "stderrMarker": "NONE",
              "stdoutSize": "ZERO", "stderrSize": "ZERO",
              "metadataAccepted": False, "inputClass": input_class}
    try:
        repo = rt._new_owned_directory(workspace / ("rpm-repository-" + arch), "probe RPM repository").path
        rt._new_owned_directory(repo / "Packages", "probe RPM packages")
        for name in sorted(packages):
            rt._exclusive_write(repo / "Packages" / name, packages[name], "probe RPM")
        staged = meta._snapshot(repo, ("", "Packages"),
                                expected={"Packages/" + name for name in packages})
        home = rt._new_owned_directory(workspace / ("metadata-home-" + arch), "empty probe home").path
        public_environment = SimpleNamespace(_env=lambda h: rt.ProtectedSigningRuntime._env(None, h))
        env = meta._metadata_tool_env(public_environment, home, workspace, "rpm-" + arch)
        result["stage"] = "TOOL"
        with rt._private_umask():
            observed = runner.run((rt.NATIVE_CREATEREPO, *meta.CREATEREPO_FLAGS, str(repo)),
                                  cwd=workspace, env=env, stdin=b"", phase="rpm-metadata-create")
        result.update(toolExit="ZERO" if observed.returncode == 0 else "NONZERO",
                      stderrMarker=marker(observed.stderr, observed.returncode),
                      stdoutSize=size_bucket(len(observed.stdout)),
                      stderrSize=size_bucket(len(observed.stderr)))
        if observed.returncode != 0:
            result["code"] = "COMMAND_FAILED"
            return result
        result["stage"] = "SNAPSHOT"
        created = meta._snapshot(repo, ("", "Packages", "repodata"))
        result["stage"] = "PRESERVATION"
        repodata = {name for name in created if name.startswith("repodata/")}
        meta._same(staged, created, repodata)
        result["stage"] = "METADATA"
        meta._rpm_metadata(created, packages)
        result.update(stage="DONE", code="NONE", metadataAccepted=True)
    except Exception as error:
        result["code"] = diagnostic_code(error)
    return result


def require_result_shape(result: dict) -> None:
    keys = {"architecture", "stage", "code", "toolExit", "stderrMarker",
            "stdoutSize", "stderrSize", "metadataAccepted", "inputClass"}
    buckets = {"ZERO", "UP_TO_4K", "UP_TO_64K", "UP_TO_256K"}
    if (type(result) is not dict or set(result) != keys
            or any(type(result[k]) is not str for k in keys - {"metadataAccepted"})
            or result["architecture"] not in ARCHES or result["stage"] not in STAGES
            or result["code"] not in CODES
            or result["toolExit"] not in {"NOT_RETURNED", "ZERO", "NONZERO"}
            or result["stderrMarker"] not in MARKERS
            or result["stdoutSize"] not in buckets or result["stderrSize"] not in buckets
            or type(result["metadataAccepted"]) is not bool
            or result["inputClass"] not in INPUT_CLASSES):
        raise ValueError("RESULT_REFUSED")


def validate_result(result: dict) -> dict:
    require_result_shape(result)
    expected_exit = ("NOT_RETURNED" if result["stage"] == "SETUP" else
                     "NONZERO" if result["stage"] == "TOOL" and result["code"] == "COMMAND_FAILED" else
                     "NOT_RETURNED" if result["stage"] == "TOOL" else "ZERO")
    if result["toolExit"] != expected_exit:
        raise ValueError("RESULT_REFUSED")
    accepted = result["metadataAccepted"]
    if ((result["code"] == "NONE") != (result["stage"] == "DONE")
            or (result["code"] == "COMMAND_FAILED") != (
                result["stage"] == "TOOL" and result["toolExit"] == "NONZERO")
            or result["toolExit"] != "NONZERO" and result["stderrMarker"] != "NONE"):
        raise ValueError("RESULT_REFUSED")
    if accepted != (result["stage"] == "DONE" and result["code"] == "NONE"
                    and result["toolExit"] == "ZERO"):
        raise ValueError("RESULT_REFUSED")
    return result

