"""Pinned bootstrap for a proposed public, credential-free RPM metadata probe."""
from __future__ import annotations

import argparse
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

BUNDLE_SHA256 = "8d133f5614251cb224dd48ba0401addfcab4a5f76fb430f818e06f53aea1ac72"
LEAF_SHA256 = "be9f081a98b10a5c8b554d799e66ffa3bff6f8ab92817d73da773378559311fd"
BUNDLE_FILES = {"metadata_core.py", "probe_inputs.py", "probe_host.py", "inputs.json"}
SIGNER_DIR = "tools/verification/current_signer"
RUNTIME_MODULES = frozenset({
    "protected_signing_runtime", "repository_metadata_assembly", "protected_passphrase_fd",
    "owned_gpg_agent", "signing_status_proof", "current_protected_signing",
})


def read_regular(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    before = os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= maximum):
        raise ValueError("SOURCE_REFUSED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(maximum + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    key = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
    if (key(before) != key(opened) or key(opened) != key(after)
            or key(after) != key(os.lstat(path)) or len(body) != before.st_size):
        raise ValueError("SOURCE_REFUSED")
    return body


def hashed(path: Path, expected: str) -> bytes:
    raw = read_regular(path)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("SOURCE_REFUSED")
    return raw


def install_held_modules(held: dict, *, forbidden=frozenset()) -> None:
    """Only digest-pinned source enters this loader; no caller-selected module path."""
    if any(name in sys.modules for name in set(held) | set(forbidden)):
        raise ValueError("MODULE_PREIMPORTED")

    class Loader(importlib.abc.Loader):
        def __init__(self, name):
            self.name = name

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            path, body = held[self.name]
            module.__file__ = str(path)
            exec(compile(body, str(path), "exec", dont_inherit=True), module.__dict__)

    class Finder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname in forbidden:
                raise ImportError("PROBE_IMPORT_FORBIDDEN")
            if fullname in held:
                return importlib.util.spec_from_loader(fullname, Loader(fullname),
                                                       origin=str(held[fullname][0]))
            return None

    sys.meta_path.insert(0, Finder())


def load_bundle(directory: Path) -> dict:
    manifest = json.loads(hashed(directory / "manifest.json", BUNDLE_SHA256))
    if set(manifest) != {"schema", "files"} or manifest["schema"] != "tf.keyfree-rpm-source-bundle.v1":
        raise ValueError("SOURCE_REFUSED")
    if set(manifest["files"]) != BUNDLE_FILES:
        raise ValueError("SOURCE_REFUSED")
    held = {}
    profile = None
    for name, record in manifest["files"].items():
        body = hashed(directory / name, record["sha256"])
        if len(body) != record["bytes"]:
            raise ValueError("SOURCE_REFUSED")
        if name.endswith(".py"):
            module_name = "tf_rpm_probe_" + {"metadata_core.py": "core",
                                           "probe_inputs.py": "inputs",
                                           "probe_host.py": "host"}[name]
            held[module_name] = (directory / name, body)
        else:
            profile = json.loads(body)
    install_held_modules(held)
    import tf_rpm_probe_inputs
    return tf_rpm_probe_inputs.validate_profile(profile)


def runtime_modules(p_root: Path):
    manifest_path = p_root / SIGNER_DIR / "leaf-manifest.json"
    manifest = json.loads(hashed(manifest_path, LEAF_SHA256))
    held = {}
    forbidden = set()
    for relative, expected in manifest["files"].items():
        if not relative.startswith("tools/verification/") or ".." in relative.split("/"):
            raise ValueError("SOURCE_REFUSED")
        body = hashed(p_root / relative, expected)
        if relative.endswith(".py") and Path(relative).parent.as_posix() == SIGNER_DIR:
            name = Path(relative).stem
            if name not in RUNTIME_MODULES:
                forbidden.add(name)
                continue
            if name in held:
                raise ValueError("SOURCE_REFUSED")
            held[name] = (p_root / relative, body)
    if set(held) != RUNTIME_MODULES:
        raise ValueError("SOURCE_REFUSED")
    install_held_modules(held, forbidden=frozenset(forbidden))
    import protected_signing_runtime
    import repository_metadata_assembly
    return protected_signing_runtime, repository_metadata_assembly


def container_observation(profile: dict) -> dict:
    import tf_rpm_probe_core as core
    if (sys.platform != "linux" or min(os.getuid(), os.getgid()) <= 0
            or not sys.flags.isolated or not sys.flags.dont_write_bytecode):
        raise ValueError("CONTAINER_REFUSED")
    if any(any(token in name.upper() for token in
               ("SECRET", "TOKEN", "PASSPHRASE", "PASSWORD", "PRIVATE_KEY", "SIGNING_KEY", "SSH_AUTH"))
           for name in os.environ):
        raise ValueError("CONTAINER_REFUSED")
    workspace = Path("/work/workspace")
    st = os.lstat(workspace)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) != 0o700 or list(workspace.iterdir())):
        raise ValueError("CONTAINER_REFUSED")
    runtime, metadata = runtime_modules(Path("/work/p"))
    try:
        tool = core.binary_identity()
    except Exception:
        return {"schema": core.SCHEMA, "cases": [], "signingPerformed": False,
                "publicationAuthority": False, "privateKeyAccess": False,
                "tool": {"status": "REFUSED", "path": "/usr/bin/createrepo_c", "bytes": 0,
                         "sha256": None, "versionObserved": False}}
    results = []
    for index, case in enumerate(profile["cases"]):
        packages = core.public_packages(case, Path("/work/inputs"))
        work = runtime._new_owned_directory(workspace / ("case-" + str(index)), "public metadata case").path
        observed = core.run_one(case, packages, work, runtime, metadata,
                                runtime.NativeProtectedProcessRunner())
        results.append(core.validate_result(observed))
        if observed["code"] not in core.CONTINUABLE_CODES:
            break
    if core.binary_identity() != tool:
        raise ValueError("TOOL_IDENTITY_REFUSED")
    return {"schema": core.SCHEMA, "cases": results, "signingPerformed": False,
            "publicationAuthority": False, "privateKeyAccess": False, "tool": tool}


def arguments():
    parser = argparse.ArgumentParser(description="Credential-free RPM metadata diagnostic")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--host", action="store_true")
    modes.add_argument("--container", action="store_true")
    parser.add_argument("--expected-entry-sha256", required=True)
    for name in ("p-root", "r-root", "p-commit", "work-root", "result-out"):
        parser.add_argument("--" + name)
    return parser.parse_args()


def main() -> int:
    try:
        args = arguments()
        hashed(Path(__file__), args.expected_entry_sha256)
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            raise ValueError("PYTHON_FLAGS")
        profile = load_bundle(Path(__file__).parent)
        if args.container:
            print(json.dumps(container_observation(profile), sort_keys=True))
            return 0
        if not all(getattr(args, k) for k in ("p_root", "r_root", "p_commit", "work_root", "result_out")):
            raise ValueError("HOST_ARGUMENTS")
        import tf_rpm_probe_host
        result = tf_rpm_probe_host.run_host(args, profile)
        target = Path(args.result_out)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("x", encoding="utf-8") as output:
            target.chmod(0o600)
            json.dump(result, output, sort_keys=True)
            output.write("\n")
        print(json.dumps({"schema": result["schema"], "status": result["status"],
                          "stage": result["stage"], "code": result["code"]}))
        return 0 if result["status"] == "diagnostic-complete" else 1
    except Exception:
        print('{"schema":"tf.keyfree-rpm-bootstrap-refusal.v1","code":"ENTRY_REFUSED"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

