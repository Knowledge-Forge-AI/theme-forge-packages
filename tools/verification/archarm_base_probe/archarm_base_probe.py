"""Prepared key-free native ArchARM base probe; adoption requires owner approval."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import time
import urllib.request
import uuid


class Refusal(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refusal(code)


def _relative(name):
    require(isinstance(name, str) and bool(name), "MEMBER_NAME")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    require(bool(name) and not name.startswith("/") and "\x00" not in name, "MEMBER_NAME")
    require(all(p not in ("", ".", "..") for p in name.split("/")), "MEMBER_NAME")
    return name


def _link_target(member, target, *, hardlink):
    require(isinstance(target, str) and bool(target) and "\x00" not in target,
            "LINK_TARGET")
    # Absolute symlinks are interpreted inside the container root. No extraction
    # to the host occurs. Hardlink targets are archive-relative names.
    require(not (hardlink and target.startswith("/")), "LINK_TARGET")
    parts = [] if hardlink or target.startswith("/") else member.split("/")[:-1]
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            require(bool(parts), "LINK_ESCAPE")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def inspect_members(path, pin):
    """Inspect headers and three public unit files; never extract a rootfs."""
    exceptions = {r["path"]: r for r in pin["literalEscapes"]}
    require(len(exceptions) == 3, "EXCEPTION_PIN")
    seen, observed, special, hardlinks = set(), {}, [], []
    count = size = roots = 0
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            count += 1
            require(count <= pin["members"], "ARCHIVE_LIMIT")
            if member.name in (".", "./") and member.isdir():
                roots += 1
                continue
            name = _relative(member.name)
            require(name not in seen, "DUPLICATE_MEMBER")
            seen.add(name)
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(), "SPECIAL_MEMBER")
            require(member.size >= 0, "MEMBER_SIZE")
            size += member.size
            require(count <= pin["members"] and size <= pin["declaredBytes"], "ARCHIVE_LIMIT")
            if "\\" in name:
                record = exceptions.get(name)
                require(record is not None and member.isfile()
                        and member.size == record["size"] and member.mode == record["mode"], "LITERAL_ESCAPE")
                body = archive.extractfile(member).read(record["size"] + 1)
                require(hashlib.sha256(body).hexdigest() == record["sha256"], "LITERAL_ESCAPE")
                observed[name] = record
            if member.mode & 0o6000:
                special.append({"path": name, "type": member.type.decode("ascii"),
                                "mode": member.mode, "size": member.size})
            if member.issym() or member.islnk():
                if "\\" in member.linkname:
                    require({"path": name, "target": member.linkname} in
                            pin["literalEscapeLinks"], "LINK_TARGET")
                target = _link_target(name, member.linkname, hardlink=member.islnk())
                if member.islnk():
                    hardlinks.append(target)
    require(count == pin["members"] and size == pin["declaredBytes"], "ARCHIVE_INVENTORY")
    require(roots == pin["rootDirectoryHeaders"], "ARCHIVE_INVENTORY")
    require(set(observed) == set(exceptions), "LITERAL_ESCAPE")
    require(sorted(special, key=lambda r: r["path"]) ==
            sorted(pin["setIdMembers"], key=lambda r: r["path"]), "SETID_INVENTORY")
    require(all(target in seen for target in hardlinks), "HARDLINK_TARGET")
    return {"members": count, "declaredBytes": size, "literalEscapes": len(observed),
            "setIdMembers": len(special), "filesystemExtraction": False}


def check_file(path, expected_size, expected_sha):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and not path.is_symlink()
            and s.st_size == expected_size, "INPUT_FILE")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    require(h.hexdigest() == expected_sha, "INPUT_HASH")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refusal("INPUT_REDIRECT")


def download(url, destination, size, sha):
    require(url.startswith("https://fl.us.mirror.archlinuxarm.org/os/"), "INPUT_URL")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    total = 0
    deadline = time.monotonic() + 900
    with opener.open(url, timeout=30) as response, destination.open("xb") as output:
        require(response.status == 200 and response.geturl() == url, "INPUT_TRANSPORT")
        require(int(response.headers.get("Content-Length", "-1")) == size, "INPUT_SIZE")
        while True:
            require(time.monotonic() <= deadline, "INPUT_TIMEOUT")
            chunk = response.read(min(1024 * 1024, size - total + 1))
            if not chunk:
                break
            total += len(chunk)
            require(total <= size, "INPUT_SIZE")
            output.write(chunk)
    check_file(destination, size, sha)


def command(argv, env, *, timeout=120, limit=4096):
    """Bound one direct child, with no stderr retention or inherited credentials."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() <= deadline, "COMMAND_TIMEOUT")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        data.extend(chunk)
                        require(len(data) <= limit, "COMMAND_OUTPUT_LIMIT")
            # Keep the leader unreaped until group cleanup, so its PID cannot be
            # reused between wait and killpg. This probe runs only on Linux.
            while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
                require(time.monotonic() <= deadline, "COMMAND_TIMEOUT")
                time.sleep(0.01)
    finally:
        # Terminate the owned group even when its leader already exited.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        code = proc.wait(timeout=10)
        proc.stdout.close()
    return code, bytes(data)


def remove_fresh_docker_home(root):
    """Remove only bounded opaque client metadata in this fresh owned directory."""
    require(stat.S_ISDIR(root.lstat().st_mode) and not root.is_symlink(), "DOCKER_HOME_CHANGED")
    files, directories = [], []
    total = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in [*dirs, *names]:
            path = Path(parent) / name
            relative = path.relative_to(root)
            require(len(relative.parts) <= 5 and name.casefold() not in {"db", "raw", ".serena"}
                    and not re.search(r"(?:\.db|\.sqlite)(?:$|[.-])", name, re.I), "DOCKER_HOME_CHANGED")
            s = path.lstat()
            require(not stat.S_ISLNK(s.st_mode), "DOCKER_HOME_CHANGED")
            if stat.S_ISDIR(s.st_mode):
                directories.append(path)
            else:
                require(stat.S_ISREG(s.st_mode) and path.suffix == ".json", "DOCKER_HOME_CHANGED")
                files.append(path)
                total += s.st_size
            require(len(files) + len(directories) <= 64 and total <= 256 * 1024, "DOCKER_HOME_CHANGED")
    for path in files:
        path.unlink()
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        path.rmdir()
    root.rmdir()


def native_probe(work, pin, certificate):
    require(platform.system() == "Linux" and platform.machine() in ("aarch64", "arm64"), "NATIVE_ARM_HOST")
    require(not work.exists() and work.parent.is_dir(), "FRESH_WORK_ROOT")
    work.mkdir(mode=0o700)
    home = work / "public-home"
    home.mkdir(mode=0o700)
    (home / "common.conf").write_text("")
    docker_home = work / "docker-home"
    docker_home.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "GNUPGHOME": str(home),
           "LANG": "C", "LC_ALL": "C", "TMPDIR": str(work)}
    docker_env = {**env, "HOME": str(docker_home), "DOCKER_CONFIG": str(docker_home)}
    def docker(args, **kwargs):
        return command(["docker", *args], docker_env, **kwargs)
    result = {"schema": "tf.archarm-key-free-base-probe.v1", "nativeArmHost": True,
              "signingSecretsUsed": False, "packageInstallation": False,
              "publicationAuthority": False, "containerCreated": False,
              "cleanupComplete": False, "status": "fail"}
    rootfs, signature = work / "rootfs.tar.gz", work / "rootfs.tar.gz.sig"
    tag = "tf-archarm-base-probe:" + uuid.uuid4().hex
    name = "tf-archarm-base-probe-" + uuid.uuid4().hex
    import_requested = container_requested = False
    try:
        download(pin["rootfsUrl"], rootfs, pin["rootfsBytes"], pin["rootfsSha256"])
        download(pin["rootfsUrl"] + ".sig", signature, pin["signatureBytes"], pin["signatureSha256"])
        check_file(certificate, pin["publicKeyBytes"], pin["publicKeySha256"])
        code, status = command(["gpgv", "--homedir", str(home), "--keyring", str(certificate),
                                "--status-fd", "1", str(signature), str(rootfs)], env)
        valid = [line.split() for line in status.decode("ascii", "strict").splitlines()
                 if line.startswith("[GNUPG:] VALIDSIG ")]
        require(code == 0 and len(valid) == 1 and len(valid[0]) == 12
                and valid[0][2] == pin["publicKeyFingerprint"]
                and valid[0][11] == pin["publicKeyFingerprint"], "PUBLIC_SIGNATURE")
        result["publicSignatureVerified"] = True
        result["archive"] = inspect_members(rootfs, pin)
        code, engine = docker(["info", "--format", "{{.OSType}}/{{.Architecture}}"])
        require(code == 0 and engine.strip() in (b"linux/aarch64", b"linux/arm64"), "NATIVE_ARM_ENGINE")
        absent_code, absent = docker(["image", "inspect", tag])
        require(absent_code == 1 and absent.strip() == b"[]", "OWNED_TAG_COLLISION")
        import_requested = True
        require(docker(["import", "--platform", "linux/arm64", str(rootfs), tag],
                       timeout=900)[0] == 0, "IMPORT_FAILED")
        code, arch = docker(["image", "inspect", "--format", "{{.Architecture}}", tag])
        require(code == 0 and arch.strip() == b"arm64", "IMAGE_ARCHITECTURE")
        container_requested = True
        script = ('set -eu; . /etc/os-release; test "$ID" = archarm; '
                  'test "$(uname -m)" = aarch64; '
                  'pacman --version >/dev/null; makepkg --version >/dev/null; repo-add --version >/dev/null')
        code, _ = docker(["run", "--name", name, "--platform", "linux/arm64",
                           "--network", "none", "--read-only", "--cap-drop", "ALL",
                           "--security-opt", "no-new-privileges", "--pids-limit", "64",
                           "--memory", "512m", "--cpus", "1", "--user", "65534:65534",
                           tag, "/bin/sh", "-c", script])
        require(code == 0, "NATIVE_BASE_TOOLS")
        result.update(containerCreated=True, nativeBaseToolsPassed=True, status="pass")
    except Refusal as error:
        result["refusal"] = str(error)
    except Exception:
        result["refusal"] = "UNCLASSIFIED_PROBE_FAILURE"
    finally:
        clean = True
        try:
            if container_requested:
                clean = docker(["rm", "-f", name])[0] == 0
                code, absent = docker(["container", "inspect", name])
                clean = code == 1 and absent.strip() == b"[]" and clean
            if import_requested:
                # Remove only this fresh, owned tag. Never remove by image ID or prune.
                clean = docker(["rmi", "--no-prune", tag])[0] == 0 and clean
                code, absent = docker(["image", "inspect", tag])
                clean = code == 1 and absent.strip() == b"[]" and clean
                # An interrupted import can leave uncertain daemon state. Stop and
                # rely on disposable VM teardown rather than claiming admission.
                clean = result.get("nativeBaseToolsPassed") is True and clean
        except Exception:
            clean = False
        result["cleanupComplete"] = clean
        if not clean:
            result["status"] = "fail"
        # Public inputs only; keep no rootfs or downloaded signatures after probe.
        try:
            for path in (rootfs, signature):
                if path.is_file() and not path.is_symlink():
                    path.unlink()
        except OSError:
            result["cleanupComplete"] = False
            result["status"] = "fail"
        try:
            remove_fresh_docker_home(docker_home)
            require({p.name for p in home.iterdir()} == {"common.conf"}, "PUBLIC_HOME_CHANGED")
            require((home / "common.conf").is_file() and not (home / "common.conf").is_symlink(), "PUBLIC_HOME_CHANGED")
            (home / "common.conf").unlink()
            home.rmdir()
            work.rmdir()
        except Exception:
            result["cleanupComplete"] = False
            result["status"] = "fail"
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--inspect-local", type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    pin = json.loads((here / "ROOTFS-PIN.json").read_text())
    try:
        if args.inspect_local:
            check_file(args.inspect_local, pin["rootfsBytes"], pin["rootfsSha256"])
            result = inspect_members(args.inspect_local, pin)
            result["status"] = "pass"
        else:
            result = native_probe(args.work, pin, here / "archlinuxarm-builder-public.gpg")
    except Refusal as error:
        result = {"status": "fail", "refusal": str(error), "cleanupComplete": False}
    except Exception:
        result = {"status": "fail", "refusal": "UNCLASSIFIED_PROBE_FAILURE", "cleanupComplete": False}
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
