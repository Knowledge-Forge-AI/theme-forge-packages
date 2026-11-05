"""Key-free observation of the pinned RS9 collector on the public Ubuntu host.

This deliberately does not exercise the signer image, unsigned-input lease,
network isolation gate, native package tools, signing or publication.
Only closed labels are retained; collector packets and archives stay ephemeral.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
from datetime import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

REPOSITORY = "Knowledge-Forge-AI/theme-forge-packages"
WORKFLOW_REF = REPOSITORY + "/.github/workflows/probe-current-distribution-intake.yml@refs/heads/main"
P_COMMIT = "3783fff1376b5698dcce6fbbae903fba12580cc9"
P_TREE = "d263c2e17ada51b78107992eba4cb09bc487da37"
R_COMMIT = "42942b2d0f60059102c3baf43c5045e1ff42da7e"
R_TREE = "d10cfd5d3a07f7bc16f8729964c9f789ad1792be"
R_RUN = 41935969366
DESCRIPTOR_SHA256 = "972fc30c36a5c351bb38cf792c2b4f6d0732f8d0355d4fb0d81b80fce744a665"
CLOSURE_SHA256 = "998b752179e47e9624551f17ed728febaa0d6a6b75ac8e82a9ff536541e65cd5"
PHASES = frozenset({"CONTEXT", "SOURCE", "IMPORT", "COLLECT_REVALIDATE", "PACKET", "COMPLETE"})


class Refusal(Exception):
    pass


class Discard(io.TextIOBase):
    def write(self, value):
        return len(value)


def physical_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise Refusal()
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise Refusal()
    return path


def held_bytes(path, limit=2 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_size > limit:
            raise Refusal()
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        if len(data) > limit or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise Refusal()
        return data
    finally:
        os.close(fd)


def authenticate_context(env):
    if (env.get("GITHUB_REPOSITORY") != REPOSITORY or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or env.get("GITHUB_REF") != "refs/heads/main" or env.get("GITHUB_RUN_ATTEMPT") != "1"
            or env.get("GITHUB_WORKFLOW_REF") != WORKFLOW_REF or not re.fullmatch(r"[1-9][0-9]{0,19}", env.get("GITHUB_RUN_ID", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", ""))):
        raise Refusal()
    if any(any(marker in key.upper() for marker in ("PASSPHRASE", "PRIVATE_KEY", "SIGNING_KEY", "PACKAGE_SIGNING", "GNUPG", "GPG_AGENT", "SSH_AUTH_SOCK")) for key in env):
        raise Refusal()
    if not env.get("GH_TOKEN") or any(key in env for key in ("GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")):
        raise Refusal()
    return env["GITHUB_RUN_ID"]


def clean_git(root, commit, tree):
    env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
    def read(args):
        value = subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "safe.directory=" + str(root), "-C", str(root), *args], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if value.returncode or len(value.stdout) > 65536 or len(value.stderr) > 65536:
            raise Refusal()
        return value.stdout
    if read(["rev-parse", "HEAD"]).strip() != commit.encode() or read(["rev-parse", "HEAD^{tree}"]).strip() != tree.encode() or read(["status", "--porcelain", "--untracked-files=all"]):
        raise Refusal()


def closed_codes(root):
    # Exact clean, pinned public source only. Never derive a label from API text.
    codes = set()
    for path in (root / "src/rs9").glob("*.py"):
        tree = ast.parse(held_bytes(path).decode())
        codes.update(node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and type(node.value) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{1,95}", node.value))
    return frozenset(codes)


def packet_view(packet, codes):
    def code(value):
        return value if type(value) is str and value in codes else "UNLISTED_CODE"
    def rows(value):
        if type(value) is not list:
            return ["UNLISTED_CODE"]
        return sorted(set(code(item) for item in value))[:8]
    if type(packet) is not dict:
        raise Refusal()
    validation = packet.get("validation")
    artifacts = packet.get("artifacts")
    scope = packet.get("diagnostic_scope")
    if type(validation) is not dict or type(scope) is not dict or type(artifacts) is not list or len(artifacts) > 128 or any(type(row) is not dict for row in artifacts):
        raise Refusal()
    status = validation.get("status")
    summary = scope.get("summary_binding")
    return {"validationStatus": status if status in {"pass", "fail", "not-run"} else "UNLISTED_STATUS",
            "validationReasons": rows(validation.get("reasons")),
            "artifactCollectionReasons": rows(packet.get("artifact_collection_reasons", [])),
            "artifactFailureCodes": rows([row.get("reason") for row in artifacts if row.get("collection") == "failed"]),
            "verifiedArtifacts": sum(row.get("collection") == "verified" for row in artifacts),
            "failedArtifacts": sum(row.get("collection") == "failed" for row in artifacts),
            "expiredArtifacts": sum(row.get("expired") is True for row in artifacts),
            "expectedArtifactCount": len(artifacts) == 12,
            "packetPredicates": {
                "classificationQualified": packet.get("classification") == "qualified-current-distribution-candidate",
                "generationCurrent": packet.get("generation") == "theme-forge-current-202610",
                "scopeMatches": packet.get("qualification_scope") == "current-distribution-only",
                "sourceCommitBound": packet.get("source_commit") == R_COMMIT,
                "runIdBound": type(packet.get("run_id")) is int and packet.get("run_id") == R_RUN,
                "currentDistributionQualificationTrue": scope.get("current_distribution_qualification") is True,
                "fullLive1False": scope.get("full_live1_qualification") is False,
                "publishedReadyFalse": scope.get("published_linux_nix_ready") is False,
                "productionFalse": packet.get("production_enabled") is False,
                "publicationFalse": packet.get("publication_authority") is False,
            },
            "summaryBinding": summary if summary in {"verified", "missing", "invalid", "failed"} else "UNLISTED_BINDING"}


@contextlib.contextmanager
def quiet_process_output():
    """Suppress Python streams and inherited child file descriptors, restoring ours."""
    saved = [os.dup(1), os.dup(2)]
    sink = os.open(os.devnull, os.O_WRONLY | os.O_CLOEXEC)
    try:
        os.dup2(sink, 1)
        os.dup2(sink, 2)
        with contextlib.redirect_stdout(Discard()), contextlib.redirect_stderr(Discard()):
            yield
    finally:
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for fd in [sink, *saved]:
            os.close(fd)


def collection_observation(config, collection, verifier, contract_error, codes):
    """One real verification call; packet absence never erases its closed outcome."""
    result = {"verifiedContextPassed": False, "exceptionCode": "NONE", "packet": None,
              "packetState": "UNAVAILABLE", "hostedSummaryPresent": False, "probeFault": False}
    with quiet_process_output():
        try:
            verifier(config, collection, zip_transport="public-release-relay", timeout=120)
            result["verifiedContextPassed"] = True
        except contract_error as error:
            # Actual pinned ContractError stores code directly; no property execution.
            value = vars(error).get("code")
            result["exceptionCode"] = value if type(value) is str and value in codes else "UNLISTED_CODE"
        except Exception as error:
            families = {OSError: "NON_CONTRACT_OSERROR", subprocess.TimeoutExpired: "NON_CONTRACT_TIMEOUT",
                        json.JSONDecodeError: "NON_CONTRACT_JSON", ValueError: "NON_CONTRACT_VALUE",
                        KeyError: "NON_CONTRACT_KEY", TypeError: "NON_CONTRACT_TYPE"}
            result["exceptionCode"] = families.get(type(error), "NON_CONTRACT_OTHER")
        try:
            result["packet"] = packet_view(json.loads(held_bytes(collection / "manager-packet.json")), codes)
            result["packetState"] = "AVAILABLE"
        except BaseException:
            result["probeFault"] = True
        try:
            fd = os.open(collection / "hosted-summary/hosted-summary.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                result["hostedSummaryPresent"] = stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            finally:
                os.close(fd)
        except BaseException:
            pass
    return result


def fresh_collection(run_id):
    # Collector's demonstrated path contract; preserve the actual HOME.
    root = physical_directory(Path.home())
    for part in ("Documents", "agent", "outbox", "release-starport-9_dev"):
        root = root / part
        if not root.exists():
            root.mkdir(mode=0o700)
        physical_directory(root)
    leaf = root / ("tf-keyfree-intake-" + run_id)
    leaf.mkdir(mode=0o700)  # exclusive; never reuse an earlier attempt
    return leaf, (leaf.stat().st_dev, leaf.stat().st_ino)


def remove_collection(root, identity):
    # No running product/native process is created by this collector. Refuse
    # links, foreign owners or special files rather than following them.
    try:
        if (root.lstat().st_dev, root.lstat().st_ino) != identity or root.is_symlink():
            return False
        for path in [root, *root.rglob("*")]:
            info = path.lstat()
            if info.st_uid != os.getuid() or not (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)):
                return False
        shutil.rmtree(root)
        return not root.exists()
    except BaseException:
        return False


def observe(p_root, r_root):
    result = {"schema": "tf.keyfree-current-distribution-intake.v1", "status": "refused", "phase": "CONTEXT",
              "sourceRun": R_RUN, "sourceCommit": R_COMMIT, "signingOrPublicationAuthority": False,
              "signerContainerExercised": False, "nativeFailureCauseProved": False,
              "verifiedContextPassed": False, "exceptionCode": "NONE", "packet": None,
              "collectionCleanupConfirmed": False, "probeFault": False}
    collection = identity = None
    codes = frozenset()
    try:
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode or sys.platform != "linux":
            raise Refusal()
        run_id = authenticate_context(os.environ)
        result["phase"] = "SOURCE"
        p_root, r_root = physical_directory(p_root), physical_directory(r_root)
        if p_root == r_root or p_root in r_root.parents or r_root in p_root.parents:
            raise Refusal()
        clean_git(p_root, P_COMMIT, P_TREE)
        clean_git(r_root, R_COMMIT, R_TREE)
        descriptor_bytes = held_bytes(p_root / "tools/verification/current-rs9-inputs.json")
        closure_bytes = held_bytes(p_root / "tools/verification/current_signer/source_closure.py")
        if hashlib.sha256(descriptor_bytes).hexdigest() != DESCRIPTOR_SHA256 or hashlib.sha256(closure_bytes).hexdigest() != CLOSURE_SHA256:
            raise Refusal()
        codes = closed_codes(r_root)
        result["phase"] = "IMPORT"
        # Execute precisely the authenticated source, never a second unchecked read.
        spec = importlib.util.spec_from_loader("source_closure", loader=None)
        closure = importlib.util.module_from_spec(spec)
        exec(compile(closure_bytes, "<authenticated-source-closure>", "exec"), closure.__dict__)
        closure.apply_process_git_scope(p_root, r_root)
        sys.path.insert(0, str(r_root / "src"))
        from rs9.qualified_distribution_inputs import SourceBoundConfiguration, _verified_context
        from rs9.errors import ContractError
        doc = json.loads(descriptor_bytes)["rs9"]
        if (doc["source_commit"], doc["source_tree"], doc["run_id"]) != (R_COMMIT, R_TREE, R_RUN) or shutil.which("gh") is None:
            raise Refusal()
        config = SourceBoundConfiguration(repository=r_root, source_commit=doc["source_commit"], source_tree=doc["source_tree"], run_id=doc["run_id"], not_before=datetime.fromisoformat(doc["not_before"].replace("Z", "+00:00")), **{key: doc[key] for key in ("workflow_sha256", "contract_sha256", "builder_source_sha256", "configuration_sha256", "release_ingestion_sha256")})
        collection, identity = fresh_collection(run_id)
        result["phase"] = "COLLECT_REVALIDATE"
        result.update(collection_observation(config, collection, _verified_context, ContractError, codes))
        result["status"] = "observed-pass" if result["verifiedContextPassed"] and not result["probeFault"] else "observed-fail"
        result["phase"] = "COMPLETE"
    except BaseException:
        result["probeFault"] = True
        if result["exceptionCode"] == "NONE":
            result["exceptionCode"] = "PROBE_REFUSED"
    finally:
        if collection is not None:
            result["collectionCleanupConfirmed"] = remove_collection(collection, identity)
        if not result["collectionCleanupConfirmed"]:
            result["status"] = "refused"
    return result


def _main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--p-root", required=True)
    parser.add_argument("--r-root", required=True)
    parser.add_argument("--result-out", required=True)
    args = parser.parse_args()
    result = observe(args.p_root, args.r_root)
    destination = Path(args.result_out)
    physical_directory(destination.parent)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    # Fixed outcomes only. A diagnostic refusal remains a failed workflow.
    return 0 if result["status"] == "observed-pass" else 1


def main():
    with quiet_process_output():
        try:
            return _main()
        except BaseException:
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
