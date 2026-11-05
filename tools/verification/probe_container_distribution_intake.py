"""One key-free collector command inside the existing admitted signer image.

No signer worker, secret frame, native package operation or isolation claim.
Container uncertainty retains resources for the disposable runner's teardown.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

OBSERVER_REL = "tools/verification/probe_current_distribution_intake.py"
OBSERVER_SHA = "0712929f7ee4d16b74acc170a90373a0c096dc62b42818949f7aa4e3d9f3e3a0"
ISOLATION_REL = "tools/verification/isolation_probe/current_signer_isolation_probe.py"
ISOLATION_SHA = "b26c143b255ae8fe1e5598b2320a7a8eb529a7cb030953645515bc49e4f91116"
CONTEXT_KEYS = ("GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF", "GITHUB_RUN_ID", "GITHUB_SHA")
DOCKER = "/usr/bin/docker"
OWNER_KEY = "ai.knowledge-forge.keyfree-collector-owner"
MAX_RESULT = 65536
CONTAINER_CODE = (
    "import runpy,sys;"
    "sys.argv=['/work/collector.py','--p-root','/work/p','--r-root','/work/r',"
    "'--result-out','/work/export/RESULT.json'];"
    "runpy.run_path('/work/collector.py',run_name='__main__')"
)


class Refusal(Exception):
    pass


def load_held(path, digest, name):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 131072:
            raise Refusal()
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(131073)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise Refusal()
    finally:
        os.close(fd)
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, "<authenticated-keyfree-module>", "exec"), module.__dict__)
    return module


def docker_argv(*, image, python, p_root, r_root, observer_file, export_root, name, owner, uid, gid):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image) or python != "/usr/bin/python3":
        raise Refusal()
    if not re.fullmatch(r"tf-intake-[1-9][0-9]{0,19}-[0-9a-f]{32}", name) or not re.fullmatch(r"[0-9a-f]{64}", owner):
        raise Refusal()
    for path in (p_root, r_root, observer_file, export_root):
        if not Path(path).is_absolute() or any(char in str(path) for char in (",", "\n", "\0")):
            raise Refusal()
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0:
        raise Refusal()
    return [DOCKER, "run", "--rm", "-i", "--pull", "never", "--name", name,
            "--label", OWNER_KEY + "=" + owner, "--network", "bridge", "--user", f"{uid}:{gid}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", f"type=bind,src={p_root},dst=/work/p,readonly",
            "--mount", f"type=bind,src={r_root},dst=/work/r,readonly",
            "--mount", f"type=bind,src={observer_file},dst=/work/collector.py,readonly",
            "--mount", f"type=bind,src={export_root},dst=/work/export",
            "--tmpfs", f"/work/workspace:rw,exec,nosuid,nodev,mode=0700,uid={uid},gid={gid}",
            *[item for key in ("GH_TOKEN", *CONTEXT_KEYS) for item in ("-e", key)],
            image, python, "-I", "-B", "/usr/local/libexec/tf-runtime-entry/container_process_entry.py",
            "--", python, "-I", "-B", "-c", CONTAINER_CODE]


def command(argv, env, *, timeout, capture=False):
    value = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    if capture and len(value.stdout) > 65536:
        raise Refusal()
    return value


def absent(name, env, run=command):
    # Documented substring filtering includes the generated name. Any match,
    # including an unrelated longer name, conservatively retains custody.
    # No global inventory, name reuse, kill or container deletion is attempted.
    query_env = {key: value for key, value in env.items() if key != "GH_TOKEN"}
    value = run([DOCKER, "container", "ls", "--all", "--filter", "name=" + name, "--format", "{{.ID}}"], query_env, timeout=30, capture=True)
    return value.returncode == 0 and value.stdout.strip() == b""


def run_owned_container(argv, name, env, run=command):
    result = {"attempted": False, "exit": "UNAVAILABLE", "absenceConfirmed": False}
    if not absent(name, env, run):
        return result
    try:
        result["attempted"] = True
        value = run(argv, env, timeout=1500)
        result["exit"] = "ZERO" if value.returncode == 0 else "NONZERO"
    except BaseException:
        result["exit"] = "INTERRUPTED_OR_TIMEOUT"
    finally:
        try:
            result["absenceConfirmed"] = absent(name, env, run)
        except BaseException:
            result["absenceConfirmed"] = False
    return result


def closed_observation(doc, codes):
    # Revalidate the inner observer's closed vocabulary. Do not retain its raw
    # JSON, unrecognized fields, paths or the host-only execution-context flag.
    if type(doc) is not dict or doc.get("schema") != "tf.keyfree-current-distribution-intake.v1":
        raise Refusal()
    expected = {"schema", "status", "phase", "sourceRun", "sourceCommit", "signingOrPublicationAuthority",
                "signerContainerExercised", "nativeFailureCauseProved", "verifiedContextPassed", "exceptionCode",
                "packet", "collectionCleanupConfirmed", "probeFault"}
    if not expected <= set(doc) or not set(doc) <= expected | {"packetState", "hostedSummaryPresent"}:
        raise Refusal()
    if type(doc["sourceRun"]) is not int or doc["sourceRun"] != 41935969366 or type(doc["sourceCommit"]) is not str or doc["sourceCommit"] != "42942b2d0f60059102c3baf43c5045e1ff42da7e":
        raise Refusal()
    if doc["signingOrPublicationAuthority"] is not False or doc["nativeFailureCauseProved"] is not False or doc["signerContainerExercised"] is not False:
        raise Refusal()
    out = {"sourceRun": doc["sourceRun"], "sourceCommit": doc["sourceCommit"]}
    choices = {"status": {"observed-pass", "observed-fail", "refused"},
               "phase": {"CONTEXT", "SOURCE", "IMPORT", "COLLECT_REVALIDATE", "PACKET", "COMPLETE"},
               "exceptionCode": set(codes) | {"NONE", "UNLISTED_CODE", "PROBE_REFUSED", "NON_CONTRACT_OSERROR", "NON_CONTRACT_TIMEOUT", "NON_CONTRACT_JSON", "NON_CONTRACT_VALUE", "NON_CONTRACT_KEY", "NON_CONTRACT_TYPE", "NON_CONTRACT_OTHER"},
               "packetState": {"AVAILABLE", "UNAVAILABLE"}}
    for key, values in choices.items():
        value = doc.get(key, "UNAVAILABLE")
        if type(value) is not str or value not in values:
            raise Refusal()
        out[key] = value
    for key in ("verifiedContextPassed", "collectionCleanupConfirmed", "probeFault"):
        if type(doc[key]) is not bool:
            raise Refusal()
        out[key] = doc[key]
    if "hostedSummaryPresent" in doc:
        if type(doc["hostedSummaryPresent"]) is not bool:
            raise Refusal()
        out["hostedSummaryPresent"] = doc["hostedSummaryPresent"]
    packet = doc["packet"]
    out["packet"] = None
    if packet is not None:
        keys = {"validationStatus", "validationReasons", "artifactCollectionReasons", "artifactFailureCodes", "verifiedArtifacts", "failedArtifacts", "expiredArtifacts", "expectedArtifactCount", "packetPredicates", "summaryBinding"}
        if type(packet) is not dict or set(packet) != keys:
            raise Refusal()
        if packet["validationStatus"] not in {"pass", "fail", "not-run", "UNLISTED_STATUS"} or packet["summaryBinding"] not in {"verified", "missing", "invalid", "failed", "UNLISTED_BINDING"}:
            raise Refusal()
        for key in ("validationReasons", "artifactCollectionReasons", "artifactFailureCodes"):
            if type(packet[key]) is not list or len(packet[key]) > 8 or any(type(item) is not str or item not in set(codes) | {"UNLISTED_CODE"} for item in packet[key]):
                raise Refusal()
        for key in ("verifiedArtifacts", "failedArtifacts", "expiredArtifacts"):
            if type(packet[key]) is not int or not 0 <= packet[key] <= 128:
                raise Refusal()
        predicates = packet["packetPredicates"]
        names = {"classificationQualified", "generationCurrent", "scopeMatches", "sourceCommitBound", "runIdBound", "currentDistributionQualificationTrue", "fullLive1False", "publishedReadyFalse", "productionFalse", "publicationFalse"}
        if type(packet["expectedArtifactCount"]) is not bool or type(predicates) is not dict or set(predicates) != names or any(type(value) is not bool for value in predicates.values()):
            raise Refusal()
        out["packet"] = packet
    if (out["packetState"] == "AVAILABLE") != (packet is not None):
        raise Refusal()
    if out["status"] == "observed-pass" and (
        not out["verifiedContextPassed"] or out["probeFault"] or not out["collectionCleanupConfirmed"]
        or out.get("hostedSummaryPresent") is not True or out["exceptionCode"] != "NONE"
        or packet is None or packet["validationStatus"] != "pass" or packet["validationReasons"]
        or packet["artifactCollectionReasons"] or packet["artifactFailureCodes"]
        or packet["verifiedArtifacts"] != 12 or packet["failedArtifacts"] or packet["expiredArtifacts"]
        or not packet["expectedArtifactCount"] or packet["summaryBinding"] != "verified"
        or not all(packet["packetPredicates"].values())
    ):
        raise Refusal()
    return out


def strict_json(raw):
    def nonfinite(_):
        raise Refusal()
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise Refusal()
            out[key] = value
        return out
    return json.loads(raw, parse_constant=nonfinite, object_pairs_hook=unique)


def execute(p_root, r_root, observer_root, work_root, export_root):
    out = {"schema": "tf.keyfree-container-distribution-intake.v1", "status": "refused", "stage": "SOURCE",
           "refusal": "NONE", "sourceRun": 41935969366, "imagePrepared": False,
           "imageDisposalConfirmed": False, "container": None, "observation": None,
           "imageRuntimeExercised": False, "signerWorkerOrSigningExercised": False,
           "nativeFailureCauseProved": False, "signingOrPublicationAuthority": False}
    lease = None
    mods = {}
    iso = None
    token = ""
    try:
        if sys.platform != "linux" or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            raise Refusal()
        p_root, r_root, observer_root = (Path(value) for value in (p_root, r_root, observer_root))
        if any(not root.is_absolute() or root.resolve() != root for root in (p_root, r_root, observer_root)):
            raise Refusal()
        observer = load_held(observer_root / OBSERVER_REL, OBSERVER_SHA, "_frozen_host_collector")
        run_id = observer.authenticate_context(os.environ)
        for root in (p_root, r_root, observer_root):
            observer.physical_directory(root)
        observer.clean_git(p_root, observer.P_COMMIT, observer.P_TREE)
        observer.clean_git(r_root, observer.R_COMMIT, observer.R_TREE)
        codes = observer.closed_codes(r_root)
        iso = load_held(p_root / ISOLATION_REL, ISOLATION_SHA, "_frozen_isolation_probe")
        iso.verify_production_pins(p_root)
        mods = iso.load_production_leaves(p_root, iso.HOST_LEAVES)
        bridge, sc = mods["runtime_workflow_bridge"], mods["source_closure"]
        token = bridge.pop_readonly_gh_token(os.environ)
        bridge.require_key_free_bridge_env(os.environ, allow_gh_token=False)
        def recheck():
            observer.clean_git(p_root, observer.P_COMMIT, observer.P_TREE)
            observer.clean_git(r_root, observer.R_COMMIT, observer.R_TREE)
            git_env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
            tree = command(["/usr/bin/git", "-C", str(observer_root), "rev-parse", "HEAD^{tree}"], git_env, timeout=30, capture=True)
            if tree.returncode or not re.fullmatch(rb"[0-9a-f]{40}\n", tree.stdout):
                raise Refusal()
            observer.clean_git(observer_root, os.environ["GITHUB_SHA"], tree.stdout.decode().strip())
            if hashlib.sha256(observer.held_bytes(observer_root / OBSERVER_REL)).hexdigest() != OBSERVER_SHA:
                raise Refusal()
            iso.verify_production_pins(p_root)
            sc.authenticate_leaf_closure(p_root, expected_leaf_manifest_sha256=iso.PINNED_LEAF_MANIFEST_SHA256, require_unimported=False)
        recheck()
        out["stage"] = "IMAGE"
        lease = iso.prepare_runtime_image(p_dir=p_root, work_dir=Path(work_root), run_suffix=run_id,
                                          token=token, environ=os.environ, mods=mods, recheck=recheck)
        out.update(imagePrepared=True, imageManifestSha256=lease["manifest_sha256"], imageRecipeSha256=lease["recipe_sha256"])
        observer.physical_directory(Path(export_root).parent)
        Path(export_root).mkdir(mode=0o700)
        observer.physical_directory(export_root)
        nonce = secrets.token_hex(16)
        name = "tf-intake-" + run_id + "-" + nonce
        owner = hashlib.sha256((run_id + nonce).encode()).hexdigest()
        args = docker_argv(image=lease["image_id"], python=lease["container_python"], p_root=p_root,
                           r_root=r_root, observer_file=observer_root / OBSERVER_REL, export_root=export_root,
                           name=name, owner=owner, uid=os.getuid(), gid=os.getgid())
        env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL", *CONTEXT_KEYS) if key in os.environ}
        env["GH_TOKEN"] = token
        recheck()
        out["stage"] = "CONTAINER"
        out["container"] = run_owned_container(args, name, env)
        env.pop("GH_TOKEN", None)
        token = ""
        if not out["container"]["absenceConfirmed"]:
            out["refusal"] = "CONTAINER_CUSTODY_UNCONFIRMED"
            return out
        out["stage"] = "RESULT"
        raw = observer.held_bytes(Path(export_root) / "RESULT.json", MAX_RESULT)
        out["observation"] = closed_observation(strict_json(raw), codes)
        out["imageRuntimeExercised"] = True
        recheck()
        Path(export_root, "RESULT.json").unlink()
        Path(export_root).rmdir()
        if out["observation"]["status"] == "observed-pass" and out["container"]["exit"] == "ZERO":
            out["status"] = "observed-pass"
        else:
            out["status"] = "observed-fail"
        out["stage"] = "COMPLETE"
    except BaseException as error:
        if iso is not None and isinstance(error, iso.ProbeRefusal):
            lease = vars(error).get("probe_lease", lease)
            out["refusal"] = iso._label(error)
            if vars(error).get("stage") in iso.IMAGE_STAGES:
                out["imageStage"] = vars(error)["stage"]
        else:
            out["refusal"] = "PREPARATION_OR_OBSERVATION_REFUSED"
    finally:
        token = ""
        can_dispose = out["container"] is None or out["container"]["absenceConfirmed"]
        if iso is not None and can_dispose:
            disposal = iso.dispose_runtime_image(lease, mods)
            out["imageDisposalConfirmed"] = disposal["confirmed"]
        if not out["imageDisposalConfirmed"]:
            out["status"] = "refused"
            if out["refusal"] == "NONE":
                out["refusal"] = "IMAGE_CUSTODY_UNCONFIRMED"
    return out


def main():
    # Suppress descriptors before imports or external processes. The outer
    # workflow also redirects them; only the fixed result is retained.
    sink = os.open(os.devnull, os.O_WRONLY | os.O_CLOEXEC)
    os.dup2(sink, 1)
    os.dup2(sink, 2)
    os.close(sink)
    try:
        parser = argparse.ArgumentParser(allow_abbrev=False)
        for name in ("p-root", "r-root", "observer-root", "work-root", "export-root", "result-out"):
            parser.add_argument("--" + name, required=True)
        args = parser.parse_args()
        result = execute(args.p_root, args.r_root, args.observer_root, args.work_root, args.export_root)
        destination = Path(args.result_out)
        if destination.parent.resolve() != destination.parent:
            raise Refusal()
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
        return 0 if result["status"] == "observed-pass" else 1
    except BaseException:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
