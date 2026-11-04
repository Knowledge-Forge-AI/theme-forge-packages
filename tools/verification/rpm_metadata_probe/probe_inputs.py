"""Exact original public artifact intake; no generic archive extraction."""
from __future__ import annotations

import json
from pathlib import Path
import re
import stat
import zipfile

from tf_rpm_probe_core import ARCHES, INPUT_CLASSES, held_file, sha

R_COMMIT = "99e70054256a1411ff0ce4cdbf026f9e75618a84"
R_TREE = "d15be370bf5705a86352d8cded72c06416acb2f4"
R_RUN = 41838474598
PROFILE_KEYS = {"schema", "RCommit", "RTree", "RRun", "artifacts", "cases"}


def validate_profile(profile: dict) -> dict:
    if (type(profile) is not dict or set(profile) != PROFILE_KEYS
            or profile["schema"] != "tf.keyfree-rpm-inputs.v1"
            or (profile["RCommit"], profile["RTree"], profile["RRun"])
            != (R_COMMIT, R_TREE, R_RUN)
            or type(profile["artifacts"]) is not list or len(profile["artifacts"]) != 12
            or type(profile["cases"]) is not list or len(profile["cases"]) != 4):
        raise ValueError("PROFILE_REFUSED")
    pairs = [(c["architecture"], c["inputClass"]) for c in profile["cases"]]
    if pairs != [(arch, kind) for arch in ARCHES for kind in INPUT_CLASSES]:
        raise ValueError("PROFILE_REFUSED")
    for case in profile["cases"]:
        validate_case(case)
    return profile


def validate_case(case: dict) -> None:
    if (set(case) != {"architecture", "inputClass", "artifactId", "packages"}
            or type(case["packages"]) is not list or len(case["packages"]) != 4):
        raise ValueError("PROFILE_REFUSED")
    prefix = ("objects/lane-work/unsigned-custody/files/" if case["inputClass"] == "unsigned"
              else "objects/lane-work/rpm/fedora/43/" + case["architecture"] + "/Packages/")
    names = set()
    for item in case["packages"]:
        validate_package(item, prefix, names)
        names.add(item["name"])


def validate_package(item: dict, prefix: str, seen: set) -> None:
    if (set(item) != {"member", "name", "bytes", "sha256"}
            or type(item["name"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\.rpm", item["name"])
            or item["name"] in seen or item["member"] != prefix + item["name"]
            or type(item["bytes"]) is not int or not 0 < item["bytes"] <= 64 * 1024 * 1024
            or type(item["sha256"]) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
        raise ValueError("PROFILE_REFUSED")


def selected_artifacts(profile: dict) -> list[dict]:
    ids = {case["artifactId"] for case in profile["cases"]}
    result = [a for a in profile["artifacts"] if a["id"] in ids]
    expected = {"candidate-rpm-" + arch + "-linux" for arch in ARCHES}
    if (len(ids) != 2 or len(result) != 2
            or {a["name"] for a in result} != expected):
        raise ValueError("PROFILE_REFUSED")
    for case in profile["cases"]:
        matching = [a for a in result if a["id"] == case["artifactId"]]
        if len(matching) != 1 or matching[0]["name"] != "candidate-rpm-" + case["architecture"] + "-linux":
            raise ValueError("PROFILE_REFUSED")
    return result


def write_package(destination: Path, body: bytes, item: dict) -> None:
    if len(body) != item["bytes"] or sha(body) != item["sha256"]:
        raise ValueError("PACKAGE_REFUSED")
    target = destination / (item["sha256"] + ".rpm")
    if target.exists():
        if held_file(target, item["bytes"]) != body:
            raise ValueError("PACKAGE_REFUSED")
        return
    with target.open("xb") as stream:
        target.chmod(0o600)
        stream.write(body)


def admit_zip(path: Path, artifact: dict, cases: list[dict], destination: Path) -> None:
    raw = held_file(path, 256 * 1024 * 1024)
    if len(raw) != artifact["size_in_bytes"] or "sha256:" + sha(raw) != artifact["digest"]:
        raise ValueError("ARCHIVE_REFUSED")
    # This file is fixed by an original Actions SHA-256 before ZIP parsing.
    import io
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if (not 0 < len(entries) <= 512 or len({e.filename for e in entries}) != len(entries)
                or sum(e.file_size for e in entries) > 512 * 1024 * 1024):
            raise ValueError("ARCHIVE_REFUSED")
        for case in cases:
            for item in case["packages"]:
                info = archive.getinfo(item["member"])
                if (not stat.S_ISREG(info.external_attr >> 16) or info.flag_bits & 1
                        or info.file_size != item["bytes"]):
                    raise ValueError("ARCHIVE_REFUSED")
                write_package(destination, archive.read(info), item)


def prepare_inputs(profile: dict, destination: Path, session) -> None:
    """The host entry supplies the genuine anonymous PublicReleaseTransport session."""
    validate_profile(profile)
    destination.mkdir(mode=0o700)
    total = [0]
    for artifact in selected_artifacts(profile):
        target = destination / (str(artifact["id"]) + ".zip")
        session.download(artifact, target, total_tracker=total)
        cases = [c for c in profile["cases"] if c["artifactId"] == artifact["id"]]
        admit_zip(target, artifact, cases, destination)
        target.unlink()
    expected = {item["sha256"] + ".rpm" for c in profile["cases"] for item in c["packages"]}
    if {p.name for p in destination.iterdir()} != expected:
        raise ValueError("INPUT_INVENTORY_REFUSED")

