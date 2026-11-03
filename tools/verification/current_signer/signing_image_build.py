"""Bounded source-only Theme Forge key-free runtime image builder and contract."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Any, Callable, Mapping, Protocol

DOCKER_BINARY = "/usr/bin/docker"
CONTAINER_PYTHON_PATH = "/usr/bin/python3"
STAGE_DIR_IN_CONTAINER = "/tmp/tf-rpm-stage"
SUPPLEMENTAL_NOTICE_DIR_IN_CONTAINER = "/usr/share/licenses/python-pip-wheel-upstream-vendor-notices"

ADMISSION_MANIFEST_SCHEMA = "tf.current-signer-runtime-image-admission-manifest.v1"
ADMISSION_MANIFEST_STATUS = "admitted-key-free-runtime-image-inputs"
BUILD_RECEIPT_SCHEMA = "tf.current-signer-runtime-image-build-receipt.v1"
PROPOSED_PRIVILEGE_PURPOSE = (
    "proposed-key-free-image-build-container-root-and-rpm-scriptlets-pending-owner-admission"
)
IMAGE_DISPOSAL_OBLIGATION = "same-job-owned-tag-removal-and-image-id-absence-confirmation"

CLASS_ADMISSION_GATE_OPEN = True
UNADMITTED_MANIFEST_PIN = "0" * 64
ADMITTED_MANIFEST_SHA256 = "ba93088c618c9f9aa27f4bbae41309c72efe325f5e56389dd83878c8b51c67d6"

APPROVED_BASE_IMAGE_DIGEST = "c5e15bd1e07c25904d0c5b9865fb7ee4589f8ca234e635742b0c1195838f4bfd"
APPROVED_BASE_IMAGE = f"registry.fedoraproject.org/fedora@sha256:{APPROVED_BASE_IMAGE_DIGEST}"

QUARANTINE_SHA256 = "db2eb505c0b66eae7efe8a3e18b19c37b3374fea28cae83904c9d7e5b8d83b00"
ROOTS_SHA256 = "05422a81ce3f2ac359b2673717436f46f4628cdbbaa187b78e76680962616be3"
BASE_ROOT_PROOF_SHA256 = "4b7b901c5af119da873ca3a33d13c0dd5872b4b594fa8b97cf6435c318e0ee70"
CPIO_VERIFIED_SHA256 = "773d78dffed7b38d75e4bb88ff632ad4acba805aad569b0ed63b83c6a29587a1"
FEDORA_CERT_METADATA_SHA256 = "a23807b970d73ecd99674119f0802fac1f3c2aa57306fdf8fc102e3b2261d28d"
FEDORA_ORIGINAL_CERT_METADATA_SHA256 = "cd72e3564a538c2ce80d13482aa1c32ca7fcd82f4d855f755e5e4a54808815ef"
FEDORA_SELECTION_PROOF_SHA256 = "8bf7784776008403db0849b90029b82d0b6455ac1217f37bbe20a8de4cb20d2a"
REQUIRED_TOOLS_SHA256 = "57b03679a204c26304e22887eba28749d41ad8049b74453840d9e6f1a7f21e68"

SOURCE_QUARANTINE_RUN = 41549016980
CPIO_TOTAL_MEMBERS = 4551
TOTAL_QUARANTINE_BYTES = 35067774

BASE_METADATA_SCHEMA = "tf.current-signing-base-metadata.v1"
BASE_METADATA_SHA256 = "83615df4edc9191371604bea60c3da8f43cb6855569b15278db8c5754802a1e5"
BASE_METADATA_SOURCE_COMMIT = "1d83ba1841391870aba9783508a4d66ce06d777a"
BASE_METADATA_SOURCE_RUN = 41565171218
EMPTY_STREAM_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
BASE_METADATA_OUTPUTS: dict[str, tuple[int, int, str]] = {
    "conflicts": (2222, 40, "cd00d86e8ce441e6e813dc869e9bd9733ee0155c4bf23406a08bf0645b1c5710"),
    "members": (2795974, 26297, "3e30f9f420c8338b6a13387156bbff0715fa3984e4662df0888a860742093855"),
    "obsoletes": (2567, 47, "45fe78907acd8e34b902c0333b8ef3691faf5e9367ca1dca0f84611da1d080ab"),
    "packages": (18306, 142, "bfd0730c71bc3809aa170ee71d560a611cc1ae184fc7dbce2ec78aa6a437417a"),
    "provides": (86773, 1289, "a8f7a5a7119ce5ba5a2897a4b12170b186283e1377a18da0c5bb7474d76eaafb"),
    "requires": (221764, 3216, "9c3fd5a03965d7abc358683ca10361963c3d810219f5641678ee297dc134658d"),
    "scripts": (332445, 176, "89234d5775ac23c350d073c8320c4ab3d5b4d0151a19b6db1c8507a05ef0fcff"),
}

SUPPLEMENTAL_NOTICE_SCHEMA = "tf.pip-vendor-supplemental-notices.v1"
UPSTREAM_NOTICE_PINS_SHA256 = "da205b4305b5aaacce4ff900dc33badf4397c19cd66dc6e6095d4993ba879942"
VENDOR_BYTE_JOIN_SHA256 = "7c7898ce195049478839333b84e6b6b6dc5467a39b09e55a26eecd707952aba1"
PIP_INSPECTION_SHA256 = "4f7b0b6dfe9cefe7f844c29292b3fa7b819c59b5cdc630dd3f340603a76d7a22"
PIP_UPSTREAM_REPOSITORY = "pypa/pip"
PIP_UPSTREAM_TAG = "25.1.1"
PIP_UPSTREAM_COMMIT = "01857ef79f59a98db592bacb6e7b48f354528c80"
PIP_WHEEL_PACKAGE = "python-pip-wheel-25.1.1-19.fc43.noarch.rpm"
PIP_WHEEL_PATH_IN_CONTAINER = "/usr/share/python-wheels/pip-25.1.1-py3-none-any.whl"
PIP_WHEEL_SHA256 = "252c2336f8dc1dacad21180c23ad9d9ea696e38b894dab6cb1e3995c40d9b1db"
PIP_VENDOR_TOTAL_FILES = 279
PIP_VENDOR_EXACT_MATCHED_FILES = 276
PIP_VENDOR_FEDORA_MODIFIED_FILES: tuple[str, ...] = (
    "pip/_vendor/certifi/core.py",
    "pip/_vendor/truststore/_openssl.py",
    "pip/_vendor/urllib3/poolmanager.py",
)
SUPPLEMENTAL_NOTICE_CONTEXT_FILENAME = "UPSTREAM-NOTICE-PINS.json"
SUPPLEMENTAL_NOTICE_TOTAL_FILES = 23
SUPPLEMENTAL_NOTICE_TOTAL_BYTES = 77247

# Keyed by retainedFile -> (upstream_path, git_blob_sha1, size_bytes, sha256)
UPSTREAM_NOTICE_PINS: dict[str, tuple[str, str, int, str]] = {
    "upstream-notices/cachecontrol/LICENSE.txt": (
        "src/pip/_vendor/cachecontrol/LICENSE.txt",
        "d8b3b56d361cfaa04de6304c96c328f27266f74e",
        558,
        "86eeee87be2a43f3ff1f56496f451f69243926f025fedbb033666c304c4c161b",
    ),
    "upstream-notices/certifi/LICENSE": (
        "src/pip/_vendor/certifi/LICENSE",
        "62b076cdee58ec8f34034141ba0befd9015b0c7e",
        989,
        "e93716da6b9c0d5a4a1df60fe695b370f0695603d21f6f83f053e42cfc10caf7",
    ),
    "upstream-notices/dependency_groups/LICENSE.txt": (
        "src/pip/_vendor/dependency_groups/LICENSE.txt",
        "b9723b85ed7adb32f8c2b4ee880c06ec3061da50",
        1099,
        "1ab36e3e2a4ba8631625384f87e9e091db1faed034c5b23325b3239abf2cc525",
    ),
    "upstream-notices/distlib/LICENSE.txt": (
        "src/pip/_vendor/distlib/LICENSE.txt",
        "c31ac56d772f7061c8b42f0ee96063b7a94a4859",
        14531,
        "808e10c8a6ab8deb149ff9b3fb19f447a808094606d712a9ca57fead3552599d",
    ),
    "upstream-notices/distro/LICENSE": (
        "src/pip/_vendor/distro/LICENSE",
        "e06d2081865a766a8668acc12878f98b27fc9ea0",
        11325,
        "cb5e8e7e5f4a3988e1063c142c60dc2df75605f4c46515e776e3aca6df976e14",
    ),
    "upstream-notices/idna/LICENSE.md": (
        "src/pip/_vendor/idna/LICENSE.md",
        "19b6b45242c16a1025465309eec2ca5009319de3",
        1541,
        "a59f0b0ef3635874109a4461ca44ff7a70d50696e814767bfaf721d4c9b0db0f",
    ),
    "upstream-notices/msgpack/COPYING": (
        "src/pip/_vendor/msgpack/COPYING",
        "f067af3aae15a5b494f0eeb15a7064c176e30fd5",
        614,
        "492dedba85da5872f78e6091bcd1fea474d660d35acb4dee964b8aab3f007427",
    ),
    "upstream-notices/packaging/LICENSE": (
        "src/pip/_vendor/packaging/LICENSE",
        "6f62d44e4ef733c0e713afcd2371fed7f2b3de67",
        197,
        "cad1ef5bd340d73e074ba614d26f7deaca5c7940c3d8c34852e65c4909686c48",
    ),
    "upstream-notices/packaging/LICENSE.APACHE": (
        "src/pip/_vendor/packaging/LICENSE.APACHE",
        "f433b1a53f5b830a205fd2df78e2b34974656c7b",
        10174,
        "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594",
    ),
    "upstream-notices/packaging/LICENSE.BSD": (
        "src/pip/_vendor/packaging/LICENSE.BSD",
        "42ce7b75c92fb01a3f6ed17eea363f756b7da582",
        1344,
        "b70e7e9b742f1cc6f948b34c16aa39ffece94196364bc88ff0d2180f0028fac5",
    ),
    "upstream-notices/pkg_resources/LICENSE": (
        "src/pip/_vendor/pkg_resources/LICENSE",
        "1bb5a44356f00884a71ceeefd24ded6caaba2418",
        1023,
        "86da0f01aeae46348a3c3d465195dc1ceccde79f79e87769a64b8da04b2a4741",
    ),
    "upstream-notices/platformdirs/LICENSE": (
        "src/pip/_vendor/platformdirs/LICENSE",
        "f35fed9191b1142ddaada8a96de4a9461c5d796c",
        1089,
        "29e0fd62e929850e86eb28c3fdccf0cefdf4fa94879011cffb3d0d4bed6d4db6",
    ),
    "upstream-notices/pygments/LICENSE": (
        "src/pip/_vendor/pygments/LICENSE",
        "446a1a805c8a949579fb8a9799f2bec7777349dc",
        1331,
        "a9d66f1d526df02e29dce73436d34e56e8632f46c275bbdffc70569e882f9f17",
    ),
    "upstream-notices/pyproject_hooks/LICENSE": (
        "src/pip/_vendor/pyproject_hooks/LICENSE",
        "b0ae9dbc262b5f7ed4cb6f964cfb5eb5c0d0b0be",
        1081,
        "1b22b049b5267d6dfc23a67bf4a84d8ec04b9fdfb1a51d360e42b4342c8b4154",
    ),
    "upstream-notices/requests/LICENSE": (
        "src/pip/_vendor/requests/LICENSE",
        "67db8588217f266eb561f75fae738656325deac9",
        10142,
        "09e8a9bcec8067104652c168685ab0931e7868f9c8284b66f5ae6edae5f1130b",
    ),
    "upstream-notices/resolvelib/LICENSE": (
        "src/pip/_vendor/resolvelib/LICENSE",
        "b9077766e9b9bdcae49ea5c8fced750ed13ec8f7",
        751,
        "f388fd38cad13112c1dc0f669bbe80e7f84541edbafb72f3030d2ca7642c3c9d",
    ),
    "upstream-notices/rich/LICENSE": (
        "src/pip/_vendor/rich/LICENSE",
        "4415505566f261c802b671426be529a31f914137",
        1056,
        "deed7c17a4318158190a3ea239cc879a5a50271cebb98ae7025f48fbe58dca15",
    ),
    "upstream-notices/tomli/LICENSE": (
        "src/pip/_vendor/tomli/LICENSE",
        "e859590f886cd78344206af1a8ccb3080d4385e0",
        1072,
        "b80816b0d530b8accb4c2211783790984a6e3b61922c2b5ee92f3372ab2742fe",
    ),
    "upstream-notices/tomli/LICENSE-HEADER": (
        "src/pip/_vendor/tomli/LICENSE-HEADER",
        "aba78dd2cfc42c15dc73d0e8841245bd4df89d31",
        121,
        "97ce9330905a172dde870ee0361d89beb95ba3bd0f4545796aa91a8c01a43531",
    ),
    "upstream-notices/tomli_w/LICENSE": (
        "src/pip/_vendor/tomli_w/LICENSE",
        "e859590f886cd78344206af1a8ccb3080d4385e0",
        1072,
        "b80816b0d530b8accb4c2211783790984a6e3b61922c2b5ee92f3372ab2742fe",
    ),
    "upstream-notices/truststore/LICENSE": (
        "src/pip/_vendor/truststore/LICENSE",
        "7ec568c1136eb8ec86aa05cf7abacfb54c3e5ead",
        1086,
        "33be7b7e8fa4fd19b1760e1a8ed8a668bdab852c91b692dd41424bcb725a9fca",
    ),
    "upstream-notices/typing_extensions.LICENSE": (
        "src/pip/_vendor/typing_extensions.LICENSE",
        "f26bcf4d2de6eb136e31006ca3ab447d5e488adf",
        13936,
        "3b2f81fe21d181c499c59a256c8e1968455d6689d269aa85373bfb6af41da3bf",
    ),
    "upstream-notices/urllib3/LICENSE.txt": (
        "src/pip/_vendor/urllib3/LICENSE.txt",
        "429a1767e4476707d2e45ee499e3c834ca4b187f",
        1115,
        "c37bf186e27cf9dbe9619e55edfe3cea7b30091ceb3da63c7dacbe0e6d77907b",
    ),
}

FEDORA_CERT_SCHEMA = "tf.runtime-upstream-public-certificate.v1"
FEDORA_CERT_FINGERPRINT = "C6E7F081CF80E13146676E88829B606631645531"
FEDORA_CERT_BYTES = 1672
FEDORA_CERT_SHA256 = "2b1449a082d3264dda8e18369f04e9ac4163bf3f8cb530b0783dc2ab064a08ec"
FEDORA_CERT_CONTEXT_FILENAME = "RPM-GPG-KEY-fedora-43-primary.asc"
FEDORA_ORIGINAL_BUNDLE_SOURCE_URL = "https://fedoraproject.org/fedora.gpg"
FEDORA_ORIGINAL_BUNDLE_BYTES = 4704
FEDORA_ORIGINAL_BUNDLE_SHA256 = "3b8a3660cca4851a67f67f56819e37e2f6b37ac8e905cb571b25d2127d1b7618"
FEDORA_SELECTED_BINARY_BYTES = 1176
FEDORA_SELECTED_BINARY_SHA256 = "f2511c2a5ee5d7490b23db762403a5847e31a1920fa9d5362a2ddb62dd08c814"
FEDORA_SELECTED_PACKET_TAGS: tuple[int, ...] = (6, 13, 2)

WORKER_RUNTIME_UID = 1001
WORKER_RUNTIME_GID = 1001
MAX_ARCHIVE_FILE_BYTES = 16 * 1024 * 1024
MAX_SMALL_SOURCE_BYTES = 512 * 1024
MAX_ENGINE_STREAM_BYTES = 4 * 1024 * 1024

QUARANTINE_ARCHIVES: dict[str, tuple[int, str]] = {
    "bsdtar-3.8.4-1.fc43.x86_64.rpm": (66937, "ede00592d76367c9f6698ff0e3702cf2d389d3ebd9f564ab7cb67acc6a49dedc"),
    "createrepo_c-1.2.1-3.fc43.x86_64.rpm": (78187, "b46d9b26bb67df14e7132cfddd1420ac17652e142cec3f291f9abd4c627c2876"),
    "createrepo_c-libs-1.2.1-3.fc43.x86_64.rpm": (113640, "d1df01e1a1b4992d68bd26a7f85feb800ef053073a79af0c1c5ddfdc20670348"),
    "drpm-0.5.2-8.fc42.x86_64.rpm": (65888, "17f3cf05443bcd71c1bf007b08dbfabe0233007f368f6f388946534e9c43ef72"),
    "expat-2.9.0-1.fc43.x86_64.rpm": (134230, "bcd653e070124a0bd97be1218ff92823361f645a3c17de25bed13c7356b82c5a"),
    "gh-2.87.3-1.fc43.x86_64.rpm": (11526853, "a5d23ea024e4dfda6522693c3446c874961ddf2fb2c65b327d75f277435fa279"),
    "git-core-2.56.0-1.fc43.x86_64.rpm": (5965667, "6aa10d035b4cd3e431983fe2ee2d6438346e98751c08537571f6fa42fbc8b318"),
    "gpgme-1.24.3-6.fc43.x86_64.rpm": (223757, "674c54afa0e2238e49fa8cb419c65cd7d575ee5b3c8fe91c2bf252b5cbc57772"),
    "less-710-1.fc43.x86_64.rpm": (231205, "bd3959bd08e33e1739c429037e6585de5052a1fbf2c0867d7f1bbef9cc184f93"),
    "libalpm-7.0.0-5.fc43.x86_64.rpm": (283126, "c89219442886ba27e39b239eec458531af9d7bf77e17a1e37477b11aee0e6bd3"),
    "libblkid-2.41.6-1.fc43.x86_64.rpm": (127094, "c0d22ec59a418dcfdf25fea3f8b16343d27d8c8c79eba961d5192fbf11c72435"),
    "libcbor-0.12.0-6.fc43.x86_64.rpm": (34315, "0cdabd5c8220186eb77a1768b87418112d34794277fb24453a8432f2fb5bfaf7"),
    "libedit-3.1-58.20260512cvs.fc43.x86_64.rpm": (107702, "f194ddf604b629de9cec615f0fe01782e248b3b96406a0bf0808c860b829b657"),
    "libfdisk-2.41.6-1.fc43.x86_64.rpm": (166222, "59ae2579323a917dc4707157d26a8aaeadee4f7ae9d6e46d0b1cb78676ff27e2"),
    "libfido2-1.16.0-3.fc43.x86_64.rpm": (100818, "e9ca30655b9837a8539357954ab9c0ebfe8c165f9f05ad50d07af1546daaea34"),
    "liblastlog2-2.41.6-1.fc43.x86_64.rpm": (24856, "47ba5e2a0ca9222e7346d7603fd3a36dac5bcc1dae8bc31f1fd084572fb365ce"),
    "libmount-2.41.6-1.fc43.x86_64.rpm": (168402, "974a95d405a43a2f74a7e2d8e4cdf68477a3b1a6ff3a1be4b7aac3617e9ab270"),
    "libsmartcols-2.41.6-1.fc43.x86_64.rpm": (86618, "81431f1ec8efd1226d6fdc4741116a70d0c84663b0824b037160bd723d31b8fc"),
    "libuuid-2.41.6-1.fc43.x86_64.rpm": (27546, "f44d3a21605cbdb17c74dec8d2a66f3e9e6ed936fa98fbcbccda18cc48928597"),
    "mpdecimal-4.0.1-2.fc43.x86_64.rpm": (99440, "2e0113c2e1c6edacdd9b548419036cfb1bdb0df6bfca7cd6717c00c80f365ca9"),
    "openssh-10.0p1-14.fc43.x86_64.rpm": (346250, "7e1bca628ed7f3097727e302cf9db01e561534b90245f980f9d6642bf124f44a"),
    "openssh-clients-10.0p1-14.fc43.x86_64.rpm": (764359, "4bf39ae0d35a9b1f34e5445570180518a65370e5bb8085586100830d75d148b7"),
    "pacman-7.0.0-5.fc43.x86_64.rpm": (789989, "20554352bb5397d1860d6df1a87e4ca972d4e708db13054cf1d3a2e7c0a243d6"),
    "pacman-filesystem-7.0.0-5.fc43.noarch.rpm": (8125, "175599f9f9b4813d0b246dd4f17ea67506d17f34f06652f7a3ee88db6c619d08"),
    "python-pip-wheel-25.1.1-19.fc43.noarch.rpm": (1263076, "89412371b52d49564857ebbd913883f0bd423f0d3cb257fa74972adf7067d165"),
    "python3-3.14.8-1.fc43.x86_64.rpm": (30117, "8b694a1cf2b705a6b1a8d2d23af65762eb37d066fd163fe6280fd4de0af7830a"),
    "python3-libs-3.14.8-1.fc43.x86_64.rpm": (10397258, "3f50083ab43a13cd4b2562aab9094adb42d375bc4d4c492506785bec9263dfac"),
    "rpm-sign-6.0.2-1.fc43.x86_64.rpm": (19948, "db398e82a2f788f8125cae2f713aca891f18c4a6858022ea6f166fc067272923"),
    "util-linux-2.41.6-1.fc43.x86_64.rpm": (1251048, "d9a7554b32a063c78ad646b828244fd1c2e450fb410feae30004174c7658735f"),
    "util-linux-core-2.41.6-1.fc43.x86_64.rpm": (565101, "0c83b25539e4fb9481c0b2c56ea074957325b47c1fa55525ae4dc150f6758c15"),
}

EXPECTED_ROOTS: dict[str, tuple[str, str, str, str, int, str, bool]] = {
    "bsdtar": ("bsdtar-3.8.4-1.fc43.x86_64.rpm", "3.8.4", "1.fc43", "x86_64", 66937, "ede00592d76367c9f6698ff0e3702cf2d389d3ebd9f564ab7cb67acc6a49dedc", False),
    "createrepo_c": ("createrepo_c-1.2.1-3.fc43.x86_64.rpm", "1.2.1", "3.fc43", "x86_64", 78187, "b46d9b26bb67df14e7132cfddd1420ac17652e142cec3f291f9abd4c627c2876", False),
    "createrepo_c-libs": ("createrepo_c-libs-1.2.1-3.fc43.x86_64.rpm", "1.2.1", "3.fc43", "x86_64", 113640, "d1df01e1a1b4992d68bd26a7f85feb800ef053073a79af0c1c5ddfdc20670348", False),
    "gh": ("gh-2.87.3-1.fc43.x86_64.rpm", "2.87.3", "1.fc43", "x86_64", 11526853, "a5d23ea024e4dfda6522693c3446c874961ddf2fb2c65b327d75f277435fa279", False),
    "git-core": ("git-core-2.56.0-1.fc43.x86_64.rpm", "2.56.0", "1.fc43", "x86_64", 5965667, "6aa10d035b4cd3e431983fe2ee2d6438346e98751c08537571f6fa42fbc8b318", False),
    "gnupg2": ("gnupg2-2.4.9-5.fc43.x86_64.rpm", "2.4.9", "5.fc43", "x86_64", 1715869, "1a2890c505f5f9b7ba56d2401077626ca7bcecf3656e65ecf8d8213f0ac9ce55", True),
    "libalpm": ("libalpm-7.0.0-5.fc43.x86_64.rpm", "7.0.0", "5.fc43", "x86_64", 283126, "c89219442886ba27e39b239eec458531af9d7bf77e17a1e37477b11aee0e6bd3", False),
    "libarchive": ("libarchive-3.8.4-1.fc43.x86_64.rpm", "3.8.4", "1.fc43", "x86_64", 432792, "3a4e745c98f0765c3b2ba4d5c9563defd23787cfad2d0065a7f1cd616e63beec", True),
    "pacman": ("pacman-7.0.0-5.fc43.x86_64.rpm", "7.0.0", "5.fc43", "x86_64", 789989, "20554352bb5397d1860d6df1a87e4ca972d4e708db13054cf1d3a2e7c0a243d6", False),
    "pacman-filesystem": ("pacman-filesystem-7.0.0-5.fc43.noarch.rpm", "7.0.0", "5.fc43", "noarch", 8125, "175599f9f9b4813d0b246dd4f17ea67506d17f34f06652f7a3ee88db6c619d08", False),
    "python3": ("python3-3.14.8-1.fc43.x86_64.rpm", "3.14.8", "1.fc43", "x86_64", 30117, "8b694a1cf2b705a6b1a8d2d23af65762eb37d066fd163fe6280fd4de0af7830a", False),
    "rpm-sign": ("rpm-sign-6.0.2-1.fc43.x86_64.rpm", "6.0.2", "1.fc43", "x86_64", 19948, "db398e82a2f788f8125cae2f713aca891f18c4a6858022ea6f166fc067272923", False),
}

BASE_RESIDENT_PROOFS: dict[str, dict[str, Any]] = {
    "gnupg2": {
        "version": "2.4.9",
        "release": "5.fc43",
        "rpm_sha256": "1a2890c505f5f9b7ba56d2401077626ca7bcecf3656e65ecf8d8213f0ac9ce55",
        "present_members": 66,
        "differing_members": 0,
        "critical_binary_path": "/usr/bin/gpg",
        "critical_binary_bytes": 1174728,
        "critical_binary_sha256": "ec13668738f91ce37f62402e39f70712ac068818eeaa7c442a6d366d63e7227b",
    },
    "libarchive": {
        "version": "3.8.4",
        "release": "1.fc43",
        "rpm_sha256": "3a4e745c98f0765c3b2ba4d5c9563defd23787cfad2d0065a7f1cd616e63beec",
        "present_members": 7,
        "differing_members": 0,
        "critical_binary_path": "/usr/lib64/libarchive.so.13.8.4",
        "critical_binary_bytes": 911208,
        "critical_binary_sha256": "167ad42f7156300350c170627724c2287727909d1bf3937d8475252025b06c40",
    },
}

REQUIRED_TOOL_PATHS: dict[str, str] = {
    "gpg": "/usr/bin/gpg",
    "gpg-agent": "/usr/bin/gpg-agent",
    "gpgconf": "/usr/bin/gpgconf",
    "rpm": "/usr/bin/rpm",
}

REQUIRED_TOOL_PINS: dict[str, tuple[str, int, str, str, tuple[str, str, str, str, str]]] = {
    "gpg": (
        "/usr/bin/gpg",
        1174728,
        "ec13668738f91ce37f62402e39f70712ac068818eeaa7c442a6d366d63e7227b",
        "gpg (GnuPG) 2.4.9",
        ("gnupg2", "0", "2.4.9", "5.fc43", "x86_64"),
    ),
    "gpg-agent": (
        "/usr/bin/gpg-agent",
        380064,
        "be481bf611257876e7d08d93130799220f7228f25a1992ebfe343a682225bc43",
        "gpg-agent (GnuPG) 2.4.9",
        ("gnupg2-gpg-agent", "0", "2.4.9", "5.fc43", "x86_64"),
    ),
    "gpgconf": (
        "/usr/bin/gpgconf",
        116608,
        "180cdd16f173dabd202e2319a603cefa906c8f69fb848d0bcebc740d4e672d83",
        "gpgconf (GnuPG) 2.4.9",
        ("gnupg2-gpgconf", "0", "2.4.9", "5.fc43", "x86_64"),
    ),
    "rpm": (
        "/usr/bin/rpm",
        20280,
        "692dfcb4e01fd6035ad7462b27c9623f13f8ed8e9f7a1e0a799a0a2c2a672125",
        "RPM version 6.0.2",
        ("rpm", "0", "6.0.2", "1.fc43", "x86_64"),
    ),
}


def relative_notice_path(retained_file: str) -> str:
    prefix = "upstream-notices/"
    if not isinstance(retained_file, str) or not retained_file.startswith(prefix):
        raise ValueError(f"Unexpected retained notice path: {retained_file!r}")
    return retained_file[len(prefix):]


def context_filename_for_notice(retained_file: str) -> str:
    return retained_file.replace("/", "__")


def container_notice_path(retained_file: str) -> str:
    return f"{SUPPLEMENTAL_NOTICE_DIR_IN_CONTAINER}/{relative_notice_path(retained_file)}"


NOTICE_CONTEXT_FILENAMES: dict[str, str] = {
    retained_file: context_filename_for_notice(retained_file)
    for retained_file in sorted(UPSTREAM_NOTICE_PINS)
}
NOTICE_CONTAINER_SUBDIRS: tuple[str, ...] = tuple(
    sorted(
        {
            f"{SUPPLEMENTAL_NOTICE_DIR_IN_CONTAINER}/{rel.split('/', 1)[0]}"
            for rel in (relative_notice_path(k) for k in UPSTREAM_NOTICE_PINS)
            if "/" in rel
        }
    )
)
ALLOWED_CONTEXT_FILENAMES: frozenset[str] = frozenset(
    {
        "Dockerfile",
        FEDORA_CERT_CONTEXT_FILENAME,
        SUPPLEMENTAL_NOTICE_CONTEXT_FILENAME,
        *QUARANTINE_ARCHIVES,
        *NOTICE_CONTEXT_FILENAMES.values(),
    }
)
ALLOWED_BUILDER_ENV_KEYS: frozenset[str] = frozenset({"PATH", "LC_ALL", "LANG"})

_FORBIDDEN_ENV_PREFIXES = (
    "GIT_",
    "GITHUB_",
    "ACTIONS_",
    "RUNNER_",
    "GPG_",
    "GNUPG",
    "PACKAGE_SIGNING_",
    "DOCKER_",
)
_FORBIDDEN_ENV_NAMES = frozenset({"GH_TOKEN", "GITHUB_TOKEN", "GPG_AGENT_INFO", "SSH_AUTH_SOCK"})
_FORBIDDEN_RECIPE_TOKENS = (
    "HTTP://",
    "HTTPS://",
    "FTP://",
    "CURL",
    "WGET",
    "--ENABLEREPO",
    "MAKECACHE",
    "--REFRESH",
    ":LATEST",
    "INSTALL_WEAK_DEPS=TRUE",
    "GPGCHECK=0",
    "GPGCHECK=FALSE",
    "LOCALPKG_GPGCHECK=0",
    "LOCALPKG_GPGCHECK=FALSE",
    "SECRET",
    "TOKEN",
    "PRIVATE_KEY",
    "PASSWORD",
    "PASSPHRASE",
)
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RUN_SUFFIX_RE = re.compile(r"^[0-9]{1,20}$")
_LOCAL_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RETAINED_BUILD_CUSTODY: list[dict[str, Any]] = []

_STDLIB_POPEN = subprocess.Popen
_STDLIB_UNAME = os.uname
_STDLIB_KILLPG = os.killpg


class ImageBuildError(RuntimeError):
    """Fixed-code builder refusal; never embeds raw paths, argv, logs, or secret material."""

    def __init__(self, code: str, message: str, *, custody_retained: bool = False):
        self.code = code
        self.reason = message
        self.custody_retained = custody_retained
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class ToolPin:
    name: str
    path: str
    bytes: int
    sha256: str
    version: str
    owner_package: tuple[str, str, str, str, str] = ("", "", "", "", "")


@dataclass(frozen=True)
class AdmissionManifest:
    manifest_sha256: str
    recipe_sha256: str
    container_python: str
    tool_pins: Mapping[str, ToolPin]
    base_metadata_sha256: str = BASE_METADATA_SHA256
    supplemental_notice_pins_sha256: str = UPSTREAM_NOTICE_PINS_SHA256


@dataclass(frozen=True)
class EngineStepReceipt:
    step: str
    exit_code: int
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str

    def record(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "exit_code": self.exit_code,
            "stdout_bytes": self.stdout_bytes,
            "stdout_sha256": self.stdout_sha256,
            "stderr_bytes": self.stderr_bytes,
            "stderr_sha256": self.stderr_sha256,
        }


@dataclass(frozen=True)
class InspectedTool:
    path: str
    bytes: int
    sha256: str
    version: str


@dataclass(frozen=True)
class ImageInspectionReport:
    image_id: str
    container_python_ok: bool
    stage_dir_absent: bool
    workspace_owner_ok: bool
    supplemental_notices_ok: bool
    tools: Mapping[str, InspectedTool]
    step_receipt: EngineStepReceipt
    supplemental_notice_pins_sha256: str = ""


@dataclass(frozen=True)
class BuildCommandPlan:
    run_id_suffix: str
    build_tag: str
    probe_container_name: str
    check_tag_argv: tuple[str, ...]
    check_container_argv: tuple[str, ...]
    pull_argv: tuple[str, ...]
    inspect_base_argv: tuple[str, ...]
    build_argv: tuple[str, ...]
    inspect_built_argv: tuple[str, ...]
    rm_container_argv: tuple[str, ...]
    rmi_tag_argv: tuple[str, ...]
    check_image_ids_argv: tuple[str, ...] = (
        DOCKER_BINARY,
        "image",
        "ls",
        "--all",
        "--no-trunc",
        "--quiet",
    )

    def probe_argv(self, image_id: str) -> tuple[str, ...]:
        return (
            DOCKER_BINARY,
            "run",
            "--rm",
            "-i",
            "--pull",
            "never",
            "--name",
            self.probe_container_name,
            "--network",
            "none",
            "--read-only",
            "--user",
            f"{WORKER_RUNTIME_UID}:{WORKER_RUNTIME_GID}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            require_local_image_id(image_id),
            CONTAINER_PYTHON_PATH,
            "-I",
            "-B",
            "-c",
            _CONTAINER_PROBE_CODE,
        )


@dataclass(frozen=True)
class ImageBuildResult:
    status: str
    execution_mode: str
    manifest_sha256: str
    recipe_sha256: str
    image_id: str
    container_python: str
    tool_digests: Mapping[str, str]
    tool_bytes: Mapping[str, int]
    tool_versions: Mapping[str, str]
    step_receipts: tuple[EngineStepReceipt, ...]
    context_cleaned: bool
    custody_retained: bool
    retained_custody_count: int
    native_execution_observed: bool
    native_ready_for_host_controller: bool
    build_tag: str = ""
    built_image_retained_for_host_controller: bool = True
    image_disposal_obligation: str = IMAGE_DISPOSAL_OBLIGATION
    image_runtime_class_admitted: bool = False
    native_qualification_satisfied: bool = False
    license_clearance_admitted: bool = False
    signing_authority: bool = False
    publication_authority: bool = False

    def receipt(self) -> dict[str, Any]:
        return {
            "schema": BUILD_RECEIPT_SCHEMA,
            "status": self.status,
            "execution_mode": self.execution_mode,
            "base_image_digest": APPROVED_BASE_IMAGE_DIGEST,
            "manifest_sha256": self.manifest_sha256,
            "recipe_sha256": self.recipe_sha256,
            "quarantine_sha256": QUARANTINE_SHA256,
            "roots_sha256": ROOTS_SHA256,
            "base_root_proof_sha256": BASE_ROOT_PROOF_SHA256,
            "base_metadata_sha256": BASE_METADATA_SHA256,
            "base_metadata_source_commit": BASE_METADATA_SOURCE_COMMIT,
            "base_metadata_source_run": BASE_METADATA_SOURCE_RUN,
            "cpio_verified_sha256": CPIO_VERIFIED_SHA256,
            "certificate_sha256": FEDORA_CERT_SHA256,
            "certificate_bytes": FEDORA_CERT_BYTES,
            "certificate_fingerprint": FEDORA_CERT_FINGERPRINT,
            "certificate_metadata_sha256": FEDORA_CERT_METADATA_SHA256,
            "original_bundle_sha256": FEDORA_ORIGINAL_BUNDLE_SHA256,
            "selected_binary_sha256": FEDORA_SELECTED_BINARY_SHA256,
            "selection_proof_sha256": FEDORA_SELECTION_PROOF_SHA256,
            "supplemental_notice_pins_sha256": UPSTREAM_NOTICE_PINS_SHA256,
            "vendor_byte_join_sha256": VENDOR_BYTE_JOIN_SHA256,
            "pip_inspection_sha256": PIP_INSPECTION_SHA256,
            "supplemental_notice_count": SUPPLEMENTAL_NOTICE_TOTAL_FILES,
            "supplemental_notice_bytes": SUPPLEMENTAL_NOTICE_TOTAL_BYTES,
            "supplemental_notice_dir": SUPPLEMENTAL_NOTICE_DIR_IN_CONTAINER,
            "source_quarantine_run": SOURCE_QUARANTINE_RUN,
            "archive_count": len(QUARANTINE_ARCHIVES),
            "total_archive_bytes": TOTAL_QUARANTINE_BYTES,
            "root_count": len(EXPECTED_ROOTS),
            "downloaded_root_count": 10,
            "base_resident_root_count": 2,
            "cpio_member_count": CPIO_TOTAL_MEMBERS,
            "context_file_count": len(ALLOWED_CONTEXT_FILENAMES),
            "image_id": self.image_id,
            "build_tag": self.build_tag,
            "container_python": self.container_python,
            "tool_digests": dict(self.tool_digests),
            "tool_bytes": dict(self.tool_bytes),
            "tool_versions": dict(self.tool_versions),
            "step_count": len(self.step_receipts),
            "steps": [s.record() for s in self.step_receipts],
            "context_cleaned": self.context_cleaned,
            "built_image_retained_for_host_controller": self.built_image_retained_for_host_controller,
            "image_disposal_obligation": self.image_disposal_obligation,
            "custody_retained": self.custody_retained,
            "retained_custody_count": self.retained_custody_count,
            "proposed_build_privilege_purpose": PROPOSED_PRIVILEGE_PURPOSE,
            "privilege_purpose_admitted": False,
            "license_clearance_admitted": False,
            "native_execution_observed": self.native_execution_observed,
            "native_ready_for_host_controller": self.native_ready_for_host_controller,
            "image_runtime_class_admitted": False,
            "native_qualification_satisfied": False,
            "signing_authority": False,
            "publication_authority": False,
        }


class ImageBuildEngine(Protocol):
    is_genuine_native_engine: bool

    def verify_targets_absent(self, plan: BuildCommandPlan, *, check_tag: bool = True) -> None: ...
    def pull_base_image(self, plan: BuildCommandPlan) -> EngineStepReceipt: ...
    def inspect_base_image(self, plan: BuildCommandPlan) -> tuple[str, EngineStepReceipt]: ...
    def build_image(self, plan: BuildCommandPlan, context_dir: Path) -> EngineStepReceipt: ...
    def inspect_built_image(self, plan: BuildCommandPlan) -> tuple[str, EngineStepReceipt]: ...
    def inspect_tools(self, plan: BuildCommandPlan, image_id: str) -> ImageInspectionReport: ...
    def remove_container(self, plan: BuildCommandPlan) -> bool: ...
    def remove_image(self, argv: tuple[str, ...]) -> bool: ...
    def confirm_image_id_absent(self, image_id: str) -> bool: ...


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1_hex(data: bytes) -> str:
    header = f"blob {len(data)}\x00".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _openpgp_crc24(data: bytes) -> int:
    value = 0xB704CE
    for byte in data:
        value ^= byte << 16
        for _ in range(8):
            value <<= 1
            if value & 0x1000000:
                value ^= 0x1864CFB
    return value & 0xFFFFFF


def _openpgp_public_packets(data: bytes) -> list[tuple[int, bytes]]:
    position = 0
    packets: list[tuple[int, bytes]] = []
    while position < len(data):
        first = data[position]
        position += 1
        if not (first & 128):
            raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Invalid OpenPGP packet header")
        if first & 64:
            tag = first & 63
            if position >= len(data):
                raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Truncated OpenPGP packet length")
            byte = data[position]
            position += 1
            if byte < 192:
                length = byte
            elif byte < 224:
                if position >= len(data):
                    raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Truncated 2-octet packet length")
                length = ((byte - 192) << 8) + data[position] + 192
                position += 1
            elif byte == 255:
                if position + 4 > len(data):
                    raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Truncated 5-octet packet length")
                length = int.from_bytes(data[position : position + 4], "big")
                position += 4
            else:
                raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Partial OpenPGP packet length forbidden")
        else:
            tag = (first >> 2) & 15
            kind = first & 3
            if kind == 3:
                raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Indeterminate OpenPGP packet length forbidden")
            count = 1 << kind
            if position + count > len(data):
                raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Truncated old-format packet length")
            length = int.from_bytes(data[position : position + count], "big")
            position += count
        if tag not in {2, 6, 13, 14, 17}:
            raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Non-public OpenPGP packet tag forbidden")
        if not (0 < length <= 65535) or position + length > len(data):
            raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "OpenPGP packet body out of bounds")
        body = data[position : position + length]
        position += length
        packets.append((tag, body))
    if not packets:
        raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Empty OpenPGP packet stream")
    return packets


def _openpgp_v4_fingerprint(pubkey_body: bytes) -> str:
    if not pubkey_body or pubkey_body[0] != 4:
        raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Primary public key packet must be OpenPGP v4")
    return hashlib.sha1(b"\x99" + len(pubkey_body).to_bytes(2, "big") + pubkey_body).hexdigest().upper()


def verify_selected_fedora_certificate_bytes(cert_bytes: bytes) -> None:
    """Verify the selected 1672-byte ASCII-armored Fedora 43 primary public certificate in pure stdlib."""
    if (
        not isinstance(cert_bytes, bytes)
        or len(cert_bytes) != FEDORA_CERT_BYTES
        or sha256_hex(cert_bytes) != FEDORA_CERT_SHA256
        or b"\r" in cert_bytes
        or b"\x00" in cert_bytes
        or b"PRIVATE KEY" in cert_bytes.upper()
        or not cert_bytes.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n")
        or not cert_bytes.endswith(b"\n-----END PGP PUBLIC KEY BLOCK-----\n")
    ):
        raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Public Fedora 43 certificate bytes or armor invalid")
    lines = cert_bytes.splitlines()
    if len(lines) < 5 or lines[0] != b"-----BEGIN PGP PUBLIC KEY BLOCK-----" or lines[1] != b"" or not lines[-2].startswith(b"="):
        raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "ASCII-armored OpenPGP certificate framing invalid")
    try:
        binary_data = base64.b64decode(b"".join(lines[2:-2]), validate=True)
        crc_bytes = base64.b64decode(lines[-2][1:], validate=True)
    except ValueError as error:
        raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Base64 or CRC24 decoding failed") from error
    if (
        len(binary_data) != FEDORA_SELECTED_BINARY_BYTES
        or sha256_hex(binary_data) != FEDORA_SELECTED_BINARY_SHA256
        or crc_bytes != _openpgp_crc24(binary_data).to_bytes(3, "big")
    ):
        raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Selected certificate binary digest or CRC24 mismatch")
    packets = _openpgp_public_packets(binary_data)
    if (
        tuple(tag for tag, _ in packets) != FEDORA_SELECTED_PACKET_TAGS
        or sum(tag == 6 for tag, _ in packets) != 1
        or _openpgp_v4_fingerprint(packets[0][1]) != FEDORA_CERT_FINGERPRINT
    ):
        raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Selected certificate packet tags or fingerprint mismatch")


def require_nonzero_sha256(value: Any, code: str = "SHA256_FORMAT_INVALID") -> str:
    if type(value) is not str or not _HEX64.fullmatch(value) or value == UNADMITTED_MANIFEST_PIN:
        raise ImageBuildError(code, "Required digest must be a non-zero 64-character lowercase hex string")
    return value


def require_git_blob_sha1(value: Any, code: str = "GIT_BLOB_FORMAT_INVALID") -> str:
    if type(value) is not str or not _HEX40.fullmatch(value) or value == ("0" * 40):
        raise ImageBuildError(code, "Required Git blob digest must be a non-zero 40-character lowercase hex string")
    return value


def _admitted_pin_matches(manifest_sha256: str) -> bool:
    return (
        type(ADMITTED_MANIFEST_SHA256) is str
        and bool(_HEX64.fullmatch(ADMITTED_MANIFEST_SHA256))
        and ADMITTED_MANIFEST_SHA256 != UNADMITTED_MANIFEST_PIN
        and manifest_sha256 == ADMITTED_MANIFEST_SHA256
    )


def require_local_image_id(image_id: Any, code: str = "IMAGE_ID_INVALID") -> str:
    if type(image_id) is not str or not _LOCAL_IMAGE_ID_RE.fullmatch(image_id):
        raise ImageBuildError(code, "Observed image ID must match sha256:<64-hex>")
    digest_part = require_nonzero_sha256(image_id.split(":", 1)[1], code)
    if digest_part == APPROVED_BASE_IMAGE_DIGEST:
        raise ImageBuildError(code, "Built image ID must differ from the unmodified base image digest")
    return image_id


def _stable_stat(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
        info.st_uid,
        info.st_gid,
    )


def physical_dir(path: str | os.PathLike[str], label: str = "directory") -> Path:
    raw = os.fspath(path) if isinstance(path, (str, os.PathLike)) else ""
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or "\x00" in raw
        or "*" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise ImageBuildError("PHYSICAL_PATH_REQUIRED", f"{label} must be a physical absolute path")
    candidate = Path(raw)
    for item in (*reversed(candidate.parents), candidate):
        try:
            info = os.lstat(item)
        except OSError as error:
            raise ImageBuildError("PHYSICAL_PATH_MISSING", f"{label} does not exist") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ImageBuildError("PHYSICAL_DIR_REQUIRED", f"{label} and ancestors must be physical directories")
    return candidate


def held_unaliased_bytes(path: str | os.PathLike[str], *, max_bytes: int = MAX_ARCHIVE_FILE_BYTES) -> bytes:
    raw = os.fspath(path) if isinstance(path, (str, os.PathLike)) else ""
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or "\x00" in raw
        or "*" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise ImageBuildError("PHYSICAL_PATH_REQUIRED", "Source file path must be a physical absolute path")
    candidate = Path(raw)
    physical_dir(candidate.parent, "file parent")
    try:
        lstat_before = os.lstat(candidate)
    except OSError as error:
        raise ImageBuildError("SOURCE_FILE_MISSING", "Required source file is missing") from error
    if stat.S_ISLNK(lstat_before.st_mode) or not stat.S_ISREG(lstat_before.st_mode):
        raise ImageBuildError("REGULAR_SOURCE_REQUIRED", "Source file must be a regular non-symlink file")
    if lstat_before.st_nlink != 1:
        raise ImageBuildError("HARDLINK_SOURCE_FORBIDDEN", "Hardlinked source files are forbidden")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(candidate, flags)
    except OSError as error:
        raise ImageBuildError("SOURCE_FILE_OPEN", "Failed to open source file") from error
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ImageBuildError("HARDLINK_SOURCE_FORBIDDEN", "Opened file must be an unaliased regular file")
        if not 0 < before.st_size <= max_bytes:
            raise ImageBuildError("SOURCE_FILE_BOUND", "Source file size is out of bounds")
        data = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    try:
        lstat_after = os.lstat(candidate)
    except OSError as error:
        raise ImageBuildError("SOURCE_FILE_CHANGED", "Source file vanished after read") from error
    if (
        len(data) != before.st_size
        or len({_stable_stat(before), _stable_stat(after), _stable_stat(lstat_before), _stable_stat(lstat_after)}) != 1
    ):
        raise ImageBuildError("SOURCE_FILE_CHANGED", "Source file changed during held read")
    return data


def parse_strict_json(raw: bytes, error_code: str = "JSON_SCHEMA_INVALID") -> dict[str, Any]:
    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ImageBuildError(error_code, "Duplicate JSON key refused")
            out[key] = value
        return out

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except ImageBuildError:
        raise
    except (UnicodeError, ValueError) as error:
        raise ImageBuildError(error_code, "Malformed JSON payload") from error
    if not isinstance(parsed, dict):
        raise ImageBuildError(error_code, "JSON root must be an object")
    return parsed


def render_offline_dockerfile() -> str:
    """Render static offline recipe; --setopt=tsflags= clears container nodocs for 4551-member CPIO parity."""
    rpm_stage_paths = " \\\n    ".join(
        f"{STAGE_DIR_IN_CONTAINER}/{name}" for name in sorted(QUARANTINE_ARCHIVES)
    )
    notice_dirs = " \\\n    ".join(
        (SUPPLEMENTAL_NOTICE_DIR_IN_CONTAINER, *NOTICE_CONTAINER_SUBDIRS)
    )
    copy_lines = [
        f"COPY --chown=0:0 --chmod=0600 {FEDORA_CERT_CONTEXT_FILENAME} {STAGE_DIR_IN_CONTAINER}/{FEDORA_CERT_CONTEXT_FILENAME}",
        *(
            f"COPY --chown=0:0 --chmod=0600 {name} {STAGE_DIR_IN_CONTAINER}/{name}"
            for name in sorted(QUARANTINE_ARCHIVES)
        ),
        (
            f"COPY --chown=0:0 --chmod=0444 {SUPPLEMENTAL_NOTICE_CONTEXT_FILENAME} "
            f"{SUPPLEMENTAL_NOTICE_DIR_IN_CONTAINER}/{SUPPLEMENTAL_NOTICE_CONTEXT_FILENAME}"
        ),
        *(
            f"COPY --chown=0:0 --chmod=0444 {NOTICE_CONTEXT_FILENAMES[retained]} {container_notice_path(retained)}"
            for retained in sorted(UPSTREAM_NOTICE_PINS)
        ),
    ]
    run_block = (
        f"RUN if ! /usr/bin/rpm -q gpg-pubkey-31645531 >/dev/null 2>&1; then "
        f"/usr/bin/rpmkeys --import {STAGE_DIR_IN_CONTAINER}/{FEDORA_CERT_CONTEXT_FILENAME}; fi && \\\n"
        f"    /usr/bin/rpmkeys --checksig {rpm_stage_paths} && \\\n"
        f"    /usr/bin/dnf install -y --disablerepo=* --setopt=install_weak_deps=False "
        f"--setopt=gpgcheck=True --setopt=localpkg_gpgcheck=True --setopt=tsflags= \\\n"
        f"    {rpm_stage_paths} && \\\n"
        f"    /usr/bin/rm -rf {STAGE_DIR_IN_CONTAINER} && \\\n"
        f"    /usr/bin/dnf clean all --disablerepo=* && \\\n"
        f"    /usr/bin/chmod 0555 \\\n"
        f"    {notice_dirs} && \\\n"
        f"    /usr/bin/install -d -m 0755 -o 0 -g 0 /work /work/p /work/r && \\\n"
        f"    /usr/bin/install -d -m 0700 -o {WORKER_RUNTIME_UID} -g {WORKER_RUNTIME_GID} /work/export /work/workspace"
    )
    return "\n".join(
        [
            f"FROM {APPROVED_BASE_IMAGE}",
            "USER 0:0",
            f"RUN /usr/bin/install -d -m 0700 -o 0 -g 0 {STAGE_DIR_IN_CONTAINER} && \\\n"
            f"    /usr/bin/install -d -m 0755 -o 0 -g 0 \\\n"
            f"    {notice_dirs}",
            *copy_lines,
            run_block,
            "ENV HOME=/work/workspace PATH=/usr/bin:/bin LC_ALL=C LANG=C",
            "WORKDIR /work/workspace",
            f"USER {WORKER_RUNTIME_UID}:{WORKER_RUNTIME_GID}",
            "",
        ]
    )


EXPECTED_DOCKERFILE_TEXT = render_offline_dockerfile()
EXPECTED_DOCKERFILE_SHA256 = sha256_hex(EXPECTED_DOCKERFILE_TEXT.encode("utf-8"))

_CONTAINER_PROBE_CODE = "\n".join(
    [
        "import hashlib, json, os, stat, subprocess",
        "tools = {",
        "    'gpg': ('/usr/bin/gpg', ('--version',)),",
        "    'gpg-agent': ('/usr/bin/gpg-agent', ('--version',)),",
        "    'gpgconf': ('/usr/bin/gpgconf', ('--version',)),",
        "    'rpm': ('/usr/bin/rpm', ('--version',)),",
        "}",
        "out = {}",
        "for k, (p, a) in tools.items():",
        "    st = os.lstat(p)",
        "    assert stat.S_ISREG(st.st_mode), k",
        "    raw = open(p, 'rb').read()",
        "    cp = subprocess.run(",
        "        (p, *a),",
        "        stdin=subprocess.DEVNULL,",
        "        stdout=subprocess.PIPE,",
        "        stderr=subprocess.PIPE,",
        "        timeout=10,",
        "        check=True,",
        "    )",
        "    out[k] = {",
        "        'path': p,",
        "        'bytes': len(raw),",
        "        'sha256': hashlib.sha256(raw).hexdigest(),",
        "        'version': cp.stdout.decode('utf-8', 'replace').splitlines()[0].strip(),",
        "    }",
        "ws = os.lstat('/work/workspace')",
        "ex = os.lstat('/work/export')",
        f"nd_path = {SUPPLEMENTAL_NOTICE_DIR_IN_CONTAINER!r}",
        "nd = os.lstat(nd_path)",
        "pins_path = nd_path + '/UPSTREAM-NOTICE-PINS.json'",
        "ps = os.lstat(pins_path)",
        "pins_raw = open(pins_path, 'rb').read()",
        "pins_sha256 = hashlib.sha256(pins_raw).hexdigest()",
        "pins_doc = json.loads(pins_raw.decode('utf-8'))",
        "notices_ok = (",
        "    stat.S_ISDIR(nd.st_mode) and nd.st_uid == 0 and nd.st_gid == 0 and stat.S_IMODE(nd.st_mode) == 0o555",
        "    and stat.S_ISREG(ps.st_mode) and ps.st_uid == 0 and ps.st_gid == 0 and stat.S_IMODE(ps.st_mode) == 0o444",
        f"    and pins_sha256 == {UPSTREAM_NOTICE_PINS_SHA256!r}",
        "    and len(pins_doc.get('files', [])) == 23",
        ")",
        "for row in pins_doc.get('files', []):",
        "    rel = row['retainedFile'].split('/', 1)[1]",
        "    fp = nd_path + '/' + rel",
        "    fst = os.lstat(fp)",
        "    fraw = open(fp, 'rb').read()",
        "    fblob = hashlib.sha1(f'blob {len(fraw)}\\x00'.encode('ascii') + fraw).hexdigest()",
        "    dirst = os.lstat(os.path.dirname(fp))",
        "    notices_ok = (",
        "        notices_ok",
        "        and stat.S_ISREG(fst.st_mode) and fst.st_uid == 0 and fst.st_gid == 0",
        "        and stat.S_IMODE(fst.st_mode) == 0o444",
        "        and stat.S_ISDIR(dirst.st_mode) and dirst.st_uid == 0 and dirst.st_gid == 0",
        "        and stat.S_IMODE(dirst.st_mode) == 0o555",
        "        and len(fraw) == row['size']",
        "        and hashlib.sha256(fraw).hexdigest() == row['sha256']",
        "        and fblob == row['gitBlob']",
        "    )",
        "print(json.dumps({",
        "    'container_python_ok': True,",
        "    'stage_dir_absent': not os.path.exists('/tmp/tf-rpm-stage'),",
        "    'workspace_owner_ok': (ws.st_uid == 1001 and ws.st_gid == 1001 and ex.st_uid == 1001 and ex.st_gid == 1001),",
        "    'supplemental_notices_ok': bool(notices_ok),",
        "    'supplemental_notice_pins_sha256': pins_sha256,",
        "    'tools': out,",
        "}))",
    ]
)


def validate_offline_dockerfile(dockerfile_text: str) -> str:
    if type(dockerfile_text) is not str or "\x00" in dockerfile_text:
        raise ImageBuildError("RECIPE_INVALID", "Dockerfile text must be a non-NUL string")
    upper_text = dockerfile_text.upper()
    if any(tok in upper_text for tok in _FORBIDDEN_RECIPE_TOKENS):
        raise ImageBuildError(
            "RECIPE_FORBIDDEN_DIRECTIVE",
            "Dockerfile contains forbidden network, repo, or secret token",
        )
    if dockerfile_text != EXPECTED_DOCKERFILE_TEXT:
        raise ImageBuildError("RECIPE_DIGEST_MISMATCH", "Dockerfile differs from exact approved offline recipe")
    return EXPECTED_DOCKERFILE_SHA256


def validate_builder_env(env_map: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(env_map, Mapping):
        raise ImageBuildError("BUILDER_ENV_INVALID", "Environment must be a mapping")
    cleaned: dict[str, str] = {}
    for key, val in env_map.items():
        if (
            type(key) is not str
            or type(val) is not str
            or "\x00" in key
            or "\x00" in val
            or key in _FORBIDDEN_ENV_NAMES
            or key.startswith(_FORBIDDEN_ENV_PREFIXES)
            or key not in ALLOWED_BUILDER_ENV_KEYS
        ):
            raise ImageBuildError(
                "BUILDER_ENV_CREDENTIAL_LEAK",
                "Forbidden or unapproved environment variable in builder",
            )
        cleaned[key] = val
    return {"PATH": cleaned.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"}


def _validate_base_metadata_manifest_section(meta: Any) -> None:
    required_keys = {
        "schema",
        "proof_sha256",
        "base_image",
        "source_commit",
        "source_run",
        "status",
        "candidate_packages_installed",
        "signing_credentials_accessed",
        "production_acceptance",
        "container_cleanup_confirmed",
        "retained_container_count",
        "uncertain_creation_count",
        "outputs",
    }
    if (
        not isinstance(meta, dict)
        or set(meta) != required_keys
        or meta.get("schema") != BASE_METADATA_SCHEMA
        or require_nonzero_sha256(meta.get("proof_sha256"), "BASE_METADATA_PROOF_INVALID") != BASE_METADATA_SHA256
        or meta.get("base_image") != APPROVED_BASE_IMAGE
        or meta.get("source_commit") != BASE_METADATA_SOURCE_COMMIT
        or type(meta.get("source_run")) is not int
        or meta.get("source_run") != BASE_METADATA_SOURCE_RUN
        or meta.get("status") != "pass"
        or meta.get("candidate_packages_installed") is not False
        or meta.get("signing_credentials_accessed") is not False
        or meta.get("production_acceptance") is not False
        or meta.get("container_cleanup_confirmed") is not True
        or type(meta.get("retained_container_count")) is not int
        or meta.get("retained_container_count") != 0
        or type(meta.get("uncertain_creation_count")) is not int
        or meta.get("uncertain_creation_count") != 0
        or not isinstance(meta.get("outputs"), dict)
        or set(meta["outputs"]) != set(BASE_METADATA_OUTPUTS)
    ):
        raise ImageBuildError("BASE_METADATA_PROOF_INVALID", "Manifest base_metadata_proof missing or invalid")
    for family, (exp_bytes, exp_rows, exp_sha) in BASE_METADATA_OUTPUTS.items():
        row = meta["outputs"].get(family)
        if (
            not isinstance(row, dict)
            or set(row) != {"bytes", "rows", "sha256"}
            or type(row.get("bytes")) is not int
            or row.get("bytes") != exp_bytes
            or type(row.get("rows")) is not int
            or row.get("rows") != exp_rows
            or require_nonzero_sha256(row.get("sha256"), "BASE_METADATA_PROOF_INVALID") != exp_sha
        ):
            raise ImageBuildError("BASE_METADATA_PROOF_INVALID", f"Base metadata output mismatch for {family}")


def _validate_supplemental_notices_manifest_section(notices: Any) -> None:
    required_keys = {
        "schema",
        "notice_pins_sha256",
        "vendor_byte_join_sha256",
        "inspection_sha256",
        "repository",
        "tag",
        "upstream_commit",
        "package",
        "wheel_sha256",
        "total_vendor_files",
        "exact_matched_vendor_files",
        "fedora_modified_vendor_files",
        "container_notice_dir",
        "notice_file_count",
        "total_notice_bytes",
        "license_clearance_admitted",
        "files",
    }
    if (
        not isinstance(notices, dict)
        or set(notices) != required_keys
        or notices.get("schema") != SUPPLEMENTAL_NOTICE_SCHEMA
        or require_nonzero_sha256(notices.get("notice_pins_sha256"), "SUPPLEMENTAL_NOTICE_INVALID")
        != UPSTREAM_NOTICE_PINS_SHA256
        or require_nonzero_sha256(notices.get("vendor_byte_join_sha256"), "SUPPLEMENTAL_NOTICE_INVALID")
        != VENDOR_BYTE_JOIN_SHA256
        or require_nonzero_sha256(notices.get("inspection_sha256"), "SUPPLEMENTAL_NOTICE_INVALID")
        != PIP_INSPECTION_SHA256
        or notices.get("repository") != PIP_UPSTREAM_REPOSITORY
        or notices.get("tag") != PIP_UPSTREAM_TAG
        or notices.get("upstream_commit") != PIP_UPSTREAM_COMMIT
        or notices.get("package") != PIP_WHEEL_PACKAGE
        or require_nonzero_sha256(notices.get("wheel_sha256"), "SUPPLEMENTAL_NOTICE_INVALID") != PIP_WHEEL_SHA256
        or type(notices.get("total_vendor_files")) is not int
        or notices.get("total_vendor_files") != PIP_VENDOR_TOTAL_FILES
        or type(notices.get("exact_matched_vendor_files")) is not int
        or notices.get("exact_matched_vendor_files") != PIP_VENDOR_EXACT_MATCHED_FILES
        or notices.get("fedora_modified_vendor_files") != list(PIP_VENDOR_FEDORA_MODIFIED_FILES)
        or notices.get("container_notice_dir") != SUPPLEMENTAL_NOTICE_DIR_IN_CONTAINER
        or type(notices.get("notice_file_count")) is not int
        or notices.get("notice_file_count") != SUPPLEMENTAL_NOTICE_TOTAL_FILES
        or type(notices.get("total_notice_bytes")) is not int
        or notices.get("total_notice_bytes") != SUPPLEMENTAL_NOTICE_TOTAL_BYTES
        or notices.get("license_clearance_admitted") is not False
        or not isinstance(notices.get("files"), dict)
        or set(notices["files"]) != set(UPSTREAM_NOTICE_PINS)
    ):
        raise ImageBuildError("SUPPLEMENTAL_NOTICE_INVALID", "Manifest supplemental_notices section invalid")
    for retained_file, (exp_up_path, exp_blob, exp_size, exp_sha) in UPSTREAM_NOTICE_PINS.items():
        entry = notices["files"].get(retained_file)
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "git_blob", "bytes", "sha256", "context_filename", "container_path"}
            or entry.get("path") != exp_up_path
            or require_git_blob_sha1(entry.get("git_blob"), "SUPPLEMENTAL_NOTICE_INVALID") != exp_blob
            or type(entry.get("bytes")) is not int
            or entry.get("bytes") != exp_size
            or require_nonzero_sha256(entry.get("sha256"), "SUPPLEMENTAL_NOTICE_INVALID") != exp_sha
            or entry.get("context_filename") != NOTICE_CONTEXT_FILENAMES[retained_file]
            or entry.get("container_path") != container_notice_path(retained_file)
        ):
            raise ImageBuildError(
                "SUPPLEMENTAL_NOTICE_INVALID",
                f"Supplemental notice pin mismatch for {retained_file}",
            )


def authenticate_admission_manifest(
    manifest_path: str | os.PathLike[str],
    *,
    expected_manifest_sha256: str = ADMITTED_MANIFEST_SHA256,
) -> tuple[AdmissionManifest, bytes]:
    expected_pin = require_nonzero_sha256(expected_manifest_sha256, "MANIFEST_PIN_INVALID")
    raw = held_unaliased_bytes(manifest_path, max_bytes=MAX_SMALL_SOURCE_BYTES)
    actual_sha = sha256_hex(raw)
    if actual_sha != expected_pin:
        raise ImageBuildError("MANIFEST_DIGEST_MISMATCH", "Admission manifest SHA-256 does not match caller pin")
    doc = parse_strict_json(raw, "MANIFEST_SCHEMA_INVALID")
    required_top = {
        "schema",
        "status",
        "production_authority",
        "signing_credentials_present",
        "base_image",
        "source_quarantine_run",
        "quarantine_sha256",
        "roots_sha256",
        "cpio_verified_sha256",
        "cpio_member_count",
        "recipe_sha256",
        "container_python",
        "fedora_certificate",
        "base_root_byte_identity_proof",
        "base_metadata_proof",
        "supplemental_notices",
        "archives",
        "roots",
        "required_tools",
    }
    if set(doc) != required_top or doc.get("schema") != ADMISSION_MANIFEST_SCHEMA:
        raise ImageBuildError("MANIFEST_SCHEMA_INVALID", "Admission manifest field set or schema is not closed")
    if doc.get("status") != ADMISSION_MANIFEST_STATUS:
        raise ImageBuildError("MANIFEST_STATUS_UNADMITTED", "Admission manifest status is not admitted")
    if doc.get("production_authority") is not False or doc.get("signing_credentials_present") is not False:
        raise ImageBuildError("MANIFEST_AUTHORITY_INVALID", "Manifest authority or credential flags invalid")
    if doc.get("base_image") != APPROVED_BASE_IMAGE:
        raise ImageBuildError("BASE_IMAGE_MISMATCH", "Manifest base image does not match approved Fedora 43 digest")
    if (
        type(doc.get("source_quarantine_run")) is not int
        or doc["source_quarantine_run"] != SOURCE_QUARANTINE_RUN
        or require_nonzero_sha256(doc.get("quarantine_sha256"), "SOURCE_PROOF_BINDING_MISMATCH") != QUARANTINE_SHA256
        or require_nonzero_sha256(doc.get("roots_sha256"), "SOURCE_PROOF_BINDING_MISMATCH") != ROOTS_SHA256
        or require_nonzero_sha256(doc.get("cpio_verified_sha256"), "SOURCE_PROOF_BINDING_MISMATCH")
        != CPIO_VERIFIED_SHA256
        or type(doc.get("cpio_member_count")) is not int
        or doc["cpio_member_count"] != CPIO_TOTAL_MEMBERS
    ):
        raise ImageBuildError("SOURCE_PROOF_BINDING_MISMATCH", "Quarantine, roots, or CPIO proof binding mismatch")
    recipe_sha = require_nonzero_sha256(doc.get("recipe_sha256"), "RECIPE_DIGEST_MISMATCH")
    if recipe_sha != EXPECTED_DOCKERFILE_SHA256:
        raise ImageBuildError("RECIPE_DIGEST_MISMATCH", "Manifest recipe_sha256 does not match offline Dockerfile")
    if doc.get("container_python") != CONTAINER_PYTHON_PATH:
        raise ImageBuildError("CONTAINER_PYTHON_INVALID", "Manifest container_python must be /usr/bin/python3")

    cert = doc.get("fedora_certificate")
    required_cert_keys = {
        "schema",
        "primary_fingerprint",
        "bytes",
        "sha256",
        "context_filename",
        "metadata_sha256",
        "selection_proof_sha256",
        "derived_from",
    }
    if (
        not isinstance(cert, dict)
        or set(cert) != required_cert_keys
        or cert.get("schema") != FEDORA_CERT_SCHEMA
        or cert.get("primary_fingerprint") != FEDORA_CERT_FINGERPRINT
        or type(cert.get("bytes")) is not int
        or cert.get("bytes") != FEDORA_CERT_BYTES
        or require_nonzero_sha256(cert.get("sha256"), "CERTIFICATE_METADATA_MISMATCH") != FEDORA_CERT_SHA256
        or cert.get("context_filename") != FEDORA_CERT_CONTEXT_FILENAME
        or require_nonzero_sha256(cert.get("metadata_sha256"), "CERTIFICATE_METADATA_MISMATCH")
        != FEDORA_CERT_METADATA_SHA256
        or require_nonzero_sha256(cert.get("selection_proof_sha256"), "CERTIFICATE_METADATA_MISMATCH")
        != FEDORA_SELECTION_PROOF_SHA256
    ):
        raise ImageBuildError("CERTIFICATE_METADATA_MISMATCH", "Fedora 43 public certificate metadata mismatch")
    derived = cert.get("derived_from")
    if (
        not isinstance(derived, dict)
        or set(derived)
        != {
            "source_url",
            "bundle_bytes",
            "bundle_sha256",
            "selected_binary_bytes",
            "selected_binary_sha256",
            "packet_tags",
            "byte_identical_selection",
            "armor_crc24_verified",
        }
        or derived.get("source_url") != FEDORA_ORIGINAL_BUNDLE_SOURCE_URL
        or type(derived.get("bundle_bytes")) is not int
        or derived.get("bundle_bytes") != FEDORA_ORIGINAL_BUNDLE_BYTES
        or require_nonzero_sha256(derived.get("bundle_sha256"), "CERTIFICATE_METADATA_MISMATCH")
        != FEDORA_ORIGINAL_BUNDLE_SHA256
        or type(derived.get("selected_binary_bytes")) is not int
        or derived.get("selected_binary_bytes") != FEDORA_SELECTED_BINARY_BYTES
        or require_nonzero_sha256(derived.get("selected_binary_sha256"), "CERTIFICATE_METADATA_MISMATCH")
        != FEDORA_SELECTED_BINARY_SHA256
        or derived.get("packet_tags") != list(FEDORA_SELECTED_PACKET_TAGS)
        or derived.get("byte_identical_selection") is not True
        or derived.get("armor_crc24_verified") is not True
    ):
        raise ImageBuildError("CERTIFICATE_METADATA_MISMATCH", "Fedora 43 certificate derivation provenance mismatch")

    proof = doc.get("base_root_byte_identity_proof")
    if (
        not isinstance(proof, dict)
        or set(proof) != {"schema", "proof_sha256", "base_manifest_sha256", "roots"}
        or proof.get("schema") != "task.public-base-root-byte-identity.v1"
        or require_nonzero_sha256(proof.get("proof_sha256"), "BASE_ROOT_PROOF_INVALID") != BASE_ROOT_PROOF_SHA256
        or require_nonzero_sha256(proof.get("base_manifest_sha256"), "BASE_ROOT_PROOF_INVALID")
        != APPROVED_BASE_IMAGE_DIGEST
        or not isinstance(proof.get("roots"), dict)
        or set(proof["roots"]) != set(BASE_RESIDENT_PROOFS)
    ):
        raise ImageBuildError("BASE_ROOT_PROOF_INVALID", "Base-resident root byte-identity proof missing or invalid")
    for rname, expected_proof in BASE_RESIDENT_PROOFS.items():
        row = proof["roots"].get(rname)
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "version",
                "release",
                "rpm_sha256",
                "upstream_header_signature",
                "compressed_payload_digests",
                "present_members",
                "differing_members",
                "critical_binary_path",
                "critical_binary_bytes",
                "critical_binary_sha256",
            }
            or row.get("upstream_header_signature") != "passed"
            or row.get("compressed_payload_digests") != "passed"
            or any(row.get(k) != v for k, v in expected_proof.items())
        ):
            raise ImageBuildError("BASE_ROOT_PROOF_INVALID", f"Base-resident proof mismatch for {rname}")

    _validate_base_metadata_manifest_section(doc.get("base_metadata_proof"))
    _validate_supplemental_notices_manifest_section(doc.get("supplemental_notices"))

    archives = doc.get("archives")
    roots = doc.get("roots")
    tools_doc = doc.get("required_tools")
    if not isinstance(archives, dict) or set(archives) != set(QUARANTINE_ARCHIVES):
        raise ImageBuildError("ARCHIVE_INVENTORY_MISMATCH", "Manifest archives must match exact 30 quarantine RPMs")
    for fname, (exp_bytes, exp_sha) in QUARANTINE_ARCHIVES.items():
        entry = archives.get(fname)
        if (
            not isinstance(entry, dict)
            or set(entry) != {"bytes", "sha256"}
            or type(entry.get("bytes")) is not int
            or entry["bytes"] != exp_bytes
            or require_nonzero_sha256(entry.get("sha256"), "ARCHIVE_INVENTORY_MISMATCH") != exp_sha
        ):
            raise ImageBuildError("ARCHIVE_INVENTORY_MISMATCH", f"Archive digest or byte count mismatch for {fname}")

    if not isinstance(roots, dict) or set(roots) != set(EXPECTED_ROOTS):
        raise ImageBuildError("ROOT_ACCOUNTING_MISMATCH", "Manifest roots must account for all 12 runtime roots")
    for rname, (fname, ver, rel, arch, rbytes, rsha, base_res) in EXPECTED_ROOTS.items():
        rentry = roots.get(rname)
        if (
            not isinstance(rentry, dict)
            or set(rentry) != {"filename", "version", "release", "arch", "bytes", "sha256", "base_resident"}
            or rentry.get("filename") != fname
            or rentry.get("version") != ver
            or rentry.get("release") != rel
            or rentry.get("arch") != arch
            or type(rentry.get("bytes")) is not int
            or rentry["bytes"] != rbytes
            or require_nonzero_sha256(rentry.get("sha256"), "ROOT_ACCOUNTING_MISMATCH") != rsha
            or type(rentry.get("base_resident")) is not bool
            or rentry.get("base_resident") is not base_res
        ):
            raise ImageBuildError("ROOT_ACCOUNTING_MISMATCH", f"Root accounting mismatch for {rname}")

    if not isinstance(tools_doc, dict) or set(tools_doc) != set(REQUIRED_TOOL_PINS):
        raise ImageBuildError("TOOL_PIN_INVALID", "Manifest required_tools must match exact required tool set")
    pins: dict[str, ToolPin] = {}
    for tname, (exp_path, exp_bytes, exp_sha, exp_ver, exp_owner) in REQUIRED_TOOL_PINS.items():
        tentry = tools_doc.get(tname)
        if (
            not isinstance(tentry, dict)
            or set(tentry) != {"path", "bytes", "sha256", "version", "owner_package"}
            or tentry.get("path") != exp_path
            or type(tentry.get("bytes")) is not int
            or tentry["bytes"] != exp_bytes
            or type(tentry.get("version")) is not str
            or tentry["version"].strip() != exp_ver
            or "\x00" in tentry["version"]
            or tentry.get("owner_package") != list(exp_owner)
        ):
            raise ImageBuildError("TOOL_PIN_INVALID", f"Invalid tool pin entry for {tname}")
        tsha = require_nonzero_sha256(tentry.get("sha256"), "TOOL_PIN_INVALID")
        if tsha != exp_sha:
            raise ImageBuildError("TOOL_PIN_INVALID", f"Tool digest mismatch for {tname}")
        if tname == "gpg" and (
            tentry["bytes"] != BASE_RESIDENT_PROOFS["gnupg2"]["critical_binary_bytes"]
            or tsha != BASE_RESIDENT_PROOFS["gnupg2"]["critical_binary_sha256"]
        ):
            raise ImageBuildError("TOOL_PIN_INVALID", "gpg tool pin must match base-resident gnupg2 binary proof")
        pins[tname] = ToolPin(tname, exp_path, exp_bytes, tsha, exp_ver, exp_owner)

    return AdmissionManifest(actual_sha, recipe_sha, CONTAINER_PYTHON_PATH, pins), raw


def _measure_source(
    name: str,
    data: bytes,
    source_digest_fn: Callable[[str, bytes], tuple[int, str]] | None = None,
) -> tuple[int, str]:
    return (len(data), sha256_hex(data)) if source_digest_fn is None else source_digest_fn(name, data)


def _verify_physical_base_metadata_proof(metadata_bytes: bytes) -> None:
    if sha256_hex(metadata_bytes) != BASE_METADATA_SHA256:
        raise ImageBuildError("BASE_METADATA_PROOF_INVALID", "Base metadata proof file digest mismatch")
    doc = parse_strict_json(metadata_bytes, "BASE_METADATA_PROOF_INVALID")
    if (
        doc.get("schema") != BASE_METADATA_SCHEMA
        or doc.get("base_image") != APPROVED_BASE_IMAGE
        or doc.get("status") != "pass"
        or doc.get("error_code") is not None
        or doc.get("failure_phase") is not None
        or doc.get("candidate_packages_installed") is not False
        or doc.get("signing_credentials_accessed") is not False
        or doc.get("production_acceptance") is not False
        or doc.get("container_cleanup_confirmed") is not True
        or doc.get("retained_container_count") != 0
        or doc.get("uncertain_creation_count") != 0
        or doc.get("source_commit") != BASE_METADATA_SOURCE_COMMIT
        or type(doc.get("source_run")) is not int
        or doc.get("source_run") != BASE_METADATA_SOURCE_RUN
        or not isinstance(doc.get("outputs"), dict)
        or set(doc["outputs"]) != set(BASE_METADATA_OUTPUTS)
        or not isinstance(doc.get("query_facts"), dict)
        or set(doc["query_facts"]) != set(BASE_METADATA_OUTPUTS)
    ):
        raise ImageBuildError("BASE_METADATA_PROOF_INVALID", "Base metadata proof document failed verification")
    for family, (exp_bytes, exp_rows, exp_sha) in BASE_METADATA_OUTPUTS.items():
        out_row = doc["outputs"].get(family)
        qf_row = doc["query_facts"].get(family)
        if (
            not isinstance(out_row, dict)
            or out_row.get("bytes") != exp_bytes
            or out_row.get("rows") != exp_rows
            or out_row.get("sha256") != exp_sha
            or not isinstance(qf_row, dict)
            or qf_row.get("exit_code") != 0
            or qf_row.get("stderr_bytes") != 0
            or qf_row.get("stderr_sha256") != EMPTY_STREAM_SHA256
            or qf_row.get("stdout_bytes") != exp_bytes
            or qf_row.get("stdout_sha256") != exp_sha
        ):
            raise ImageBuildError("BASE_METADATA_PROOF_INVALID", f"Base metadata family {family} failed verification")


def _verify_physical_supplemental_notices(
    notice_manifest_bytes: bytes,
    supplemental_notice_dir: str | os.PathLike[str],
    *,
    source_digest_fn: Callable[[str, bytes], tuple[int, str]] | None = None,
) -> dict[str, bytes]:
    if sha256_hex(notice_manifest_bytes) != UPSTREAM_NOTICE_PINS_SHA256:
        raise ImageBuildError("SUPPLEMENTAL_NOTICE_INVALID", "Supplemental notice manifest digest mismatch")
    doc = parse_strict_json(notice_manifest_bytes, "SUPPLEMENTAL_NOTICE_INVALID")
    files_list = doc.get("files")
    if (
        set(doc) != {"repository", "tag", "commit", "files"}
        or doc.get("repository") != PIP_UPSTREAM_REPOSITORY
        or doc.get("tag") != PIP_UPSTREAM_TAG
        or doc.get("commit") != PIP_UPSTREAM_COMMIT
        or not isinstance(files_list, list)
        or len(files_list) != SUPPLEMENTAL_NOTICE_TOTAL_FILES
    ):
        raise ImageBuildError("SUPPLEMENTAL_NOTICE_INVALID", "Supplemental notice manifest structure mismatch")
    seen_retained: set[str] = set()
    for row in files_list:
        if not isinstance(row, dict) or set(row) != {"path", "gitBlob", "size", "sha256", "retainedFile", "sourceUrl"}:
            raise ImageBuildError("SUPPLEMENTAL_NOTICE_INVALID", "Supplemental notice row schema invalid")
        retained = row.get("retainedFile")
        if type(retained) is not str or retained in seen_retained or retained not in UPSTREAM_NOTICE_PINS:
            raise ImageBuildError("SUPPLEMENTAL_NOTICE_INVALID", "Supplemental notice retainedFile invalid")
        seen_retained.add(retained)
        exp_path, exp_blob, exp_size, exp_sha = UPSTREAM_NOTICE_PINS[retained]
        expected_url = f"https://github.com/{PIP_UPSTREAM_REPOSITORY}/blob/{PIP_UPSTREAM_COMMIT}/{exp_path}"
        if (
            row.get("path") != exp_path
            or row.get("gitBlob") != exp_blob
            or row.get("size") != exp_size
            or row.get("sha256") != exp_sha
            or row.get("sourceUrl") != expected_url
        ):
            raise ImageBuildError("SUPPLEMENTAL_NOTICE_INVALID", f"Supplemental notice pin mismatch for {retained}")

    notice_root = physical_dir(supplemental_notice_dir, "supplemental notice directory")
    expected_top_entries: set[str] = set()
    expected_subdir_files: dict[str, set[str]] = {}
    for retained in UPSTREAM_NOTICE_PINS:
        rel = relative_notice_path(retained)
        if "/" in rel:
            subdir, fname = rel.split("/", 1)
            expected_top_entries.add(subdir)
            expected_subdir_files.setdefault(subdir, set()).add(fname)
        else:
            expected_top_entries.add(rel)

    if set(os.listdir(notice_root)) != expected_top_entries:
        raise ImageBuildError(
            "SUPPLEMENTAL_NOTICE_INVENTORY_MISMATCH",
            "Supplemental notice root directory entries do not match closed inventory",
        )
    for subdir, exp_files in sorted(expected_subdir_files.items()):
        sub_path = physical_dir(notice_root / subdir, "supplemental notice subdirectory")
        if set(os.listdir(sub_path)) != exp_files:
            raise ImageBuildError(
                "SUPPLEMENTAL_NOTICE_INVENTORY_MISMATCH",
                f"Supplemental notice subdirectory {subdir} entries do not match closed inventory",
            )

    notice_payloads: dict[str, bytes] = {}
    total_bytes = 0
    for retained, (_, exp_blob, exp_size, exp_sha) in sorted(UPSTREAM_NOTICE_PINS.items()):
        rel = relative_notice_path(retained)
        data = held_unaliased_bytes(notice_root / rel, max_bytes=MAX_SMALL_SOURCE_BYTES)
        if source_digest_fn is None:
            if len(data) != exp_size or sha256_hex(data) != exp_sha or git_blob_sha1_hex(data) != exp_blob:
                raise ImageBuildError(
                    "SUPPLEMENTAL_NOTICE_DIGEST_MISMATCH",
                    f"Supplemental notice file bytes, SHA-256, or Git blob mismatch for {retained}",
                )
            obs_size = len(data)
        else:
            obs_size, obs_sha = _measure_source(retained, data, source_digest_fn)
            if obs_size != exp_size or obs_sha != exp_sha:
                raise ImageBuildError(
                    "SUPPLEMENTAL_NOTICE_DIGEST_MISMATCH",
                    f"Supplemental notice file bytes, SHA-256, or Git blob mismatch for {retained}",
                )
            if obs_size == len(data) and obs_sha == sha256_hex(data) and git_blob_sha1_hex(data) != exp_blob:
                raise ImageBuildError(
                    "SUPPLEMENTAL_NOTICE_DIGEST_MISMATCH",
                    f"Supplemental notice file bytes, SHA-256, or Git blob mismatch for {retained}",
                )
        notice_payloads[retained] = data
        total_bytes += obs_size
    if total_bytes != SUPPLEMENTAL_NOTICE_TOTAL_BYTES:
        raise ImageBuildError("SUPPLEMENTAL_NOTICE_DIGEST_MISMATCH", "Total supplemental notice bytes mismatch")
    return notice_payloads


def verify_physical_sources(
    *,
    archive_dir: str | os.PathLike[str],
    certificate_path: str | os.PathLike[str],
    base_root_proof_path: str | os.PathLike[str],
    base_metadata_proof_path: str | os.PathLike[str],
    supplemental_notice_manifest_path: str | os.PathLike[str],
    supplemental_notice_dir: str | os.PathLike[str],
    source_digest_fn: Callable[[str, bytes], tuple[int, str]] | None = None,
) -> tuple[bytes, bytes, bytes, bytes, dict[str, bytes], dict[str, bytes]]:
    arch_dir = physical_dir(archive_dir, "archive directory")
    cert_bytes = held_unaliased_bytes(certificate_path, max_bytes=MAX_SMALL_SOURCE_BYTES)
    if _measure_source(FEDORA_CERT_CONTEXT_FILENAME, cert_bytes, source_digest_fn) != (
        FEDORA_CERT_BYTES,
        FEDORA_CERT_SHA256,
    ):
        raise ImageBuildError("CERTIFICATE_CONTENT_INVALID", "Public Fedora 43 certificate bytes or armor invalid")
    verify_selected_fedora_certificate_bytes(cert_bytes)

    proof_bytes = held_unaliased_bytes(base_root_proof_path, max_bytes=MAX_SMALL_SOURCE_BYTES)
    if sha256_hex(proof_bytes) != BASE_ROOT_PROOF_SHA256:
        raise ImageBuildError("BASE_ROOT_PROOF_INVALID", "Base-resident root proof file digest mismatch")

    metadata_bytes = held_unaliased_bytes(base_metadata_proof_path, max_bytes=MAX_SMALL_SOURCE_BYTES)
    _verify_physical_base_metadata_proof(metadata_bytes)

    notice_manifest_bytes = held_unaliased_bytes(
        supplemental_notice_manifest_path, max_bytes=MAX_SMALL_SOURCE_BYTES
    )
    notice_payloads = _verify_physical_supplemental_notices(
        notice_manifest_bytes,
        supplemental_notice_dir,
        source_digest_fn=source_digest_fn,
    )

    if set(os.listdir(arch_dir)) != set(QUARANTINE_ARCHIVES):
        raise ImageBuildError("ARCHIVE_DIR_INVENTORY_MISMATCH", "Archive directory file set does not match 30 RPMs")
    archive_payloads: dict[str, bytes] = {}
    for fname, (exp_bytes, exp_sha) in sorted(QUARANTINE_ARCHIVES.items()):
        data = held_unaliased_bytes(arch_dir / fname, max_bytes=MAX_ARCHIVE_FILE_BYTES)
        if _measure_source(fname, data, source_digest_fn) != (exp_bytes, exp_sha):
            raise ImageBuildError("ARCHIVE_DIGEST_MISMATCH", f"Physical archive bytes/hash mismatch for {fname}")
        archive_payloads[fname] = data
    return cert_bytes, proof_bytes, metadata_bytes, notice_manifest_bytes, archive_payloads, notice_payloads


def _make_command_plan(run_id_suffix: str, context_dir: Path | None = None) -> BuildCommandPlan:
    if type(run_id_suffix) is not str or not _RUN_SUFFIX_RE.fullmatch(run_id_suffix):
        raise ImageBuildError("RUN_SUFFIX_INVALID", "run_id_suffix must be 1..20 ASCII digits")
    ctx_str = str(context_dir) if context_dir is not None else "/nonexistent-build-context"
    dockerfile_str = str(context_dir / "Dockerfile") if context_dir is not None else "/nonexistent-build-context/Dockerfile"
    build_tag = f"tf-signing-runtime-build:{run_id_suffix}"
    probe_name = f"tf-signing-runtime-probe-{run_id_suffix}"
    return BuildCommandPlan(
        run_id_suffix=run_id_suffix,
        build_tag=build_tag,
        probe_container_name=probe_name,
        check_tag_argv=(DOCKER_BINARY, "image", "ls", "--all", "--quiet", "--filter", f"reference={build_tag}"),
        check_container_argv=(
            DOCKER_BINARY,
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"name=^/{probe_name}$",
        ),
        pull_argv=(DOCKER_BINARY, "pull", APPROVED_BASE_IMAGE),
        inspect_base_argv=(
            DOCKER_BINARY,
            "image",
            "inspect",
            "--format",
            "{{.Id}}|{{json .RepoDigests}}",
            APPROVED_BASE_IMAGE,
        ),
        build_argv=(
            DOCKER_BINARY,
            "build",
            "--network=none",
            "--pull=false",
            "--no-cache",
            "--force-rm",
            "--tag",
            build_tag,
            "--file",
            dockerfile_str,
            ctx_str,
        ),
        inspect_built_argv=(DOCKER_BINARY, "image", "inspect", "--format", "{{.Id}}", build_tag),
        rm_container_argv=(DOCKER_BINARY, "rm", "-f", probe_name),
        rmi_tag_argv=(DOCKER_BINARY, 'rmi', '--no-prune', build_tag),
    )


def build_command_plan(run_id_suffix: str, context_dir: Path) -> BuildCommandPlan:
    if type(run_id_suffix) is not str or not _RUN_SUFFIX_RE.fullmatch(run_id_suffix):
        raise ImageBuildError("RUN_SUFFIX_INVALID", "run_id_suffix must be 1..20 ASCII digits")
    ctx = physical_dir(context_dir, "build context directory")
    return _make_command_plan(run_id_suffix, ctx)


def _dir_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


def _write_context_file(context_dir: Path, filename: str, payload: bytes) -> None:
    if filename not in ALLOWED_CONTEXT_FILENAMES or "/" in filename or "\x00" in filename:
        raise ImageBuildError("CONTEXT_FILENAME_FORBIDDEN", "Context filename is not in closed allowlist")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(context_dir / filename, flags, 0o600)
    except OSError as error:
        raise ImageBuildError("CONTEXT_WRITE_FAILED", "Failed to create exclusive context file") from error
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            info = os.fstat(stream.fileno())
            if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != len(payload):
                raise ImageBuildError("CONTEXT_WRITE_FAILED", "Context file permissions or size invalid")
    except ImageBuildError:
        raise
    except OSError as error:
        raise ImageBuildError("CONTEXT_WRITE_FAILED", "Failed while writing exclusive context file") from error


def _release_build_context(context_dir: Path, expected_identity: tuple[int, ...]) -> bool:
    fd: int | None = None
    try:
        fd = os.open(
            context_dir,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        if _dir_identity(os.fstat(fd)) != expected_identity or not (set(os.listdir(fd)) <= ALLOWED_CONTEXT_FILENAMES):
            raise ValueError("CONTEXT_STATE_UNSAFE")
        for name in sorted(os.listdir(fd)):
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid():
                raise ValueError("CONTEXT_ENTRY_UNSAFE")
            os.unlink(name, dir_fd=fd)
        if os.listdir(fd) or _dir_identity(os.lstat(context_dir)) != expected_identity:
            raise ValueError("CONTEXT_NOT_EMPTY")
        os.rmdir(context_dir)
    except BaseException:
        _RETAINED_BUILD_CUSTODY.append({"kind": "context_dir", "identity": expected_identity})
        return False
    finally:
        if fd is not None:
            os.close(fd)
    return True


def _stage_build_context(
    work_root: Path,
    run_id_suffix: str,
    cert_bytes: bytes,
    archive_payloads: Mapping[str, bytes],
    notice_manifest_bytes: bytes | None = None,
    notice_payloads: Mapping[str, bytes] | None = None,
) -> tuple[Path, tuple[int, ...]]:
    """Create 0700 context directory and own cleanup/custody from mkdir onward."""
    if type(run_id_suffix) is not str or not _RUN_SUFFIX_RE.fullmatch(run_id_suffix):
        raise ImageBuildError("RUN_SUFFIX_INVALID", "run_id_suffix must be 1..20 ASCII digits")
    context_dir = physical_dir(work_root, "work root") / f"tf-signing-image-context-{run_id_suffix}"
    try:
        os.mkdir(context_dir, 0o700)
    except OSError as error:
        raise ImageBuildError(
            "BUILD_CONTEXT_CREATE_FAILED",
            "Failed to create fresh 0700 build context",
            custody_retained=False,
        ) from error

    identity: tuple[int, ...] | None = None
    try:
        identity = _dir_identity(os.lstat(context_dir))
        os.chmod(context_dir, 0o700)
        identity = _dir_identity(os.lstat(context_dir))
        if identity[4] != 0o700:
            raise ImageBuildError("BUILD_CONTEXT_MODE_INVALID", "Build context directory must have mode 0700")
        _write_context_file(context_dir, "Dockerfile", EXPECTED_DOCKERFILE_TEXT.encode("utf-8"))
        _write_context_file(context_dir, FEDORA_CERT_CONTEXT_FILENAME, cert_bytes)
        if notice_manifest_bytes is not None:
            _write_context_file(context_dir, SUPPLEMENTAL_NOTICE_CONTEXT_FILENAME, notice_manifest_bytes)
        for fname, payload in sorted(archive_payloads.items()):
            _write_context_file(context_dir, fname, payload)
        if notice_payloads is not None:
            if set(notice_payloads) != set(UPSTREAM_NOTICE_PINS):
                raise ImageBuildError(
                    "SUPPLEMENTAL_NOTICE_INVENTORY_MISMATCH",
                    "Supplemental notice payload set does not match closed 23-file inventory",
                )
            for retained_file, payload in sorted(notice_payloads.items()):
                _write_context_file(context_dir, NOTICE_CONTEXT_FILENAMES[retained_file], payload)
        return context_dir, identity
    except BaseException as error:
        if identity is None:
            _RETAINED_BUILD_CUSTODY.append({"kind": "context_dir", "path": str(context_dir)})
            cleaned = False
        else:
            cleaned = _release_build_context(context_dir, identity)
        custody_retained = (not cleaned) or bool(_RETAINED_BUILD_CUSTODY)
        if isinstance(error, ImageBuildError):
            raise ImageBuildError(error.code, error.reason, custody_retained=custody_retained) from None
        if isinstance(error, OSError):
            raise ImageBuildError(
                "BUILD_CONTEXT_CREATE_FAILED",
                "Failed to initialize 0700 build context",
                custody_retained=custody_retained,
            ) from error
        raise


def _verify_staged_context(
    context_dir: Path,
    expected_identity: tuple[int, ...],
    source_digest_fn: Callable[[str, bytes], tuple[int, str]] | None = None,
) -> None:
    info = os.lstat(context_dir)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or _dir_identity(info) != expected_identity
        or set(os.listdir(context_dir)) != ALLOWED_CONTEXT_FILENAMES
    ):
        raise ImageBuildError("CONTEXT_STATE_CHANGED", "Build context directory identity, mode, or inventory changed")
    dockerfile_path = context_dir / "Dockerfile"
    if (
        stat.S_IMODE(os.lstat(dockerfile_path).st_mode) != 0o600
        or sha256_hex(held_unaliased_bytes(dockerfile_path, max_bytes=MAX_SMALL_SOURCE_BYTES))
        != EXPECTED_DOCKERFILE_SHA256
    ):
        raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged Dockerfile or mode changed before build")
    cert_ctx_path = context_dir / FEDORA_CERT_CONTEXT_FILENAME
    raw_cert = held_unaliased_bytes(cert_ctx_path, max_bytes=MAX_SMALL_SOURCE_BYTES)
    if (
        stat.S_IMODE(os.lstat(cert_ctx_path).st_mode) != 0o600
        or _measure_source(FEDORA_CERT_CONTEXT_FILENAME, raw_cert, source_digest_fn)
        != (FEDORA_CERT_BYTES, FEDORA_CERT_SHA256)
    ):
        raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged Fedora certificate or mode changed before build")
    try:
        verify_selected_fedora_certificate_bytes(raw_cert)
    except ImageBuildError as error:
        raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged Fedora certificate content changed before build") from error
    notice_manifest_ctx_path = context_dir / SUPPLEMENTAL_NOTICE_CONTEXT_FILENAME
    if (
        stat.S_IMODE(os.lstat(notice_manifest_ctx_path).st_mode) != 0o600
        or sha256_hex(held_unaliased_bytes(notice_manifest_ctx_path, max_bytes=MAX_SMALL_SOURCE_BYTES))
        != UPSTREAM_NOTICE_PINS_SHA256
    ):
        raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged supplemental notice manifest or mode changed")
    for fname, (exp_bytes, exp_sha) in sorted(QUARANTINE_ARCHIVES.items()):
        arch_ctx_path = context_dir / fname
        if (
            stat.S_IMODE(os.lstat(arch_ctx_path).st_mode) != 0o600
            or _measure_source(
                fname,
                held_unaliased_bytes(arch_ctx_path, max_bytes=MAX_ARCHIVE_FILE_BYTES),
                source_digest_fn,
            )
            != (exp_bytes, exp_sha)
        ):
            raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged archive or mode changed before build")
    for retained, (_, exp_blob, exp_size, exp_sha) in sorted(UPSTREAM_NOTICE_PINS.items()):
        ctx_name = NOTICE_CONTEXT_FILENAMES[retained]
        notice_ctx_path = context_dir / ctx_name
        raw_notice = held_unaliased_bytes(notice_ctx_path, max_bytes=MAX_SMALL_SOURCE_BYTES)
        if stat.S_IMODE(os.lstat(notice_ctx_path).st_mode) != 0o600:
            raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged supplemental notice file or mode changed")
        if source_digest_fn is None:
            if (
                len(raw_notice) != exp_size
                or sha256_hex(raw_notice) != exp_sha
                or git_blob_sha1_hex(raw_notice) != exp_blob
            ):
                raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged supplemental notice file or mode changed")
        else:
            obs_size, obs_sha = _measure_source(retained, raw_notice, source_digest_fn)
            if obs_size != exp_size or obs_sha != exp_sha:
                raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged supplemental notice file or mode changed")
            if (
                obs_size == len(raw_notice)
                and obs_sha == sha256_hex(raw_notice)
                and git_blob_sha1_hex(raw_notice) != exp_blob
            ):
                raise ImageBuildError("CONTEXT_STATE_CHANGED", "Staged supplemental notice file or mode changed")


class BoundedDockerSubprocessEngine:
    """Bounded stdlib subprocess adapter with both-pipe caps, deadline, and process-group custody."""

    __slots__ = (
        "_allow_native",
        "_timeout",
        "_observed_native_steps",
        "_popen_factory",
        "_uname_fn",
        "_killpg_fn",
    )

    def __init__(
        self,
        *,
        allow_native_execution: bool = False,
        timeout_seconds: float = 600.0,
        popen_factory: Callable[..., Any] | None = None,
        uname_fn: Callable[[], Any] | None = None,
        killpg_fn: Callable[[int, int], None] | None = None,
    ) -> None:
        self._allow_native = bool(allow_native_execution)
        self._timeout = float(timeout_seconds)
        self._observed_native_steps: list[EngineStepReceipt] = []
        self._popen_factory = popen_factory
        self._uname_fn = uname_fn
        self._killpg_fn = killpg_fn

    @property
    def is_genuine_native_engine(self) -> bool:
        return (
            type(self) is BoundedDockerSubprocessEngine
            and self._allow_native
            and self._popen_factory is None
            and self._uname_fn is None
            and self._killpg_fn is None
            and subprocess.Popen is _STDLIB_POPEN
            and os.uname is _STDLIB_UNAME
            and os.killpg is _STDLIB_KILLPG
        )

    def _run_bounded(self, step: str, argv: tuple[str, ...]) -> tuple[int, bytes, bytes, EngineStepReceipt]:
        if type(self) is not BoundedDockerSubprocessEngine or not self._allow_native:
            raise ImageBuildError(
                "NATIVE_EXECUTION_NOT_AUTHORIZED",
                "Native Docker execution is disabled in this environment",
            )
        uname_fn = self._uname_fn or os.uname
        popen_fn = self._popen_factory or subprocess.Popen
        killpg_fn = self._killpg_fn or os.killpg
        info = uname_fn()
        sysname = getattr(info, "sysname", None) or (info[0] if isinstance(info, tuple) and len(info) > 0 else "")
        machine = getattr(info, "machine", None) or (info[4] if isinstance(info, tuple) and len(info) > 4 else "")
        if sysname != "Linux" or machine != "x86_64":
            raise ImageBuildError("NON_LINUX_HOST_FORBIDDEN", "Native builder requires Linux x86_64 host")
        if not argv or argv[0] != DOCKER_BINARY or any(not t or "\x00" in t for t in argv):
            raise ImageBuildError("ENGINE_ARGV_INVALID", "Engine argv failed static validation")
        env = validate_builder_env({"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        try:
            proc = popen_fn(
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as error:
            raise ImageBuildError("ENGINE_EXECUTION_FAILED", f"Failed to spawn engine step {step}") from error

        deadline = time.monotonic() + self._timeout
        stdout_buf = bytearray()
        stderr_buf = bytearray()
        sel = selectors.DefaultSelector()
        try:
            for pipe, target_buf in ((proc.stdout, stdout_buf), (proc.stderr, stderr_buf)):
                if pipe is None:
                    raise OSError("Missing subprocess standard stream pipe")
                fd = pipe.fileno()
                os.set_blocking(fd, False)
                sel.register(fd, selectors.EVENT_READ, data=target_buf)
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("ENGINE_STEP_TIMEOUT")
                for key, _ in sel.select(timeout=min(remaining, 0.25)):
                    target_buf = key.data
                    try:
                        chunk = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        sel.unregister(key.fd)
                        continue
                    if len(target_buf) + len(chunk) > MAX_ENGINE_STREAM_BYTES:
                        raise OverflowError("ENGINE_STREAM_OVERFLOW")
                    target_buf.extend(chunk)
            rc = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except BaseException as error:
            try:
                killpg_fn(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5.0)
            except BaseException:
                _RETAINED_BUILD_CUSTODY.append({"kind": "child_process", "pid": proc.pid})
                raise ImageBuildError(
                    "ENGINE_CHILD_CUSTODY_RETAINED",
                    "Engine child termination unconfirmed",
                    custody_retained=True,
                ) from None
            if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
                code = "ENGINE_TIMEOUT"
            elif isinstance(error, OverflowError):
                code = "ENGINE_IO_OVERFLOW"
            else:
                code = "ENGINE_EXECUTION_FAILED"
            raise ImageBuildError(code, f"Engine step {step} failed bounds") from None
        finally:
            sel.close()
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except BaseException:
                        pass

        try:
            killpg_fn(proc.pid, 0)
        except ProcessLookupError:
            pass
        else:
            try:
                killpg_fn(proc.pid, signal.SIGKILL)
                killpg_fn(proc.pid, 0)
                _RETAINED_BUILD_CUSTODY.append({"kind": "process_group", "pgid": proc.pid})
                raise ImageBuildError(
                    "ENGINE_CHILD_CUSTODY_RETAINED",
                    "Lingering engine process-group descendant survived SIGKILL",
                    custody_retained=True,
                )
            except ProcessLookupError:
                raise ImageBuildError(
                    "ENGINE_LINGERING_DESCENDANT",
                    f"Engine step {step} left lingering process-group descendant",
                ) from None

        out = bytes(stdout_buf)
        err = bytes(stderr_buf)
        rec = EngineStepReceipt(step, rc, len(out), sha256_hex(out), len(err), sha256_hex(err))
        self._observed_native_steps.append(rec)
        return rc, out, err, rec

    def verify_targets_absent(self, plan: BuildCommandPlan, *, check_tag: bool = True) -> None:
        rc, out, _, _ = self._run_bounded("check_container_absent", plan.check_container_argv)
        if rc != 0 or out.strip():
            raise ImageBuildError(
                "PREEXISTING_DOCKER_RESOURCE",
                "Probe container name already exists or check failed",
            )
        if check_tag:
            rc_t, out_t, _, _ = self._run_bounded("check_tag_absent", plan.check_tag_argv)
            if rc_t != 0 or out_t.strip():
                raise ImageBuildError("PREEXISTING_DOCKER_RESOURCE", "Build tag already exists or check failed")

    def pull_base_image(self, plan: BuildCommandPlan) -> EngineStepReceipt:
        rc, _, _, rec = self._run_bounded("pull_base_image", plan.pull_argv)
        if rc != 0:
            raise ImageBuildError("BASE_IMAGE_PULL_FAILED", "Base image pull returned non-zero")
        return rec

    def inspect_base_image(self, plan: BuildCommandPlan) -> tuple[str, EngineStepReceipt]:
        rc, out, _, rec = self._run_bounded("inspect_base_image", plan.inspect_base_argv)
        text = out.decode("utf-8", "replace").strip()
        if rc != 0 or APPROVED_BASE_IMAGE not in text:
            raise ImageBuildError("BASE_IMAGE_INSPECT_MISMATCH", "Local base image digest inspection failed")
        return text.split("|", 1)[0].strip(), rec

    def build_image(self, plan: BuildCommandPlan, context_dir: Path) -> EngineStepReceipt:
        rc, _, _, rec = self._run_bounded("build_image", plan.build_argv)
        if rc != 0:
            raise ImageBuildError("DOCKER_BUILD_FAILED", "Offline Docker build failed")
        return rec

    def inspect_built_image(self, plan: BuildCommandPlan) -> tuple[str, EngineStepReceipt]:
        rc, out, _, rec = self._run_bounded("inspect_built_image", plan.inspect_built_argv)
        if rc != 0:
            raise ImageBuildError("IMAGE_INSPECT_FAILED", "Built image inspection failed")
        return require_local_image_id(out.decode("utf-8", "replace").strip()), rec

    def inspect_tools(self, plan: BuildCommandPlan, image_id: str) -> ImageInspectionReport:
        rc, out, _, rec = self._run_bounded("inspect_tools", plan.probe_argv(image_id))
        if rc != 0:
            raise ImageBuildError("TOOL_PROBE_FAILED", "In-image tool inspection probe failed")
        payload = parse_strict_json(out, "TOOL_PROBE_SCHEMA_INVALID")
        tools_raw = payload.get("tools")
        if not isinstance(tools_raw, dict) or set(tools_raw) != set(REQUIRED_TOOL_PATHS):
            raise ImageBuildError("TOOL_PROBE_SCHEMA_INVALID", "Probe tool set mismatch")
        inspected: dict[str, InspectedTool] = {}
        for tname in REQUIRED_TOOL_PATHS:
            row = tools_raw.get(tname)
            if not isinstance(row, dict):
                raise ImageBuildError("TOOL_PROBE_SCHEMA_INVALID", "Invalid tool probe entry")
            inspected[tname] = InspectedTool(
                str(row.get("path", "")),
                int(row.get("bytes", -1)),
                str(row.get("sha256", "")),
                str(row.get("version", "")),
            )
        notices_ok = payload.get("supplemental_notices_ok") is True
        pins_sha_raw = payload.get("supplemental_notice_pins_sha256")
        pins_sha = pins_sha_raw if type(pins_sha_raw) is str else ""
        return ImageInspectionReport(
            image_id=image_id,
            container_python_ok=payload.get("container_python_ok") is True,
            stage_dir_absent=payload.get("stage_dir_absent") is True,
            workspace_owner_ok=payload.get("workspace_owner_ok") is True,
            supplemental_notices_ok=notices_ok,
            tools=inspected,
            step_receipt=rec,
            supplemental_notice_pins_sha256=pins_sha,
        )

    def remove_container(self, plan: BuildCommandPlan) -> bool:
        if (
            type(plan) is not BuildCommandPlan
            or type(plan.run_id_suffix) is not str
            or not _RUN_SUFFIX_RE.fullmatch(plan.run_id_suffix)
            or plan.probe_container_name != f"tf-signing-runtime-probe-{plan.run_id_suffix}"
            or plan.rm_container_argv != (DOCKER_BINARY, "rm", "-f", plan.probe_container_name)
            or plan.check_container_argv
            != (
                DOCKER_BINARY,
                "container",
                "ls",
                "--all",
                "--quiet",
                "--filter",
                f"name=^/{plan.probe_container_name}$",
            )
        ):
            return False
        try:
            self._run_bounded("remove_container", plan.rm_container_argv)
            rc, out, _, _ = self._run_bounded("check_container_absent", plan.check_container_argv)
            return rc == 0 and not out.strip()
        except BaseException:
            return False

    def remove_image(self, argv: tuple[str, ...]) -> bool:
        target = _validate_remove_image_argv(argv)
        if target is None:
            return False
        try:
            if self._run_bounded("remove_image", argv)[0] == 0:
                return True
            rc, out, _, _ = self._run_bounded(
                "check_tag_absent",
                (DOCKER_BINARY, "image", "ls", "--all", "--quiet", "--filter", f"reference={target}"),
            )
            return rc == 0 and not out.strip()
        except BaseException:
            return False

    def confirm_image_id_absent(self, image_id: str) -> bool:
        try:
            target = require_local_image_id(image_id)
            rc, out, _, _ = self._run_bounded(
                "check_image_id_absent",
                (DOCKER_BINARY, "image", "ls", "--all", "--no-trunc", "--quiet"),
            )
            if rc != 0:
                return False
            present_ids = {
                line.strip() for line in out.decode("ascii").splitlines() if line.strip()
            }
            if any(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in present_ids):
                return False
            return target not in present_ids
        except BaseException:
            return False


def _validate_remove_image_argv(argv: Any) -> str | None:
    if type(argv) is not tuple or len(argv) != 4:
        return None
    binary, subcmd, no_prune, target = argv
    if (
        binary != DOCKER_BINARY
        or subcmd != "rmi"
        or no_prune != "--no-prune"
        or type(target) is not str
        or not target
        or "\x00" in target
        or target.startswith("-")
        or target == APPROVED_BASE_IMAGE
        or APPROVED_BASE_IMAGE_DIGEST in target
    ):
        return None
    if target.startswith("tf-signing-runtime-build:"):
        suffix = target.split(":", 1)[1]
        if _RUN_SUFFIX_RE.fullmatch(suffix):
            return target
    return None


def _verify_and_remove_owned_image(
    engine: ImageBuildEngine,
    plan: BuildCommandPlan,
    expected_image_id: str,
    *,
    known_base_image_id: str | None = None,
) -> None:
    image_id = require_local_image_id(expected_image_id)
    if known_base_image_id is None:
        try:
            observed_base_raw, _ = engine.inspect_base_image(plan)
        except ImageBuildError as error:
            _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
            _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
            raise ImageBuildError(error.code, error.reason, custody_retained=True) from None
        except BaseException as error:
            _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
            _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
            raise ImageBuildError(
                "BASE_IMAGE_INSPECT_MISMATCH",
                "Local base image inspection failed during disposal",
                custody_retained=True,
            ) from error
        observed_base_id = observed_base_raw.strip() if isinstance(observed_base_raw, str) else ""
    else:
        observed_base_id = known_base_image_id.strip()

    if observed_base_id and image_id == observed_base_id:
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
        raise ImageBuildError(
            "IMAGE_ID_INVALID",
            "Built image ID collides with local base image config ID",
            custody_retained=True,
        )

    try:
        observed_tag_raw, _ = engine.inspect_built_image(plan)
    except ImageBuildError as error:
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
        raise ImageBuildError(error.code, error.reason, custody_retained=True) from None
    except BaseException as error:
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
        raise ImageBuildError(
            "IMAGE_INSPECT_FAILED",
            "Built image tag inspection failed during disposal",
            custody_retained=True,
        ) from error

    observed_tag_text = observed_tag_raw.strip() if isinstance(observed_tag_raw, str) else ""
    if observed_base_id and observed_tag_text == observed_base_id:
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
        raise ImageBuildError(
            "IMAGE_ID_INVALID",
            "Tagged image ID collides with local base image config ID",
            custody_retained=True,
        )

    try:
        observed_tag_id = require_local_image_id(observed_tag_text)
    except ImageBuildError as error:
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
        raise ImageBuildError(error.code, error.reason, custody_retained=True) from None

    if observed_tag_id != image_id:
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
        raise ImageBuildError(
            "IMAGE_TAG_TARGET_MISMATCH",
            "Daemon tag-to-image ID disagrees with expected built image ID",
            custody_retained=True,
        )

    tag_removed = bool(engine.remove_image(plan.rmi_tag_argv))
    if not tag_removed:
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
        raise ImageBuildError(
            "IMAGE_DISPOSAL_UNCONFIRMED",
            "Post-host-controller runtime image tag disposal unconfirmed",
            custody_retained=True,
        )

    confirm_fn = getattr(engine, "confirm_image_id_absent", None)
    id_removed = bool(confirm_fn(image_id)) if callable(confirm_fn) else False
    if not id_removed:
        _RETAINED_BUILD_CUSTODY.append({"kind": "image_id", "id": image_id})
        raise ImageBuildError(
            "IMAGE_DISPOSAL_UNCONFIRMED",
            "Post-host-controller runtime image ID disposal unconfirmed",
            custody_retained=True,
        )


def _verify_inspection_report(
    manifest: AdmissionManifest,
    expected_image_id: str,
    report: ImageInspectionReport,
) -> tuple[dict[str, str], dict[str, int], dict[str, str]]:
    if report.image_id != expected_image_id:
        raise ImageBuildError("SESSION_IMAGE_MISMATCH", "Tool inspection report does not match built image ID")
    if (
        not (
            report.container_python_ok is True
            and report.stage_dir_absent is True
            and report.workspace_owner_ok is True
            and report.supplemental_notices_ok is True
        )
        or report.supplemental_notice_pins_sha256 != manifest.supplemental_notice_pins_sha256
        or report.supplemental_notice_pins_sha256 != UPSTREAM_NOTICE_PINS_SHA256
    ):
        raise ImageBuildError(
            "IMAGE_LAYOUT_INVALID",
            "Built image failed python, staging-cleanup, workspace-owner, or supplemental-notice check",
        )
    if set(report.tools) != set(REQUIRED_TOOL_PATHS):
        raise ImageBuildError("TOOL_DIGEST_MISMATCH", "Inspected tool set does not match required tools")
    digests: dict[str, str] = {}
    sizes: dict[str, int] = {}
    versions: dict[str, str] = {}
    for tname, pin in manifest.tool_pins.items():
        obs = report.tools.get(tname)
        if (
            obs is None
            or obs.path != pin.path
            or obs.bytes != pin.bytes
            or require_nonzero_sha256(obs.sha256, "TOOL_DIGEST_MISMATCH") != pin.sha256
            or obs.version.strip() != pin.version
        ):
            raise ImageBuildError("TOOL_DIGEST_MISMATCH", f"Observed tool bytes/hash/version mismatch for {tname}")
        digests[tname] = obs.sha256
        sizes[tname] = obs.bytes
        versions[tname] = obs.version.strip()
    return digests, sizes, versions


def execute_signing_image_build(
    *,
    manifest_path: str | os.PathLike[str],
    archive_dir: str | os.PathLike[str],
    certificate_path: str | os.PathLike[str],
    base_root_proof_path: str | os.PathLike[str],
    base_metadata_proof_path: str | os.PathLike[str],
    supplemental_notice_manifest_path: str | os.PathLike[str],
    supplemental_notice_dir: str | os.PathLike[str],
    work_root: str | os.PathLike[str],
    run_id_suffix: str,
    expected_manifest_sha256: str = ADMITTED_MANIFEST_SHA256,
    engine: ImageBuildEngine | None = None,
    caller_env: Mapping[str, str] | None = None,
    pre_build_recheck_hook: Callable[[], None] | None = None,
    source_digest_fn: Callable[[str, bytes], tuple[int, str]] | None = None,
) -> ImageBuildResult:
    validate_offline_dockerfile(EXPECTED_DOCKERFILE_TEXT)
    if caller_env is not None:
        validate_builder_env(caller_env)
    manifest, initial_manifest_raw = authenticate_admission_manifest(
        manifest_path, expected_manifest_sha256=expected_manifest_sha256
    )
    (
        cert_bytes,
        proof_bytes,
        metadata_bytes,
        notice_manifest_bytes,
        archive_payloads,
        notice_payloads,
    ) = verify_physical_sources(
        archive_dir=archive_dir,
        certificate_path=certificate_path,
        base_root_proof_path=base_root_proof_path,
        base_metadata_proof_path=base_metadata_proof_path,
        supplemental_notice_manifest_path=supplemental_notice_manifest_path,
        supplemental_notice_dir=supplemental_notice_dir,
        source_digest_fn=source_digest_fn,
    )
    work_dir = physical_dir(work_root, "work root")
    if type(run_id_suffix) is not str or not _RUN_SUFFIX_RE.fullmatch(run_id_suffix):
        raise ImageBuildError("RUN_SUFFIX_INVALID", "run_id_suffix must be 1..20 ASCII digits")
    if engine is None:
        raise ImageBuildError("ENGINE_REQUIRED", "An explicit ImageBuildEngine implementation is required")

    context_dir, context_identity = _stage_build_context(
        work_dir,
        run_id_suffix,
        cert_bytes,
        archive_payloads,
        notice_manifest_bytes=notice_manifest_bytes,
        notice_payloads=notice_payloads,
    )
    plan: BuildCommandPlan | None = None
    steps: list[EngineStepReceipt] = []
    base_id = ""
    observed_image_id: str | None = None
    caught_error: ImageBuildError | None = None
    build_attempted = False
    tag_created = False
    probe_attempted = False
    succeeded = False

    def _recheck_all() -> None:
        rechecked_manifest_raw = held_unaliased_bytes(manifest_path, max_bytes=MAX_SMALL_SOURCE_BYTES)
        (
            rechecked_cert,
            rechecked_proof,
            rechecked_metadata,
            rechecked_notice_manifest,
            rechecked_archives,
            rechecked_notices,
        ) = verify_physical_sources(
            archive_dir=archive_dir,
            certificate_path=certificate_path,
            base_root_proof_path=base_root_proof_path,
            base_metadata_proof_path=base_metadata_proof_path,
            supplemental_notice_manifest_path=supplemental_notice_manifest_path,
            supplemental_notice_dir=supplemental_notice_dir,
            source_digest_fn=source_digest_fn,
        )
        if (
            rechecked_manifest_raw != initial_manifest_raw
            or sha256_hex(rechecked_manifest_raw) != manifest.manifest_sha256
            or rechecked_cert != cert_bytes
            or rechecked_proof != proof_bytes
            or rechecked_metadata != metadata_bytes
            or rechecked_notice_manifest != notice_manifest_bytes
            or rechecked_archives != archive_payloads
            or rechecked_notices != notice_payloads
        ):
            raise ImageBuildError("SOURCE_STATE_CHANGED", "Source files changed before build execution")
        _verify_staged_context(context_dir, context_identity, source_digest_fn=source_digest_fn)

    try:
        plan = build_command_plan(run_id_suffix, context_dir)
        if pre_build_recheck_hook is not None:
            pre_build_recheck_hook()
        _recheck_all()
        engine.verify_targets_absent(plan, check_tag=True)
        steps.append(engine.pull_base_image(plan))
        base_id, base_rec = engine.inspect_base_image(plan)
        steps.append(base_rec)
        _recheck_all()
        build_attempted = True
        steps.append(engine.build_image(plan, context_dir))
        tag_created = True
        built_id, built_rec = engine.inspect_built_image(plan)
        steps.append(built_rec)
        candidate_image_id = require_local_image_id(built_id)
        if base_id and candidate_image_id == base_id:
            raise ImageBuildError("IMAGE_ID_INVALID", "Built image ID equals base image ID")
        observed_image_id = candidate_image_id
        engine.verify_targets_absent(plan, check_tag=False)
        probe_attempted = True
        report = engine.inspect_tools(plan, observed_image_id)
        steps.append(report.step_receipt)
        tool_digests, tool_bytes, tool_versions = _verify_inspection_report(manifest, observed_image_id, report)
        succeeded = True
    except ImageBuildError as error:
        caught_error = error
    except Exception as error:
        caught_error = ImageBuildError("ENGINE_EXECUTION_FAILED", "Engine execution failed")
        caught_error.__cause__ = error
    finally:
        context_cleaned = _release_build_context(context_dir, context_identity)
        cleanup_failed = not context_cleaned
        dispose_on_exit = (not succeeded) or cleanup_failed or bool(_RETAINED_BUILD_CUSTODY)
        if dispose_on_exit and plan is not None:
            daemon_uncertain = caught_error is not None and caught_error.code in {
                "ENGINE_TIMEOUT",
                "ENGINE_IO_OVERFLOW",
                "ENGINE_CHILD_CUSTODY_RETAINED",
                "ENGINE_LINGERING_DESCENDANT",
            }
            if (not succeeded) and probe_attempted and not engine.remove_container(plan):
                _RETAINED_BUILD_CUSTODY.append({"kind": "container", "name": plan.probe_container_name})
                cleanup_failed = True
            if build_attempted:
                if observed_image_id is None:
                    tag_present_or_uncertain = tag_created or daemon_uncertain
                    if not tag_present_or_uncertain:
                        try:
                            engine.verify_targets_absent(plan, check_tag=True)
                        except BaseException:
                            tag_present_or_uncertain = True
                    if tag_present_or_uncertain:
                        _RETAINED_BUILD_CUSTODY.append({"kind": "image_tag", "tag": plan.build_tag})
                        cleanup_failed = True
                else:
                    try:
                        _verify_and_remove_owned_image(
                            engine,
                            plan,
                            observed_image_id,
                            known_base_image_id=base_id,
                        )
                    except ImageBuildError:
                        cleanup_failed = True

    custody_retained = cleanup_failed or bool(_RETAINED_BUILD_CUSTODY)
    if caught_error is not None:
        raise ImageBuildError(caught_error.code, caught_error.reason, custody_retained=custody_retained) from None
    if custody_retained:
        raise ImageBuildError(
            "BUILD_CLEANUP_UNCONFIRMED",
            "Build context or resource cleanup unconfirmed",
            custody_retained=True,
        )
    expected_steps = (
        "pull_base_image",
        "inspect_base_image",
        "build_image",
        "inspect_built_image",
        "inspect_tools",
    )
    genuine_native = bool(
        source_digest_fn is None
        and type(engine) is BoundedDockerSubprocessEngine
        and engine.is_genuine_native_engine
        and tuple(s.step for s in steps) == expected_steps
        and all(s.exit_code == 0 and any(s is obs for obs in engine._observed_native_steps) for s in steps)
    )
    native_ready = bool(
        genuine_native and CLASS_ADMISSION_GATE_OPEN and _admitted_pin_matches(manifest.manifest_sha256)
    )
    return ImageBuildResult(
        status="ready-native" if native_ready else "verified-source-preparation",
        execution_mode="native-subprocess-engine" if genuine_native else "injected-test-engine",
        manifest_sha256=manifest.manifest_sha256,
        recipe_sha256=manifest.recipe_sha256,
        image_id=observed_image_id or "",
        container_python=manifest.container_python,
        tool_digests=tool_digests,
        tool_bytes=tool_bytes,
        tool_versions=tool_versions,
        step_receipts=tuple(steps),
        context_cleaned=context_cleaned,
        custody_retained=False,
        retained_custody_count=len(_RETAINED_BUILD_CUSTODY),
        native_execution_observed=genuine_native,
        native_ready_for_host_controller=native_ready,
        build_tag=plan.build_tag if plan is not None else f"tf-signing-runtime-build:{run_id_suffix}",
        built_image_retained_for_host_controller=True,
        image_disposal_obligation=IMAGE_DISPOSAL_OBLIGATION,
    )


def dispose_built_image(result: ImageBuildResult, engine: ImageBuildEngine) -> dict[str, Any]:
    """Dispose the retained build tag and local image ID after same-job host controller completion."""
    if type(result) is not ImageBuildResult:
        raise ImageBuildError("RESULT_TYPE_INVALID", "Expected an ImageBuildResult instance")
    if engine is None:
        raise ImageBuildError("ENGINE_REQUIRED", "An explicit ImageBuildEngine implementation is required")
    image_id = require_local_image_id(result.image_id)
    if (
        type(result.build_tag) is not str
        or not result.build_tag.startswith("tf-signing-runtime-build:")
        or not _RUN_SUFFIX_RE.fullmatch(result.build_tag.split(":", 1)[1])
    ):
        raise ImageBuildError("BUILD_TAG_INVALID", "Result build_tag must match tf-signing-runtime-build:<suffix>")
    run_id_suffix = result.build_tag.split(":", 1)[1]
    plan = _make_command_plan(run_id_suffix)
    _verify_and_remove_owned_image(engine, plan, image_id)
    return {
        "build_tag": result.build_tag,
        "image_id": image_id,
        "tag_removed": True,
        "image_id_removed": True,
        "custody_retained": bool(_RETAINED_BUILD_CUSTODY),
    }


def to_host_controller_image_kwargs(result: ImageBuildResult) -> dict[str, str]:
    if (
        type(result) is not ImageBuildResult
        or result.custody_retained
        or not result.context_cleaned
        or result.retained_custody_count != 0
    ):
        raise ImageBuildError("CUSTODY_RETAINED_REFUSAL", "Cannot bind image when cleanup custody is retained")
    require_local_image_id(result.image_id)
    if set(result.tool_digests) != set(REQUIRED_TOOL_PATHS):
        raise ImageBuildError("TOOL_DIGEST_MISMATCH", "Result is missing required verified tool digests")
    for tname in REQUIRED_TOOL_PATHS:
        require_nonzero_sha256(result.tool_digests[tname], "TOOL_DIGEST_MISMATCH")
    if not (
        CLASS_ADMISSION_GATE_OPEN
        and _admitted_pin_matches(result.manifest_sha256)
        and result.native_execution_observed
        and result.native_ready_for_host_controller
        and result.status == "ready-native"
        and result.execution_mode == "native-subprocess-engine"
    ):
        raise ImageBuildError(
            "NON_NATIVE_ENGINE_EVIDENCE",
            "Fake, test, or unadmitted class result cannot satisfy native host controller",
        )
    return {
        "container_image": result.image_id,
        "container_python": result.container_python,
        "expected_gpg_sha256": result.tool_digests["gpg"],
        "expected_rpm_sha256": result.tool_digests["rpm"],
    }
