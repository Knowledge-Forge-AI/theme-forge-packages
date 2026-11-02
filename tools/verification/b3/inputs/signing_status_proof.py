"""Inactive, pure GnuPG 2.4.9 metadata checks for the fixed CI identity.

Inputs must eventually come from the authenticated owned-home GPG consumer.
These parsers neither authenticate a caller's bytes nor perform cryptography.
They return public identity facts only and never include input in errors.
The consumer must provide its trusted current clock; a bootstrap timestamp is
neither key creation time nor proof of clock freshness.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re

PRIMARY = "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF"
SUBKEY = "C021E00EE3D37C459B0E1CB3199F8028126E8A8C"
MAX_BYTES = 262144
MAX_LINES = 256
_HEX = re.compile(r"[0-9A-F]{40}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,11})\Z")
_VALIDITIES = frozenset({"o", "-", "q", "m", "f", "u", "w", "s"})
_IGNORED_LISTING = frozenset({"tru", "uid", "uat", "grp"})
_NEUTRAL_STATUS = frozenset({
    "NEWSIG", "SIG_ID", "KEY_CONSIDERED", "TRUST_UNDEFINED",
    "TRUST_MARGINAL", "TRUST_FULLY", "TRUST_ULTIMATE",
})


class ProofError(ValueError):
    """A fixed failure code, with no input data or tool diagnostics."""


def _fail(code: str) -> None:
    raise ProofError(code)


def _lines(data: bytes) -> list[str]:
    if type(data) is not bytes or not data or len(data) > MAX_BYTES:
        _fail("INPUT_BOUND")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        _fail("INPUT_ENCODING")
    if any(_forbidden_character(c) for c in text):
        _fail("INPUT_CONTROL")
    if not text.endswith("\n"):
        _fail("INPUT_FRAMING")
    lines = text[:-1].split("\n")
    if len(lines) > MAX_LINES or any(not line for line in lines):
        _fail("INPUT_LINES")
    return lines


def _forbidden_character(char: str) -> bool:
    return ((ord(char) < 32 and char != "\n") or 127 <= ord(char) <= 159
            or (char.isspace() and char not in " \n"))


def _epoch(value: str) -> int:
    if not _DECIMAL.fullmatch(value):
        _fail("TIME_FORMAT")
    return int(value)


def _now(value: int) -> None:
    if type(value) is not int or not 0 < value < 253402300800:
        _fail("NOW_FORMAT")


def _usable_interval(created: int, expires: int, now: int) -> None:
    if not 0 < created <= now or expires and expires <= now:
        _fail("TIME_UNUSABLE")


def _key_record(fields: list[str], now: int) -> dict[str, str]:
    if len(fields) < 15 or fields[1] not in _VALIDITIES:
        _fail("KEY_SHAPE_OR_VALIDITY")
    if fields[2:4] != ["4096", "1"]:
        _fail("KEY_FORMAT")
    created = _epoch(fields[5])
    expires = _epoch(fields[6]) if fields[6] else 0
    _usable_interval(created, expires, now)
    if "D" in fields[11]:
        _fail("KEY_DISABLED")
    return {"kind": fields[0], "id": fields[4], "capabilities": fields[11],
            "secret": fields[14]}


def _attach_fingerprint(keys: list[dict[str, str]], fields: list[str]) -> None:
    if not keys or "fingerprint" in keys[-1] or len(fields) < 10:
        _fail("KEY_FINGERPRINT_ORDER")
    if not _HEX.fullmatch(fields[9]):
        _fail("KEY_FINGERPRINT_FORMAT")
    keys[-1]["fingerprint"] = fields[9]


def _listing_records(data: bytes, now: int) -> list[dict[str, str]]:
    keys: list[dict[str, str]] = []
    for line in _lines(data):
        fields = line.split(":")
        tag = fields[0]
        _require_pending_fingerprint(keys, tag)
        if tag in {"sec", "ssb"}:
            keys.append(_key_record(fields, now))
        elif tag == "fpr":
            _attach_fingerprint(keys, fields)
        elif tag not in _IGNORED_LISTING:
            _fail("KEY_RECORD_UNEXPECTED")
    return keys


def _require_pending_fingerprint(keys: list[dict[str, str]], tag: str) -> None:
    if keys and "fingerprint" not in keys[-1] and tag != "fpr":
        _fail("KEY_FINGERPRINT_MISSING")


def _key_usage(key: dict[str, str], marker: str) -> None:
    if key["secret"] != marker:
        _fail("KEY_SECRET_OR_CAPABILITY")
    caps = key["capabilities"]
    if key["kind"] == "ssb":
        if caps != "s":
            _fail("KEY_SECRET_OR_CAPABILITY")
    elif "c" not in caps or set(caps) - set("cCS") or len(caps) != len(set(caps)):
        _fail("KEY_SECRET_OR_CAPABILITY")


def inspect_ci_secret_metadata(data: bytes, *, now: int) -> dict[str, object]:
    """Require one stub primary and exactly the available signing subkey.

    Expected invocation lists ALL secret keys with colon/fingerprint/secret
    metadata in the isolated home. A '+' does not prove passphrase protection.
    Required options are --with-colons --fixed-list-mode --with-secret
    --with-fingerprint --with-fingerprint --list-secret-keys, without a selector.
    """
    _now(now)
    keys = _listing_records(data, now)
    if len(keys) != 2 or [k["kind"] for k in keys] != ["sec", "ssb"]:
        _fail("KEY_TOPOLOGY")
    for key, expected, marker in zip(keys, (PRIMARY, SUBKEY), ("#", "+")):
        if key.get("fingerprint") != expected or key["id"] != expected[-16:]:
            _fail("KEY_IDENTITY")
        _key_usage(key, marker)
    return {"schema": "tf.ci-secret-metadata-proof.v1", "primaryFingerprint": PRIMARY,
            "signingSubkeyFingerprint": SUBKEY, "primarySecretAvailable": False,
            "signingSecretAvailable": True, "cryptographicVerification": False}


def _valid_signature(fields: list[str], now: int) -> None:
    if len(fields) != 10 or fields[0] != SUBKEY or fields[9] != PRIMARY:
        _fail("SIGNATURE_IDENTITY")
    created, expires = _epoch(fields[2]), _epoch(fields[3])
    _usable_interval(created, expires, now)
    expected_date = datetime.fromtimestamp(created, timezone.utc).strftime("%Y-%m-%d")
    if fields[1] != expected_date:
        _fail("SIGNATURE_DATE")
    _signature_format(fields)


def _signature_format(fields: list[str]) -> None:
    # This private fixed adapter accepts the current RSA binary signatures only.
    if fields[4:7] != ["4", "0", "1"] or fields[7] not in {"8", "9", "10", "11"} or fields[8] != "00":
        _fail("SIGNATURE_FORMAT")


def _successful_exit(returncode: int) -> None:
    if type(returncode) is not int or returncode != 0:
        _fail("VERIFY_EXIT")


def _status_records(data: bytes) -> list[tuple[str, list[str]]]:
    records = []
    for line in _lines(data):
        if not line.startswith("[GNUPG:] "):
            _fail("STATUS_PREFIX")
        tag, _, arguments = line[9:].partition(" ")
        fields = arguments.split(" ") if arguments else []
        if "" in fields or line.endswith(" "):
            _fail("STATUS_FRAMING")
        records.append((tag, fields))
    return records


def _good_signature(fields: list[str], state: dict[str, int]) -> None:
    if state["newsig"] != 1 or state["good"] or state["valid"] or not fields or fields[0] != SUBKEY[-16:]:
        _fail("GOOD_SIGNATURE_IDENTITY_OR_ORDER")
    state["good"] += 1


def _consume_status(tag: str, fields: list[str], state: dict[str, int], now: int) -> None:
    if tag == "GOODSIG":
        _good_signature(fields, state)
    elif tag == "VALIDSIG":
        if state["valid"] or state["good"] != 1:
            _fail("VALID_SIGNATURE_ORDER")
        _valid_signature(fields, now)
        state["valid"] += 1
    elif tag in _NEUTRAL_STATUS:
        _neutral_status(tag, fields)
    else:
        _fail("STATUS_REJECTED")


def _neutral_status(tag: str, fields: list[str]) -> None:
    if tag == "KEY_CONSIDERED" and fields != [PRIMARY, "0"]:
        _fail("CONSIDERED_KEY")
    if tag.startswith("TRUST_"):
        if not fields or fields[0] != "0":
            _fail("TRUST_STATUS")


def _new_signature(state: dict[str, int]) -> None:
    state["newsig"] += 1
    if state["newsig"] > 1 or state["good"] or state["valid"]:
        _fail("MULTIPLE_SIGNATURE_CONTEXTS")


def inspect_detached_verification(data: bytes, *, returncode: int, now: int) -> dict[str, object]:
    """Check fixed-tool status-fd output, not human stderr or an exit alone.

    VALIDSIG can coexist with an expired/revoked signature status. Only a
    single matching GOODSIG/VALIDSIG pair and neutral records are accepted.
    """
    _now(now)
    _successful_exit(returncode)
    state = {"good": 0, "valid": 0, "newsig": 0}
    for tag, fields in _status_records(data):
        _consume_status(tag, fields, state, now)
        if tag == "NEWSIG":
            _new_signature(state)
    if state["good"] != 1 or state["valid"] != 1:
        _fail("SIGNATURE_PROOF_MISSING")
    return {"schema": "tf.detached-signature-status-proof.v1",
            "primaryFingerprint": PRIMARY, "signingSubkeyFingerprint": SUBKEY,
            "statusPair": "GOODSIG+VALIDSIG", "toolExit": 0}
