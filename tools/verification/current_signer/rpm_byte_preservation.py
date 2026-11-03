"""Exact RPM byte preservation; signature validity is a separate verification."""
from dataclasses import dataclass
import hashlib
import base64
import binascii

from rs9.rpm_header import inspect_rpm, parse_header

MAX_BYTES = 512 * 1024 * 1024


class PreservationError(ValueError):
    pass


@dataclass(frozen=True)
class RpmSections:
    lead: bytes
    main_header: bytes
    payload: bytes


def sections(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise PreservationError("RPM_INPUT")
    try:
        _, _, payload = inspect_rpm(data)
        _, signature_end = parse_header(data, 96)
        main_start = (signature_end + 7) & ~7
        _, main_end = parse_header(data, main_start)
    except (ValueError, TypeError, KeyError, IndexError, OverflowError):
        raise PreservationError("RPM_FORMAT") from None
    if not 96 <= signature_end <= main_start < main_end <= len(data):
        raise PreservationError("RPM_BOUNDARIES")
    if data[main_end:] != payload:
        raise PreservationError("RPM_PARSER_DISAGREEMENT")
    return RpmSections(data[:96], data[main_start:main_end], payload)


def preservation(unsigned, signed):
    before, after = sections(unsigned), sections(signed)
    if unsigned == signed:
        raise PreservationError("RPM_OBJECT_UNCHANGED")
    if before.lead != after.lead:
        raise PreservationError("RPM_LEAD_CHANGED")
    if before.main_header != after.main_header:
        raise PreservationError("RPM_MAIN_HEADER_CHANGED")
    if before.payload != after.payload:
        raise PreservationError("RPM_PAYLOAD_CHANGED")
    sha = lambda data: hashlib.sha256(data).hexdigest()
    return {
        "unsigned_sha256": sha(unsigned),
        "signed_sha256": sha(signed),
        "main_header_sha256": sha(before.main_header),
        "main_header_bytes": len(before.main_header),
        "compressed_payload_sha256": sha(before.payload),
        "compressed_payload_bytes": len(before.payload),
        "lead_sha256": sha(before.lead),
    }


def header_signature(data: bytes, max_signature_bytes: int) -> tuple[bytes, bytes]:
    """Return the exact signed main header and its single embedded signature.

    RPM6.0.2 uses signature-header tag268/BIN for RSA v4 mode, or
    tag278/STRING_ARRAY containing canonical base64 for v6 mode. Accept one
    format only; legacy whole-package, DSA and mixed signatures are refused.
    Parsing/framing proves no cryptography. The caller must verify these exact
    bytes through GPG and verify the complete RPM with RPM independently.
    """
    parts = sections(data)
    try:
        tags, _ = parse_header(data, 96)
        present = set(tags) & {267, 268, 278, 1002, 1005, 1006}
        if present == {268}:
            entry = tags[268]
            if entry["type"] != 7:
                raise ValueError("signature type")
            packet = entry["raw"]
            if entry["count"] != len(packet):
                raise ValueError("signature count")
        elif present == {278}:
            entry = tags[278]
            if entry["type"] != 8 or entry["count"] != 1 or len(entry["value"]) != 1:
                raise ValueError("signature count")
            encoded = entry["value"][0].encode("ascii")
            if len(encoded) > ((max_signature_bytes + 2) // 3) * 4:
                raise ValueError("signature bound")
            packet = base64.b64decode(encoded, validate=True)
            if base64.b64encode(packet) != encoded:
                raise ValueError("signature encoding")
        else:
            raise ValueError("signature set")
        if (type(packet) is not bytes or not 2 <= len(packet) <= max_signature_bytes
                or packet[0] not in {0x88, 0x89, 0x8a, 0x8b, 0xc2}):
            raise ValueError("signature packet")
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError, binascii.Error):
        raise PreservationError("RPM_HEADER_SIGNATURE") from None
    return parts.main_header, packet
