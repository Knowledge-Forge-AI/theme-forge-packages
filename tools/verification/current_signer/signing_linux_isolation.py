"""Fixed Linux metadata predicate; source preparation, not native acceptance."""
from __future__ import annotations

from pathlib import Path
import sys

from signing_network_gate import GateError

MAX_PROC_BYTES = 1024 * 1024
_TABLES = ("route", "ipv6_route", "tcp", "tcp6", "udp", "udp6")
_TCP_CLOSING_STATES = frozenset({"04", "05", "07", "08", "09", "0B"})
_TCP_ACTIVE_STATES = frozenset({"01", "02", "03", "0C"})
ISOLATION_DETAIL_CODES = frozenset({
    "LO_INTERFACE_MISSING",
    "NON_LO_INTERFACE_PRESENT",
    "PROC_TABLE_SET_MISMATCH",
    "IPV4_NON_LO_ROUTE",
    "IPV6_NON_LO_ROUTE",
    "SOCKET_ROW_MALFORMED",
    "UDP_V4_SOCKET",
    "UDP_V6_SOCKET",
    "TCP_V4_LISTEN",
    "TCP_V6_LISTEN",
    "TCP_V4_CLOSING_STATE",
    "TCP_V6_CLOSING_STATE",
    "TCP_V4_ACTIVE_STATE",
    "TCP_V6_ACTIVE_STATE",
    "TCP_OTHER_STATE",
})


def _classify_socket_violation(name: str, fields: list[str]) -> str:
    if len(fields) < 10:
        return "SOCKET_ROW_MALFORMED"
    if name == "udp":
        return "UDP_V4_SOCKET"
    if name == "udp6":
        return "UDP_V6_SOCKET"
    state = fields[3]
    v6 = name == "tcp6"
    if state == "0A":
        return "TCP_V6_LISTEN" if v6 else "TCP_V4_LISTEN"
    if state in _TCP_CLOSING_STATES:
        return "TCP_V6_CLOSING_STATE" if v6 else "TCP_V4_CLOSING_STATE"
    if state in _TCP_ACTIVE_STATES:
        return "TCP_V6_ACTIVE_STATE" if v6 else "TCP_V4_ACTIVE_STATE"
    return "TCP_OTHER_STATE"


def require_isolated_facts(interfaces: tuple[str, ...], tables: dict[str, bytes]) -> None:
    if interfaces != ("lo",) or set(tables) != set(_TABLES):
        detail = (
            "PROC_TABLE_SET_MISMATCH"
            if set(tables) != set(_TABLES)
            else ("LO_INTERFACE_MISSING" if "lo" not in interfaces else "NON_LO_INTERFACE_PRESENT")
        )
        raise GateError("ISOLATION_INTERFACE_OR_TABLES", detail=detail)
    for name, body in tables.items():
        if type(body) is not bytes or len(body) > MAX_PROC_BYTES:
            raise GateError("ISOLATION_METADATA_BOUND")
        try:
            lines = body.decode("ascii").splitlines()
        except UnicodeError:
            raise GateError("ISOLATION_METADATA_FORMAT") from None
        if name == "route":
            if not lines or not lines[0].split() or lines[0].split()[0] != "Iface":
                raise GateError("ISOLATION_ROUTE_FORMAT")
            if any(len(row.split()) != 11 or row.split()[0] != "lo" for row in lines[1:]):
                raise GateError("ISOLATION_EXTERNAL_ROUTE", detail="IPV4_NON_LO_ROUTE")
        elif name == "ipv6_route":
            # Kernel loopback routes are legitimate; an empty IPv6 table is
            # not required. No interface other than lo may remain.
            if any(len(row.split()) != 10 or row.split()[-1] != "lo" for row in lines):
                raise GateError("ISOLATION_EXTERNAL_ROUTE", detail="IPV6_NON_LO_ROUTE")
        else:
            if not lines or lines[0].split()[:2] != ["sl", "local_address"]:
                raise GateError("ISOLATION_SOCKET_FORMAT")
            for row in lines[1:]:
                fields = row.split()
                # TCP TIME_WAIT has no active listener or usable connection.
                # Every other socket (including Docker's UDP DNS listener)
                # refuses the private phase pending actual native diagnosis.
                if len(fields) < 10 or name.startswith("udp") or fields[3] != "06":
                    raise GateError(
                        "ISOLATION_SOCKET_PRESENT",
                        detail=_classify_socket_violation(name, fields),
                    )


def prove_linux_isolation() -> None:
    """Read only fixed namespace metadata; never return raw addresses/routes."""
    if sys.platform != "linux":
        raise GateError("ISOLATION_REQUIRES_LINUX")
    try:
        interfaces = tuple(sorted(p.name for p in Path("/sys/class/net").iterdir()))
        tables = {}
        for name in _TABLES:
            with (Path("/proc/net") / name).open("rb") as source:
                tables[name] = source.read(MAX_PROC_BYTES + 1)
    except OSError:
        raise GateError("ISOLATION_METADATA_UNAVAILABLE") from None
    require_isolated_facts(interfaces, tables)
