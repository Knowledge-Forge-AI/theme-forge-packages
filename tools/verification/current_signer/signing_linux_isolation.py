"""Fixed Linux metadata predicate; source preparation, not native acceptance."""
from __future__ import annotations

from pathlib import Path
import sys

from signing_network_gate import GateError

MAX_PROC_BYTES = 1024 * 1024
_TABLES = ("route", "ipv6_route", "tcp", "tcp6", "udp", "udp6")


def require_isolated_facts(interfaces: tuple[str, ...], tables: dict[str, bytes]) -> None:
    if interfaces != ("lo",) or set(tables) != set(_TABLES):
        raise GateError("ISOLATION_INTERFACE_OR_TABLES")
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
                raise GateError("ISOLATION_EXTERNAL_ROUTE")
        elif name == "ipv6_route":
            # Kernel loopback routes are legitimate; an empty IPv6 table is
            # not required. No interface other than lo may remain.
            if any(len(row.split()) != 10 or row.split()[-1] != "lo" for row in lines):
                raise GateError("ISOLATION_EXTERNAL_ROUTE")
        else:
            if not lines or lines[0].split()[:2] != ["sl", "local_address"]:
                raise GateError("ISOLATION_SOCKET_FORMAT")
            for row in lines[1:]:
                fields = row.split()
                # TCP TIME_WAIT has no active listener or usable connection.
                # Every other socket (including Docker's UDP DNS listener)
                # refuses the private phase pending actual native diagnosis.
                if len(fields) < 10 or name.startswith("udp") or fields[3] != "06":
                    raise GateError("ISOLATION_SOCKET_PRESENT")


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
