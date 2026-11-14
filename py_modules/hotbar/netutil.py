# Network helpers: the source address allowlist, the local address lookup and the failed-login throttle.
import ipaddress
import socket
from collections import OrderedDict
from dataclasses import dataclass, field

_ALLOWED_SOURCES = tuple(
    ipaddress.IPv4Network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8")
)


def is_allowed_source(address: str | None) -> bool:
    """True for an IPv4 address in the private, link-local or loopback ranges. Anything else is refused."""
    if not isinstance(address, str):
        return False
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return any(ip in net for net in _ALLOWED_SOURCES)


def default_local_ip() -> str | None:
    """The address this machine would use to reach a private network, or None if it has none.
    Connecting a datagram socket only picks a route, so nothing is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.255.255.255", 1))
            address = probe.getsockname()[0]
    except OSError:
        return None
    # A loopback address is no use to a phone, so it does not count.
    if not is_allowed_source(address) or ipaddress.IPv4Address(address).is_loopback:
        return None
    return address


@dataclass
class _Entry:
    failures: list[int] = field(default_factory=list)  # times of recent failures, ms
    blocked_until_ms: int = 0


class AddressThrottle:
    """Blocks a source address for `window_ms` once it has `max_failures` failures within `window_ms`."""

    def __init__(self, max_failures: int, window_ms: int, table_max: int = 1024):
        self._max_failures = max_failures
        self._window_ms = window_ms
        self._table_max = table_max
        self._entries: OrderedDict[str, _Entry] = OrderedDict()

    def blocked(self, address: str, now_ms: int) -> bool:
        entry = self._entries.get(address)
        return entry is not None and entry.blocked_until_ms > now_ms

    def record_failure(self, address: str, now_ms: int) -> None:
        entry = self._entries.setdefault(address, _Entry())
        self._entries.move_to_end(address)
        entry.failures = [t for t in entry.failures if now_ms - t < self._window_ms] + [now_ms]
        if len(entry.failures) >= self._max_failures:
            entry.blocked_until_ms = now_ms + self._window_ms
            entry.failures.clear()
        if len(self._entries) > self._table_max:
            self._prune(now_ms)

    def _prune(self, now_ms: int) -> None:
        idle = [
            address
            for address, entry in self._entries.items()
            if entry.blocked_until_ms <= now_ms and all(now_ms - t >= self._window_ms for t in entry.failures)
        ]
        for address in idle:
            del self._entries[address]
        # Still over the cap means many addresses are active at once: the least recently seen go.
        while len(self._entries) > self._table_max:
            self._entries.popitem(last=False)
