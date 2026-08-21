"""Target-scope enforcement for authorized security testing."""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


def _hostname(value: str) -> str:
    candidate = value.strip()
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or candidate.split("/", 1)[0]).rstrip(".").lower()


@dataclass
class ScopePolicy:
    """Allow only targets explicitly covered by configured entries.

    Entries may be hostnames, wildcard hostnames, IP addresses, or CIDR ranges.
    An empty allow-list denies every target by default.
    """

    allowed: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.allowed = [entry.strip() for entry in self.allowed if entry.strip()]
        self.excluded = [entry.strip() for entry in self.excluded if entry.strip()]

    def contains(self, target: str) -> bool:
        host = _hostname(target)
        if not host or not self.allowed:
            return False
        return self._matches_any(host, self.allowed) and not self._matches_any(host, self.excluded)

    @staticmethod
    def _matches_any(host: str, entries: list[str]) -> bool:
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            host_ip = None

        for entry in entries:
            normalized = entry.strip().lower()
            if "/" not in normalized:
                normalized = _hostname(normalized)
            try:
                if host_ip is not None:
                    if host_ip in ipaddress.ip_network(normalized, strict=False):
                        return True
                elif "/" not in normalized and "*" not in normalized:
                    if host == normalized or host.endswith(f".{normalized}"):
                        return True
                elif fnmatch.fnmatch(host, normalized):
                    return True
            except ValueError:
                if fnmatch.fnmatch(host, normalized):
                    return True
        return False
