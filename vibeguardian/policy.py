"""What VibeGuardian may do without a person, read from ``.vibeguardian.toml``.

    [retire]
    auto = true            # false: every leak waits for a person to approve
    max_services = 3       # retiring a key that more services use waits for approval
    protected = []         # services (globs on the full name) that always wait

    [replacement]
    limit_to_used_apis = true  # a leaked key that works on every API is replaced
    used_days = 30             # by one limited to the APIs it called in these days

A missing file means these defaults. An unknown setting is an error, so a
typo cannot silently loosen the policy.
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_KNOWN = {
    "retire": {"auto", "max_services", "protected"},
    "replacement": {"limit_to_used_apis", "used_days"},
}


@dataclass(frozen=True)
class Policy:
    auto: bool = True
    max_services: int = 3
    protected: tuple[str, ...] = ()
    limit_to_used_apis: bool = True
    used_days: int = 30

    def approval_reason(self, services: list[str]) -> str | None:
        """Why a person must approve retiring a key these services use, or None."""
        if not self.auto:
            return "the policy sets retire.auto = false, so every retirement needs a person"
        hit = sorted(s for s in services if any(fnmatch.fnmatch(s, p) for p in self.protected))
        if hit:
            return f"the policy protects {', '.join(hit)}"
        if len(services) > self.max_services:
            return f"{len(services)} services use this key, above the policy's limit of {self.max_services}"
        return None


def parse(text: str) -> Policy:
    data: dict[str, Any] = tomllib.loads(text) if text.strip() else {}
    for section, values in data.items():
        if section not in _KNOWN or not isinstance(values, dict):
            raise ValueError(f"unknown policy section [{section}]")
        unknown = set(values) - _KNOWN[section]
        if unknown:
            raise ValueError(f"unknown setting(s) in [{section}]: {', '.join(sorted(unknown))}")
    retire, replacement = data.get("retire", {}), data.get("replacement", {})
    policy = Policy(
        auto=bool(retire.get("auto", True)),
        max_services=int(retire.get("max_services", 3)),
        protected=tuple(str(p) for p in retire.get("protected", [])),
        limit_to_used_apis=bool(replacement.get("limit_to_used_apis", True)),
        used_days=int(replacement.get("used_days", 30)),
    )
    if policy.max_services < 0 or not 1 <= policy.used_days <= 42:
        raise ValueError("max_services must be >= 0 and used_days between 1 and 42 (Monitoring keeps 6 weeks)")
    return policy


def load(path: str | Path | None) -> Policy:
    if not path or not Path(path).exists():
        return Policy()
    return parse(Path(path).read_text(encoding="utf-8"))
