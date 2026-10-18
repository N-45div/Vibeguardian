"""Read GitLab secret detection findings and recover the leaked values.

GitLab's secret detection writes ``gl-secret-detection-report.json``. Each
finding has a file, a line, and the commit that introduced it. VibeGuardian
re-reads that line from the repository to get the value, because the value
is what Google needs to look the key up. The value stays in memory: only its
fingerprint is written anywhere.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from vibeguardian.secret import fingerprint

# Google API keys, in both formats Google issues:
#   classic        "AIza" + 35 URL-safe characters (39 in all)
#   authorization  "AQ." + 50 URL-safe characters (53 in all), bound to a
#                  service account; what Google AI Studio issues since 2026.
#                  50 characters of base64 for 37 bytes always end in A, Q, g
#                  or w, and the left edge keeps "FAQ." text out.
GOOGLE_API_KEY = re.compile(
    r"AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"
    r"|(?<![0-9A-Za-z_\-])AQ\.[0-9A-Za-z_\-]{49}[AQgw](?![0-9A-Za-z_\-])"
)


@dataclass(frozen=True)
class Leak:
    kind: str  # "google_api_key" or "unsupported"
    rule: str
    file: str
    line: int
    commit: str
    value: str | None  # in memory only; never serialised

    @property
    def fingerprint(self) -> str | None:
        return fingerprint(self.value) if self.value else None

    def public(self) -> dict[str, Any]:
        """Everything about the leak except the value."""
        return {
            "kind": self.kind,
            "rule": self.rule,
            "file": self.file,
            "line": self.line,
            "commit": self.commit,
            "fingerprint": self.fingerprint,
        }


def _rule(finding: dict[str, Any]) -> str:
    for ident in finding.get("identifiers") or []:
        if ident.get("value"):
            return str(ident["value"])
    return str(finding.get("name", "unknown"))


def git_line(commit: str, path: str, line: int, repo: str = ".") -> str:
    """Return one line of a file as it was at ``commit``."""
    text = subprocess.run(
        ["git", "-C", repo, "show", f"{commit}:{path}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    lines = text.splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else ""


def files_containing(value: str, repo: str = ".") -> list[str]:
    """Tracked files at HEAD that still contain ``value``.

    Reads the files in Python rather than passing the value to a command, so
    the value never appears in a process list or a log.
    """
    listed = subprocess.run(
        ["git", "-C", repo, "ls-files", "-z"], check=True, capture_output=True
    ).stdout.split(b"\0")
    needle = value.encode("utf-8")
    hits = []
    for name in filter(None, listed):
        path = Path(repo) / name.decode("utf-8", "replace")
        try:
            if needle in path.read_bytes():
                hits.append(name.decode("utf-8", "replace"))
        except OSError:
            continue
    return hits


def read_leaks(
    report_path: str,
    *,
    read_line: Callable[[str, str, int], str] = git_line,
) -> list[Leak]:
    """Parse a secret detection report into leaks, recovering Google API key values."""
    path = Path(report_path)
    if not path.exists():
        return []
    report = json.loads(path.read_text(encoding="utf-8"))
    leaks: list[Leak] = []
    seen: set[tuple[str, str]] = set()
    for finding in report.get("vulnerabilities", []):
        location = finding.get("location", {})
        file = location.get("file", "")
        line = int(location.get("start_line") or 0)
        commit = (location.get("commit") or {}).get("sha", "")
        rule = _rule(finding)
        candidates = GOOGLE_API_KEY.findall(str(finding.get("raw_source_code_extract", "")))
        if not candidates and commit and file and line:
            try:
                candidates = GOOGLE_API_KEY.findall(read_line(commit, file, line))
            except (subprocess.CalledProcessError, FileNotFoundError):
                candidates = []
        if not candidates:
            leaks.append(Leak("unsupported", rule, file, line, commit, None))
            continue
        for value in candidates:
            key = (value, file)
            if key in seen:
                continue
            seen.add(key)
            leaks.append(Leak("google_api_key", rule, file, line, commit, value))
    return leaks
