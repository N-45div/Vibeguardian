"""Stop a Google API key before it is committed.

``vg scan-staged`` reads only the lines a commit adds (the staged diff) and
finds Google API keys in both formats. Run as a git pre-commit hook it blocks
the commit and names each key by file, line and fingerprint, never by value.
``vg install-hook`` installs it for one repository; the repository's
``.pre-commit-hooks.yaml`` offers it to the pre-commit framework.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from vibeguardian.leaks import GOOGLE_API_KEY
from vibeguardian.secret import fingerprint

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass(frozen=True)
class StagedKey:
    file: str
    line: int
    value: str  # in memory only; never printed

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.value)

    @property
    def kind(self) -> str:
        return "authorization key" if self.value.startswith("AQ.") else "API key"


def staged_keys(repo: str = ".") -> list[StagedKey]:
    """Google API keys on lines the staged changes add, in file order."""
    diff = subprocess.run(
        ["git", "-C", repo, "diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
    ).stdout
    found: list[StagedKey] = []
    file, line, in_header = None, 0, False
    for row in diff.splitlines():
        if row.startswith("diff --git "):
            file, in_header = None, True
        elif in_header and row.startswith("+++ "):
            # A file header only comes before the first hunk: an added line
            # that itself starts with "++" must not be read as one.
            file = row[6:] if row.startswith("+++ b/") else None
        elif (hunk := _HUNK.match(row)) is not None:
            line, in_header = int(hunk.group(1)), False
        elif not in_header and row.startswith("+") and file is not None:
            found.extend(StagedKey(file, line, m.group(0)) for m in GOOGLE_API_KEY.finditer(row[1:]))
            line += 1
    return found


def report(keys: list[StagedKey], verdicts: dict[str, str] | None = None) -> str:
    lines = ["VibeGuardian: this commit adds a Google API key, so it was stopped. Nothing was committed."]
    for k in keys:
        status = f"  {verdicts[k.fingerprint]}" if verdicts and k.fingerprint in verdicts else ""
        lines.append(f"  {k.file}:{k.line}  {k.kind}  {k.fingerprint}{status}")
    lines += [
        "Keep keys out of the code: read them from an environment variable or Secret Manager.",
        "If this key was ever pushed or shared, retire it: vg retire --key-env <VAR> --project <project>",
        "To commit anyway, for a value you know is not a real key: git commit --no-verify",
    ]
    return "\n".join(lines)


HOOK = """#!/bin/sh
# Installed by vg install-hook: stops commits that add a Google API key.
exec "{python}" -m vibeguardian.cli scan-staged
"""


def install_hook(repo: str = ".", force: bool = False) -> Path:
    """Write .git/hooks/pre-commit for this repository; refuse to replace another hook."""
    hooks = subprocess.run(["git", "-C", repo, "rev-parse", "--git-path", "hooks"],
                           capture_output=True, text=True, check=True).stdout.strip()
    path = Path(repo, hooks) if not Path(hooks).is_absolute() else Path(hooks)
    target = path / "pre-commit"
    if target.exists() and not force and "vg install-hook" not in target.read_text(encoding="utf-8", errors="replace"):
        raise FileExistsError(f"{target} already exists; add 'vg scan-staged' to it, or use --force")
    path.mkdir(parents=True, exist_ok=True)
    target.write_text(HOOK.format(python=Path(sys.executable).as_posix()), encoding="utf-8", newline="\n")
    target.chmod(0o755)
    return target
