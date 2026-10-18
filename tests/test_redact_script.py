import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".gitlab" / "duo" / "redact-google-keys.sh"
KEY = "AIza" + "D" * 35
bash = shutil.which("bash")
pytestmark = pytest.mark.skipif(bash is None or shutil.which("git") is None, reason="needs bash and git")


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def make_repo(tmp_path, content):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "t")
    (repo / "app.py").write_text(content)
    git(repo, "add", "app.py")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def run(repo, goal=""):
    return subprocess.run(
        [bash, str(SCRIPT)], cwd=repo, capture_output=True, text=True, env={"PATH": __import__("os").environ["PATH"], "DUO_WORKFLOW_GOAL": goal}
    )


def test_replaces_keys_with_fingerprint_placeholders(tmp_path):
    repo = make_repo(tmp_path, f'A = "{KEY}"\nB = 1\nC = "{KEY}"\n')
    result = run(repo)
    assert result.returncode == 0, result.stderr
    hex12 = hashlib.sha256(KEY.encode()).hexdigest()[:12]
    text = (repo / "app.py").read_text()
    assert KEY not in text
    assert text.count(f"VIBEGUARDIAN_REDACTED_{hex12}") == 2
    listing = (repo / ".vibeguardian" / "redactions.txt").read_text().splitlines()
    assert listing == [f"app.py:1 sha256:{hex12}", f"app.py:3 sha256:{hex12}"]
    assert KEY not in result.stdout + result.stderr


def test_longer_key_shaped_strings_are_left_alone(tmp_path):
    longer = KEY + "D"  # 40 characters: not a Google API key
    repo = make_repo(tmp_path, f'X = "{longer}"\n')
    result = run(repo)
    assert result.returncode == 0, result.stderr
    assert (repo / "app.py").read_text() == f'X = "{longer}"\n'
    assert (repo / ".vibeguardian" / "redactions.txt").read_text() == ""


def test_key_at_line_start_and_end_is_redacted(tmp_path):
    repo = make_repo(tmp_path, f"{KEY}\n")
    result = run(repo)
    assert result.returncode == 0, result.stderr
    assert KEY not in (repo / "app.py").read_text()


def test_clean_checkout_passes_with_nothing_to_do(tmp_path):
    repo = make_repo(tmp_path, "A = 1\n")
    result = run(repo)
    assert result.returncode == 0, result.stderr
    assert (repo / ".vibeguardian" / "redactions.txt").read_text() == ""
