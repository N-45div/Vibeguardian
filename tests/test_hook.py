import subprocess

import pytest

from vibeguardian.hook import install_hook, report, staged_keys

CLASSIC = "AIza" + "H" * 35  # key shapes built at runtime, so no key-shaped literal sits in the source
AUTH = "AQ." + "Ab8RN6" + "h" * 43 + "g"


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "old.py").write_text(f'OLD = "{CLASSIC}"\n')  # already committed: not this commit's doing
    git(tmp_path, "add", "old.py")
    git(tmp_path, "commit", "-q", "-m", "init", "--no-verify")
    return tmp_path


def test_only_lines_this_commit_adds_are_checked(repo):
    (repo / "app.py").write_text(f'A = 1\nKEY = "{AUTH}"\nB = 2\n')
    (repo / "old.py").write_text(f'OLD = "{CLASSIC}"\nNEW = 1\n')
    git(repo, "add", "app.py", "old.py")
    keys = staged_keys(str(repo))
    assert [(k.file, k.line, k.kind) for k in keys] == [("app.py", 2, "Google authorization key")]


def test_unstaged_edits_do_not_count(repo):
    (repo / "app.py").write_text("A = 1\n")
    git(repo, "add", "app.py")
    (repo / "app.py").write_text(f'A = "{CLASSIC}"\n')  # in the working tree only
    assert staged_keys(str(repo)) == []


def test_an_added_line_that_starts_with_plus_plus_is_not_a_file_header(repo):
    (repo / "notes.txt").write_text(f'++ {CLASSIC}\n')
    git(repo, "add", "notes.txt")
    assert [(k.file, k.line) for k in staged_keys(str(repo))] == [("notes.txt", 1)]


def test_the_report_names_keys_by_fingerprint_only(repo):
    (repo / "app.py").write_text(f'KEY = "{CLASSIC}"\n')
    git(repo, "add", "app.py")
    keys = staged_keys(str(repo))
    text = report(keys, {keys[0].fingerprint: "LIVE: Google accepts it"})
    assert CLASSIC not in text
    assert keys[0].fingerprint in text and "app.py:1" in text and "LIVE" in text


def test_install_hook_stops_a_real_commit_and_lets_a_clean_one_through(repo):
    hook = install_hook(str(repo))
    assert hook.name == "pre-commit"
    (repo / "app.py").write_text(f'KEY = "{AUTH}"\n')
    git(repo, "add", "app.py")
    blocked = subprocess.run(["git", "-C", str(repo), "commit", "-m", "leak"], capture_output=True, text=True)
    assert blocked.returncode != 0
    assert "Nothing was committed" in blocked.stderr and AUTH not in blocked.stderr + blocked.stdout
    (repo / "app.py").write_text('KEY = os.environ["GEMINI_API_KEY"]\n')
    git(repo, "add", "app.py")
    git(repo, "commit", "-q", "-m", "clean")


def test_install_hook_will_not_replace_someone_elses_hook(repo):
    other = repo / ".git" / "hooks" / "pre-commit"
    other.write_text("#!/bin/sh\necho mine\n")
    with pytest.raises(FileExistsError):
        install_hook(str(repo))
    assert install_hook(str(repo), force=True).read_text().startswith("#!/bin/sh")


# Other providers' key shapes, built at runtime from gitleaks' patterns.
OPENAI = "sk-proj-" + "a" * 74 + "T3BlbkFJ" + "b" * 74
ANTHROPIC = "sk-ant-api03-" + "c" * 93 + "AA"
HUGGINGFACE = "hf_" + "d" * 34
PERPLEXITY = "pplx-" + "e" * 48


def test_other_ai_providers_keys_are_stopped_with_where_to_revoke_them(repo):
    (repo / "keys.env").write_text(f"OPENAI={OPENAI}\nANTHROPIC={ANTHROPIC}\nHF={HUGGINGFACE}\nPPLX={PERPLEXITY}\n")
    git(repo, "add", "keys.env")
    keys = staged_keys(str(repo))
    assert [(k.line, k.kind) for k in keys] == [
        (1, "OpenAI key"), (2, "Anthropic key"), (3, "Hugging Face token"), (4, "Perplexity key")]
    text = report(keys)
    assert "platform.openai.com/api-keys" in text and "console.anthropic.com/settings/keys" in text
    assert "vg retire" not in text  # VibeGuardian retires only Google keys
    assert not any(v in text for v in (OPENAI, ANTHROPIC, HUGGINGFACE, PERPLEXITY))


def test_names_and_words_that_only_look_like_keys_are_left_alone(repo):
    (repo / "notes.txt").write_text(
        "export GOOGLE_APPLICATION_CREDENTIALS=creds.json\n"
        "pip install sk-learn-preprocessing\n"
        '<div class="md-toolbar-container">\n'
        "hf_hub_download(repo_id)\n"
        "Read the FAQ.\n")
    git(repo, "add", "notes.txt")
    assert staged_keys(str(repo)) == []
