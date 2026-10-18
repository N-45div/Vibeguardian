import json

from vibeguardian.leaks import GOOGLE_API_KEY, read_leaks
from vibeguardian.secret import fingerprint

KEY = "AIza" + "B" * 35


def report(tmp_path, findings):
    path = tmp_path / "gl-secret-detection-report.json"
    path.write_text(json.dumps({"vulnerabilities": findings}))
    return str(path)


def finding(file="app/config.py", line=3, sha="abc123", raw=None, rule="gcp-api-key"):
    data = {
        "name": "Google API key",
        "identifiers": [{"type": "gitleaks_rule_id", "value": rule}],
        "location": {"file": file, "start_line": line, "commit": {"sha": sha}},
    }
    if raw is not None:
        data["raw_source_code_extract"] = raw
    return data


def test_regex_matches_only_full_google_keys():
    assert GOOGLE_API_KEY.fullmatch(KEY)
    assert not GOOGLE_API_KEY.search("AIza" + "B" * 30)
    assert not GOOGLE_API_KEY.search(KEY + "B")


def test_value_recovered_from_the_commit_line(tmp_path):
    seen = []

    def read_line(commit, file, line):
        seen.append((commit, file, line))
        return f'GEMINI_API_KEY = "{KEY}"'

    leaks = read_leaks(report(tmp_path, [finding()]), read_line=read_line)
    assert seen == [("abc123", "app/config.py", 3)]
    assert leaks[0].kind == "google_api_key"
    assert leaks[0].value == KEY


def test_raw_extract_used_when_present(tmp_path):
    leaks = read_leaks(report(tmp_path, [finding(raw=KEY)]), read_line=lambda *a: "")
    assert leaks[0].value == KEY


def test_public_view_never_carries_the_value(tmp_path):
    leaks = read_leaks(report(tmp_path, [finding(raw=KEY)]), read_line=lambda *a: "")
    public = leaks[0].public()
    assert KEY not in json.dumps(public)
    assert public["fingerprint"] == fingerprint(KEY)


def test_other_secret_types_are_reported_as_unsupported(tmp_path):
    leaks = read_leaks(
        report(tmp_path, [finding(rule="aws-access-token")]),
        read_line=lambda *a: "AWS_KEY=AKIAEXAMPLEEXAMPLE12",
    )
    assert [(l.kind, l.value) for l in leaks] == [("unsupported", None)]


def test_missing_report_means_no_leaks(tmp_path):
    assert read_leaks(str(tmp_path / "nope.json")) == []


def test_files_containing_looks_only_at_tracked_files_at_head(tmp_path):
    import shutil
    import subprocess

    if shutil.which("git") is None:
        return
    from vibeguardian.leaks import files_containing

    repo = tmp_path / "r"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q", "-b", "main")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (repo / "app.py").write_text(f'K = "{KEY}"\n')
    (repo / "clean.py").write_text("x = 1\n")
    run("add", ".")
    run("commit", "-q", "-m", "leak")
    assert files_containing(KEY, str(repo)) == ["app.py"]
    (repo / "app.py").write_text("K = None\n")
    run("commit", "-qam", "fix")
    assert files_containing(KEY, str(repo)) == []  # still in history, not in HEAD


def test_same_key_in_one_file_is_reported_once(tmp_path):
    leaks = read_leaks(
        report(tmp_path, [finding(line=3), finding(line=9)]), read_line=lambda *a: KEY
    )
    assert len(leaks) == 1


AUTH_KEY = "AQ." + "Ab8RN6" + "c" * 43 + "g"  # authorization key shape, built at runtime


def test_regex_matches_authorization_keys_too():
    assert len(AUTH_KEY) == 53
    assert GOOGLE_API_KEY.fullmatch(AUTH_KEY)
    assert GOOGLE_API_KEY.search(f'GEMINI_API_KEY="{AUTH_KEY}"').group(0) == AUTH_KEY
    assert not GOOGLE_API_KEY.search("F" + AUTH_KEY)  # "FAQ." text
    assert not GOOGLE_API_KEY.search(AUTH_KEY + "c")  # too long
    assert not GOOGLE_API_KEY.search(AUTH_KEY[:-1])  # too short
    assert not GOOGLE_API_KEY.search(AUTH_KEY[:-1] + "b")  # 37 bytes of base64 cannot end in "b"


def test_an_authorization_key_finding_is_a_google_key(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"vulnerabilities": [{
        "identifiers": [{"value": "GCPVertexExpressModeKey"}],
        "raw_source_code_extract": f'KEY = "{AUTH_KEY}"',
        "location": {"file": "app.py", "start_line": 3, "commit": {"sha": "c1"}},
    }]}))
    [leak] = read_leaks(report)
    assert leak.kind == "google_api_key" and leak.value == AUTH_KEY
    assert leak.public()["fingerprint"] == fingerprint(AUTH_KEY)
