import pytest

from vibeguardian.secret import fingerprint, redact

KEY = "AIza" + "SyD-example-not-a-real-key-000000000"  # built at runtime: no key-shaped literal in the source


def test_fingerprint_is_stable_and_short():
    assert fingerprint(KEY) == fingerprint(KEY)
    assert fingerprint(KEY).startswith("sha256:")
    assert len(fingerprint(KEY)) == len("sha256:") + 12


def test_fingerprint_never_contains_the_secret():
    assert KEY not in fingerprint(KEY)


def test_different_secrets_get_different_fingerprints():
    assert fingerprint(KEY) != fingerprint(KEY + "x")


def test_fingerprint_rejects_empty():
    with pytest.raises(ValueError):
        fingerprint("")


def test_redact_replaces_every_occurrence():
    text = f"key={KEY} again {KEY}"
    out = redact(text, KEY)
    assert KEY not in out
    assert out.count(fingerprint(KEY)) == 2


def test_redact_ignores_empty_secrets():
    assert redact("nothing here", "") == "nothing here"
