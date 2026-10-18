import pytest

from vibeguardian.policy import Policy, load, parse

SVC = "projects/p/locations/us-central1/services/"


def test_defaults_when_there_is_no_file(tmp_path):
    assert load(tmp_path / "missing.toml") == Policy()
    assert load(None) == Policy()
    assert parse("") == Policy()


def test_parse_reads_every_setting():
    policy = parse("""
[retire]
auto = true
max_services = 1
protected = ["*/services/payments*"]

[replacement]
limit_to_used_apis = false
used_days = 7
""")
    assert policy == Policy(auto=True, max_services=1, protected=("*/services/payments*",),
                            limit_to_used_apis=False, used_days=7)


@pytest.mark.parametrize("text", [
    "[retire]\nmax_servces = 3\n",
    "[retier]\nauto = true\n",
    "[replacement]\nused_days = 90\n",
    "[retire]\nmax_services = -1\n",
])
def test_a_typo_or_an_impossible_value_is_an_error_not_a_looser_policy(text):
    with pytest.raises(ValueError):
        parse(text)


def test_approval_reasons():
    assert Policy().approval_reason([SVC + "a"]) is None
    assert "limit of 1" in Policy(max_services=1).approval_reason([SVC + "a", SVC + "b"])
    assert "protects" in Policy(protected=("*/services/pay*",)).approval_reason([SVC + "payments"])
    assert "retire.auto = false" in Policy(auto=False).approval_reason([])
    assert Policy(max_services=0).approval_reason([]) is None
