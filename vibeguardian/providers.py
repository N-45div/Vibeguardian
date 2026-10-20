"""API keys from other AI providers, so they are caught too.

VibeGuardian retires and proves dead only Google keys. For these it can stop
the commit (or warn about the clipboard) and say where the key is revoked.

The patterns are gitleaks' rules (MIT, github.com/gitleaks/gitleaks,
config/gitleaks.toml): a fixed prefix plus a fixed body, and for OpenAI the
"T3BlbkFJ" marker every key carries, so ordinary text does not match.
Providers without such a precise rule are left out on purpose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_EDGE_L = r"(?<![A-Za-z0-9_\-])"
_EDGE_R = r"(?![A-Za-z0-9_\-])"


@dataclass(frozen=True)
class Provider:
    name: str
    label: str
    pattern: re.Pattern[str]
    revoke_at: str


OTHER_PROVIDERS = [
    Provider("openai", "OpenAI key", re.compile(
        _EDGE_L + r"(?:sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ"
        r"(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})" + _EDGE_R),
        "https://platform.openai.com/api-keys"),
    Provider("anthropic", "Anthropic key", re.compile(
        _EDGE_L + r"sk-ant-(?:api03|admin01)-[a-zA-Z0-9_\-]{93}AA" + _EDGE_R),
        "https://console.anthropic.com/settings/keys"),
    Provider("huggingface", "Hugging Face token", re.compile(
        _EDGE_L + r"(?:hf_|api_org_)[A-Za-z]{34}" + _EDGE_R),
        "https://huggingface.co/settings/tokens"),
    Provider("perplexity", "Perplexity key", re.compile(
        _EDGE_L + r"pplx-[a-zA-Z0-9]{48}" + _EDGE_R),
        "https://www.perplexity.ai/settings/api"),
]


def find_other_keys(text: str) -> list[tuple[Provider, re.Match[str]]]:
    return [(p, m) for p in OTHER_PROVIDERS for m in p.pattern.finditer(text)]
