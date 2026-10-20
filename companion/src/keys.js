// Spot Google API keys in text without ever keeping or showing the value.
//
// Only the fingerprint (sha256 plus 12 hex characters, the same form the
// vg CLI uses) and a masked preview leave this module.

const crypto = require("node:crypto");

// Classic keys ("AIza" + 35) and authorization keys ("AQ." + 50, ending in
// A, Q, g or w), not glued to more key characters.
const GOOGLE_API_KEY = /(?<![0-9A-Za-z_-])(?:AIza[0-9A-Za-z_-]{35}|AQ\.[0-9A-Za-z_-]{49}[AQgw])(?![0-9A-Za-z_-])/;

function findGoogleKey(text) {
  if (typeof text !== "string" || text.length > 100000) return null;
  const match = text.match(GOOGLE_API_KEY);
  return match ? match[0] : null;
}

// Other AI providers' keys, from gitleaks' rules (MIT). VibeGuardian cannot
// retire these; it says where they are revoked.
const L = "(?<![0-9A-Za-z_-])";
const R = "(?![0-9A-Za-z_-])";
const OTHER_PROVIDERS = [
  {
    name: "openai",
    label: "OpenAI key",
    revokeAt: "https://platform.openai.com/api-keys",
    pattern: new RegExp(`${L}(?:sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})${R}`),
  },
  {
    name: "anthropic",
    label: "Anthropic key",
    revokeAt: "https://console.anthropic.com/settings/keys",
    pattern: new RegExp(`${L}sk-ant-(?:api03|admin01)-[a-zA-Z0-9_-]{93}AA${R}`),
  },
  {
    name: "huggingface",
    label: "Hugging Face token",
    revokeAt: "https://huggingface.co/settings/tokens",
    pattern: new RegExp(`${L}(?:hf_|api_org_)[A-Za-z]{34}${R}`),
  },
  {
    name: "perplexity",
    label: "Perplexity key",
    revokeAt: "https://www.perplexity.ai/settings/api",
    pattern: new RegExp(`${L}pplx-[a-zA-Z0-9]{48}${R}`),
  },
];

// The first other-provider key in the text, or null: { provider, value }.
function findOtherKey(text) {
  if (typeof text !== "string" || text.length > 100000) return null;
  for (const provider of OTHER_PROVIDERS) {
    const match = text.match(provider.pattern);
    if (match) return { provider, value: match[0] };
  }
  return null;
}

function fingerprint(value) {
  const hex = crypto.createHash("sha256").update(value, "utf8").digest("hex");
  return `sha256:${hex.slice(0, 12)}`;
}

// "AIza…k3Fq": enough to recognise, not enough to use.
function mask(value) {
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

module.exports = { findGoogleKey, findOtherKey, OTHER_PROVIDERS, fingerprint, mask };
