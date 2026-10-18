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

function fingerprint(value) {
  const hex = crypto.createHash("sha256").update(value, "utf8").digest("hex");
  return `sha256:${hex.slice(0, 12)}`;
}

// "AIza…k3Fq": enough to recognise, not enough to use.
function mask(value) {
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

module.exports = { findGoogleKey, fingerprint, mask };
