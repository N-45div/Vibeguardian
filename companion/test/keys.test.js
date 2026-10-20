const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const { findGoogleKey, fingerprint, mask } = require("../src/keys");

const KEY = "AIza" + "E".repeat(35);

test("finds a key inside surrounding text", () => {
  assert.strictEqual(findGoogleKey(`GEMINI_API_KEY="${KEY}"\n`), KEY);
});

test("ignores key-shaped strings that are too long or too short", () => {
  assert.strictEqual(findGoogleKey(KEY + "E"), null);
  assert.strictEqual(findGoogleKey("AIza" + "E".repeat(30)), null);
  assert.strictEqual(findGoogleKey("x" + KEY), null);
});

test("ignores non-text and very large clipboard contents", () => {
  assert.strictEqual(findGoogleKey(undefined), null);
  assert.strictEqual(findGoogleKey("a".repeat(100001) + KEY), null);
});

test("fingerprint matches the vg CLI format", () => {
  const hex = crypto.createHash("sha256").update(KEY).digest("hex").slice(0, 12);
  assert.strictEqual(fingerprint(KEY), `sha256:${hex}`);
});

test("mask never reveals the usable middle of the key", () => {
  const masked = mask(KEY);
  assert.strictEqual(masked, "AIza…EEEE");
  assert.ok(!masked.includes(KEY.slice(4, -4)));
});

test("finds authorization keys too, and not FAQ. text", () => {
  const authKey = "AQ." + "Ab8RN6" + "c".repeat(43) + "g";
  assert.strictEqual(findGoogleKey(`GEMINI_API_KEY="${authKey}"`), authKey);
  assert.strictEqual(findGoogleKey("F" + authKey), null);
  assert.strictEqual(findGoogleKey(authKey + "c"), null);
});

test("spots other AI providers' keys, and not words that only look like them", () => {
  const { findOtherKey } = require("../src/keys");
  const openai = "sk-proj-" + "a".repeat(74) + "T3BlbkFJ" + "b".repeat(74);
  const anthropic = "sk-ant-api03-" + "c".repeat(93) + "AA";
  assert.strictEqual(findOtherKey(`OPENAI_API_KEY=${openai}`).provider.name, "openai");
  assert.strictEqual(findOtherKey(anthropic).value, anthropic);
  assert.strictEqual(findOtherKey("hf_" + "d".repeat(34)).provider.label, "Hugging Face token");
  for (const text of ["pip install sk-learn-preprocessing", "hf_hub_download(repo_id)", "md-toolbar-container"]) {
    assert.strictEqual(findOtherKey(text), null);
  }
});
