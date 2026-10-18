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
