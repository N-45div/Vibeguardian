const test = require("node:test");
const assert = require("node:assert/strict");
const { keysView } = require("../src/inventory");

const key = (over) => ({
  uid: "u1",
  display_name: "app key",
  age_days: 12,
  calls: 40,
  regions: ["us-central1"],
  restrictions: { apis: ["generativelanguage.googleapis.com"], apps: [], unrestricted: false },
  flags: [],
  ...over,
});

test("summarises the risky keys", () => {
  const view = keysView({ days: 7, keys: [
    key({ uid: "a", flags: ["unrestricted", "unused"], calls: 0, regions: [],
          restrictions: { apis: [], apps: [], unrestricted: true } }),
    key({ uid: "b" }),
  ] });
  assert.equal(view.summary, "2 keys · 1 unrestricted · 1 unused");
  assert.equal(view.keys[0].limits, "no limits");
  assert.deepEqual(view.keys[0].flags.map((f) => f.label), ["works on every API", "no calls in 7 days"]);
  assert.equal(view.keys[0].detail, "12 days old · 0 calls in 7 days");
  assert.equal(view.keys[1].detail, "12 days old · 40 calls in 7 days · from us-central1");
  assert.equal(view.keys[1].limits, "generativelanguage.googleapis.com");
});

test("an empty project still reads well", () => {
  assert.equal(keysView({ days: 7, keys: [] }).summary, "0 keys");
  assert.equal(keysView({ days: 7, keys: [key({ age_days: 1, calls: 1 })] }).keys[0].detail,
    "1 day old · 1 call in 7 days · from us-central1");
});

test("several regions read as a count, so the line stays short", () => {
  const view = keysView({ days: 7, keys: [key({ regions: ["asia-southeast1", "us-central1", "us-east4"], calls: 20 })] });
  assert.equal(view.keys[0].detail, "12 days old · 20 calls in 7 days · from 3 regions");
});
