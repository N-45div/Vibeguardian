const test = require("node:test");
const assert = require("node:assert/strict");
const { vgCommand } = require("../src/vg");

test("vgCommand prefers python -m when VG_PYTHON is set", () => {
  assert.deepEqual(vgCommand({ VG_PYTHON: "py.exe", VG_CLI: "vg.exe" }), { command: "py.exe", prefix: ["-m", "vibeguardian.cli"] });
  assert.deepEqual(vgCommand({ VG_CLI: "vg.exe" }), { command: "vg.exe", prefix: [] });
  assert.deepEqual(vgCommand({}), { command: "vg", prefix: [] });
});
