// Run the vg CLI. A key is passed in an environment variable, never as an
// argument, so it cannot show up in a process list or a crash report.

const { spawn } = require("node:child_process");

// VG_PYTHON runs the CLI as `python -m vibeguardian.cli`. Windows Smart App
// Control blocks the unsigned vg.exe launcher pip writes, but not a signed
// python.exe. VG_CLI names a vg executable; the default is `vg` on PATH.
function vgCommand(env = process.env) {
  if (env.VG_PYTHON) return { command: env.VG_PYTHON, prefix: ["-m", "vibeguardian.cli"] };
  return { command: env.VG_CLI || "vg", prefix: [] };
}

// Runs `vg <args>`; each JSON line on stdout goes to onEvent. Resolves with
// the exit code and the last JSON object printed.
function runVg(args, { key, onEvent } = {}) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    if (key) env.VG_LEAKED = key;
    let child;
    try {
      const { command, prefix } = vgCommand();
      child = spawn(command, [...prefix, ...args], { env, windowsHide: true });
    } catch (err) {
      resolve({ code: -1, last: null, error: `could not start vg: ${err.code || err.message}` });
      return;
    }
    let buffer = "";
    let last = null;
    child.stdout.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line.startsWith("{")) continue;
        try {
          last = JSON.parse(line);
          if (onEvent) onEvent(last);
        } catch {
          // not an event line
        }
      }
    });
    child.on("error", (err) => resolve({ code: -1, last, error: `could not start vg: ${err.code || err.message}` }));
    child.on("close", (code) => resolve({ code, last }));
  });
}

module.exports = { runVg, vgCommand };
