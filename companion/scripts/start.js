// Launch the app. Terminals inside VS Code (an Electron app) set
// ELECTRON_RUN_AS_NODE=1, which makes Electron behave like plain Node and
// crash on require("electron"). Clear it before starting.

const { spawn } = require("node:child_process");
const path = require("node:path");
const electron = require("electron"); // from plain Node this is the binary's path

const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;

const child = spawn(electron, ["."], { stdio: "inherit", env, cwd: path.resolve(__dirname, "..") });
child.on("exit", (code) => process.exit(code ?? 0));
