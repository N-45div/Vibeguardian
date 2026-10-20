// VibeGuardian companion: a tray app that notices when you copy a Google API
// key, says whether it is live, and can retire it and prove it dead.
//
// The key value stays in this process. The window only ever gets the
// fingerprint and a masked preview.

const { app, BrowserWindow, Tray, Notification, clipboard, ipcMain, nativeImage, screen } = require("electron");
const fs = require("node:fs");
const path = require("node:path");
const { findGoogleKey, fingerprint, mask } = require("./src/keys");
const { runVg } = require("./src/vg");
const { keysView } = require("./src/inventory");

const POLL_MS = 800;
// A small popover: the panel is 300 px wide inside a transparent window with
// room for its shadow, and the window takes the panel's height.
const WIDTH = 320;
const MIN_HEIGHT = 90;
const MAX_HEIGHT = 620;
const FORGET_KEY_AFTER_MS = 10 * 60 * 1000;

let tray = null;
let win = null;
let settings = { project: "", watching: true, openAtLogin: false };
let lastText = "";
let current = null; // { key, fp, masked, report, at }
let busy = false;

// VG_DEBUG=1 prints what the app is doing. Fingerprints only, never values.
const debug = (...args) => {
  if (process.env.VG_DEBUG) console.log("[vg]", ...args);
};

const settingsFile = () => path.join(app.getPath("userData"), "settings.json");
const icon = (state) => nativeImage.createFromPath(path.join(__dirname, "assets", `tray-${state}.png`));

function loadSettings() {
  try {
    settings = { ...settings, ...JSON.parse(fs.readFileSync(settingsFile(), "utf8")) };
  } catch {
    // first run
  }
}

function saveSettings() {
  fs.mkdirSync(path.dirname(settingsFile()), { recursive: true });
  fs.writeFileSync(settingsFile(), JSON.stringify(settings, null, 2));
}

function publicState() {
  return {
    settings,
    key: current && {
      fp: current.fp, masked: current.masked, report: current.report, at: current.at, retired: current.retired || null,
    },
    busy,
  };
}

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

function setTray(state, tooltip) {
  tray.setImage(icon(state));
  tray.setToolTip(`VibeGuardian: ${tooltip}`);
  send("state", publicState());
}

function notify(title, body) {
  if (Notification.isSupported()) new Notification({ title, body, icon: icon("alert") }).show();
}

function describe(report) {
  if (!report) return "could not check";
  const parts = [report.live ? "LIVE" : "dead (Google rejects it)"];
  if (report.owned && report.restrictions) {
    parts.push(report.restrictions.unrestricted ? "unrestricted" : `limited to ${report.restrictions.apis.join(", ") || "apps"}`);
  }
  if (report.age_days != null) parts.push(`${report.age_days} days old`);
  if (report.owned === false) parts.push("not in your project");
  return parts.join(", ");
}

async function checkKey(key) {
  const fp = fingerprint(key);
  current = { key, fp, masked: mask(key), report: null, at: Date.now() };
  setTray("checking", "checking a copied key");
  const args = ["check-key", "--key-env", "VG_LEAKED"];
  if (settings.project) args.push("--project", settings.project);
  debug("checking", fp);
  const { code, last, error } = await runVg(args, { key });
  debug("check finished", fp, "exit", code, error || "", last ? `live=${last.live}` : "no report");
  if (!current || current.fp !== fp) return;
  current.report = last && last.fingerprint === fp ? last : null;
  if (!current.report) {
    setTray("ok", "watching your clipboard");
    send("error", error || "vg check-key gave no answer");
    return;
  }
  if (current.report.live) {
    setTray("alert", `a LIVE key is on your clipboard (${current.masked})`);
    notify("Live Google API key copied", `${current.masked}: ${describe(current.report)}`);
  } else {
    setTray("ok", "watching your clipboard");
  }
  setTimeout(() => {
    if (current && current.fp === fp && !busy) {
      current.key = null; // forget the value; keep the report
    }
  }, FORGET_KEY_AFTER_MS);
}

// Newer Electron versions return a Promise from clipboard reads; older ones a string.
async function readClipboard() {
  const text = await Promise.resolve(clipboard.readText());
  return typeof text === "string" ? text : "";
}

let polling = false;
async function pollClipboard() {
  if (!settings.watching || busy || polling) return;
  polling = true;
  let text;
  try {
    text = await readClipboard();
  } finally {
    polling = false;
  }
  if (text === lastText) return;
  lastText = text;
  const key = findGoogleKey(text);
  debug("clipboard changed", `${text.length} chars`, key ? `google key ${fingerprint(key)}` : "no google key");
  if (!key) return;
  if (current && current.fp === fingerprint(key) && current.report) return;
  checkKey(key);
}

async function retire() {
  if (busy || !current || !current.key) return { ok: false, reason: "copy the key again first" };
  if (!settings.project) return { ok: false, reason: "set your Google Cloud project first" };
  busy = true;
  const started = Date.now();
  const key = current.key;
  const masked = current.masked;
  setTray("checking", "retiring the key");
  send("progress", { step: "started", at: started });
  const retired = await runVg(
    ["retire", "--key-env", "VG_LEAKED", "--project", settings.project, "--out", path.join(app.getPath("temp"), "vg-retire.jsonl")],
    {
      key,
      onEvent: (e) => {
        send("progress", { step: e.event, detail: e, at: Date.now() });
        // Development only: also snapshot the window mid-retirement.
        if (process.env.VG_SNAPSHOT_MID && e.event === "service_rolled") {
          setTimeout(async () => {
            const image = await win.webContents.capturePage();
            fs.writeFileSync(process.env.VG_SNAPSHOT_MID, image.toPNG());
          }, 500);
        }
      },
    },
  );
  const outcome = retired.last && retired.last.outcome;
  if (outcome !== "retired") {
    busy = false;
    setTray("alert", "the key could not be retired");
    send("progress", { step: "failed", outcome, reason: retired.last && retired.last.reason, error: retired.error });
    return { ok: false, reason: (retired.last && retired.last.reason) || outcome || retired.error };
  }
  send("progress", { step: "proving", at: Date.now() });
  const proof = await runVg(
    ["prove", "--key-env", "VG_LEAKED", "--stable", "6", "--interval", "5", "--max-minutes", "10",
     "--out", path.join(app.getPath("temp"), "vg-prove.jsonl")],
    { key },
  );
  busy = false;
  if (current) current.key = null;
  const dead = proof.last && proof.last.event === "verdict" && proof.last.dead;
  const seconds = Math.round((Date.now() - started) / 1000);
  if (dead) {
    if (current && current.masked === masked) {
      current.retired = { seconds, probes: proof.last.probes };
      if (current.report) current.report = { ...current.report, live: false };
    }
    setTray("ok", "watching your clipboard");
    send("progress", { step: "proven", seconds, probes: proof.last.probes });
    notify("Key retired and proven dead", `${masked}: DEAD in ${seconds} s. Google rejected it ${proof.last.probes} times in a row.`);
  } else {
    setTray("alert", "retired, but not yet proven dead");
    send("progress", { step: "not_proven", seconds });
  }
  return { ok: dead, seconds };
}

// Next to the tray icon: above it when the taskbar is at the bottom.
function placeNearTray() {
  const trayBounds = tray.getBounds();
  const { workArea } = screen.getDisplayNearestPoint({ x: trayBounds.x, y: trayBounds.y });
  const [w, h] = win.getSize();
  const x = Math.min(Math.max(trayBounds.x + trayBounds.width / 2 - w / 2, workArea.x), workArea.x + workArea.width - w);
  const y = trayBounds.y > workArea.y + workArea.height / 2 ? workArea.y + workArea.height - h : workArea.y;
  win.setPosition(Math.round(x), Math.round(y));
}

function showWindow() {
  placeNearTray();
  win.show();
  win.focus();
}

function createWindow() {
  win = new BrowserWindow({
    width: WIDTH,
    height: 160,
    show: false,
    frame: false,
    transparent: true,
    hasShadow: false,
    resizable: false,
    skipTaskbar: true,
    alwaysOnTop: true,
    backgroundColor: "#00000000",
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false },
  });
  win.loadFile(path.join(__dirname, "renderer", "index.html"));
  win.on("blur", () => {
    if (!process.env.VG_SNAPSHOT) win.hide();
  });
}

ipcMain.on("resize", (_e, height) => {
  const h = Math.min(Math.max(Math.round(Number(height) || 0), MIN_HEIGHT), MAX_HEIGHT);
  if (!win || win.isDestroyed() || win.getSize()[1] === h) return;
  // Windows will not shrink a non-resizable window below its first size.
  win.setResizable(true);
  win.setSize(WIDTH, h);
  win.setResizable(false);
  if (win.isVisible() && !process.env.VG_SNAPSHOT) placeNearTray();
});
ipcMain.handle("get-state", () => publicState());
ipcMain.handle("retire", () => retire());
ipcMain.handle("list-keys", async () => {
  if (!settings.project) return { error: "Set your Google Cloud project below to see its keys." };
  const { code, last, error } = await runVg(["keys", "--project", settings.project]);
  debug("keys finished, exit", code, error || "");
  if (!last || !Array.isArray(last.keys)) return { error: error || `vg keys failed (exit ${code})` };
  return { view: keysView(last) };
});
ipcMain.handle("set-project", (_e, project) => {
  settings.project = String(project || "").trim();
  saveSettings();
  return publicState();
});
ipcMain.handle("set-watching", (_e, on) => {
  settings.watching = Boolean(on);
  saveSettings();
  setTray(settings.watching ? "ok" : "paused", settings.watching ? "watching your clipboard" : "paused");
  return publicState();
});
ipcMain.handle("set-open-at-login", (_e, on) => {
  settings.openAtLogin = Boolean(on);
  app.setLoginItemSettings({ openAtLogin: settings.openAtLogin });
  saveSettings();
  return publicState();
});
ipcMain.handle("dismiss", () => {
  current = null;
  setTray(settings.watching ? "ok" : "paused", "watching your clipboard");
  return publicState();
});

if (!app.requestSingleInstanceLock()) app.quit();

// Development only: render snapshots at a higher pixel density (VG_SNAPSHOT_SCALE=2).
if (process.env.VG_SNAPSHOT && process.env.VG_SNAPSHOT_SCALE) {
  app.commandLine.appendSwitch("force-device-scale-factor", process.env.VG_SNAPSHOT_SCALE);
}

app.whenReady().then(async () => {
  loadSettings();
  tray = new Tray(icon(settings.watching ? "ok" : "paused"));
  tray.setToolTip("VibeGuardian: watching your clipboard");
  tray.on("click", () => (win.isVisible() ? win.hide() : showWindow()));
  createWindow();
  lastText = await readClipboard(); // do not react to what was copied before launch
  setInterval(() => void pollClipboard(), POLL_MS);

  // Development only: render the window to a PNG and quit, to check the UI.
  // The page may have finished loading during the clipboard read above.
  if (process.env.VG_SNAPSHOT) {
    if (win.webContents.isLoading()) await new Promise((r) => win.webContents.once("did-finish-load", r));
    if (process.env.VG_SNAPSHOT_TAB) {
      await win.webContents.executeJavaScript(`document.getElementById("tab-${process.env.VG_SNAPSHOT_TAB}").click()`);
      await new Promise((r) => setTimeout(r, Number(process.env.VG_SNAPSHOT_WAIT_MS || 12000)));
    }
    if (process.env.VG_SNAPSHOT_CHECK) {
      lastText = "";
      await Promise.resolve(clipboard.writeText(process.env.VG_SNAPSHOT_CHECK));
      await new Promise((r) => setTimeout(r, Number(process.env.VG_SNAPSHOT_WAIT_MS || 12000)));
      if (process.env.VG_SNAPSHOT_RETIRE) {
        const result = await retire(); // presses "Retire it now" for real
        debug("retire result", JSON.stringify(result));
        await new Promise((r) => setTimeout(r, 1500));
      }
    }
    win.show();
    await new Promise((r) => setTimeout(r, 600));
    const image = await win.webContents.capturePage();
    fs.writeFileSync(process.env.VG_SNAPSHOT, image.toPNG());
    if (process.env.VG_SNAPSHOT_CHECK) await Promise.resolve(clipboard.writeText("")); // remove the test key
    app.exit(0);
  }
});

app.on("window-all-closed", (e) => e.preventDefault()); // live in the tray
