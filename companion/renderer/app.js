// Window logic. It only ever sees fingerprints and masked previews.

const $ = (id) => document.getElementById(id);

// The retire steps, in order, as the CLI reports them.
const STEPS = [
  ["started", "Starting"],
  ["identified", "Found the key in your project"],
  ["consumers_found", "Found what uses it"],
  ["replacement_created", "Made a replacement with the same limits"],
  ["replacement_live", "Google accepts the replacement"],
  ["secret_version_added", "Stored the replacement"],
  ["service_rolled", "Moved your app onto it"],
  ["old_key_deleted", "Deleted the leaked key"],
  ["old_version_disabled", "Disabled the old secret version"],
  ["proving", "Asking Google until it refuses the old key"],
];
const API_NAMES = {
  "generativelanguage.googleapis.com": "Gemini",
  "aiplatform.googleapis.com": "Vertex AI",
  "maps-backend.googleapis.com": "Maps",
  "youtube.googleapis.com": "YouTube",
};

let view = "home";
let keysLoaded = false;

// The window sizes itself to the panel, so it is never taller than what it shows.
function fit() {
  requestAnimationFrame(() => window.vg.resize(Math.ceil($("panel").getBoundingClientRect().height) + 20));
}

function chip(text, bad = false) {
  const span = document.createElement("span");
  span.className = bad ? "chip bad" : "chip";
  span.textContent = text;
  return span;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function limitsText(restrictions) {
  if (restrictions.unrestricted) return null;
  if (restrictions.apis.length === 1) return `${API_NAMES[restrictions.apis[0]] || restrictions.apis[0]} only`;
  if (restrictions.apis.length > 1) return `${restrictions.apis.length} APIs`;
  return "locked to apps";
}

function renderChips(key, settings) {
  const r = key.report;
  const chips = $("chips");
  chips.replaceChildren();
  if (key.masked.startsWith("AQ.")) chips.append(chip("authorization key"));
  if (r.owned) {
    const limits = limitsText(r.restrictions);
    chips.append(limits ? chip(limits) : chip("works on every API", true));
    if (r.age_days != null) chips.append(chip(`${plural(r.age_days, "day")} old`, r.age_days > 180));
  } else if (r.owned === false) {
    chips.append(chip("not in your project"));
  } else if (!settings.project) {
    chips.append(chip("set a project to see more"));
  }
}

function render(state) {
  $("project").value = state.settings.project || "";
  $("watching").checked = state.settings.watching;
  $("login").checked = state.settings.openAtLogin;
  $("dot").classList.toggle("paused", !state.settings.watching);

  const key = state.key;
  $("idle").hidden = Boolean(key);
  $("keycard").hidden = !key;
  $("status").textContent = state.settings.watching ? "Watching your clipboard" : "Paused";
  $("idle-hint").textContent = state.settings.watching
    ? "Copy a Google API key and I'll check it."
    : "Turn watching back on in settings.";
  if (!key) return fit();

  $("masked").textContent = key.masked;
  const r = key.report;
  const verdict = $("verdict");
  if (!r) {
    verdict.textContent = "CHECKING";
    verdict.className = "pill checking";
    $("chips").replaceChildren();
    $("actions").hidden = true;
    $("hint").textContent = "Asking Google about this key.";
    return fit();
  }
  verdict.textContent = r.live ? "LIVE" : "DEAD";
  verdict.className = `pill ${r.live ? "live" : "dead"}`;
  renderChips(key, state.settings);
  if (key.retired) {
    $("actions").hidden = true;
    $("hint").textContent = "";
    showStamp(`DEAD in ${key.retired.seconds} s`, `Google refused it ${key.retired.probes} times in a row. Your app runs on the new key.`);
    return fit();
  }
  $("actions").hidden = state.busy;
  $("retire").disabled = !(r.live && r.owned && !state.busy);
  $("hint").textContent = !r.live
    ? "Google already rejects this key."
    : r.owned
      ? ""
      : "Only keys in your project can be retired here.";
  fit();
}

function showStamp(big, small, bad = false) {
  $("progress").hidden = true;
  $("stamp").hidden = false;
  $("stamp").className = bad ? "stamp bad" : "stamp";
  $("stamp-big").textContent = big;
  $("stamp-small").textContent = small;
}

function showProgress(step) {
  const index = STEPS.findIndex(([name]) => name === step);
  if (index < 0) return;
  $("progress").hidden = false;
  $("stamp").hidden = true;
  $("actions").hidden = true;
  $("hint").textContent = "";
  $("bar").style.width = `${Math.round(((index + 1) / (STEPS.length + 1)) * 100)}%`;
  $("step").textContent = STEPS[index][1];
}

function renderKeys(result) {
  $("keys-summary").textContent = result.summary;
  const list = $("keylist");
  list.replaceChildren();
  for (const k of result.keys) {
    const li = document.createElement("li");
    li.className = "keyrow";
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = k.title;
    name.title = k.title;
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = k.detail;
    const chips = document.createElement("div");
    chips.className = "chips";
    const apis = k.limits.split(", ");
    const limits = k.limits === "no limits" ? "works on every API"
      : apis.length === 1 && API_NAMES[apis[0]] ? `${API_NAMES[apis[0]]} only` : k.limits;
    chips.append(chip(limits, k.limits === "no limits"));
    for (const f of k.flags) if (f.flag !== "unrestricted") chips.append(chip(f.label, f.tone === "bad"));
    li.append(name, meta, chips);
    list.append(li);
  }
  fit();
}

async function loadKeys() {
  $("keys-summary").textContent = "Asking Google...";
  $("keys-refresh").disabled = true;
  fit();
  const result = await window.vg.listKeys();
  $("keys-refresh").disabled = false;
  if (result.error) {
    $("keys-summary").textContent = result.error;
    $("keylist").replaceChildren();
    return fit();
  }
  keysLoaded = true;
  renderKeys(result.view);
}

function showView(name) {
  view = name;
  const titles = { home: "VibeGuardian", keys: "Your keys", settings: "Settings" };
  for (const v of ["home", "keys", "settings"]) $(`view-${v}`).hidden = v !== name;
  $("title").textContent = titles[name];
  $("tab-clipboard").hidden = name === "home";
  $("logo").hidden = name !== "home";
  $("tab-keys").hidden = name !== "home";
  $("tab-settings").hidden = name !== "home";
  if (name === "keys" && !keysLoaded) loadKeys();
  fit();
}

window.vg.onState(render);
window.vg.onError((message) => {
  $("error").hidden = false;
  $("error").textContent = message;
  fit();
});
window.vg.onProgress((p) => {
  $("error").hidden = true;
  if (p.step === "proven") {
    showStamp(`DEAD in ${p.seconds} s`, `Google refused it ${p.probes} times in a row. Your app runs on the new key.`);
  } else if (p.step === "failed") {
    showStamp("Not retired", p.reason || "Nothing was changed. The old key still works.", true);
  } else if (p.step === "not_proven") {
    showStamp("Not proven yet", "Retired, but Google has not refused it enough times yet.", true);
  } else {
    showProgress(p.step);
  }
  fit();
});

$("retire").addEventListener("click", async () => {
  $("retire").disabled = true;
  const result = await window.vg.retire();
  if (!result.ok && result.reason) {
    $("error").hidden = false;
    $("error").textContent = result.reason;
    fit();
  }
});
$("dismiss").addEventListener("click", async () => {
  $("stamp").hidden = true;
  $("progress").hidden = true;
  render(await window.vg.dismiss());
});
$("tab-clipboard").addEventListener("click", () => showView("home"));
$("tab-keys").addEventListener("click", () => showView("keys"));
$("tab-settings").addEventListener("click", () => showView("settings"));
$("keys-refresh").addEventListener("click", () => loadKeys());
$("project").addEventListener("change", async (e) => {
  render(await window.vg.setProject(e.target.value));
  keysLoaded = false;
});
$("watching").addEventListener("change", async (e) => render(await window.vg.setWatching(e.target.checked)));
$("login").addEventListener("change", async (e) => render(await window.vg.setOpenAtLogin(e.target.checked)));

window.vg.getState().then(render);
