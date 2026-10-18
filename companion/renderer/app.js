// Window logic. It only ever sees fingerprints and masked previews.

const $ = (id) => document.getElementById(id);

const STEP_LABELS = {
  started: "Starting",
  identified: "Found the key in your project",
  consumers_found: "Found what uses it",
  replacement_created: "Created a replacement with the same limits",
  replacement_live: "Google accepts the replacement",
  secret_version_added: "Stored the replacement in Secret Manager",
  service_rolled: "Rolled the service onto the replacement",
  old_key_deleted: "Deleted the leaked key",
  old_version_disabled: "Disabled the old secret version",
  proving: "Asking Google, repeatedly, if the old key still works",
};

function fact(label, value, bad) {
  const li = document.createElement("li");
  const a = document.createElement("span");
  const b = document.createElement("span");
  a.textContent = label;
  b.textContent = value;
  if (bad) b.className = "bad";
  li.append(a, b);
  return li;
}

function render(state) {
  $("project").value = state.settings.project || "";
  $("watching").checked = state.settings.watching;
  $("login").checked = state.settings.openAtLogin;
  const key = state.key;
  $("status").textContent = !state.settings.watching
    ? "Paused. I am not watching your clipboard."
    : key && key.report && key.report.live
      ? "A live Google API key is on your clipboard."
      : "Watching your clipboard for Google API keys.";

  $("empty").hidden = Boolean(key);
  $("keycard").hidden = !key;
  if (!key) return;

  $("masked").textContent = key.masked;
  $("fp").textContent = key.fp;
  const r = key.report;
  const verdict = $("verdict");
  const facts = $("facts");
  facts.replaceChildren();
  if (!r) {
    verdict.textContent = "CHECKING";
    verdict.className = "pill checking";
    $("retire").disabled = true;
    return;
  }
  verdict.textContent = r.live ? "LIVE" : "DEAD";
  verdict.className = `pill ${r.live ? "live" : "dead"}`;
  if (key.retired) {
    facts.append(fact("Retired", `proven dead in ${key.retired.seconds} s`));
    facts.append(fact("Proof", `Google rejected it ${key.retired.probes} times in a row`));
    $("retire").disabled = true;
    $("hint").textContent = "Your services now use the replacement. This key no longer works anywhere.";
    return;
  }
  facts.append(fact("Google says", r.live ? "accepted" : String(r.google_says)));
  if (r.owned) {
    facts.append(fact("Project", r.project_number));
    if (r.display_name) facts.append(fact("Name", r.display_name));
    if (r.age_days != null) facts.append(fact("Age", `${r.age_days} days`, r.age_days > 180));
    const limits = r.restrictions.unrestricted
      ? "none: works on every API"
      : [...r.restrictions.apis, ...r.restrictions.apps].join(", ");
    facts.append(fact("Limited to", limits, r.restrictions.unrestricted));
  } else if (r.owned === false) {
    facts.append(fact("Project", "not one of yours"));
  } else if (r.lookup_error || !state.settings.project) {
    facts.append(fact("Project", "set your project below to see more"));
  }
  const canRetire = r.live && r.owned && !state.busy;
  $("retire").disabled = !canRetire;
  $("hint").textContent = !r.live
    ? "Google already rejects this key. Nothing to do."
    : r.owned
      ? "Retiring rolls out a replacement first, then deletes this key and proves it dead."
      : "To retire it I need it to be in your project.";
}

function addStep(text, done = true) {
  const li = document.createElement("li");
  li.textContent = text;
  if (done) li.className = "done";
  $("steps").append(li);
}

window.vg.onState(render);
window.vg.onError((message) => {
  $("error").hidden = false;
  $("error").textContent = message;
});
window.vg.onProgress((p) => {
  $("progress").hidden = false;
  if (p.step === "started") {
    $("steps").replaceChildren();
    $("stamp").hidden = true;
  }
  if (STEP_LABELS[p.step]) addStep(STEP_LABELS[p.step]);
  if (p.step === "proven") {
    $("stamp").hidden = false;
    $("stamp").className = "stamp";
    $("stamp").textContent = `DEAD in ${p.seconds} s`;
  }
  if (p.step === "failed" || p.step === "not_proven") {
    $("stamp").hidden = false;
    $("stamp").className = "stamp bad";
    $("stamp").textContent = p.step === "failed" ? "NOT RETIRED" : "NOT YET PROVEN";
    if (p.reason) addStep(p.reason, false);
  }
  $("progress").scrollIntoView({ block: "end", behavior: "smooth" });
});

let keysLoaded = false;

function small(text) {
  const p = document.createElement("p");
  p.className = "small";
  p.textContent = text;
  return p;
}

function renderKeys(view) {
  $("keys-summary").textContent = view.summary;
  const list = $("keylist");
  list.replaceChildren();
  for (const k of view.keys) {
    const li = document.createElement("li");
    li.className = "card keyrow";
    const title = document.createElement("div");
    title.className = "keytitle";
    title.textContent = k.title;
    const flags = document.createElement("div");
    flags.className = "flags";
    for (const f of k.flags) {
      const span = document.createElement("span");
      span.className = `flag ${f.tone}`;
      span.textContent = f.label;
      flags.append(span);
    }
    li.append(title, small(k.detail), small(`Limited to: ${k.limits}`));
    if (k.flags.length) li.append(flags);
    list.append(li);
  }
}

async function loadKeys() {
  $("keys-summary").textContent = "Asking Google...";
  $("keys-refresh").disabled = true;
  const result = await window.vg.listKeys();
  $("keys-refresh").disabled = false;
  if (result.error) {
    $("keys-summary").textContent = result.error;
    $("keylist").replaceChildren();
    return;
  }
  keysLoaded = true;
  renderKeys(result.view);
}

function showTab(name) {
  for (const tab of ["clipboard", "keys"]) {
    $(`tab-${tab}`).classList.toggle("active", tab === name);
    $(`tab-${tab}`).setAttribute("aria-selected", String(tab === name));
    $(`pane-${tab}`).hidden = tab !== name;
  }
  if (name === "keys" && !keysLoaded) loadKeys();
}

$("tab-clipboard").addEventListener("click", () => showTab("clipboard"));
$("tab-keys").addEventListener("click", () => showTab("keys"));
$("keys-refresh").addEventListener("click", () => loadKeys());

$("retire").addEventListener("click", async () => {
  $("retire").disabled = true;
  const result = await window.vg.retire();
  if (!result.ok && result.reason) {
    $("error").hidden = false;
    $("error").textContent = result.reason;
  }
});
$("dismiss").addEventListener("click", async () => render(await window.vg.dismiss()));
$("project").addEventListener("change", async (e) => {
  render(await window.vg.setProject(e.target.value));
  keysLoaded = false;
  if (!$("pane-keys").hidden) loadKeys();
});
$("watching").addEventListener("change", async (e) => render(await window.vg.setWatching(e.target.checked)));
$("login").addEventListener("change", async (e) => render(await window.vg.setOpenAtLogin(e.target.checked)));

window.vg.getState().then(render);
