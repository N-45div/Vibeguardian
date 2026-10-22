// VibeGuardian live drill page. Every value from a drill record goes in with textContent:
// Gemini's reply is text from outside, never markup.
const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const ORDER = ["us-central1", "europe-west1", "asia-northeast1", "australia-southeast1", "southamerica-east1"];
let timer = null;
let running = null;

function node(tag, attrs = {}, text) {
  const n = tag.startsWith("svg:") ? document.createElementNS(SVG, tag.slice(4)) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text !== undefined) n.textContent = text;
  return n;
}

function secs(v) { return v == null ? "—" : `${Number(v).toFixed(1)} s`; }

async function start() {
  const btn = $("start");
  if (running) return show(running, true);
  btn.disabled = true;
  try {
    const r = await fetch("/api/drills", { method: "POST", headers: { "X-VG-Drill": "1" } });
    const body = await r.json();
    if (!r.ok) { $("start-note").textContent = body.error || "Could not start a drill."; btn.disabled = false; return; }
    show(body.id, true);
  } catch {
    $("start-note").textContent = "Could not reach the drill service. Try again in a moment.";
    btn.disabled = false;
  }
}

function show(id, push) {
  if (push) history.pushState(null, "", `/d/${id}`);
  $("drill").hidden = false;
  $("drill").scrollIntoView({ behavior: "smooth", block: "start" });
  poll(id);
}

async function poll(id) {
  clearTimeout(timer);
  try {
    const r = await fetch(`/api/drills/${id}`);
    if (r.status === 404) { notFound(id); return; }
    const rec = await r.json();
    render(rec);
    if (rec.status === "running") timer = setTimeout(() => poll(id), 1000);
    else { $("start").disabled = false; $("start").textContent = "Run another drill"; loadStats(); }
  } catch { timer = setTimeout(() => poll(id), 2000); }
}

function notFound(id) {
  $("drill-title").textContent = `Drill ${id}`;
  $("drill-headline").textContent = "No drill with this link.";
  $("drill-pill").textContent = "NOT FOUND";
  $("drill-pill").className = "pill";
}

function phase(rec) {
  const names = rec.steps.map((s) => s.step);
  if (names.includes("deleted")) return "Deleted. Asking Google from five places…";
  if (names.includes("accepted")) return "Gemini answered. Using the key…";
  if (names.includes("created")) return "Waiting for Gemini 4 Argon to answer with the new key…";
  return "Making a throwaway Gemini key…";
}

function render(rec) {
  const v = rec.verdict;
  $("drill-title").textContent = `Drill ${rec.id}${rec.started_at ? " · " + new Date(rec.started_at * 1000).toLocaleString() : ""}`;
  $("drill-fp").textContent = rec.fingerprint ? `key ${rec.fingerprint} · ${rec.model || "gemini-4-argon"}` : "";
  const pill = $("drill-pill");
  const revivals = (v && v.revivals) || [];
  if (!v) { pill.textContent = "RUNNING"; pill.className = "pill run"; $("drill-headline").textContent = phase(rec); }
  else if (v.state === "proven_dead") {
    pill.textContent = "PROVEN DEAD"; pill.className = "pill dead";
    $("drill-headline").textContent = revivals.length ? "The deleted key still worked somewhere, then died." : "Proven dead from every place.";
  } else if (v.state === "not_proven") {
    pill.textContent = "STILL ANSWERING"; pill.className = "pill alive";
    $("drill-headline").textContent = "Not every place refused the deleted key in time.";
  } else { pill.textContent = "STOPPED"; pill.className = "pill"; $("drill-headline").textContent = v.message; }
  renderSteps(rec);
  lastRecord = rec;
  renderChart(rec);
  renderVerdict(rec);
}

function renderSteps(rec) {
  const by = (name) => rec.steps.filter((s) => s.step === name);
  const accepted = by("accepted")[0];
  const used = by("used");
  const answered = used.filter((s) => s.verdict === "alive").length;
  const items = [
    ["Throwaway key created", rec.fingerprint || "…", by("created").length > 0],
    ["Gemini 4 Argon answered", accepted ? `"${accepted.answer || ""}" after ${secs(accepted.after_s)}` : "waiting…", !!accepted],
    ["Used it 5 times", used.length ? `${answered} of ${used.length} answered` : "…", used.length >= 5],
    ["Deleted", rec.deleted_at ? "t = 0, then the proof" : "…", !!rec.deleted_at],
  ];
  const list = $("steps");
  list.replaceChildren(...items.map(([title, detail, done]) => {
    const li = node("li", { class: done ? "done" : "todo" });
    li.append(node("b", {}, title), node("span", {}, detail));
    return li;
  }));
}

function renderChart(rec) {
  const svg = $("chart");
  const names = ORDER.filter((n) => rec.places && rec.places[n]).concat(
    Object.keys(rec.places || {}).filter((n) => !ORDER.includes(n)));
  const rows = names.length || 5;
  // On a phone the names sit above each row, so the dots get the full width.
  const compact = svg.getBoundingClientRect().width < 560;
  const W = compact ? 360 : 900, x0 = compact ? 6 : 170, x1 = compact ? 300 : 790;
  const top = compact ? 38 : 44, gap = compact ? 58 : 52, H = top + gap * (rows - 1) + (compact ? 52 : 46);
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  let maxT = 0;
  for (const n of names) for (const r of rec.places[n].rounds) maxT = Math.max(maxT, r.t);
  const tmax = Math.max(90, Math.ceil((maxT + 10) / 30) * 30);
  const X = (t) => x0 + (t / tmax) * (x1 - x0);
  const parts = [];
  names.forEach((n, i) => {
    const p = rec.places[n], y = top + i * gap + (compact ? 10 : 0);
    if (compact) {
      const name = node("svg:text", { x: 0, y: y - 16, "font-size": 13, "font-weight": 500, fill: "#141414" }, p.label);
      name.append(node("svg:tspan", { dx: 6, "font-size": 10, "font-weight": 400, fill: "#6b6b6b", "font-family": "Geist Mono, monospace" }, n));
      parts.push(name);
    } else {
      parts.push(node("svg:text", { x: 0, y: y - 1, "font-size": 14, "font-weight": 500, fill: "#141414" }, p.label));
      parts.push(node("svg:text", { x: 0, y: y + 15, "font-size": 11, fill: "#6b6b6b", "font-family": "Geist Mono, monospace" }, n));
    }
    parts.push(node("svg:line", { x1: x0, y1: y, x2: x1, y2: y, stroke: "rgba(20,20,20,0.10)" }));
    for (const r of p.rounds) {
      if (r.verdict === "alive") continue;
      parts.push(node("svg:circle", { cx: X(r.t), cy: y, r: r.verdict === "dead" ? 4.5 : 3.5, fill: r.verdict === "dead" ? "#2f9e66" : "#b9b9b9" }));
    }
    for (const r of p.rounds.filter((r) => r.verdict === "alive")) {
      parts.push(node("svg:circle", { cx: X(r.t), cy: y, r: 7.5, fill: "#d9443f", stroke: "#fff", "stroke-width": 2 }));
      const said = compact ? `${r.t.toFixed(1)} s` : `${r.answer ? `Gemini: "${r.answer}"` : "listed models"} · ${r.t.toFixed(1)} s`;
      parts.push(node("svg:text", { x: X(r.t), y: compact ? y + 20 : y - 13, "font-size": 11, fill: "#a8302b", "text-anchor": "middle", "font-family": "Geist Mono, monospace" }, said));
    }
    const status = p.state === "proven_dead" ? `✓ ${secs(p.proven_at)}` : p.state === "unreachable" ? "no answer"
      : p.state === "waiting" ? "" : `${p.streak} / ${rec.stable || 12}`;
    parts.push(node("svg:text", { x: W - 2, y: y + 5, "font-size": 13, "text-anchor": "end", fill: p.state === "proven_dead" ? "#2f9e66" : "#5e5e5e", "font-family": "Geist Mono, monospace" }, status));
  });
  for (let t = 0; t <= tmax; t += compact ? 60 : 30) {
    const anchor = t === 0 && compact ? "start" : "middle";
    parts.push(node("svg:text", { x: X(t), y: H - 6, "font-size": 11, fill: "#6b6b6b", "text-anchor": anchor, "font-family": "Geist Mono, monospace" }, `${t} s`));
  }
  svg.replaceChildren(...parts);
}

function renderVerdict(rec) {
  const v = rec.verdict, box = $("verdict"), share = $("share");
  if (!v) { box.hidden = true; share.hidden = true; return; }
  const revivals = v.revivals || [];
  box.hidden = false;
  box.className = `verdict ${v.state === "failed" ? "fail" : revivals.length || v.state === "not_proven" ? "alive" : "dead"}`;
  const first = revivals[0];
  const lead = first
    ? `A deleted key still worked: ${first.answer ? `Gemini 4 Argon answered "${first.answer}"` : "Google listed models"} in ${first.label}, ${secs(first.t)} after deletion.`
    : v.message;
  const detail = [];
  if (first) detail.push(v.message);
  if (revivals.length > 1) detail.push(`${revivals.length} answers after deletion in all.`);
  if ((v.unreachable || []).length) detail.push(`No answer from ${v.unreachable.join(", ")}, so it is left out of the proof.`);
  if (!first && v.state === "proven_dead") detail.push("No place answered after the key was deleted.");
  box.replaceChildren(document.createTextNode(lead), ...(detail.length ? [node("small", {}, detail.join(" "))] : []));
  share.hidden = false;
  $("share-url").textContent = `${location.origin}/d/${rec.id}`;
}

async function loadStats() {
  try {
    const s = await (await fetch("/api/stats")).json();
    running = s.running;
    if (running && !location.pathname.startsWith("/d/")) $("start").textContent = "Watch the drill in progress";
    const tiles = [
      [String(s.drills), "drills run"],
      [String(s.with_revival), "drills where a deleted key still worked somewhere"],
      [String(s.gemini_answered ?? 0), "drills where Gemini 4 Argon answered a deleted key"],
      [s.latest_revival_s == null ? "—" : secs(s.latest_revival_s), "latest call a deleted key got answered (sent after deletion)"],
    ];
    $("stats-grid").replaceChildren(...tiles.map(([n, label]) => {
      const d = node("div", { class: "stat" });
      d.append(node("b", {}, n), node("p", {}, label));
      return d;
    }));
    $("recent").replaceChildren(...(s.recent || []).map((r) => {
      const li = node("li");
      const a = node("a", { href: `/d/${r.id}` }, r.id);
      const what = r.state === "proven_dead" ? (r.revivals ? `a deleted key worked ${r.revivals}×, then proven dead · ${secs(r.seconds)}` : `proven dead · ${secs(r.seconds)}`)
        : r.state === "not_proven" ? "still answering at the end" : r.state ? "stopped" : "running";
      li.append(a, node("span", { class: r.revivals || r.state === "not_proven" ? "bad" : "ok" }, what),
        node("span", { class: "muted" }, r.started_at ? new Date(r.started_at * 1000).toLocaleDateString() : ""));
      return li;
    }));
  } catch { /* stats are a nice-to-have */ }
}

document.addEventListener("DOMContentLoaded", () => {
  $("start").addEventListener("click", start);
  $("copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("share-url").textContent); $("copy").textContent = "Copied"; } catch { /* no clipboard */ }
  });
  const m = location.pathname.match(/^\/d\/([a-z0-9]{10})$/);
  if (m) show(m[1], false);
  loadStats();
});
window.addEventListener("popstate", () => location.reload());
let lastRecord = null;
const renderAgain = () => { if (lastRecord) renderChart(lastRecord); };
window.addEventListener("resize", () => { clearTimeout(window.__vgResize); window.__vgResize = setTimeout(renderAgain, 150); });
