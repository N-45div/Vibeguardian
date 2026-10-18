// Turn `vg keys` output into what the keys tab shows. No key values exist in
// that output: only names, ages, limits, and call counts.

function flagLabel(flag, days) {
  switch (flag) {
    case "unrestricted":
      return { label: "works on every API", tone: "bad" };
    case "old":
      return { label: "over 180 days old", tone: "warn" };
    case "unused":
      return { label: `no calls in ${days} days`, tone: "quiet" };
    default:
      return { label: flag, tone: "quiet" };
  }
}

const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

function keysView(result) {
  const keys = (result && result.keys) || [];
  const days = (result && result.days) || 7;
  const count = (flag) => keys.filter((k) => k.flags.includes(flag)).length;
  const summary = [plural(keys.length, "key")];
  for (const flag of ["unrestricted", "old", "unused"]) {
    if (count(flag)) summary.push(`${count(flag)} ${flag}`);
  }
  return {
    summary: summary.join(" · "),
    keys: keys.map((k) => ({
      uid: k.uid,
      title: k.display_name || k.uid,
      detail: [
        k.age_days != null ? `${plural(k.age_days, "day")} old` : null,
        `${plural(k.calls, "call")} in ${days} days`,
        k.regions.length ? `from ${k.regions.join(", ")}` : null,
      ].filter(Boolean).join(" · "),
      limits: k.restrictions.unrestricted
        ? "no limits"
        : [...k.restrictions.apis, ...k.restrictions.apps].join(", "),
      flags: k.flags.map((flag) => ({ flag, ...flagLabel(flag, days) })),
    })),
  };
}

module.exports = { keysView };
