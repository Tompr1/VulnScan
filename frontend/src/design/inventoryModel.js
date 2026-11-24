// Device inventory — pure helpers shared by the inventory pages (no React,
// no fetch), so they run under `node --test` (frontend/tests/).

// Deep links to device pages: see routes.js (they name the client).

// ── Severities ───────────────────────────────────────────────────────────
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function severityRank(severity) {
  const rank = SEVERITIES.indexOf((severity || "").toLowerCase());
  return rank === -1 ? SEVERITIES.length : rank;
}

/** Most exposed devices first: highest severity, then issue count, then name. */
export function compareDevices(a, b) {
  return (
    severityRank(a.highest_severity) - severityRank(b.highest_severity) ||
    (b.issue_count || 0) - (a.issue_count || 0) ||
    (a.name || "").localeCompare(b.name || "")
  );
}

/** Issues by risk: exploited first, then severity, then risk score. */
export function compareIssues(a, b) {
  return (
    Number(!!b.is_kev) - Number(!!a.is_kev) ||
    severityRank(a.severity) - severityRank(b.severity) ||
    (b.risk_score || 0) - (a.risk_score || 0)
  );
}

/** Devices whose worst issue is at least ``minSeverity`` ("" = all devices). */
export function filterBySeverity(devices, minSeverity) {
  if (!minSeverity) return devices;
  if (minSeverity === "none") return devices.filter(d => !d.issue_count);
  const limit = severityRank(minSeverity);
  return devices.filter(d => d.issue_count > 0 && severityRank(d.highest_severity) <= limit);
}

export function summarizeFleet(devices) {
  const summary = { total: devices.length, withIssues: 0, critical: 0, high: 0, issues: 0 };
  for (const device of devices) {
    if (device.issue_count > 0) summary.withIssues += 1;
    summary.issues += device.issue_count || 0;
    if (device.highest_severity === "critical") summary.critical += 1;
    if (device.highest_severity === "high") summary.high += 1;
  }
  return summary;
}

// ── Labels ───────────────────────────────────────────────────────────────
export const PLATFORMS = [
  { id: "windows", label: "Windows" },
  { id: "macos", label: "macOS" },
  { id: "ios", label: "iOS / iPadOS" },
  { id: "android", label: "Android" },
  { id: "linux", label: "Linux" },
  { id: "other", label: "Other" },
];

export function platformLabel(platform) {
  return (PLATFORMS.find(p => p.id === platform) || { label: platform || "—" }).label;
}

export const RULE_LABELS = {
  os_vulnerable: "Known vulnerabilities (OS)",
  app_vulnerable: "Known vulnerabilities (software)",
  os_unsupported: "OS out of support",
  os_support_ending: "OS support ending",
  os_outdated: "OS not up to date",
  android_patch_outdated: "Android security patch",
  app_unsupported: "Software out of support",
  app_outdated: "Software not up to date",
  audit_incomplete: "Audit incomplete",
};

export function ruleLabel(rule) {
  return RULE_LABELS[rule] || rule;
}

export function describeChange(change) {
  const { kind, subject, before, after } = change;
  switch (kind) {
    case "device_enrolled": return "Device enrolled";
    case "device_removed": return "Device removed from the fleet manager";
    case "os_updated": return `${subject} updated: ${before || "?"} → ${after || "?"}`;
    case "app_installed": return `${subject} ${after || ""} installed`.replace(/\s+/g, " ").trim();
    case "app_removed": return `${subject} ${before || ""} removed`.replace(/\s+/g, " ").trim();
    case "app_updated": return `${subject} updated: ${before || "?"} → ${after || "?"}`;
    default: return `${kind}: ${subject}`;
  }
}

/** "Device: PC-04\nUser: …" evidence → [["Device", "PC-04"], …]. */
export function evidencePairs(evidence) {
  return (evidence || "")
    .split("\n")
    .map(line => {
      const at = line.indexOf(": ");
      return at > 0 ? [line.slice(0, at), line.slice(at + 2)] : null;
    })
    .filter(Boolean);
}

/** Relative age of an ISO date: "today", "3 days ago", "never". */
export function ageText(iso, now = new Date()) {
  if (!iso) return "never";
  const days = Math.floor((now - new Date(iso)) / 86400000);
  if (Number.isNaN(days)) return "—";
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  return `${days} days ago`;
}
