// Scan probes — pure helpers (no React, no fetch), tested under `node --test`.

export const SCAN_TYPE_LABELS = { internal: "Internal network", external: "External / web", api: "API" };

// Probe status from the API → label and the .status pill colour.
const STATUS = {
  online:  { label: "online",  pill: "done" },
  offline: { label: "offline", pill: "failed" },
  pending: { label: "waiting for enrollment", pill: "queued" },
  revoked: { label: "revoked", pill: "cancelled" },
};

export function probeStatus(status) {
  return STATUS[status] || { label: status || "unknown", pill: "queued" };
}

/** The scan types of a client after ticking or unticking one, in the API's order. */
export function toggledScanTypes(current, scanType, on, delegable) {
  const chosen = new Set(current || []);
  if (on) chosen.add(scanType); else chosen.delete(scanType);
  return (delegable || []).filter(t => chosen.has(t));
}

/** What to run on the probe VM, in deploy/probe, to enroll it (deploy/probe/README.md).
 * A local scope, when given, is the client's own extra limit on the probe. */
export function enrollCommand(platformUrl, token, localAllowlist = "") {
  // "--token=…": a value starting with "-" stays a value (tokens from older
  // platforms could).
  const scope = (localAllowlist || "").replace(/\s+/g, "");
  if (!ALLOWLIST_PATTERN.test(scope)) {
    throw new Error("Local allowlist: CIDRs, IPs or .domain suffixes separated by commas");
  }
  return `docker compose run --rm probe enroll --platform ${platformUrl.replace(/\/+$/, "")} --token=${token}`
    + (scope ? ` --local-allowlist=${scope}` : "");
}

/** Clients whose jobs wait for a probe they do not have: scan types Root
 * sent to a probe (beyond those that always run there, which are refused
 * without one), or jobs already waiting. */
export function clientsWithoutProbe(clients, probes, probeOnly = []) {
  const usable = new Set((probes || []).filter(p => p.status === "online" || p.status === "offline").map(p => p.workspace_id));
  const always = new Set(probeOnly || []);
  return (clients || []).filter(c => !usable.has(c.id)
    && ((c.probe_scan_types || []).some(t => !always.has(t)) || (c.waiting_jobs || 0) > 0));
}

/** A client's allowed networks as typed in Root, or the platform default. */
export function allowlistText(entries) {
  return (entries || []).join(", ");
}

/** When a probe was last heard from: probes call every few seconds, so
 * minutes matter (inventoryModel.ageText counts in days). */
export function seenText(iso, now = Date.now()) {
  if (!iso) return "never";
  const seconds = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (Number.isNaN(seconds)) return "never";
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

// ── Appliance first boot (deploy/appliance) ─────────────────────────────────

const ALLOWLIST_PATTERN = /^[A-Za-z0-9.,:/*_-]*$/;
const PEM_PATTERN = /^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----\s*$/;

/** A host name from the probe's name: "Paris HQ" → "v0cday-probe-paris-hq". */
export function applianceHostname(probeName) {
  const slug = (probeName || "").normalize("NFD").replace(/[̀-ͯ]/g, "")
    .toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return `v0cday-probe${slug ? "-" + slug : ""}`.slice(0, 63).replace(/-+$/, "");
}

/**
 * The cloud-init user-data of an appliance's first boot: it writes the seed
 * the appliance enrolls with (deploy/appliance/files/v0cday-probe-firstboot).
 * Throws an Error with a message for the user when an input is unusable.
 */
export function cloudInitUserData({ platformUrl, token, probeName, localAllowlist = "", caPem = "", allowHttp = false }) {
  const platform = (platformUrl || "").replace(/\/+$/, "");
  if (!/^https:\/\/[^\s]+$/.test(platform) && !(allowHttp && /^http:\/\/[^\s]+$/.test(platform))) {
    throw new Error("The platform address must start with https://");
  }
  if (!/^[A-Za-z0-9_-]{20,}$/.test(token || "")) throw new Error("Invalid enrollment token");
  const allowlist = (localAllowlist || "").replace(/\s+/g, "");
  if (!ALLOWLIST_PATTERN.test(allowlist)) {
    throw new Error("Local allowlist: CIDRs, IPs or .domain suffixes separated by commas");
  }
  const pem = (caPem || "").trim();
  if (pem && !PEM_PATTERN.test(pem)) throw new Error("The CA must be a PEM certificate (-----BEGIN CERTIFICATE-----…)");

  const seed = [`V0CDAY_PLATFORM=${platform}`, `V0CDAY_TOKEN=${token}`];
  if (allowlist) seed.push(`V0CDAY_LOCAL_ALLOWLIST=${allowlist}`);
  if (allowHttp) seed.push("V0CDAY_ALLOW_HTTP=1");
  const indent = (text) => text.split(/\r?\n/).map(line => `      ${line}`).join("\n");

  const lines = [
    "#cloud-config",
    `# v0cday scan probe "${(probeName || "").replace(/[\r\n"]/g, " ")}": first-boot configuration.`,
    "# It holds a ONE-TIME enrollment token: hand it over like a password, and",
    "# delete it once the probe shows online in Root > Scan probes.",
    `hostname: ${applianceHostname(probeName)}`,
    "write_files:",
    "  - path: /etc/v0cday-probe/seed.env",
    "    owner: root:root",
    "    permissions: '0600'",
    "    content: |",
    indent(seed.join("\n")),
  ];
  if (pem) {
    lines.push(
      "  - path: /etc/v0cday-probe/ca.pem",
      "    owner: root:root",
      "    permissions: '0644'",
      "    content: |",
      indent(pem),
    );
  }
  return lines.join("\n") + "\n";
}

// ── Operations ───────────────────────────────────────────────────────────────

// Probe image against the one the platform asks for (PROBE_IMAGE).
const IMAGE_STATUS = {
  current:        { label: "up to date", pill: "done" },
  update_pending: { label: "update pending", pill: "running" },
  unknown:        { label: "image not reported", pill: "queued" },
  unmanaged:      { label: "", pill: "" },
};

export function imageStatus(status) {
  return IMAGE_STATUS[status] || IMAGE_STATUS.unknown;
}

// ── Updates of probes installed from the source ──────────────────────────────

/** "a1b2c3d4e5…" → "a1b2c3d". */
export function shortBuild(build) {
  return build ? String(build).slice(0, 7) : "";
}

/** The probe's code next to the platform's (code_status from the API),
 * with the last update asked from Root. Appliances follow their image. */
export function codeStatus(probe) {
  if (!probe || probe.code_status === "appliance") return { label: "", pill: "" };
  if (probe.update_status === "requested") return { label: "update asked", pill: "running" };
  if (probe.update_status === "running") return { label: "updating…", pill: "running" };
  if (probe.code_status === "current") return { label: "code up to date", pill: "done" };
  if (probe.update_status === "failed") return { label: "update failed", pill: "failed" };
  if (probe.code_status === "outdated") return { label: "update available", pill: "queued" };
  return { label: "code not reported", pill: "queued" };
}

/** Whether Root can ask this probe to update: an enrolled probe installed
 * from the source, whose code is not the platform's, with no update going. */
export function canUpdate(probe, platformBuild) {
  if (!probe || !platformBuild) return false;
  if (probe.status !== "online" && probe.status !== "offline") return false;
  if (probe.update_status === "requested" || probe.update_status === "running") return false;
  return probe.code_status === "outdated" || probe.code_status === "unknown";
}

/** code_status counts of the enrolled probes, as GET /probes/updates gives
 * them, from the probe list (kept live by the page's refresh). */
export function codeCounts(probes) {
  const counts = {};
  for (const p of probes || []) {
    if (p.status !== "online" && p.status !== "offline") continue;
    counts[p.code_status] = (counts[p.code_status] || 0) + 1;
  }
  return counts;
}

/** One line for the "Check for updates" result. */
export function updateSummary(check) {
  if (!check) return "";
  if (!check.platform_build) {
    return "The platform does not know which commit it runs (deploy it with scripts/deploy.sh, or set PLATFORM_BUILD): probes cannot be compared.";
  }
  const counts = check.counts || {};
  const parts = [];
  if (counts.outdated) parts.push(`${counts.outdated} can be updated`);
  if (counts.updating) parts.push(`${counts.updating} updating`);
  if (counts.current) parts.push(`${counts.current} up to date`);
  if (counts.unknown) parts.push(`${counts.unknown} not reporting their code (too old: update them by hand once)`);
  if (counts.appliance) parts.push(`${counts.appliance} appliance${counts.appliance > 1 ? "s" : ""} (update${counts.appliance > 1 ? "" : "s"} itself from PROBE_IMAGE)`);
  const head = `Platform code ${shortBuild(check.platform_build)}`;
  return parts.length ? `${head}: ${parts.join(", ")}.` : `${head}: no enrolled probe.`;
}

/** "registry/v0cday-probe@sha256:abcdef…" → "v0cday-probe@abcdef123456". */
export function shortImage(reference) {
  if (!reference) return "";
  const [name, digest] = reference.split("@sha256:");
  const base = name.split("/").pop();
  return digest ? `${base}@${digest.slice(0, 12)}` : base;
}

const EVENT_LABELS = {
  created: "Created",
  token_renewed: "New enrollment token",
  enrolled: "Enrolled",
  revoked: "Revoked",
  job_claimed: "Took a scan",
  job_refused: "Scan could not run",
  report_received: "Sent its results",
  image_changed: "Image changed",
  offline: "Went offline",
  online: "Back online",
  update_requested: "Update asked",
  update_started: "Update started",
  update_done: "Updated",
  update_failed: "Update failed",
};

export function eventLabel(kind) {
  return EVENT_LABELS[kind] || kind;
}

/** Events that need attention, shown in red. */
export function isAlarmEvent(kind) {
  return kind === "offline" || kind === "revoked" || kind === "job_refused" || kind === "update_failed";
}

/** Counts for the Root overview: online, offline, pending enrollment. */
export function probeCounts(probes) {
  const counts = { online: 0, offline: 0, pending: 0 };
  for (const p of probes || []) if (p.status in counts) counts[p.status] += 1;
  return counts;
}
