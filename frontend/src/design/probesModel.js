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

/** What to run on the probe VM, in deploy/probe, to enroll it (deploy/probe/README.md). */
export function enrollCommand(platformUrl, token) {
  return `docker compose run --rm probe enroll --platform ${platformUrl.replace(/\/+$/, "")} --token ${token}`;
}

/** Clients that have scan types on a probe but no probe able to run them. */
export function clientsWithoutProbe(clients, probes) {
  const usable = new Set((probes || []).filter(p => p.status === "online" || p.status === "offline").map(p => p.workspace_id));
  return (clients || []).filter(c => (c.probe_scan_types || []).length && !usable.has(c.id));
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
};

export function eventLabel(kind) {
  return EVENT_LABELS[kind] || kind;
}

/** Events that need attention, shown in red. */
export function isAlarmEvent(kind) {
  return kind === "offline" || kind === "revoked" || kind === "job_refused";
}

/** Counts for the Root overview: online, offline, pending enrollment. */
export function probeCounts(probes) {
  const counts = { online: 0, offline: 0, pending: 0 };
  for (const p of probes || []) if (p.status in counts) counts[p.status] += 1;
  return counts;
}
