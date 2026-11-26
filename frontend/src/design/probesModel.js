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

/** What to run on the probe VM to enroll it (the agent comes with the probe image). */
export function enrollCommand(platformUrl, token) {
  return `v0cday-probe enroll --platform ${platformUrl.replace(/\/+$/, "")} --token ${token}`;
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
