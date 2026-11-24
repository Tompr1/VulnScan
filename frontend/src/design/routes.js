// Client-aware routes — pure helpers (no React, no fetch), tested under
// `node --test` (frontend/tests/).
//
// Every page lives under its client: "#/c/<client id>/<page>", and a device
// page under "#/c/<client id>/inventory/devices/<device id>". Alert links use
// the same form (backend: app/inventory/alerts.py DeviceLinks), so a link
// opens the right client whichever one was open last. Hash routes need no
// server rewrite.

export const PAGES = [
  "dashboard", "assets", "inventory", "jobs", "profiles", "reports",
  "credentials", "datasets", "threat-intel", "attack-graph", "analytics", "settings", "access",
];
export const DEFAULT_PAGE = "dashboard";

// Pages only a global admin of the MSP may open (they act on every client).
const GLOBAL_ADMIN_PAGES = new Set(["datasets", "access"]);

/** "#/c/<client>/<page>[/devices/<id>]" */
export function routeHash({ clientId, page = DEFAULT_PAGE, deviceId = null }) {
  const base = `#/c/${clientId}/${page}`;
  return page === "inventory" && deviceId != null ? `${base}/devices/${deviceId}` : base;
}

/**
 * The route a hash names: {clientId, page, deviceId}.
 * - clientId is null for a link from before clients were in the URL
 *   ("#/inventory/devices/7"): it opens in the current client;
 * - an unknown page of a client falls back to its dashboard;
 * - null when the hash names no route at all.
 */
export function parseRoute(hash) {
  const path = (hash || "").replace(/^#/, "").replace(/\/+$/, "");
  const parts = path.split("/").slice(1); // "" before the leading "/"
  if (parts[0] === "c") {
    if (!/^\d+$/.test(parts[1] || "")) return null;
    return pageRoute(Number(parts[1]), parts.slice(2), true);
  }
  if (parts.length && PAGES.includes(parts[0])) return pageRoute(null, parts, false);
  return null;
}

function pageRoute(clientId, parts, lenient) {
  const page = PAGES.includes(parts[0]) ? parts[0] : null;
  if (!page) return lenient ? { clientId, page: DEFAULT_PAGE, deviceId: null } : null;
  const device = page === "inventory" && parts[1] === "devices" && /^\d+$/.test(parts[2] || "") ? Number(parts[2]) : null;
  return { clientId, page, deviceId: device };
}

/** Whether this session may open the page (Datasets, Access: global admins only). */
export function canOpenPage(page, user) {
  return !GLOBAL_ADMIN_PAGES.has(page) || !!user?.is_global_admin;
}

/**
 * What the app does with the URL once signed in:
 * - {action: "pick"}: no client open yet — show the client picker;
 * - {action: "redirect", hash}: rewrite the URL in place (no route, an old
 *   link without client, a page this session may not open);
 * - {action: "switch", clientId}: the link names another client — open it;
 * - {action: "show", route}: render the page.
 */
export function resolveRoute(route, user) {
  const current = user?.workspace_id ?? null;
  if (route?.clientId != null && route.clientId !== current) return { action: "switch", clientId: route.clientId };
  if (current == null) return { action: "pick" };
  if (!route || route.clientId == null) {
    return { action: "redirect", hash: routeHash({ clientId: current, page: route?.page, deviceId: route?.deviceId }) };
  }
  if (!canOpenPage(route.page, user)) return { action: "redirect", hash: routeHash({ clientId: current }) };
  return { action: "show", route };
}

// ── Client display ───────────────────────────────────────────────────────

/** Up to two initials of a client's name ("Acme Corp" → "AC"). */
export function clientInitials(name) {
  const words = (name || "").trim().split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] || "?").slice(0, 2);
  return letters.toUpperCase();
}

/** A stable hue per client, to tell clients apart at a glance. */
export function clientHue(id) {
  return (Number(id) * 137) % 360;
}

/** Clients matching a search, by name. */
export function filterClients(clients, query) {
  const q = (query || "").trim().toLowerCase();
  return q ? clients.filter(c => (c.name || "").toLowerCase().includes(q)) : clients;
}
