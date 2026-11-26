// Routes — pure helpers (no React, no fetch), tested under `node --test`
// (frontend/tests/).
//
// Like the ADOMs of FortiManager, the app works in one context at a time:
// - a client: "#/c/<client id>/<page>", a device page under
//   "#/c/<client id>/inventory/devices/<device id>". Alert links use the same
//   form (backend: app/inventory/alerts.py DeviceLinks), so a link opens the
//   right client whichever one was open last;
// - Root, the platform itself, for global admins: "#/root/<page>" — what
//   every client shares (reference datasets, Threat Intel), the clients and
//   the accounts (super admins included), the platform's version.
// Hash routes need no server rewrite.

export const CLIENT_PAGES = [
  "dashboard", "assets", "inventory", "jobs", "profiles", "reports",
  "credentials", "threat-intel", "attack-graph", "analytics", "settings",
];
export const ROOT_PAGES = ["overview", "access", "probes", "datasets", "threat-intel", "platform"];
export const DEFAULT_PAGE = "dashboard";
export const ROOT_DEFAULT_PAGE = "overview";

// Pages that lived in each client before Root existed: old links open them in Root.
const MOVED_TO_ROOT = new Set(["datasets", "access"]);
// Pages of a client only its admins open: an analyst or a viewer lands on
// the dashboard instead.
const ADMIN_PAGES = new Set(["settings"]);

/** May this session open this page of its client? */
export function canOpenPage(user, page) {
  return !ADMIN_PAGES.has(page) || user?.role === "admin" || !!user?.is_global_admin;
}

/** "#/root/<page>", or "#/c/<client>/<page>[/devices/<id>]" */
export function routeHash({ root = false, clientId = null, page, deviceId = null }) {
  if (root) return `#/root/${ROOT_PAGES.includes(page) ? page : ROOT_DEFAULT_PAGE}`;
  const base = `#/c/${clientId}/${page || DEFAULT_PAGE}`;
  return page === "inventory" && deviceId != null ? `${base}/devices/${deviceId}` : base;
}

/**
 * The route a hash names: {root, clientId, page, deviceId}.
 * - Root: {root: true, clientId: null}; an unknown Root page is its overview;
 * - clientId is null for a link from before clients were in the URL
 *   ("#/inventory/devices/7"): it opens in the current client;
 * - an unknown page of a client falls back to its dashboard;
 * - Datasets and Access of a client (old links) are Root's;
 * - null when the hash names no route at all.
 */
export function parseRoute(hash) {
  const path = (hash || "").replace(/^#/, "").replace(/\/+$/, "");
  const parts = path.split("/").slice(1); // "" before the leading "/"
  if (parts[0] === "root") return rootRoute(parts[1]);
  if (parts[0] === "c") {
    if (!/^\d+$/.test(parts[1] || "")) return null;
    return clientRoute(Number(parts[1]), parts.slice(2), true);
  }
  if (parts.length && (CLIENT_PAGES.includes(parts[0]) || MOVED_TO_ROOT.has(parts[0]))) return clientRoute(null, parts, false);
  return null;
}

function rootRoute(page) {
  return { root: true, clientId: null, page: ROOT_PAGES.includes(page) ? page : ROOT_DEFAULT_PAGE, deviceId: null };
}

function clientRoute(clientId, parts, lenient) {
  if (MOVED_TO_ROOT.has(parts[0])) return rootRoute(parts[0]);
  const page = CLIENT_PAGES.includes(parts[0]) ? parts[0] : null;
  if (!page) return lenient ? { root: false, clientId, page: DEFAULT_PAGE, deviceId: null } : null;
  const device = page === "inventory" && parts[1] === "devices" && /^\d+$/.test(parts[2] || "") ? Number(parts[2]) : null;
  return { root: false, clientId, page, deviceId: device };
}

/** The session is on Root: a global admin with no client open. */
export function isRootSession(user) {
  return !!user?.is_global_admin && (user?.workspace_id ?? null) == null;
}

/**
 * What the app does with the URL once signed in:
 * - {action: "pick"}: nothing open yet — show the selection window;
 * - {action: "redirect", hash}: rewrite the URL in place (no route, an old
 *   link, Root asked by an account that may not open it);
 * - {action: "switch", clientId}: the link names another client — open it;
 * - {action: "switch-root"}: the link names Root, a client is open — open Root;
 * - {action: "show", route}: render the page.
 */
export function resolveRoute(route, user) {
  const current = user?.workspace_id ?? null;
  const globalAdmin = !!user?.is_global_admin;
  if (route?.root) {
    if (!globalAdmin) return current == null ? { action: "pick" } : { action: "redirect", hash: routeHash({ clientId: current }) };
    return current == null ? { action: "show", route } : { action: "switch-root" };
  }
  if (route?.clientId != null && route.clientId !== current) return { action: "switch", clientId: route.clientId };
  if (current == null) {
    // On Root, a link without a client cannot say which client it means.
    return isRootSession(user) && !route ? { action: "redirect", hash: routeHash({ root: true }) } : { action: "pick" };
  }
  if (!route || route.clientId == null) {
    return { action: "redirect", hash: routeHash({ clientId: current, page: route?.page, deviceId: route?.deviceId }) };
  }
  if (!canOpenPage(user, route.page)) return { action: "redirect", hash: routeHash({ clientId: current }) };
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
