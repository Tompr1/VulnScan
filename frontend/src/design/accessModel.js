// Access administration — pure helpers (no React, no fetch), tested under
// `node --test` (frontend/tests/).

export const ROLES = ["admin", "analyst", "viewer"];

export const ROLE_HELP = {
  admin: "Admin — everything on the client, its users included",
  analyst: "Analyst — runs scans, handles findings",
  viewer: "Viewer — read-only",
};

/** Who a grant is given to: "tech@msp.example" or "Group Niveau 1". */
export function principalLabel(grant) {
  if (grant.user) return grant.user.email || `User #${grant.user.id}`;
  if (grant.user_group) return `Group ${grant.user_group.name}`;
  return "—";
}

/** What a grant opens: "Acme" or "Client group Santé". */
export function scopeLabel(grant) {
  if (grant.client) return grant.client.name;
  if (grant.client_group) return `Client group ${grant.client_group.name}`;
  return "—";
}

/**
 * Why a user reaches a client through one grant, in a sentence:
 * "Direct grant on the client", "Through group Niveau 1, on client group Santé".
 */
export function describeSource(source) {
  const who = source.user_group ? `Through group ${source.user_group.name}` : "Direct grant";
  const on = source.client_group ? `on client group ${source.client_group.name}` : "on the client";
  return `${who}, ${on}`;
}

/** Add or remove an id from a list of ids (kept sorted). */
export function toggleId(ids, id) {
  const set = new Set(ids);
  if (set.has(id)) set.delete(id); else set.add(id);
  return [...set].sort((a, b) => a - b);
}

/** Names of the ids, in the order of `rows` ({id, name|email}). */
export function namesOf(ids, rows, key = "name") {
  const wanted = new Set(ids);
  return rows.filter(row => wanted.has(row.id)).map(row => row[key]);
}

/** Grants concerning a user or group, a client or client group (for counts). */
export function grantsOf(grants, { userId, userGroupId, clientId, clientGroupId }) {
  return grants.filter(g =>
    (userId != null && g.user?.id === userId) ||
    (userGroupId != null && g.user_group?.id === userGroupId) ||
    (clientId != null && g.client?.id === clientId) ||
    (clientGroupId != null && g.client_group?.id === clientGroupId));
}
