// Assets — pure helpers (no React, no fetch), tested under `node --test`.

// A child with a target is a host (an asset registered on a scan target), not a sub-folder.
export const isHost = (a) => (a.target_list || []).length > 0 && !!a.parent_id;

const byName = (a, b) => (a.name || "").localeCompare(b.name || "", undefined, { sensitivity: "base" });

// The tree view: each asset right under its parent, by name, with its depth.
// An asset whose parent is gone (or that loops) is shown at the top level.
export function treeRows(assets) {
  const ids = new Set(assets.map(a => a.id));
  const kids = new Map();
  for (const a of assets) {
    const parent = a.parent_id && ids.has(a.parent_id) && a.parent_id !== a.id ? a.parent_id : null;
    if (!kids.has(parent)) kids.set(parent, []);
    kids.get(parent).push(a);
  }
  const rows = [];
  const seen = new Set();
  const walk = (parent, depth) => {
    for (const a of (kids.get(parent) || []).slice().sort(byName)) {
      if (seen.has(a.id)) continue;
      seen.add(a.id);
      rows.push({ asset: a, depth });
      walk(a.id, depth + 1);
    }
  };
  walk(null, 0);
  // Parent loops never reach the top: show them anyway.
  for (const a of assets.slice().sort(byName)) {
    if (!seen.has(a.id)) { seen.add(a.id); rows.push({ asset: a, depth: 0 }); walk(a.id, 1); }
  }
  return rows;
}

// Folders a discovered host can be added to, with their path ("FW / Sophos").
export function folderChoices(assets) {
  const byId = new Map(assets.map(a => [a.id, a]));
  const path = (a) => {
    const names = [];
    const seen = new Set();
    for (let cur = a; cur && !seen.has(cur.id); cur = byId.get(cur.parent_id)) {
      seen.add(cur.id);
      names.unshift(cur.name);
    }
    return names.join(" / ");
  };
  return assets
    .filter(a => !isHost(a))
    .map(a => ({ id: a.id, label: path(a) }))
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { sensitivity: "base" }));
}

// Counts for the Assets page header.
export function assetCounts(assets) {
  const top = assets.filter(a => !a.parent_id).length;
  const hosts = assets.filter(isHost).length;
  return { folders: top, subFolders: assets.length - top - hosts, hosts };
}

// How a target is shown: its alias first when it has one.
export const targetLabel = (t) => (t.name ? `${t.name} (${t.target})` : t.target);

// Scan kinds sent as internal scans: they run on the client's probe only.
export const NETWORK_SCAN_KINDS = ["network", "iot"];

/** Whether a scan kind cannot be launched now: a network scan while the
 * client has no probe online. Unknown availability blocks nothing (the
 * platform refuses the scan itself). */
export function scanKindBlocked(kind, availability) {
  return NETWORK_SCAN_KINDS.includes(kind) && availability?.available === false;
}
