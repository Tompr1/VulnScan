// API client — wraps fetch with bearer-token auth + JSON handling.
//
// VITE_API_URL behavior:
//   - empty / unset       → same-origin relative URLs (use a reverse proxy in prod,
//                           Vite's built-in proxy in dev — see vite.config.js)
//   - "http://host:port"  → absolute URL (must match the page's protocol or be
//                           reachable from the browser; CORS must be open on the backend)
const RAW_API = import.meta.env.VITE_API_URL?.trim()?.replace(/\/$/, "") ?? "";
const API = RAW_API; // empty string = relative paths

export { API };

export function setToken(t) { localStorage.setItem("vs_token", t); }
export function getToken()  { return localStorage.getItem("vs_token"); }
export function clearToken() {
  localStorage.removeItem("vs_token");
  localStorage.removeItem("vs_user");
}
export function setUser(u)  { localStorage.setItem("vs_user", JSON.stringify(u)); }
export function getUser() {
  try { return JSON.parse(localStorage.getItem("vs_user") || "null"); } catch { return null; }
}
// On a client, the role held there; on Root (no client open), a super admin
// administers what every client shares (reference data, Threat Intel).
function onRoot(u) {
  return !!u?.is_global_admin && u.workspace_id == null;
}
export function canEdit() {
  const u = getUser();
  return !!u && (u.role === "admin" || u.role === "analyst" || onRoot(u));
}
export function isAdmin() {
  const u = getUser();
  return !!u && (u.role === "admin" || onRoot(u));
}
/** Global admin of the MSP: every client, and what they all share (datasets, platform). */
export function isGlobalAdmin() {
  return !!getUser()?.is_global_admin;
}

// The app listens to these: the session ended (401 on an authenticated
// call), or the open client is no longer reachable (grant removed, no client
// chosen) — then the client picker is shown again.
export const SESSION_ENDED_EVENT = "vs:session-ended";
export const CLIENT_LOST_EVENT = "vs:client-lost";
// The session's client list or role changed (a client was created, renamed…).
export const SESSION_UPDATED_EVENT = "vs:session-updated";
// Also lost: Root, when the account is no longer a global admin.
const CLIENT_LOST_DETAILS = ["No client selected", "No access to this client", "Requires a global admin"];

export async function api(path, opts = {}) {
  const token = getToken();
  const isForm = opts.body instanceof FormData;
  const headers = { ...(opts.headers || {}) };

  if (!isForm && opts.body !== undefined) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers,
    body: isForm ? opts.body : opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  // Without a token (sign-in), a 401 is a refused password, reported below.
  if (res.status === 401 && token) {
    clearToken();
    window.dispatchEvent(new CustomEvent(SESSION_ENDED_EVENT));
    throw new Error("Session expired — please sign in again");
  }

  if (!res.ok) {
    let msg = res.statusText;
    try {
      const txt = await res.text();
      if (txt) {
        try {
          const parsed = JSON.parse(txt);
          const detail = parsed.detail;
          if (Array.isArray(detail)) {
            // FastAPI 422 validation errors — flatten to "loc: msg" lines
            msg = detail
              .map((d) => {
                const loc = Array.isArray(d?.loc) ? d.loc.filter((x) => x !== "body").join(".") : "";
                const m = d?.msg || "";
                return loc ? `${loc}: ${m}` : m;
              })
              .filter(Boolean)
              .join("; ") || txt;
          } else if (typeof detail === "string") {
            msg = detail;
          } else if (detail) {
            msg = JSON.stringify(detail);
          } else {
            msg = txt;
          }
        } catch { msg = txt; }
      }
    } catch {}
    if (res.status === 403 && CLIENT_LOST_DETAILS.some(d => String(msg).startsWith(d))) {
      window.dispatchEvent(new CustomEvent(CLIENT_LOST_EVENT, { detail: msg }));
    }
    throw new Error(msg);
  }

  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

// ── Auth ─────────────────────────────────────────────────────────────
// A session opens one client at a time: the token names it, and the role
// stored here is the user's role on that client.
function saveSession(email, r) {
  setToken(r.token);
  setUser({
    email,
    role: r.role,
    workspace_id: r.workspace_id,
    is_global_admin: !!r.is_global_admin,
    clients: r.clients || [],
  });
}

export async function login(email, password) {
  const r = await api("/auth/login", { method: "POST", body: { email, password } });
  saveSession(email, r);
  return r;
}

/** Open another client: a new token, with the role held there. */
export async function selectClient(clientId) {
  const r = await api(`/auth/select-client/${clientId}`, { method: "POST" });
  saveSession(getUser()?.email, r);
  return r;
}

/** Open Root, the platform itself (global admins): a session with no client. */
export async function selectRoot() {
  const r = await api("/auth/select-root", { method: "POST" });
  saveSession(getUser()?.email, r);
  return r;
}

/** Reload the open context's session (client list, role) after an access change. */
export async function refreshSession() {
  const clientId = getUser()?.workspace_id;
  try {
    if (clientId == null) await selectRoot(); else await selectClient(clientId);
  } catch {
    // The open client was deleted or is out of reach: choose another one.
    window.dispatchEvent(new CustomEvent(CLIENT_LOST_EVENT, { detail: "No access to this client" }));
    return;
  }
  window.dispatchEvent(new CustomEvent(SESSION_UPDATED_EVENT));
}

// ── Scan probes (global admins, Root) ───────────────────────────────
export const probesApi = {
  list:          ()               => api("/probes"),
  create:        (body)           => api("/probes", { method: "POST", body }),
  renew:         (id)             => api(`/probes/${id}/enrollment`, { method: "POST" }),
  events:        (id)             => api(`/probes/${id}/events`),
  revoke:        (id)             => api(`/probes/${id}/revoke`, { method: "POST" }),
  remove:        (id)             => api(`/probes/${id}`, { method: "DELETE" }),
  setExecution:  (clientId, scanTypes) => api(`/probes/clients/${clientId}/execution`, { method: "PUT", body: { scan_types: scanTypes } }),
};

// ── Access administration (global admins) ───────────────────────────
export const accessApi = {
  clients:           ()         => api("/access/clients"),
  createClient:      (body)     => api("/access/clients", { method: "POST", body }),
  updateClient:      (id, body) => api(`/access/clients/${id}`, { method: "PATCH", body }),
  clientData:        (id)       => api(`/access/clients/${id}/data`),
  // Deletes the client and all its data for good; `name` confirms it.
  deleteClient:      (id, name) => api(`/access/clients/${id}?confirm=${encodeURIComponent(name)}`, { method: "DELETE" }),

  clientGroups:      ()         => api("/access/client-groups"),
  createClientGroup: (body)     => api("/access/client-groups", { method: "POST", body }),
  updateClientGroup: (id, body) => api(`/access/client-groups/${id}`, { method: "PATCH", body }),
  deleteClientGroup: (id)       => api(`/access/client-groups/${id}`, { method: "DELETE" }),

  users:             ()         => api("/access/users"),
  createUser:        (body)     => api("/access/users", { method: "POST", body }),
  updateUser:        (id, body) => api(`/access/users/${id}`, { method: "PATCH", body }),
  deleteUser:        (id)       => api(`/access/users/${id}`, { method: "DELETE" }),
  effectiveAccess:   (id)       => api(`/access/users/${id}/access`),

  userGroups:        ()         => api("/access/user-groups"),
  createUserGroup:   (body)     => api("/access/user-groups", { method: "POST", body }),
  updateUserGroup:   (id, body) => api(`/access/user-groups/${id}`, { method: "PATCH", body }),
  deleteUserGroup:   (id)       => api(`/access/user-groups/${id}`, { method: "DELETE" }),

  grants:            ()         => api("/access/grants"),
  createGrant:       (body)     => api("/access/grants", { method: "POST", body }),
  updateGrant:       (id, body) => api(`/access/grants/${id}`, { method: "PATCH", body }),
  deleteGrant:       (id)       => api(`/access/grants/${id}`, { method: "DELETE" }),
};

export const clientsApi = {
  // The clients this account may open, with a few counters for the picker.
  overview: () => api("/auth/clients"),
};

export async function me() { return api("/auth/me"); }

export function logout() { clearToken(); }

// ── Credentials ──────────────────────────────────────────────────────
export const credentialsApi = {
  list:   ()         => api("/credentials"),
  create: (body)     => api("/credentials", { method: "POST", body }),
  update: (id, body) => api(`/credentials/${id}`, { method: "PUT", body }),
  delete: (id)       => api(`/credentials/${id}`, { method: "DELETE" }),
};

// ── Datasets ─────────────────────────────────────────────────────────
export const datasetsApi = {
  list:    ()        => api("/datasets"),
  create:  (body)    => api("/datasets", { method: "POST", body }),
  update:  (id, body)=> api(`/datasets/${id}`, { method: "PATCH", body }),
  toggle:  (id)      => api(`/datasets/${id}/toggle`, { method: "PATCH" }),
  delete:  (id)      => api(`/datasets/${id}`, { method: "DELETE" }),
  refresh: (body)    => api("/datasets/refresh", { method: "POST", body }),
  refreshStatus: ()  => api("/datasets/refresh/status"),
};

// ── Settings ─────────────────────────────────────────────────────────
export const settingsApi = {
  info:        ()      => api("/settings/info"),
  stats:       ()      => api("/settings/stats"),
  listUsers:   ()      => api("/settings/users"),
  createUser:  (body)  => api("/settings/users", { method: "POST", body }),
  deleteUser:  (id)    => api(`/settings/users/${id}`, { method: "DELETE" }),
  changePassword: (body) => api("/settings/users/me/password", { method: "PUT", body }),
  resetPassword: (id, body) => api(`/settings/users/${id}/password`, { method: "PUT", body }),
  allowlist:   ()      => api("/settings/allowlist"),
  updateAllowlist: (body) => api("/settings/allowlist", { method: "PUT", body }),
  updateCheck: ()      => api("/settings/update/check"),
  updateStatus:()      => api("/settings/update/status"),
  triggerUpdate: ()    => api("/settings/update/trigger", { method: "POST" }),
  // Scheduled refresh of the reference datasets: one for the whole platform (Root).
  datasetRefresh:     ()     => api("/settings/dataset-refresh"),
  saveDatasetRefresh: (body) => api("/settings/dataset-refresh", { method: "PUT", body }),
};

// ── Integrations ─────────────────────────────────────────────────────
export const integrationsApi = {
  list:    ()                  => api("/integrations"),
  save:    (provider, body)    => api(`/integrations/${provider}`,        { method: "POST",   body }),
  // body is optional — if supplied, backend tests with the in-flight config;
  // if omitted, backend falls back to the last saved config for the provider.
  test:    (provider, body)    => api(`/integrations/${provider}/test`,   { method: "POST",   body }),
  remove:  (provider)          => api(`/integrations/${provider}`,        { method: "DELETE" }),
};

// ── AI ───────────────────────────────────────────────────────────────
export const aiApi = {
  providers:      ()          => api("/ai/providers"),
  analyze:        (body)      => api("/ai/analyze", { method: "POST", body }),
  status:         (id)        => api(`/ai/status/${id}`),
  jobResults:     (jobId)     => api(`/ai/results/${jobId}`),
  saveProvider:   (body)      => api("/ai/providers", { method: "POST", body }),
  updateProvider: (id, body)  => api(`/ai/providers/${id}`, { method: "PUT", body }),
  deleteProvider: (id)        => api(`/ai/providers/${id}`, { method: "DELETE" }),
  testProvider:   (id)        => api(`/ai/providers/${id}/test`, { method: "POST" }),
};

// ── Assets ───────────────────────────────────────────────────────────
export const assetsApi = {
  list:    ()           => api("/assets"),
  get:     (id)         => api(`/assets/${id}`),
  create:  (body)       => api("/assets", { method: "POST", body }),
  update:  (id, body)   => api(`/assets/${id}`, { method: "PATCH", body }),
  delete:  (id)         => api(`/assets/${id}`, { method: "DELETE" }),
  jobs:    (id)         => api(`/assets/${id}/jobs`),
  targets: (id)         => api(`/assets/${id}/targets`),
};

// ── Reports ──────────────────────────────────────────────────────────
export const reportsApi = {
  list:        ()                  => api("/reports"),
  download:    async (jobId, fmt, templateId = null) => {
    const token = getToken();
    const params = new URLSearchParams({ format: fmt });
    if (templateId) params.set("template_id", String(templateId));
    const res = await fetch(`${API}/reports/${jobId}/download?${params}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      let msg = res.statusText;
      try { const txt = await res.text(); if (txt) msg = txt; } catch {}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const cd = res.headers.get("Content-Disposition") || "";
    const m = cd.match(/filename="([^"]+)"/);
    const filename = m ? m[1] : `report-${jobId}.${fmt}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(url);
  },

  // Templates
  listTemplates:   ()         => api("/reports/templates"),
  listSections:    ()         => api("/reports/templates/sections"),
  createTemplate:  (body)     => api("/reports/templates", { method: "POST", body }),
  updateTemplate:  (id, body) => api(`/reports/templates/${id}`, { method: "PATCH", body }),
  cloneTemplate:   (id)       => api(`/reports/templates/${id}/clone`, { method: "POST" }),
  deleteTemplate:  (id)       => api(`/reports/templates/${id}`, { method: "DELETE" }),
};

// ── SLA (extends settingsApi) ───────────────────────────────────────
export const slaApi = {
  get:     ()     => api("/settings/sla"),
  update:  (body) => api("/settings/sla", { method: "PUT", body }),
  reset:   ()     => api("/settings/sla/reset", { method: "POST" }),
};

// ── Notification Preferences ────────────────────────────────────────
export const notificationPrefsApi = {
  get:   ()     => api("/settings/notifications"),
  save:  (body) => api("/settings/notifications", { method: "PUT", body }),
  reset: ()     => api("/settings/notifications/reset", { method: "POST" }),
};

// ── Auto AI Analysis ────────────────────────────────────────────────
export const autoAiApi = {
  get:    ()     => api("/settings/auto-ai"),
  update: (body) => api("/settings/auto-ai", { method: "PUT", body }),
};

// ── SLA Breach Alert ────────────────────────────────────────────────
export const slaAlertApi = {
  get:    ()     => api("/settings/sla-alert"),
  update: (body) => api("/settings/sla-alert", { method: "PUT", body }),
};

// ── Auto Report Generation ──────────────────────────────────────────
export const autoReportApi = {
  get:    () => api("/settings/auto-report"),
  update: (body) => api("/settings/auto-report", { method: "PUT", body }),
};

// ── Events (live activity) ───────────────────────────────────────────
export const eventsApi = {
  recent:  (limit = 20) => api(`/events/recent?limit=${limit}`),
};

// ── Web Auth helper (login form inspector + test login) ─────────────
export const webAuthApi = {
  inspect:   (login_url)               => api("/scan/web-auth/inspect",    { method: "POST", body: { login_url } }),
  testLogin: (web_auth, base_url)      => api("/scan/web-auth/test-login", { method: "POST", body: { web_auth, base_url } }),
};

// ── Threat Intel (fused NVD + EPSS + CISA KEV) ──────────────────────
export const threatIntelApi = {
  stats:    ()                  => api("/threat-intel/stats"),
  list:     (params = {})       => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v === undefined || v === null || v === "" || v === false) return;
      qs.set(k, String(v));
    });
    const s = qs.toString();
    return api(`/threat-intel/cves${s ? "?" + s : ""}`);
  },
  detail:   (cveId)             => api(`/threat-intel/cves/${encodeURIComponent(cveId)}`),
  refresh:  ()                  => api("/threat-intel/refresh", { method: "POST" }),
};

// ── API Scanner ─────────────────────────────────────────────────────
export const apiScannerApi = {
  checks:    ()                    => api("/scan/api-scanner/checks"),
  parse:     (formData)            => api("/scan/api-scanner/parse", { method: "POST", body: formData }),
  createJob: (formData)            => api("/scan/api-scanner/jobs",  { method: "POST", body: formData }),
};

// ── Graph ────────────────────────────────────────────────────────────
export const graphApi = {
  attackMap:       ()       => api("/graph/attack-map"),
  sync:            (full = true) => api(`/graph/sync?full=${full}`, { method: "POST" }),
  sharedVulns:     ()       => api("/graph/shared-vulns"),
  blastRadius:     (target) => api(`/graph/blast-radius/${encodeURIComponent(target)}`),
  stats:           ()       => api("/graph/stats"),
  mostVulnerable:  ()       => api("/graph/most-vulnerable"),
};

// ── Analytics ────────────────────────────────────────────────────────
export const analyticsApi = {
  discover:     (body)             => api("/analytics/discover", { method: "POST", body }),
  trending:     (days=30, interval="daily") => api(`/analytics/trending?days=${days}&interval=${interval}`),
  diff:         (jobA, jobB)       => api(`/analytics/diff?job_a=${jobA}&job_b=${jobB}`),
  executive:    ()                 => api("/analytics/executive"),
  compare:      (jobA, jobB)       => api(`/analytics/compare?job_a=${jobA}&job_b=${jobB}`),
  reverify:     (jobId)            => api("/analytics/reverify", { method: "POST", body: { job_id: jobId } }),
};

// ── Scan ─────────────────────────────────────────────────────────────
// ── Device inventory (Intune) ────────────────────────────────────────
export const inventoryApi = {
  listConnections:  ()         => api("/inventory/connections"),
  createConnection: (body)     => api("/inventory/connections", { method: "POST", body }),
  updateConnection: (id, body) => api(`/inventory/connections/${id}`, { method: "PUT", body }),
  deleteConnection: (id)       => api(`/inventory/connections/${id}`, { method: "DELETE" }),
  testConnection:   (id)       => api(`/inventory/connections/${id}/test`, { method: "POST" }),
  syncConnection:   (id)       => api(`/inventory/connections/${id}/sync`, { method: "POST" }),

  listDevices: ({ platform, q } = {}) => {
    const params = new URLSearchParams();
    if (platform) params.set("platform", platform);
    if (q) params.set("q", q);
    const query = params.toString();
    return api(`/inventory/devices${query ? `?${query}` : ""}`);
  },
  getDevice: (id) => api(`/inventory/devices/${id}`),

  getAlertSettings:  ()     => api("/inventory/alert-settings"),
  saveAlertSettings: (body) => api("/inventory/alert-settings", { method: "PUT", body }),
};

export const scanApi = {
  listJobs:   ()       => api("/scan/jobs"),
  getJob:     (id)     => api(`/scan/jobs/${id}`),
  createJob:  (body)   => api("/scan/jobs", { method: "POST", body }),
  cancelJob:  (id)     => api(`/scan/jobs/${id}/cancel`, { method: "POST" }),
  deleteJob:  (id)     => api(`/scan/jobs/${id}`, { method: "DELETE" }),
  rescanJob:  (id)     => api(`/scan/jobs/${id}/rescan`, { method: "POST" }),

  listProfiles:   ()           => api("/scan/profiles"),
  createProfile:  (body)       => api("/scan/profiles", { method: "POST", body }),
  updateProfile:  (id, body)   => api(`/scan/profiles/${id}`, { method: "PUT", body }),
  deleteProfile:  (id)         => api(`/scan/profiles/${id}`, { method: "DELETE" }),

  listPlugins:    () => api("/scan/plugins"),
  history:        (target) => api(`/scan/history/${encodeURIComponent(target)}`),

  listSchedules:    ()           => api("/scan/schedules"),
  createSchedule:   (body)       => api("/scan/schedules", { method: "POST", body }),
  toggleSchedule:   (id)         => api(`/scan/schedules/${id}/toggle`, { method: "PUT" }),
  deleteSchedule:   (id)         => api(`/scan/schedules/${id}`, { method: "DELETE" }),
};
