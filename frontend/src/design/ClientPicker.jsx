import React, { useEffect, useState } from "react";
import { Icons } from "./icons.jsx";
import { clientsApi, getUser } from "../api.js";
import { ageText } from "./inventoryModel.js";
import { clientHue, clientInitials, filterClients } from "./routes.js";

// Above this many clients, the window offers a search field.
const SEARCH_FROM = 7;

/** Square badge with a client's initials, in its own colour. */
export function ClientBadge({ client, size = 28 }) {
  return (
    <span className="client-badge" style={{
      width: size, height: size, fontSize: Math.round(size * 0.4),
      background: `hsl(${clientHue(client?.id)} 52% 42%)`,
    }}>{clientInitials(client?.name)}</span>
  );
}

/** Badge of Root, the platform itself (its own colour, never a client's). */
export function RootBadge({ size = 28 }) {
  return (
    <span className="client-badge root-badge" style={{ width: size, height: size }}>
      <Icons.Shield size={Math.round(size * 0.55)}/>
    </span>
  );
}

/**
 * The window to choose where to work, like the ADOM selection of
 * FortiManager: after sign-in, and from the top bar at any time.
 * - Root (global admins only): the platform — what every client shares,
 *   the clients and the accounts;
 * - each client the account opens, with where to look first: open critical
 *   and high findings, exploited vulnerabilities (KEV), last scan.
 *
 * `current` is {root: true} or {clientId}; `onClose` (from the top bar)
 * adds a close button — after sign-in a choice must be made.
 */
export function ContextWindow({ onPickClient, onPickRoot, onSignOut, onClose = null, current = null, notice = "", version = "" }) {
  const [clients, setClients] = useState(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [opening, setOpening] = useState(null); // "root" or a client id
  const user = getUser() || {};

  useEffect(() => {
    let cancelled = false;
    clientsApi.overview()
      .then(list => { if (!cancelled) setClients(list); })
      .catch(e => { if (!cancelled) { setError(e.message); setClients([]); } });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!onClose) return;
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const open = async (target, action) => {
    setOpening(target);
    setError("");
    try { await action(); }
    catch (e) { setError(e.message); setOpening(null); }
  };

  const shown = filterClients(clients || [], query);
  const isCurrentRoot = !!current?.root;

  return (
    <div className={onClose ? "ctx-overlay" : "login-shell-centered"} onClick={onClose || undefined}>
      {!onClose && <div className="login-bg-grid"/>}
      <div className="ctx-window" role="dialog" aria-label="Select a client" onClick={e => e.stopPropagation()}>
        <div className="ctx-head">
          <div className="nav-logo" style={{width: 30, height: 30, fontSize: 13}}>V</div>
          <div style={{minWidth: 0}}>
            <div className="ctx-title">Select a client</div>
            <div className="ctx-sub">
              {user.email}{user.is_global_admin && <span className="tag root" style={{marginLeft: 8, height: 18}}>super admin</span>}
              {version && <span style={{marginLeft: 8}}>· v0cday v{version}</span>}
            </div>
          </div>
          <div style={{marginLeft: "auto", display: "flex", gap: 6}}>
            <button className="btn btn-ghost btn-sm" onClick={onSignOut}><Icons.LogOut size={12}/> Sign out</button>
            {onClose && (
              <button className="btn btn-ghost btn-icon btn-sm" onClick={onClose} aria-label="Close"><Icons.X size={14}/></button>
            )}
          </div>
        </div>

        <div className="ctx-body">
          {notice && <div className="cp-notice"><Icons.AlertTriangle size={13}/> {notice}</div>}
          {error && <div className="cp-notice error"><Icons.AlertTriangle size={13}/> {error}</div>}

          {user.is_global_admin && (
            <button className={`ctx-root ${isCurrentRoot ? "current" : ""}`} disabled={opening != null}
                    onClick={() => open("root", onPickRoot)}>
              <RootBadge size={40}/>
              <div className="cp-main">
                <div className="cp-name">
                  Root {isCurrentRoot && <span className="cp-current">open</span>}
                </div>
                <div className="ctx-root-sub">
                  Platform administration — reference data (CVE, KEV, EPSS), clients and access, super admins, updates
                </div>
              </div>
              <span className="cp-go">{opening === "root" ? <Icons.Refresh size={14} className="spin"/> : <Icons.ChevronRight size={14}/>}</span>
            </button>
          )}

          <div className="ctx-section">
            <span>Clients {clients ? <span className="muted">({clients.length})</span> : null}</span>
            {clients && clients.length >= SEARCH_FROM && (
              <div className="client-menu-search" style={{margin: 0, width: 240}}>
                <Icons.Search size={13}/>
                <input autoFocus placeholder="Search clients…" value={query} onChange={e => setQuery(e.target.value)}/>
              </div>
            )}
          </div>

          {clients === null ? (
            <div className="cp-empty"><Icons.Refresh size={14} className="spin"/> Loading clients…</div>
          ) : clients.length === 0 ? (
            <div className="cp-empty">
              {user.is_global_admin
                ? "No client yet. Open Root to create clients and give access to them."
                : "Your account has no access to any client. Ask an administrator for access."}
            </div>
          ) : shown.length === 0 ? (
            <div className="cp-empty">No client matches “{query}”.</div>
          ) : (
            <div className="ctx-grid">
              {shown.map(c => {
                const isCurrent = !isCurrentRoot && c.id === current?.clientId;
                return (
                  <button key={c.id} className={`ctx-tile ${isCurrent ? "current" : ""}`}
                          onClick={() => open(c.id, () => onPickClient(c.id))} disabled={opening != null}>
                    <div className="ctx-tile-head">
                      <ClientBadge client={c} size={32}/>
                      <div style={{minWidth: 0, flex: 1}}>
                        <div className="cp-name">{c.name}</div>
                        <div className="cp-meta">
                          <span className="tag">{c.role}</span>
                          {isCurrent && <span className="cp-current">open</span>}
                        </div>
                      </div>
                      {opening === c.id && <Icons.Refresh size={14} className="spin"/>}
                    </div>
                    <div className="cp-stats">
                      <Counter value={c.open_findings?.critical} label="critical" tone="critical"/>
                      <Counter value={c.open_findings?.high} label="high" tone="high"/>
                      <Counter value={c.open_kev} label="KEV" tone="exploited"/>
                    </div>
                    <div className="ctx-tile-foot">Last scan: {ageText(c.last_scan_at)}</div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Counter({ value = 0, label, tone }) {
  return (
    <div className={`cp-counter ${value > 0 ? tone : "zero"}`} title={`${value} open ${label}`}>
      <div className="cp-counter-value">{value}</div>
      <div className="cp-counter-label">{label}</div>
    </div>
  );
}
