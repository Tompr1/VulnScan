import React, { useEffect, useState } from "react";
import { Icons } from "./icons.jsx";
import { clientsApi, getUser } from "../api.js";
import { ageText } from "./inventoryModel.js";
import { clientHue, clientInitials, filterClients } from "./routes.js";

// Above this many clients, the picker offers a search field.
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

/**
 * The screen to choose the client to work on, after sign-in (when the
 * account reaches more than one) or when the open client is no longer
 * reachable. Each client shows where to look first: open critical and high
 * findings, exploited vulnerabilities (KEV), and its last scan.
 */
export function ClientPicker({ onPick, onSignOut, notice = "", version = "" }) {
  const [clients, setClients] = useState(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [opening, setOpening] = useState(null);
  const user = getUser() || {};

  useEffect(() => {
    let cancelled = false;
    clientsApi.overview()
      .then(list => { if (!cancelled) setClients(list); })
      .catch(e => { if (!cancelled) { setError(e.message); setClients([]); } });
    return () => { cancelled = true; };
  }, []);

  const pick = async (client) => {
    setOpening(client.id);
    setError("");
    try { await onPick(client.id); }
    catch (e) { setError(e.message); setOpening(null); }
  };

  const shown = filterClients(clients || [], query);

  return (
    <div className="login-shell-centered">
      <div className="login-bg-grid"/>
      <div className="login-card cp-card">
        <div className="login-brand" style={{justifyContent: "space-between"}}>
          <div style={{display: "flex", alignItems: "center", gap: 12}}>
            <div className="nav-logo" style={{width: 36, height: 36, fontSize: 15}}>V</div>
            <div>
              <div style={{fontSize: 16, fontWeight: 600, color: "var(--text-0)", letterSpacing: "-0.01em"}}>
                VulnScan <span style={{color: "var(--text-3)", fontWeight: 400, fontSize: 12, marginLeft: 4}}>{version ? `v${version}` : ""}</span>
              </div>
              <div style={{fontSize: 12, color: "var(--text-3)", marginTop: 1}}>
                {user.email}{user.is_global_admin && <span className="tag brand" style={{marginLeft: 8, height: 18}}>global admin</span>}
              </div>
            </div>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onSignOut}><Icons.LogOut size={12}/> Sign out</button>
        </div>

        <div className="login-head">
          <h1>Choose a client</h1>
          <div className="login-sub">
            {clients && clients.length > 0
              ? <>You have access to {clients.length} client{clients.length > 1 ? "s" : ""}. You can switch at any time from the top bar.</>
              : <>Each client has its own assets, scans, devices and reports.</>}
          </div>
        </div>

        {notice && (
          <div className="cp-notice">
            <Icons.AlertTriangle size={13}/> {notice}
          </div>
        )}
        {error && (
          <div className="cp-notice error">
            <Icons.AlertTriangle size={13}/> {error}
          </div>
        )}

        {clients && clients.length >= SEARCH_FROM && (
          <div className="login-field">
            <Icons.Search size={14}/>
            <input autoFocus placeholder="Search clients…" value={query} onChange={e => setQuery(e.target.value)}/>
          </div>
        )}

        {clients === null ? (
          <div className="cp-empty"><Icons.Refresh size={14} className="spin"/> Loading clients…</div>
        ) : clients.length === 0 ? (
          <div className="cp-empty">
            {user.is_global_admin
              ? "No client yet. Clients are created from the access administration."
              : "Your account has no access to any client. Ask an administrator for access."}
          </div>
        ) : shown.length === 0 ? (
          <div className="cp-empty">No client matches “{query}”.</div>
        ) : (
          <div className="cp-list">
            {shown.map(c => (
              <button key={c.id} className={`cp-item ${c.id === user.workspace_id ? "current" : ""}`}
                      onClick={() => pick(c)} disabled={opening != null}>
                <ClientBadge client={c} size={36}/>
                <div className="cp-main">
                  <div className="cp-name">
                    {c.name}
                    {c.id === user.workspace_id && <span className="cp-current">last opened</span>}
                  </div>
                  <div className="cp-meta">
                    <span className="tag">{c.role}</span>
                    <span>Last scan: {ageText(c.last_scan_at)}</span>
                  </div>
                </div>
                <div className="cp-stats">
                  <Counter value={c.open_findings?.critical} label="critical" tone="critical"/>
                  <Counter value={c.open_findings?.high} label="high" tone="high"/>
                  <Counter value={c.open_kev} label="KEV" tone="exploited"/>
                </div>
                <span className="cp-go">
                  {opening === c.id ? <Icons.Refresh size={14} className="spin"/> : <Icons.ChevronRight size={14}/>}
                </span>
              </button>
            ))}
          </div>
        )}
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
