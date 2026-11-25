import React, { useEffect, useState } from "react";
import { Icons } from "./icons.jsx";
import { accessApi, clientsApi, datasetsApi, settingsApi } from "../api.js";
import { ClientBadge } from "./ClientPicker.jsx";
import { ageText } from "./inventoryModel.js";
import { filterClients } from "./routes.js";
import { PlatformEnvironment, PlatformUpdates } from "./PagesOther.jsx";

// Root: the platform itself, for super admins — like the root ADOM of
// FortiManager. It holds no client data of its own: an overview of every
// client, what they all share, and the platform's system.

/** Every client at a glance, the worst first, each one a click away. */
export function RootOverview({ openClient, setPage }) {
  const [clients, setClients] = useState(null);
  const [superAdmins, setSuperAdmins] = useState(null);
  const [datasets, setDatasets] = useState(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");

  useEffect(() => {
    clientsApi.overview().then(setClients).catch(e => { setError(e.message); setClients([]); });
    accessApi.users().then(users => setSuperAdmins(users.filter(u => u.is_global_admin).length)).catch(() => {});
    datasetsApi.list().then(setDatasets).catch(() => {});
  }, []);

  const all = clients || [];
  const total = (pick) => all.reduce((sum, c) => sum + (pick(c) || 0), 0);
  // Exploited first, then critical, then high: where to look first.
  const ranked = [...filterClients(all, query)].sort((a, b) =>
    (b.open_kev - a.open_kev) || (b.open_findings.critical - a.open_findings.critical)
    || (b.open_findings.high - a.open_findings.high) || a.name.localeCompare(b.name));

  return (
    <>
      <div className="ph">
        <div>
          <h1>Platform overview</h1>
          <div className="sub">Every client of the MSP at a glance. Open one to work on its assets, scans and devices.</div>
        </div>
        <div className="actions">
          <button className="btn" onClick={() => setPage("access")}><Icons.Users size={13}/> Clients & access</button>
        </div>
      </div>
      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}

      <div className="grid-stat" style={{gridTemplateColumns: "repeat(5, 1fr)"}}>
        <Stat label="Clients" value={clients ? all.length : "…"} tone="root"/>
        <Stat label="Open critical" value={clients ? total(c => c.open_findings?.critical) : "…"} tone="critical"/>
        <Stat label="Open high" value={clients ? total(c => c.open_findings?.high) : "…"} tone="high"/>
        <Stat label="Exploited (KEV)" value={clients ? total(c => c.open_kev) : "…"} tone="critical"/>
        <Stat label="Super admins" value={superAdmins ?? "…"} tone="neutral"/>
      </div>

      <div className="card">
        <div className="toolbar">
          <div className="left"><span className="card-title">Clients</span><span className="muted" style={{fontSize: 12}}>worst first</span></div>
          <div className="right">
            <div className="field" style={{minWidth: 220}}>
              <Icons.Search size={14} className="icon"/>
              <input placeholder="Search clients…" value={query} onChange={e => setQuery(e.target.value)}/>
            </div>
          </div>
        </div>
        <div className="card-body flush">
          {clients === null ? (
            <div className="empty">Loading…</div>
          ) : !ranked.length ? (
            <div className="empty"><div className="empty-body" style={{margin: "0 auto"}}>{all.length ? "No client matches." : "No client yet."}</div></div>
          ) : (
            <table className="tbl">
              <thead><tr><th>Client</th><th className="num">Critical</th><th className="num">High</th><th className="num">KEV</th><th>Last scan</th><th style={{width: 110}}/></tr></thead>
              <tbody>
                {ranked.map(c => (
                  <tr key={c.id} className="clickable" onClick={() => openClient(c.id)}>
                    <td>
                      <div style={{display: "flex", gap: 10, alignItems: "center"}}>
                        <ClientBadge client={c} size={24}/>
                        <span style={{color: "var(--text-0)", fontWeight: 500}}>{c.name}</span>
                      </div>
                    </td>
                    <td className="num" style={{color: c.open_findings.critical ? "var(--sev-critical)" : "var(--text-4)"}}>{c.open_findings.critical}</td>
                    <td className="num" style={{color: c.open_findings.high ? "var(--sev-high)" : "var(--text-4)"}}>{c.open_findings.high}</td>
                    <td className="num">{c.open_kev ? <span className="kev">{c.open_kev} KEV</span> : <span style={{color: "var(--text-4)"}}>0</span>}</td>
                    <td className="muted" style={{fontSize: 12}}>{ageText(c.last_scan_at)}</td>
                    <td><span className="btn btn-sm">Open <Icons.ChevronRight size={11}/></span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="grid-2-eq" style={{marginTop: 16}}>
        <div className="card">
          <div className="card-head"><div><div className="card-title">Shared databases</div><div className="card-sub">Used by every client: CVE catalog, KEV, EPSS…</div></div>
            <button className="btn btn-sm" onClick={() => setPage("datasets")}>Manage</button>
          </div>
          <div className="card-body" style={{fontSize: 13, color: "var(--text-2)"}}>
            {datasets === null ? "…" : `${datasets.filter(d => d.enabled).length} enabled of ${datasets.length} reference datasets.`}
          </div>
        </div>
        <div className="card">
          <div className="card-head"><div><div className="card-title">Updates & system</div><div className="card-sub">Version, updates, environment, automatic refresh.</div></div>
            <button className="btn btn-sm" onClick={() => setPage("platform")}>Open</button>
          </div>
          <div className="card-body" style={{fontSize: 13, color: "var(--text-2)"}}>Platform-wide settings, shared by every client.</div>
        </div>
      </div>
    </>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className={`stat ${tone === "root" ? "root" : tone === "critical" ? "critical" : tone === "high" ? "high" : "neutral"}`}>
      <div className="accent-bar"/>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}

/** The platform: version and updates, scheduled refresh of the shared databases, environment. */
export function RootPlatform({ version = "" }) {
  return (
    <>
      <div className="ph">
        <div>
          <h1>Updates & system</h1>
          <div className="sub">The platform itself, shared by every client.</div>
        </div>
      </div>
      <div style={{display: "flex", flexDirection: "column", gap: 16}}>
        <div className="card">
          <div className="card-head"><div><div className="card-title">Version & updates</div></div></div>
          <div className="card-body"><PlatformUpdates version={version}/></div>
        </div>
        <div className="card">
          <div className="card-head"><div><div className="card-title">Automatic refresh of the shared databases</div>
            <div className="card-sub">Downloads CVE, KEV and EPSS again on a schedule, for every client.</div></div></div>
          <div className="card-body"><DatasetRefreshSchedule/></div>
        </div>
        <div className="card">
          <div className="card-head"><div><div className="card-title">Environment</div></div></div>
          <div className="card-body"><PlatformEnvironment/></div>
        </div>
      </div>
    </>
  );
}

const INTERVALS = [6, 12, 24, 48, 168];

function DatasetRefreshSchedule() {
  const [value, setValue] = useState(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    settingsApi.datasetRefresh().then(setValue).catch(e => setMessage(e.message));
  }, []);

  const save = async (change) => {
    const next = { ...value, ...change };
    setValue(next);
    setSaving(true);
    setMessage("");
    try { setValue(await settingsApi.saveDatasetRefresh(change)); setMessage("Saved."); }
    catch (e) { setMessage(e.message); }
    finally { setSaving(false); }
  };

  if (!value) return <div className="muted">{message || "Loading…"}</div>;
  return (
    <div style={{display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap"}}>
      <label className="login-check" style={{margin: 0}}>
        <input type="checkbox" checked={!!value.enabled} disabled={saving} onChange={e => save({ enabled: e.target.checked })}/>
        <span>Refresh automatically</span>
      </label>
      <label style={{display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--text-2)"}}>
        every
        <select className="form-input" style={{width: 130, height: 32}} value={value.interval_hours} disabled={saving || !value.enabled}
                onChange={e => save({ interval_hours: Number(e.target.value) })} aria-label="Refresh interval">
          {[...new Set([...INTERVALS, value.interval_hours])].sort((a, b) => a - b).map(h => (
            <option key={h} value={h}>{h % 24 === 0 ? `${h / 24} day${h > 24 ? "s" : ""}` : `${h} hours`}</option>
          ))}
        </select>
      </label>
      {message && <span className="muted" style={{fontSize: 12}}>{message}</span>}
    </div>
  );
}
