import React, { useState, useEffect, useCallback, useMemo } from "react";
import { Icons, Sev, Status, Empty } from "./icons.jsx";
import { inventoryApi, canEdit, isAdmin } from "../api.js";
import {
  PLATFORMS, ageText, compareDevices, compareIssues, describeChange, evidencePairs,
  filterBySeverity, platformLabel, ruleLabel, severityRank, summarizeFleet,
} from "./inventoryModel.js";

// Device inventory collected from Intune and audited after each sync:
// OS support, OS and software versions, known CVEs (CISA KEV).
// The device page is the target of the alert links (#/inventory/devices/<id>).
export function Inventory({ deviceId, openDevice, closeDevice }) {
  return deviceId != null
    ? <DeviceDetail id={deviceId} back={closeDevice}/>
    : <DeviceList openDevice={openDevice}/>;
}

const SYNC_STATUS = { ok: "done", error: "failed", queued: "queued" };
const label = { fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em" };

function useDebounced(value, delay = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

function ErrorLine({ error }) {
  if (!error) return null;
  return <div style={{color: "var(--err)", margin: "0 0 14px", fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>;
}

// ── Device list ──────────────────────────────────────────────────────────

function DeviceList({ openDevice }) {
  const [devices, setDevices] = useState([]);
  const [connections, setConnections] = useState([]);
  const [platform, setPlatform] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showConnections, setShowConnections] = useState(false);
  const search = useDebounced(q.trim());

  const refresh = useCallback(async () => {
    try {
      const [list, conns] = await Promise.all([
        inventoryApi.listDevices({ platform, q: search }),
        inventoryApi.listConnections(),
      ]);
      setDevices(list);
      setConnections(conns);
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [platform, search]);

  useEffect(() => { refresh(); }, [refresh]);
  // A queued sync finishes in the background: refresh until none is pending.
  useEffect(() => {
    if (!connections.some(c => c.last_sync_status === "queued")) return;
    const t = setInterval(refresh, 10000);
    return () => clearInterval(t);
  }, [connections, refresh]);

  const shown = useMemo(() => filterBySeverity(devices, severity).slice().sort(compareDevices), [devices, severity]);
  const summary = summarizeFleet(devices);

  return (
    <>
      <div className="ph">
        <div>
          <h1>Devices</h1>
          <div className="sub">Managed devices collected from Microsoft Intune, audited after each sync: OS support, OS and software versions, known CVEs.</div>
        </div>
        <div className="actions">
          <button className="btn" onClick={refresh}><Icons.Refresh size={14}/> Refresh</button>
          {canEdit() && <button className="btn btn-primary" onClick={() => setShowConnections(true)}><Icons.Layers size={14}/> Intune connections</button>}
        </div>
      </div>

      <ErrorLine error={error}/>

      {connections.map(c => <ConnectionBanner key={c.id} connection={c}/>)}

      {!loading && connections.length === 0 ? (
        <div className="card">
          <Empty icon={Icons.Monitor} title="No device inventory yet"
                 body="Connect a Microsoft Intune tenant to collect managed devices, their OS and installed applications."
                 action={canEdit() && <button className="btn btn-primary" onClick={() => setShowConnections(true)}><Icons.Plus size={14}/> Connect Intune</button>}/>
        </div>
      ) : (
        <>
          <div className="grid-stat" style={{gridTemplateColumns: "repeat(4, 1fr)", marginTop: 4}}>
            <div className="stat brand"><div className="accent-bar"/><div className="label"><Icons.Monitor size={12}/> Devices</div><div className="value">{summary.total}</div><div className="delta flat">{connections.length} connection{connections.length === 1 ? "" : "s"}</div></div>
            <div className="stat neutral"><div className="accent-bar"/><div className="label"><Icons.AlertTriangle size={12}/> With issues</div><div className="value">{summary.withIssues}</div><div className="delta flat">{summary.issues} open issues</div></div>
            <div className="stat critical"><div className="accent-bar"/><div className="label">Critical</div><div className="value">{summary.critical}</div><div className="delta flat">devices</div></div>
            <div className="stat high"><div className="accent-bar"/><div className="label">High</div><div className="value">{summary.high}</div><div className="delta flat">devices</div></div>
          </div>

          <div style={{display: "flex", gap: 10, alignItems: "center", marginBottom: 12, flexWrap: "wrap"}}>
            <div className="field" style={{maxWidth: 300, flex: 1}}>
              <Icons.Search size={14} className="icon"/>
              <input placeholder="Search name, user, serial…" value={q} onChange={e => setQ(e.target.value)}/>
            </div>
            <select className="form-input" style={{width: 170}} value={platform} onChange={e => setPlatform(e.target.value)}>
              <option value="">All platforms</option>
              {PLATFORMS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
            <select className="form-input" style={{width: 190}} value={severity} onChange={e => setSeverity(e.target.value)}>
              <option value="">All devices</option>
              <option value="critical">Critical issues</option>
              <option value="high">High or worse</option>
              <option value="medium">Medium or worse</option>
              <option value="none">No issue</option>
            </select>
            <span style={{marginLeft: "auto", fontSize: 12, color: "var(--text-3)"}}>{shown.length} of {devices.length}</span>
          </div>

          <div className="card">
            <div className="card-body flush">
              {loading && devices.length === 0 ? (
                <div style={{padding: 40, textAlign: "center", color: "var(--text-3)"}}>Loading devices…</div>
              ) : shown.length === 0 ? (
                <Empty icon={Icons.Search} title="No device matches" body="Change the search or the filters."/>
              ) : (
                <table className="tbl">
                  <thead><tr>
                    <th>Device</th><th>User</th><th>OS</th><th style={{width: 170}}>Issues</th>
                    <th style={{width: 110}}>Compliance</th><th style={{width: 120}}>Last check-in</th>
                  </tr></thead>
                  <tbody>
                    {shown.map(d => (
                      <tr key={d.id} className="clickable" onClick={() => openDevice(d.id)}>
                        <td>
                          <div style={{color: "var(--text-0)", fontWeight: 500}}>{d.name}</div>
                          <div className="muted mono" style={{fontSize: 11}}>{d.model || d.serial_number || ""}</div>
                        </td>
                        <td style={{fontSize: 12.5, color: "var(--text-2)"}}>{d.user_principal_name || "—"}</td>
                        <td style={{fontSize: 12.5}}>
                          <div>{platformLabel(d.platform)}</div>
                          <div className="muted mono" style={{fontSize: 11}}>{d.os_version || ""}</div>
                        </td>
                        <td>
                          {d.issue_count > 0
                            ? <span style={{display: "inline-flex", gap: 8, alignItems: "center"}}><Sev s={d.highest_severity}/><span className="mono" style={{fontSize: 12}}>{d.issue_count}</span></span>
                            : <span style={{color: "var(--ok)", fontSize: 12}}><Icons.Check size={12}/> None</span>}
                        </td>
                        <td style={{fontSize: 12, color: d.compliance_state === "noncompliant" ? "var(--err)" : "var(--text-2)"}}>{d.compliance_state || "—"}</td>
                        <td className="muted" style={{fontSize: 12}}>{ageText(d.last_check_in_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </>
      )}

      {showConnections && <ConnectionsModal close={() => { setShowConnections(false); refresh(); }}/>}
    </>
  );
}

function ConnectionBanner({ connection: c }) {
  if (c.last_sync_status !== "error" && c.last_sync_status !== "queued") return null;
  const failed = c.last_sync_status === "error";
  return (
    <div style={{
      display: "flex", gap: 10, alignItems: "flex-start", padding: "10px 14px", marginBottom: 12, borderRadius: 8, fontSize: 13,
      border: `1px solid ${failed ? "var(--err)" : "var(--line)"}`, background: "var(--surface-1)",
    }}>
      {failed ? <Icons.AlertTriangle size={14} color="var(--err)"/> : <Icons.Refresh size={14} className="spin"/>}
      <div>
        <strong>{c.name}</strong>{" — "}
        {failed ? <>last sync failed: {c.last_sync_message}</> : <>sync in progress; the list refreshes when it completes.</>}
      </div>
    </div>
  );
}

// ── Device page ──────────────────────────────────────────────────────────

function DeviceDetail({ id, back }) {
  const [device, setDevice] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("issues");

  useEffect(() => {
    let cancelled = false;
    setDevice(null);
    inventoryApi.getDevice(id)
      .then(d => { if (!cancelled) { setDevice(d); setError(""); } })
      .catch(e => { if (!cancelled) setError(e.message); });
    return () => { cancelled = true; };
  }, [id]);

  if (error) {
    return (
      <>
        <button className="btn btn-ghost btn-sm" onClick={back}><Icons.ChevronLeft size={14}/> Devices</button>
        <div className="card" style={{marginTop: 14}}><Empty icon={Icons.AlertTriangle} title="Device unavailable" body={error}/></div>
      </>
    );
  }
  if (!device) return <div style={{padding: 60, textAlign: "center", color: "var(--text-3)"}}>Loading device…</div>;

  const issues = device.issues.slice().sort(compareIssues);
  const worst = issues.reduce((w, i) => (w == null || severityRank(i.severity) < severityRank(w) ? i.severity : w), null);
  const exploited = issues.filter(i => i.is_kev).length;
  const tabs = [
    ["issues", `Issues (${issues.length})`],
    ["apps", `Applications (${device.apps.length})`],
    ["details", "Details"],
    ["history", `History (${device.changes.length})`],
  ];

  return (
    <>
      <button className="btn btn-ghost btn-sm" onClick={back} style={{marginBottom: 10}}><Icons.ChevronLeft size={14}/> Devices</button>
      <div className="ph">
        <div>
          <h1 style={{display: "flex", alignItems: "center", gap: 10}}>
            {device.name}
            {worst && <Sev s={worst}/>}
            {exploited > 0 && <span className="kev">KEV × {exploited}</span>}
            {device.removed_at && <span className="tag">removed</span>}
          </h1>
          <div className="sub">
            {platformLabel(device.platform)} {device.os_version || ""}
            {device.user_principal_name ? ` · ${device.user_principal_name}` : ""}
            {` · last check-in ${ageText(device.last_check_in_at)}`}
          </div>
        </div>
      </div>

      <AuditInfo audit={device.last_audit}/>

      <div style={{display: "flex", gap: 0, margin: "8px 0 16px", borderBottom: "1px solid var(--line)"}}>
        {tabs.map(([k, l]) => (
          <button key={k} onClick={() => setTab(k)} style={{
            padding: "10px 14px", fontSize: 13, fontWeight: 500,
            color: tab === k ? "var(--text-0)" : "var(--text-3)",
            borderBottom: tab === k ? "2px solid var(--brand)" : "2px solid transparent", marginBottom: -1,
          }}>{l}</button>
        ))}
      </div>

      {tab === "issues" && <IssueList issues={issues} audited={!!device.last_audit}/>}
      {tab === "apps" && <AppList apps={device.apps}/>}
      {tab === "details" && <DeviceProperties device={device}/>}
      {tab === "history" && <ChangeList changes={device.changes}/>}
    </>
  );
}

function AuditInfo({ audit }) {
  if (!audit) {
    return <div style={{fontSize: 13, color: "var(--text-3)", marginBottom: 8}}><Icons.Info size={13}/> Not audited yet: issues appear after the next sync.</div>;
  }
  return (
    <div style={{marginBottom: 8}}>
      <div style={{fontSize: 12.5, color: "var(--text-3)"}}>
        <Icons.Clock size={12}/> Audited {audit.audited_at ? new Date(audit.audited_at).toLocaleString() : "—"} · job #{audit.job_id} · {audit.issues} issues on {audit.devices} devices
      </div>
      {audit.warnings.length > 0 && (
        <div style={{marginTop: 8, padding: "10px 14px", borderRadius: 8, border: "1px solid var(--sev-medium)", fontSize: 13, color: "var(--text-1)"}}>
          <div style={{fontWeight: 600, marginBottom: 4}}><Icons.AlertTriangle size={13} color="var(--sev-medium)"/> Incomplete audit: a device without issues is not necessarily up to date</div>
          {audit.warnings.map(w => <div key={w}>• {w}</div>)}
        </div>
      )}
    </div>
  );
}

function IssueList({ issues, audited }) {
  const [open, setOpen] = useState(null);
  if (issues.length === 0) {
    return (
      <div className="card">
        <Empty icon={audited ? Icons.Check : Icons.Clock}
               title={audited ? "No issue on this device" : "No audit yet"}
               body={audited ? "Supported OS, up-to-date versions and no known CVE at the last audit." : "Run a sync to audit this device."}/>
      </div>
    );
  }
  return (
    <div style={{display: "flex", flexDirection: "column", gap: 8}}>
      {issues.map(issue => {
        const expanded = open === issue.id;
        const headline = issue.title.replace(/ — [^—]+$/, "");
        return (
          <div key={issue.id} className="card">
            <div onClick={() => setOpen(expanded ? null : issue.id)}
                 style={{display: "flex", gap: 10, alignItems: "center", padding: "12px 16px", cursor: "pointer"}}>
              <Sev s={issue.severity}/>
              {issue.is_kev && <span className="kev">KEV</span>}
              <span style={{flex: 1, color: "var(--text-0)", fontWeight: 500, fontSize: 13.5}}>{headline}</span>
              <span className="tag">{ruleLabel(issue.rule)}</span>
              {expanded ? <Icons.ChevronDown size={14}/> : <Icons.ChevronRight size={14}/>}
            </div>
            {expanded && <IssueBody issue={issue}/>}
          </div>
        );
      })}
    </div>
  );
}

function IssueBody({ issue }) {
  const pairs = evidencePairs(issue.evidence);
  return (
    <div style={{padding: "0 16px 16px", borderTop: "1px solid var(--line)"}}>
      <div style={{whiteSpace: "pre-wrap", fontSize: 13.5, lineHeight: 1.65, color: "var(--text-1)", marginTop: 14}}>{issue.description}</div>
      <div style={{marginTop: 14, padding: "12px 14px", borderRadius: 8, borderLeft: "3px solid var(--ok)", background: "rgba(95,184,122,0.06)"}}>
        <div style={{...label, color: "var(--ok)", fontWeight: 600, marginBottom: 6}}><Icons.Shield size={12}/> Recommended action</div>
        <div style={{whiteSpace: "pre-wrap", fontSize: 13.5, lineHeight: 1.6, color: "var(--text-1)"}}>{issue.remediation}</div>
      </div>
      {pairs.length > 0 && (
        <dl className="dl" style={{marginTop: 14}}>
          {pairs.map(([k, v]) => <React.Fragment key={k}><dt>{k}</dt><dd className="mono" style={{fontSize: 12}}>{v}</dd></React.Fragment>)}
        </dl>
      )}
      {issue.references.length > 0 && (
        <div style={{marginTop: 14, display: "flex", flexDirection: "column", gap: 4}}>
          <div className="eyebrow">References</div>
          {issue.references.map(r => (
            <a key={r} href={r} target="_blank" rel="noopener noreferrer" style={{fontSize: 12.5, color: "var(--brand-text)"}}>
              <Icons.External size={11}/> {r}
            </a>
          ))}
        </div>
      )}
      <div style={{marginTop: 12, fontSize: 11.5, color: "var(--text-3)"}}>
        Status {issue.status}{issue.sla_days != null ? ` · SLA ${issue.sla_days} days` : ""} · finding #{issue.id} (job #{issue.job_id})
      </div>
    </div>
  );
}

function AppList({ apps }) {
  const [q, setQ] = useState("");
  const shown = apps.filter(a => !q || `${a.name} ${a.publisher || ""}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="card">
      <div className="card-head">
        <div className="field" style={{maxWidth: 300}}>
          <Icons.Search size={14} className="icon"/>
          <input placeholder="Search applications…" value={q} onChange={e => setQ(e.target.value)}/>
        </div>
        <span style={{fontSize: 12, color: "var(--text-3)"}}>{shown.length} of {apps.length}</span>
      </div>
      <div className="card-body flush">
        {apps.length === 0 ? (
          <Empty icon={Icons.Layers} title="No application reported" body="Intune reports installed applications for Windows, macOS and corporate mobile devices only."/>
        ) : (
          <table className="tbl">
            <thead><tr><th>Application</th><th style={{width: 200}}>Version</th><th>Publisher</th></tr></thead>
            <tbody>
              {shown.map((a, n) => (
                <tr key={`${a.name}-${a.version}-${n}`}>
                  <td style={{color: "var(--text-0)"}}>{a.name}</td>
                  <td className="mono" style={{fontSize: 12}}>{a.version || "—"}</td>
                  <td className="muted" style={{fontSize: 12}}>{a.publisher || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function DeviceProperties({ device: d }) {
  const yesNo = v => (v == null ? "—" : v ? "Yes" : "No");
  const rows = [
    ["Platform", platformLabel(d.platform)],
    ["Operating system", `${d.os_name || ""} ${d.os_version || ""}`.trim() || "—"],
    ["Model", [d.manufacturer, d.model].filter(Boolean).join(" ") || "—"],
    ["Serial number", d.serial_number || "—"],
    ["User", d.user_principal_name || "—"],
    ["Ownership", d.ownership || "—"],
    ["Compliance", d.compliance_state || "—"],
    ["Encrypted", yesNo(d.is_encrypted)],
    ["Security patch level", d.security_patch_level || "—"],
    ["Last check-in", d.last_check_in_at ? new Date(d.last_check_in_at).toLocaleString() : "—"],
    ["First seen", d.first_seen_at ? new Date(d.first_seen_at).toLocaleString() : "—"],
    ["Fleet manager id", d.external_id],
  ];
  return (
    <div className="card"><div className="card-body">
      <dl className="dl">
        {rows.map(([k, v]) => <React.Fragment key={k}><dt>{k}</dt><dd>{v}</dd></React.Fragment>)}
      </dl>
    </div></div>
  );
}

function ChangeList({ changes }) {
  if (changes.length === 0) {
    return <div className="card"><Empty icon={Icons.Clock} title="No change recorded" body="Changes appear from the second sync on."/></div>;
  }
  return (
    <div className="card"><div className="card-body flush">
      <table className="tbl">
        <thead><tr><th style={{width: 180}}>Detected</th><th>Change</th></tr></thead>
        <tbody>
          {changes.map((c, n) => (
            <tr key={`${c.detected_at}-${n}`}>
              <td className="muted mono" style={{fontSize: 12}}>{new Date(c.detected_at).toLocaleString()}</td>
              <td style={{fontSize: 13}}>{describeChange(c)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div></div>
  );
}

// ── Intune connections ───────────────────────────────────────────────────

const EMPTY_CONNECTION = { name: "", tenant_id: "", client_id: "", client_secret: "", sync_frequency: "daily" };

function ConnectionsModal({ close }) {
  const [connections, setConnections] = useState([]);
  const [form, setForm] = useState(EMPTY_CONNECTION);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const admin = isAdmin();

  const refresh = useCallback(async () => {
    try { setConnections(await inventoryApi.listConnections()); }
    catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);

  const run = async (key, action, success) => {
    setBusy(key); setError(""); setNotice("");
    try {
      const result = await action();
      setNotice(typeof success === "function" ? success(result) : success);
      await refresh();
      return true;
    } catch (e) {
      setError(e.message);
      return false;
    } finally {
      setBusy(null);
    }
  };

  const create = async (e) => {
    e.preventDefault();
    if (await run("create", () => inventoryApi.createConnection(form), "Connection saved. Use Test, then Sync now.")) setForm(EMPTY_CONNECTION);
  };
  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: 720}}>
        <div className="drawer-head">
          <Icons.Layers size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Microsoft Intune connections</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}}><Icons.X size={14}/></button>
        </div>
        <div style={{padding: "16px 24px 24px", display: "flex", flexDirection: "column", gap: 16, maxHeight: "75vh", overflowY: "auto"}}>
          {error && <div style={{color: "var(--err)", fontSize: 12.5}}><Icons.AlertTriangle size={12}/> {error}</div>}
          {notice && <div style={{color: "var(--ok)", fontSize: 12.5}}><Icons.Check size={12}/> {notice}</div>}

          {connections.length > 0 && (
            <table className="tbl">
              <thead><tr><th>Connection</th><th style={{width: 130}}>Sync</th><th style={{width: 150}}>Last sync</th><th style={{width: 210}}/></tr></thead>
              <tbody>
                {connections.map(c => (
                  <tr key={c.id}>
                    <td>
                      <div style={{color: "var(--text-0)", fontWeight: 500}}>{c.name}</div>
                      <div className="muted mono" style={{fontSize: 11}}>tenant {c.tenant_id}</div>
                    </td>
                    <td>
                      {admin ? (
                        <select className="form-input" value={c.sync_frequency} disabled={busy != null}
                                onChange={e => run(`freq-${c.id}`, () => inventoryApi.updateConnection(c.id, { sync_frequency: e.target.value }), "Frequency saved.")}>
                          <option value="daily">Daily</option><option value="weekly">Weekly</option><option value="manual">Manual</option>
                        </select>
                      ) : <span style={{fontSize: 12.5}}>{c.sync_frequency}</span>}
                    </td>
                    <td>
                      {c.last_sync_status ? <Status s={SYNC_STATUS[c.last_sync_status] || c.last_sync_status}/> : <span className="muted">never</span>}
                      <div className="muted" style={{fontSize: 11, marginTop: 2}} title={c.last_sync_message || ""}>{c.last_sync_at ? ageText(c.last_sync_at) : ""}</div>
                    </td>
                    <td style={{textAlign: "right", whiteSpace: "nowrap"}}>
                      {admin && <button className="btn btn-sm" disabled={busy != null}
                                        onClick={() => run(`test-${c.id}`, () => inventoryApi.testConnection(c.id), r => r.message)}>
                        {busy === `test-${c.id}` ? <Icons.Refresh size={12} className="spin"/> : <Icons.Check size={12}/>} Test
                      </button>}{" "}
                      {canEdit() && <button className="btn btn-sm" disabled={busy != null}
                                            onClick={() => run(`sync-${c.id}`, () => inventoryApi.syncConnection(c.id), r => `Sync queued (job #${r.job_id}).`)}>
                        <Icons.Refresh size={12}/> Sync now
                      </button>}{" "}
                      {admin && <button className="btn btn-sm btn-ghost" disabled={busy != null} title="Delete"
                                        onClick={() => window.confirm(`Delete "${c.name}" and its device inventory? Past findings are kept.`) &&
                                          run(`delete-${c.id}`, () => inventoryApi.deleteConnection(c.id), r => `Connection deleted (${r.deleted_devices} devices).`)}>
                        <Icons.Trash size={12}/>
                      </button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {admin ? (
            <form onSubmit={create} style={{display: "flex", flexDirection: "column", gap: 12, borderTop: connections.length ? "1px solid var(--line)" : "none", paddingTop: connections.length ? 16 : 0}}>
              <div className="eyebrow" style={{margin: 0}}>New connection</div>
              <div style={{fontSize: 12.5, color: "var(--text-3)", lineHeight: 1.6}}>
                Register an application in Microsoft Entra ID, grant it the <strong>application</strong> permission
                <span className="mono"> DeviceManagementManagedDevices.Read.All</span> with admin consent (read-only),
                then create a client secret. The secret is stored encrypted and never shown again.
              </div>
              <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12}}>
                <div><label className="form-label">Name</label><input className="form-input" value={form.name} onChange={e => update("name", e.target.value)} placeholder="Tenant de test" required/></div>
                <div><label className="form-label">Sync</label>
                  <select className="form-input" value={form.sync_frequency} onChange={e => update("sync_frequency", e.target.value)}>
                    <option value="daily">Daily</option><option value="weekly">Weekly</option><option value="manual">Manual</option>
                  </select>
                </div>
                <div><label className="form-label">Tenant ID</label><input className="form-input mono" value={form.tenant_id} onChange={e => update("tenant_id", e.target.value.trim())} placeholder="00000000-0000-0000-0000-000000000000" required/></div>
                <div><label className="form-label">Client ID</label><input className="form-input mono" value={form.client_id} onChange={e => update("client_id", e.target.value.trim())} placeholder="00000000-0000-0000-0000-000000000000" required/></div>
              </div>
              <div><label className="form-label">Client secret</label><input className="form-input" type="password" autoComplete="new-password" value={form.client_secret} onChange={e => update("client_secret", e.target.value)} required minLength={8}/></div>
              <div style={{display: "flex", justifyContent: "flex-end"}}>
                <button type="submit" className="btn btn-primary" disabled={busy != null}>
                  {busy === "create" ? <><Icons.Refresh size={12} className="spin"/> Saving…</> : <><Icons.Plus size={12}/> Add connection</>}
                </button>
              </div>
            </form>
          ) : connections.length === 0 && (
            <div style={{fontSize: 13, color: "var(--text-3)"}}>An administrator can connect an Intune tenant.</div>
          )}
        </div>
      </div>
    </>
  );
}
