import React, { useState, useEffect, useCallback } from "react";
import { Icons } from "./icons.jsx";
import { analyticsApi, scanApi, assetsApi, credentialsApi } from "../api.js";
import { SevBadge, Spinner, EmptyState, Panel } from "../components/ui.jsx";

// ── Helpers ────────────────────────────────────────────────────────────
const SEV_COLORS = {
  critical: "var(--sev-critical, #e74c3c)",
  high:     "var(--sev-high, #e67e22)",
  medium:   "var(--sev-medium, #f1c40f)",
  low:      "var(--sev-low, #2ecc71)",
  info:     "var(--sev-info, #3498db)",
};

function fmtDate(dt) {
  if (!dt) return "\u2014";
  try { return new Date(dt).toISOString().replace("T", " ").slice(0, 16); }
  catch { return String(dt); }
}

// ── Tab wrapper ────────────────────────────────────────────────────────
function Tabs({ tabs, active, onChange }) {
  return (
    <div style={{ display: "flex", gap: 2, borderBottom: "1px solid var(--line)", marginBottom: 20, flexWrap: "wrap" }}>
      {tabs.map(t => (
        <button key={t.id}
          className={active === t.id ? "btn btn-primary" : "btn"}
          style={{ borderRadius: "6px 6px 0 0", fontSize: 13 }}
          onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ── Collapsible section ────────────────────────────────────────────────
function Collapsible({ title, color, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ border: `1px solid ${color}`, borderRadius: 8, marginBottom: 12, overflow: "hidden" }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          padding: "10px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 8,
          background: color + "18", fontWeight: 600, fontSize: 13, color: "var(--text-0)",
        }}>
        {open ? <Icons.ChevronDown size={14}/> : <Icons.ChevronRight size={14}/>}
        {title}
      </div>
      {open && <div style={{ padding: 14 }}>{children}</div>}
    </div>
  );
}

// ── Stat card ──────────────────────────────────────────────────────────
function StatCard({ label, value, sub }) {
  return (
    <div className="card" style={{ flex: "1 1 180px", minWidth: 160 }}>
      <div className="card-body" style={{ padding: "16px 20px" }}>
        <div style={{ fontSize: 11, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>{label}</div>
        <div style={{ fontSize: 28, fontWeight: 700, color: "var(--text-0)", fontFamily: "var(--font-display)" }}>{value ?? "\u2014"}</div>
        {sub && <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 4 }}>{sub}</div>}
      </div>
    </div>
  );
}

// ======================================================================
// Tab 1: Executive Dashboard
// ======================================================================
function ExecutiveTab() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    analyticsApi.executive()
      .then(r => { if (!cancelled) setData(r); })
      .catch(e => { if (!cancelled) setError(e.message || "Failed to load executive data"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <Spinner/>;
  if (error) return <div className="alert alert-error">{error}</div>;
  if (!data) return <EmptyState text="No executive data available"/>;

  const rp = data.risk_posture || {};
  const sla = data.sla_compliance || {};
  const topVulns = data.top_10_vulns || [];
  const categories = data.findings_by_category || {};
  const scans = data.scan_activity || {};

  const critHigh = (rp.critical || 0) + (rp.high || 0);
  const totalFindings = rp.total_findings || 0;
  const riskAvg = rp.risk_score_avg != null ? Number(rp.risk_score_avg).toFixed(1) : "\u2014";
  const slaBreached = sla.breached || 0;

  return (
    <>
      {/* Stat cards */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
        <StatCard label="Total Findings" value={totalFindings}/>
        <StatCard label="Critical + High" value={critHigh}/>
        <StatCard label="Risk Score Avg" value={riskAvg}/>
        <StatCard label="SLA Breached" value={slaBreached}/>
      </div>

      {/* Top 10 Vulnerabilities */}
      <Panel title="Top 10 Vulnerabilities">
        {topVulns.length === 0
          ? <EmptyState text="No vulnerabilities found"/>
          : (
            <div style={{ overflowX: "auto" }}>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Target</th>
                  </tr>
                </thead>
                <tbody>
                  {topVulns.slice(0, 10).map((v, i) => (
                    <tr key={i}>
                      <td>{v.title || v.name || "\u2014"}</td>
                      <td><SevBadge sev={v.severity}/></td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>{v.risk_score != null ? Number(v.risk_score).toFixed(1) : "\u2014"}</td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{v.target || "\u2014"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </Panel>

      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 16 }}>
        {/* Findings by Category */}
        <div style={{ flex: "1 1 300px" }}>
          <Panel title="Findings by Category">
            {Object.keys(categories).length === 0
              ? <EmptyState text="No category data"/>
              : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {Object.entries(categories).map(([cat, count]) => {
                    const maxCount = Math.max(...Object.values(categories), 1);
                    const pct = Math.round((count / maxCount) * 100);
                    return (
                      <div key={cat} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ width: 60, fontSize: 12, fontWeight: 600, color: "var(--text-2)", textTransform: "uppercase" }}>{cat}</span>
                        <div style={{ flex: 1, height: 20, background: "var(--surface-2)", borderRadius: 4, overflow: "hidden" }}>
                          <div style={{ width: `${pct}%`, height: "100%", background: "var(--brand)", borderRadius: 4, transition: "width 0.3s" }}/>
                        </div>
                        <span style={{ width: 40, textAlign: "right", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-1)" }}>{count}</span>
                      </div>
                    );
                  })}
                </div>
              )
            }
          </Panel>
        </div>

        {/* Scan Activity */}
        <div style={{ flex: "1 1 260px" }}>
          <Panel title="Scan Activity">
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text-3)" }}>Total scans</span>
                <span style={{ fontWeight: 600, color: "var(--text-0)" }}>{scans.total_scans ?? "\u2014"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text-3)" }}>Completed</span>
                <span style={{ fontWeight: 600, color: "var(--low, #2ecc71)" }}>{scans.completed ?? "\u2014"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text-3)" }}>Failed</span>
                <span style={{ fontWeight: 600, color: "var(--critical, #e74c3c)" }}>{scans.failed ?? "\u2014"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text-3)" }}>Last scan</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-2)" }}>{fmtDate(scans.last_scan_date)}</span>
              </div>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

// ======================================================================
// Tab 2: Vulnerability Trending
// ======================================================================
function TrendingTab() {
  const [days, setDays] = useState(30);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async (d) => {
    setLoading(true);
    setError("");
    try {
      const interval = d <= 7 ? "daily" : d <= 30 ? "daily" : "weekly";
      const r = await analyticsApi.trending(d, interval);
      setData(r);
    } catch (e) {
      setError(e.message || "Failed to load trending data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(days); }, [days, load]);

  const DAY_OPTIONS = [
    { label: "7d", value: 7 },
    { label: "30d", value: 30 },
    { label: "90d", value: 90 },
  ];

  return (
    <>
      <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        {DAY_OPTIONS.map(opt => (
          <button key={opt.value}
            className={days === opt.value ? "btn btn-primary" : "btn"}
            onClick={() => setDays(opt.value)}>
            {opt.label}
          </button>
        ))}
      </div>

      {loading && <Spinner/>}
      {error && <div className="alert alert-error">{error}</div>}

      {!loading && !error && data && (() => {
        const buckets = data.series || data.buckets || data.data || [];
        const mttr = data.mean_time_to_remediate_days ?? data.mttr;

        if (buckets.length === 0) return <EmptyState text="No trending data for this period"/>;

        const maxCount = Math.max(...buckets.map(b => b.total || b.count || 0), 1);

        return (
          <>
            {mttr != null && (
              <div style={{ marginBottom: 16 }}>
                <StatCard label="Mean Time to Remediate" value={typeof mttr === "number" ? `${mttr.toFixed(1)}d` : mttr}/>
              </div>
            )}

            <Panel title="Findings Over Time">
              <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 200, padding: "0 4px", overflowX: "auto" }}>
                {buckets.map((b, i) => {
                  const count = b.total || b.count || 0;
                  const barH = Math.max(4, (count / maxCount) * 180);
                  // Severity counts are directly on the bucket object
                  const segments = ["critical", "high", "medium", "low", "info"]
                    .filter(s => b[s])
                    .map(s => ({ sev: s, val: b[s] }));
                  if (segments.length === 0) segments.push({ sev: "info", val: count });
                  const segTotal = segments.reduce((a, s) => a + s.val, 0) || 1;

                  const tooltipLines = segments.map(s => `${s.sev}: ${s.val}`).join(", ");
                  const tooltipText = `${b.date || b.period || ""}\nTotal: ${count}\n${tooltipLines}`;

                  return (
                    <div key={i} style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: "1 1 0", minWidth: 32 }}>
                      {/* Total count above bar */}
                      <div style={{ fontSize: 10, fontWeight: 600, color: "var(--text-2)", marginBottom: 3, fontFamily: "var(--font-mono)" }}>
                        {count}
                      </div>
                      <div style={{ width: "100%", maxWidth: 44, height: barH, display: "flex", flexDirection: "column", borderRadius: "3px 3px 0 0", overflow: "hidden", cursor: "default" }}
                           title={tooltipText}>
                        {segments.map((seg, si) => (
                          <div key={si} style={{
                            flex: `${seg.val / segTotal}`,
                            background: SEV_COLORS[seg.sev] || "var(--brand)",
                            position: "relative",
                            display: "flex", alignItems: "center", justifyContent: "center",
                            minHeight: seg.val / segTotal > 0.15 ? 16 : 0,
                          }}>
                            {/* Show count inside segment if tall enough */}
                            {(seg.val / segTotal > 0.15 && seg.val > 0) && (
                              <span style={{ fontSize: 9, fontWeight: 700, color: "#fff", textShadow: "0 0 2px rgba(0,0,0,0.5)" }}>
                                {seg.val}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                      <div style={{ fontSize: 9, color: "var(--text-3)", marginTop: 4, textAlign: "center", width: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {(b.date || b.period || "").slice(-5)}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Legend with totals */}
              {(() => {
                const totals = {};
                buckets.forEach(b => {
                  ["critical","high","medium","low","info"].forEach(s => { totals[s] = (totals[s]||0) + (b[s]||0); });
                });
                return (
                  <div style={{ display: "flex", gap: 16, marginTop: 14, flexWrap: "wrap" }}>
                    {["critical", "high", "medium", "low", "info"].map(s => (
                      <div key={s} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 12 }}>
                        <span style={{ width: 10, height: 10, borderRadius: 2, background: SEV_COLORS[s], display: "inline-block" }}/>
                        <span style={{ color: "var(--text-2)", textTransform: "capitalize" }}>{s}</span>
                        <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "var(--text-1)" }}>{totals[s] || 0}</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </Panel>
          </>
        );
      })()}
    </>
  );
}

// ======================================================================
// Tab 3: Scan Comparison
// ======================================================================
function CompareTab() {
  const [jobs, setJobs] = useState([]);
  const [jobA, setJobA] = useState("");
  const [jobB, setJobB] = useState("");
  const [loading, setLoading] = useState(false);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  useEffect(() => {
    let cancelled = false;
    scanApi.listJobs()
      .then(r => { if (!cancelled) setJobs(Array.isArray(r) ? r : []); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setJobsLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const runCompare = async () => {
    if (!jobA || !jobB) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const [diff, compare] = await Promise.all([
        analyticsApi.diff(jobA, jobB),
        analyticsApi.compare(jobA, jobB),
      ]);
      setResult({ diff, compare });
    } catch (e) {
      setError(e.message || "Comparison failed");
    } finally {
      setLoading(false);
    }
  };

  const completedJobs = jobs.filter(j => j.status === "done" || j.status === "completed");

  return (
    <>
      <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 20 }}>
        <div style={{ flex: "1 1 200px" }}>
          <label className="form-label">Job A (baseline)</label>
          {jobsLoading ? <Spinner/> : (
            <select className="form-input" value={jobA} onChange={e => setJobA(e.target.value)}>
              <option value="">Select a job...</option>
              {completedJobs.map(j => (
                <option key={j.id} value={j.id}>#{j.id} - {j.target || j.targets?.join(", ") || "unknown"}</option>
              ))}
            </select>
          )}
        </div>
        <div style={{ flex: "1 1 200px" }}>
          <label className="form-label">Job B (current)</label>
          {jobsLoading ? <Spinner/> : (
            <select className="form-input" value={jobB} onChange={e => setJobB(e.target.value)}>
              <option value="">Select a job...</option>
              {completedJobs.map(j => (
                <option key={j.id} value={j.id}>#{j.id} - {j.target || j.targets?.join(", ") || "unknown"}</option>
              ))}
            </select>
          )}
        </div>
        <button className="btn btn-primary" onClick={runCompare} disabled={!jobA || !jobB || loading}>
          {loading ? "Comparing..." : "Compare"}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {result && (() => {
        const diff = result.diff || {};
        const compare = result.compare || {};
        const summary = compare.summary || diff.summary || {};
        const newFindings = diff.new || compare.new || [];
        const fixedFindings = diff.fixed || compare.fixed || [];
        const changedFindings = diff.changed_severity || diff.changed || [];

        return (
          <>
            {/* Summary cards */}
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
              <StatCard label="Improvement" value={summary.improvement_pct != null ? `${Number(summary.improvement_pct).toFixed(1)}%` : "\u2014"}/>
              <StatCard label="New Findings" value={newFindings.length}/>
              <StatCard label="Fixed Findings" value={fixedFindings.length}/>
            </div>

            {/* New findings */}
            <Collapsible title={`New Findings (${newFindings.length})`} color="var(--critical, #e74c3c)" defaultOpen={newFindings.length > 0}>
              {newFindings.length === 0
                ? <span style={{ fontSize: 13, color: "var(--text-3)" }}>No new findings</span>
                : newFindings.map((f, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                      <SevBadge sev={f.severity}/>
                      <span style={{ flex: 1, fontSize: 13, color: "var(--text-1)" }}>{f.title || f.name || "\u2014"}</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-3)" }}>{f.fingerprint || ""}</span>
                    </div>
                  ))
              }
            </Collapsible>

            {/* Fixed findings */}
            <Collapsible title={`Fixed Findings (${fixedFindings.length})`} color="var(--low, #2ecc71)" defaultOpen={fixedFindings.length > 0}>
              {fixedFindings.length === 0
                ? <span style={{ fontSize: 13, color: "var(--text-3)" }}>No fixed findings</span>
                : fixedFindings.map((f, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                      <SevBadge sev={f.severity}/>
                      <span style={{ flex: 1, fontSize: 13, color: "var(--text-1)" }}>{f.title || f.name || "\u2014"}</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-3)" }}>{f.fingerprint || ""}</span>
                    </div>
                  ))
              }
            </Collapsible>

            {/* Changed severity */}
            <Collapsible title={`Changed Severity (${changedFindings.length})`} color="var(--medium, #f1c40f)">
              {changedFindings.length === 0
                ? <span style={{ fontSize: 13, color: "var(--text-3)" }}>No severity changes</span>
                : changedFindings.map((f, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                      <SevBadge sev={f.severity || f.new_severity}/>
                      <span style={{ flex: 1, fontSize: 13, color: "var(--text-1)" }}>{f.title || f.name || "\u2014"}</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-3)" }}>{f.fingerprint || ""}</span>
                    </div>
                  ))
              }
            </Collapsible>
          </>
        );
      })()}
    </>
  );
}

// ======================================================================
// Tab 4: Asset Discovery
// ======================================================================
// Register discovered hosts as assets: one asset per host, its IP registered
// as the target. Name is pre-filled with the reverse DNS name (or the IP) and
// stays editable; folder and credential are optional.
function AddHostsModal({ hosts, close, onDone }) {
  const [rows, setRows] = useState(() => hosts.map(h => ({
    ip: h.ip,
    name: h.hostname || h.ip,
    parent_id: "",
    credential_id: "",
  })));
  const [folders, setFolders] = useState([]);
  const [creds, setCreds] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  // Inline creation: null = closed, otherwise the form's draft values.
  const [newFolder, setNewFolder] = useState(null);
  const [newCred, setNewCred] = useState(null);
  const [creating, setCreating] = useState(false);

  const createFolder = async () => {
    if (!newFolder.name.trim()) return;
    setCreating(true);
    setError("");
    try {
      const folder = await assetsApi.create({ name: newFolder.name.trim() });
      setFolders(fs => [...fs, folder]);
      setNewFolder(null);
    } catch (err) {
      setError(err.message || "Could not create the folder");
    } finally {
      setCreating(false);
    }
  };

  const createCred = async () => {
    const { name, username, secret_type, secret, passphrase } = newCred;
    if (!name.trim() || !username.trim() || !secret.trim()) {
      setError("Credential needs a name, a username and a secret");
      return;
    }
    setCreating(true);
    setError("");
    try {
      const body = {
        name: name.trim(),
        kind: "ssh",
        username: username.trim(),
        secret_type,
        secret,
        passphrase: passphrase || null,
      };
      const { id } = await credentialsApi.create(body);
      setCreds(cs => [...cs, { id, name: body.name, kind: body.kind, username: body.username, secret_type }]);
      setNewCred(null);
    } catch (err) {
      setError(err.message || "Could not create the credential");
    } finally {
      setCreating(false);
    }
  };

  useEffect(() => {
    Promise.all([assetsApi.list(), credentialsApi.list()])
      .then(([a, c]) => { setFolders(a); setCreds(c); })
      .catch(e => setError(e.message || "Could not load folders and credentials"));
  }, []);

  const update = (i, field, value) =>
    setRows(rs => rs.map((r, j) => (j === i ? { ...r, [field]: value } : r)));

  const submit = async (e) => {
    e.preventDefault();
    // Enter inside an inline folder/credential form must not create the assets.
    if (newFolder || newCred) return;
    setSubmitting(true);
    setError("");
    try {
      await assetsApi.createFromHosts({
        assets: rows.map(r => ({
          name: r.name.trim(),
          target: r.ip,
          parent_id: r.parent_id ? parseInt(r.parent_id, 10) : null,
          default_credential_id: r.credential_id ? parseInt(r.credential_id, 10) : null,
        })),
      });
      onDone(rows.length);
    } catch (err) {
      setError(err.message || "Could not create the assets");
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={submitting ? undefined : close}/>
      <div className="modal" style={{ maxWidth: 760, width: "calc(100vw - 32px)" }}>
        <div className="drawer-head">
          <Icons.FolderOpen size={16} color="var(--brand)"/>
          <span style={{ fontSize: 14, fontWeight: 600, color: "var(--text-0)" }}>
            Add {rows.length} host{rows.length > 1 ? "s" : ""} to assets
          </span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} disabled={submitting}
            style={{ marginLeft: "auto" }}><Icons.X size={14}/></button>
        </div>
        <form onSubmit={submit} style={{ padding: "16px 24px 20px", display: "flex", flexDirection: "column", gap: 12, maxHeight: "70vh", overflowY: "auto" }}>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button type="button" className="btn" disabled={submitting || !!newFolder}
              onClick={() => setNewFolder({ name: "" })}>
              <Icons.Plus size={12}/> New folder
            </button>
            <button type="button" className="btn" disabled={submitting || !!newCred}
              onClick={() => setNewCred({ name: "", username: "", secret_type: "password", secret: "", passphrase: "" })}>
              <Icons.Plus size={12}/> New credential
            </button>
          </div>

          {newFolder && (
            <div style={{ display: "flex", gap: 8, alignItems: "flex-end", padding: 12, background: "var(--surface-1)", borderRadius: 6 }}>
              <div style={{ flex: 1 }}>
                <label className="form-label">New folder name</label>
                <input className="form-input" autoFocus value={newFolder.name}
                  onChange={e => setNewFolder({ name: e.target.value })}
                  placeholder="e.g. Lab · Printers"/>
              </div>
              <button type="button" className="btn" disabled={creating} onClick={() => setNewFolder(null)}>Cancel</button>
              <button type="button" className="btn btn-primary" disabled={creating || !newFolder.name.trim()} onClick={createFolder}>
                {creating ? "Creating…" : "Create folder"}
              </button>
            </div>
          )}

          {newCred && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: 12, background: "var(--surface-1)", borderRadius: 6 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div>
                  <label className="form-label">Name</label>
                  <input className="form-input" autoFocus value={newCred.name}
                    onChange={e => setNewCred({ ...newCred, name: e.target.value })} placeholder="e.g. lab-root"/>
                </div>
                <div>
                  <label className="form-label">Username</label>
                  <input className="form-input" value={newCred.username}
                    onChange={e => setNewCred({ ...newCred, username: e.target.value })} placeholder="root"/>
                </div>
                <div>
                  <label className="form-label">Secret type</label>
                  <select className="form-input" value={newCred.secret_type}
                    onChange={e => setNewCred({ ...newCred, secret_type: e.target.value })}>
                    <option value="password">Password</option>
                    <option value="SSH_KEY">SSH private key</option>
                  </select>
                </div>
                <div>
                  <label className="form-label">Passphrase (optional)</label>
                  <input className="form-input" type="password" value={newCred.passphrase}
                    onChange={e => setNewCred({ ...newCred, passphrase: e.target.value })}/>
                </div>
              </div>
              <div>
                <label className="form-label">{newCred.secret_type === "SSH_KEY" ? "Private key" : "Password"}</label>
                {newCred.secret_type === "SSH_KEY" ? (
                  <textarea className="form-input" rows={4} value={newCred.secret}
                    onChange={e => setNewCred({ ...newCred, secret: e.target.value })}
                    style={{ height: "auto", padding: "8px 12px", fontFamily: "var(--font-mono)" }}/>
                ) : (
                  <input className="form-input" type="password" value={newCred.secret}
                    onChange={e => setNewCred({ ...newCred, secret: e.target.value })}/>
                )}
              </div>
              <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                <button type="button" className="btn" disabled={creating} onClick={() => setNewCred(null)}>Cancel</button>
                <button type="button" className="btn btn-primary" disabled={creating} onClick={createCred}>
                  {creating ? "Creating…" : "Create credential"}
                </button>
              </div>
            </div>
          )}

          {rows.map((r, i) => (
            <div key={r.ip} style={{
              display: "grid", gridTemplateColumns: "minmax(0,1.4fr) minmax(0,1fr) minmax(0,1fr)", gap: 10,
              alignItems: "end", paddingBottom: 12, borderBottom: "1px solid var(--line)",
            }}>
              <div>
                <label className="form-label">Name <span className="mono muted">({r.ip})</span></label>
                <input className="form-input" value={r.name} required
                  onChange={e => update(i, "name", e.target.value)}/>
              </div>
              <div>
                <label className="form-label">Folder (optional)</label>
                <select className="form-input" value={r.parent_id} onChange={e => update(i, "parent_id", e.target.value)}>
                  <option value="">No folder</option>
                  {folders.filter(f => !f.parent_id).map(f => (
                    <option key={f.id} value={f.id}>{f.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="form-label">Credential (optional)</label>
                <select className="form-input" value={r.credential_id} onChange={e => update(i, "credential_id", e.target.value)}>
                  <option value="">No credential</option>
                  {creds.map(c => (
                    <option key={c.id} value={c.id}>{c.name} ({c.username})</option>
                  ))}
                </select>
              </div>
            </div>
          ))}
          {error && <div style={{ color: "var(--err)", fontSize: 12.5 }}>{error}</div>}
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button type="button" className="btn" onClick={close} disabled={submitting}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={submitting || rows.length === 0}>
              {submitting ? "Creating…" : <><Icons.Check size={12}/> Create {rows.length} asset{rows.length > 1 ? "s" : ""}</>}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

function DiscoverTab() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [results, setResults] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [showAdd, setShowAdd] = useState(false);
  const [addedCount, setAddedCount] = useState(0);

  const run = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError("");
    setResults(null);
    setSelected(new Set());
    setAddedCount(0);
    try {
      // Detect if input is CIDR (contains /) or domain
      const val = input.trim();
      const body = val.includes("/") ? { network_range: val } : { domain: val };
      const r = await analyticsApi.discover(body);
      setResults(r);
    } catch (e) {
      setError(e.message || "Discovery failed");
    } finally {
      setLoading(false);
    }
  };

  // Domain response has 'discovered' array, CIDR response has network metadata
  const targets = results?.discovered || results?.targets || results?.hosts || [];
  const isCidr = results?.type === "network";

  const toggleOne = ip => setSelected(prev => {
    const next = new Set(prev);
    if (next.has(ip)) next.delete(ip); else next.add(ip);
    return next;
  });
  // Hosts already on an asset are shown but cannot be added twice.
  const newHosts = targets.filter(h => !h.asset_id);
  const allNewSelected = newHosts.length > 0 && newHosts.every(h => selected.has(h.ip));
  const toggleAll = () => setSelected(
    allNewSelected ? new Set() : new Set(newHosts.map(h => h.ip))
  );

  return (
    <>
      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", marginBottom: 20, flexWrap: "wrap" }}>
        <div style={{ flex: "1 1 300px" }}>
          <label className="form-label">Domain or CIDR range</label>
          <input className="form-input"
            placeholder="e.g. example.com or 192.168.1.0/24"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") run(); }}
          />
        </div>
        <button className="btn btn-primary" onClick={run} disabled={!input.trim() || loading}>
          {loading ? "Discovering..." : "Discover"}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {loading && <Spinner/>}

      {!loading && results && (
        <Panel title={isCidr ? `Network: ${results.network_range}` : `Discovered Targets (${targets.length})`}>
          {isCidr ? (
            <>
              <div style={{ display: "flex", gap: 18, flexWrap: "wrap", fontSize: 13, color: "var(--text-2)", marginBottom: 14 }}>
                <span>Range <strong style={{ color: "var(--text-0)" }}>{results.network_range}</strong></span>
                <span>Addresses <strong style={{ color: "var(--text-0)" }}>{results.num_addresses}</strong></span>
                <span>Hosts found <strong style={{ color: "var(--text-0)" }}>{targets.length}</strong></span>
              </div>
              {targets.length === 0 ? <EmptyState text="No live host found on this network"/> : (
                <>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, gap: 10, flexWrap: "wrap" }}>
                    <label style={{ fontSize: 13, display: "flex", gap: 8, alignItems: "center", color: "var(--text-1)", cursor: "pointer" }}>
                      <input type="checkbox" checked={allNewSelected} disabled={newHosts.length === 0} onChange={toggleAll}/>
                      Select all
                    </label>
                    <button className="btn btn-primary" disabled={selected.size === 0} onClick={() => setShowAdd(true)}>
                      <Icons.Plus size={14}/> Add {selected.size} to assets
                    </button>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {targets.map(h => (
                      <label key={h.ip} style={{
                        padding: "8px 12px", background: "var(--surface-1)", borderRadius: 6,
                        display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap",
                        cursor: h.asset_id ? "default" : "pointer",
                        fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-1)",
                      }}>
                        <input type="checkbox" checked={!h.asset_id && selected.has(h.ip)}
                          disabled={!!h.asset_id} onChange={() => toggleOne(h.ip)}/>
                        <span style={{ minWidth: 130 }}>{h.ip}</span>
                        <span style={{ color: h.hostname ? "var(--text-1)" : "var(--text-3)" }}>
                          {h.hostname || "no reverse DNS name"}
                        </span>
                        {h.asset_id && (
                          <span style={{
                            marginLeft: "auto", fontFamily: "var(--font-sans, inherit)", fontSize: 12,
                            color: "var(--ok)", background: "var(--ok-soft)", border: "1px solid var(--ok-line)",
                            borderRadius: 999, padding: "2px 10px",
                          }}>
                            Déjà présent dans les assets · {h.asset_name}
                          </span>
                        )}
                      </label>
                    ))}
                  </div>
                </>
              )}
              {addedCount > 0 && (
                <div style={{ marginTop: 12, fontSize: 13, color: "var(--text-1)" }}>
                  {addedCount} asset(s) created. They are listed in Assets.
                </div>
              )}
              {showAdd && (
                <AddHostsModal
                  hosts={targets.filter(h => selected.has(h.ip))}
                  close={() => setShowAdd(false)}
                  onDone={n => { setShowAdd(false); setSelected(new Set()); setAddedCount(n); }}
                />
              )}
            </>
          ) : targets.length === 0
            ? <EmptyState text="No targets discovered"/>
            : (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {targets.map((t, i) => {
                  const label = typeof t === "string" ? t
                    : t.hostname ? `${t.hostname}${t.ips?.length ? " → " + t.ips.join(", ") : ""}`
                    : (t.host || t.ip || t.target || JSON.stringify(t));
                  return (
                    <div key={i} style={{
                      padding: "8px 12px", background: "var(--surface-1)", borderRadius: 6,
                      fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-1)",
                    }}>
                      {label}
                    </div>
                  );
                })}
              </div>
            )
          }
        </Panel>
      )}
    </>
  );
}

// ======================================================================
// Tab 5: Re-verification
// ======================================================================
function ReverifyTab() {
  const [jobs, setJobs] = useState([]);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [selectedJob, setSelectedJob] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [newJobId, setNewJobId] = useState(null);

  useEffect(() => {
    let cancelled = false;
    scanApi.listJobs()
      .then(r => { if (!cancelled) setJobs(Array.isArray(r) ? r : []); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setJobsLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const run = async () => {
    if (!selectedJob) return;
    setLoading(true);
    setError("");
    setNewJobId(null);
    try {
      const r = await analyticsApi.reverify(selectedJob);
      setNewJobId(r.job_id || r.id || r.new_job_id || JSON.stringify(r));
    } catch (e) {
      setError(e.message || "Re-verification failed");
    } finally {
      setLoading(false);
    }
  };

  const completedJobs = jobs.filter(j => j.status === "done" || j.status === "completed");

  return (
    <>
      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", marginBottom: 20, flexWrap: "wrap" }}>
        <div style={{ flex: "1 1 300px" }}>
          <label className="form-label">Completed scan job</label>
          {jobsLoading ? <Spinner/> : (
            <select className="form-input" value={selectedJob} onChange={e => setSelectedJob(e.target.value)}>
              <option value="">Select a completed job...</option>
              {completedJobs.map(j => (
                <option key={j.id} value={j.id}>#{j.id} - {j.target || j.targets?.join(", ") || "unknown"}</option>
              ))}
            </select>
          )}
        </div>
        <button className="btn btn-primary" onClick={run} disabled={!selectedJob || loading}>
          {loading ? "Re-verifying..." : "Re-verify Findings"}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {newJobId && (
        <div className="alert alert-success" style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Icons.Check size={16}/>
          Re-verification job created: <strong style={{ fontFamily: "var(--font-mono)" }}>#{newJobId}</strong>
        </div>
      )}
    </>
  );
}

// ======================================================================
// Main Analytics component
// ======================================================================
const TABS = [
  { id: "executive",  label: "Executive Dashboard" },
  { id: "trending",   label: "Vulnerability Trending" },
  { id: "compare",    label: "Scan Comparison" },
  { id: "discover",   label: "Asset Discovery" },
  { id: "reverify",   label: "Re-verification" },
];

export function Analytics() {
  const [activeTab, setActiveTab] = useState("executive");

  return (
    <div>
      <Tabs tabs={TABS} active={activeTab} onChange={setActiveTab}/>

      {activeTab === "executive" && <ExecutiveTab/>}
      {activeTab === "trending"  && <TrendingTab/>}
      {activeTab === "compare"   && <CompareTab/>}
      {activeTab === "discover"  && <DiscoverTab/>}
      {activeTab === "reverify"  && <ReverifyTab/>}
    </div>
  );
}
