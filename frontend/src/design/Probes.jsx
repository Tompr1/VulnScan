import React, { useCallback, useEffect, useState } from "react";
import { Icons } from "./icons.jsx";
import { probesApi } from "../api.js";
import { Modal, useSubmit } from "./Access.jsx";
import {
  SCAN_TYPE_LABELS, applianceHostname, clientsWithoutProbe, cloudInitUserData, enrollCommand, eventLabel, imageStatus,
  isAlarmEvent, probeStatus, seenText, shortImage, toggledScanTypes,
} from "./probesModel.js";

// Root > Scan probes: the VMs installed on clients' networks. A probe only
// connects out to the platform; it takes the client's scans routed to it.

export function Probes() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [modal, setModal] = useState(null); // {kind: "create"} | {kind: "token", probe, enrollment} | {kind: "revoke"|"delete", probe}
  const [savingClient, setSavingClient] = useState(null);

  const refresh = useCallback(async () => {
    try { setData(await probesApi.list()); setError(""); }
    catch (e) { setError(e.message); }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 15000); // online / offline and running scans move
    return () => clearInterval(t);
  }, [refresh]);

  const setScanType = async (client, scanType, on) => {
    setSavingClient(client.id);
    try {
      await probesApi.setExecution(client.id, toggledScanTypes(client.probe_scan_types, scanType, on, data.delegable_scan_types));
      await refresh();
    } catch (e) { setError(e.message); }
    finally { setSavingClient(null); }
  };

  const renew = async (probe) => {
    try { setModal({ kind: "token", probe, enrollment: await probesApi.renew(probe.id) }); await refresh(); }
    catch (e) { setError(e.message); }
  };

  const probes = data?.probes || [];
  const clients = data?.clients || [];
  const orphans = clientsWithoutProbe(clients, probes);

  return (
    <>
      <div className="ph">
        <div>
          <h1>Scan probes</h1>
          <div className="sub">VMs on the clients' networks. They only connect out to the platform: the client opens no port.</div>
        </div>
        <div className="actions">
          <button className="btn btn-primary" onClick={() => setModal({ kind: "create" })} disabled={!clients.length}>
            <Icons.Plus size={13}/> New probe
          </button>
        </div>
      </div>
      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}
      {orphans.length > 0 && (
        <div className="card" style={{marginBottom: 16, borderColor: "var(--sev-high)"}}>
          <div className="card-body" style={{fontSize: 13, color: "var(--text-1)"}}>
            <Icons.AlertTriangle size={13} color="var(--sev-high)"/> Scans of {orphans.map(c => c.name).join(", ")} go to a probe, but no probe of
            this client is enrolled: they wait, then fail.
          </div>
        </div>
      )}

      <div className="card">
        <div className="toolbar">
          <div className="left"><span className="card-title">Probes</span></div>
          <div className="right muted" style={{fontSize: 12}} title="PROBE_IMAGE in the platform's .env">
            {data?.desired_image
              ? <>Image rolled out: <span className="mono">{data.desired_image.replace(/@sha256:([0-9a-f]{12})[0-9a-f]+$/, "@sha256:$1…")}</span></>
              : "Probes keep their image (no PROBE_IMAGE)"}
          </div>
        </div>
        <div className="card-body flush">
          {data === null ? <div className="empty">Loading…</div> : !probes.length ? (
            <div className="empty"><div className="empty-body" style={{margin: "0 auto"}}>No probe yet. Create one for a client, then enroll the VM with its token.</div></div>
          ) : (
            <table className="tbl">
              <thead><tr><th>Probe</th><th>Client</th><th>Status</th><th>Host</th><th>Versions</th><th>Last seen</th><th className="num">Scans</th><th style={{width: 150}}/></tr></thead>
              <tbody>
                {probes.map(p => {
                  const status = probeStatus(p.status);
                  const image = imageStatus(p.image_status);
                  return (
                    <tr key={p.id}>
                      <td style={{color: "var(--text-0)", fontWeight: 500}}>{p.name}</td>
                      <td>{p.client_name}</td>
                      <td>
                        <span className={`status ${status.pill}`}>{status.label}</span>
                        {p.offline_since && <div className="muted" style={{fontSize: 11}} title={p.offline_since}>client alerted {seenText(p.offline_since)}</div>}
                      </td>
                      <td className="muted" style={{fontSize: 12}}>
                        {p.hostname || "—"}
                        {p.last_seen_ip && p.last_seen_ip !== "unknown" ? <div className="mono" style={{fontSize: 11}}>{p.last_seen_ip}</div> : null}
                      </td>
                      <td className="muted" style={{fontSize: 12}}>
                        {p.version ? <span className="mono">agent v{p.version}</span> : "—"}
                        {p.appliance_version && <div className="mono" style={{fontSize: 11}}>appliance {p.appliance_version}</div>}
                        {p.image && <div className="mono" style={{fontSize: 11}} title={p.image}>{shortImage(p.image)}</div>}
                        {image.label && <span className={`status ${image.pill}`} style={{fontSize: 11}}>{image.label}</span>}
                      </td>
                      <td className="muted" style={{fontSize: 12}} title={p.last_seen_at || ""}>{seenText(p.last_seen_at)}</td>
                      <td className="num">{p.running_jobs}</td>
                      <td style={{whiteSpace: "nowrap", textAlign: "right"}}>
                        <button className="btn btn-ghost btn-icon btn-sm" title="History" aria-label="History"
                                onClick={() => setModal({ kind: "history", probe: p })}><Icons.Clock size={13}/></button>
                        {p.status !== "revoked" && (
                          <button className="btn btn-ghost btn-icon btn-sm" title="New enrollment token (reinstalled VM)" aria-label="New enrollment token"
                                  onClick={() => renew(p)}><Icons.Key size={13}/></button>
                        )}
                        {p.status !== "revoked" && (
                          <button className="btn btn-ghost btn-icon btn-sm" title="Revoke: the probe can no longer sign in" aria-label="Revoke"
                                  onClick={() => setModal({ kind: "revoke", probe: p })}><Icons.Lock size={13}/></button>
                        )}
                        <button className="btn btn-ghost btn-icon btn-sm" title="Delete" aria-label="Delete"
                                onClick={() => setModal({ kind: "delete", probe: p })}><Icons.Trash size={13}/></button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="card" style={{marginTop: 16}}>
        <div className="card-head">
          <div>
            <div className="card-title">Where each client's scans run</div>
            <div className="card-sub">Ticked scan types go to the client's probe; the others run on the platform. IaC and device inventory always run on the platform.</div>
          </div>
        </div>
        <div className="card-body flush">
          {data === null ? <div className="empty">Loading…</div> : (
            <table className="tbl">
              <thead><tr><th>Client</th>{(data.delegable_scan_types || []).map(t => <th key={t}>{SCAN_TYPE_LABELS[t] || t}</th>)}<th className="num">Waiting</th></tr></thead>
              <tbody>
                {clients.map(c => (
                  <tr key={c.id}>
                    <td style={{color: "var(--text-0)", fontWeight: 500}}>{c.name}</td>
                    {(data.delegable_scan_types || []).map(t => (
                      <td key={t}>
                        <label style={{display: "inline-flex", gap: 6, alignItems: "center", cursor: "pointer"}}>
                          <input type="checkbox" checked={(c.probe_scan_types || []).includes(t)} disabled={savingClient === c.id}
                                 onChange={e => setScanType(c, t, e.target.checked)} aria-label={`${SCAN_TYPE_LABELS[t] || t} scans of ${c.name} on its probe`}/>
                          <span className="muted" style={{fontSize: 12}}>{(c.probe_scan_types || []).includes(t) ? "probe" : "platform"}</span>
                        </label>
                      </td>
                    ))}
                    <td className="num">{c.waiting_jobs || <span style={{color: "var(--text-4)"}}>0</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {modal?.kind === "create" && (
        <CreateProbeModal clients={clients} close={() => setModal(null)}
                          onCreated={async (created) => { setModal({ kind: "token", probe: created, enrollment: created.enrollment }); await refresh(); }}/>
      )}
      {modal?.kind === "token" && <TokenModal probe={modal.probe} enrollment={modal.enrollment} close={() => setModal(null)}/>}
      {modal?.kind === "history" && <HistoryModal probe={modal.probe} close={() => setModal(null)}/>}
      {modal?.kind === "revoke" && (
        <ConfirmModal title={`Revoke ${modal.probe.name}`} danger submitLabel="Revoke" close={() => setModal(null)}
                      action={() => probesApi.revoke(modal.probe.id)} onDone={async () => { setModal(null); await refresh(); }}>
          The probe stops at its next call and can no longer sign in. Its running scans fail. A revoked probe cannot be
          enrolled again: create a new one.
        </ConfirmModal>
      )}
      {modal?.kind === "delete" && (
        <ConfirmModal title={`Delete ${modal.probe.name}`} danger submitLabel="Delete" close={() => setModal(null)}
                      action={() => probesApi.remove(modal.probe.id)} onDone={async () => { setModal(null); await refresh(); }}>
          The probe is removed; the scans it ran stay in the client's history.
        </ConfirmModal>
      )}
    </>
  );
}

function CreateProbeModal({ clients, close, onCreated }) {
  const [clientId, setClientId] = useState(clients[0]?.id || "");
  const [name, setName] = useState("");
  const [created, setCreated] = useState(null);
  const { submit, submitting, error } = useSubmit(
    async () => setCreated(await probesApi.create({ workspace_id: Number(clientId), name: name.trim() })),
    async () => {},
  );
  useEffect(() => { if (created) onCreated(created); }, [created, onCreated]);
  return (
    <Modal title="New probe" icon={Icons.Chip} close={close} onSubmit={submit} submitting={submitting} error={error}
           submitLabel="Create" canSubmit={!!clientId && !!name.trim()}>
      <div>
        <label className="form-label">Client</label>
        <select className="form-input" value={clientId} onChange={e => setClientId(e.target.value)}>
          {clients.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>
      <div>
        <label className="form-label">Name</label>
        <input className="form-input" required value={name} onChange={e => setName(e.target.value)} placeholder="Paris HQ" autoFocus maxLength={255}/>
        <div className="form-help">Where the VM is installed. The enrollment token is shown next.</div>
      </div>
    </Modal>
  );
}

function TokenModal({ probe, enrollment, close }) {
  const [copied, setCopied] = useState(false);
  const [localAllowlist, setLocalAllowlist] = useState("");
  const [caPem, setCaPem] = useState("");
  const [seedError, setSeedError] = useState("");
  const platformUrl = window.location.origin;
  const command = enrollCommand(platformUrl, enrollment.token);
  const copy = async () => {
    try { await navigator.clipboard.writeText(command); setCopied(true); } catch { setCopied(false); }
  };
  const downloadSeed = () => {
    try {
      const userData = cloudInitUserData({
        platformUrl, token: enrollment.token, probeName: probe.name, localAllowlist, caPem,
        allowHttp: platformUrl.startsWith("http://"),
      });
      const url = URL.createObjectURL(new Blob([userData], { type: "text/cloud-config" }));
      const link = Object.assign(document.createElement("a"), { href: url, download: `${applianceHostname(probe.name)}.user-data` });
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setSeedError("");
    } catch (e) { setSeedError(e.message); }
  };
  const codeStyle = {whiteSpace: "pre-wrap", wordBreak: "break-all", background: "var(--surface-1)", border: "1px solid var(--line)",
                     borderRadius: 6, padding: 12, fontSize: 12, margin: 0};
  return (
    <Modal title={`Enroll ${probe.name}`} icon={Icons.Key} close={close} onSubmit={(e) => { e.preventDefault(); close(); }}
           submitLabel="Done" width={600}>
      <div style={{fontSize: 13, color: "var(--text-1)"}}>
        The token works <b>once</b> and expires
        {enrollment.expires_at ? ` on ${new Date(enrollment.expires_at).toLocaleString()}` : " soon"}. It is shown only now.
      </div>

      <div>
        <div className="card-title" style={{fontSize: 13}}>Appliance (VM image)</div>
        <div className="form-help" style={{marginBottom: 8}}>
          Its first-boot configuration (cloud-init): give it to the VM as its user-data, or as a seed ISO
          (<span className="mono">deploy/appliance/tools/make-seed-iso.sh</span>). The VM enrolls and starts by itself.
        </div>
        <label className="form-label">Client's own scope limit (optional)</label>
        <input className="form-input mono" value={localAllowlist} onChange={e => setLocalAllowlist(e.target.value)}
               placeholder="10.0.0.0/8,.corp.local"/>
        <label className="form-label" style={{marginTop: 8}}>Platform CA certificate (optional, for Caddy's internal CA)</label>
        <textarea className="form-input mono" rows={3} value={caPem} onChange={e => setCaPem(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----" style={{fontSize: 11}}/>
        {seedError && <div style={{color: "var(--err)", fontSize: 12.5, marginTop: 6}}><Icons.AlertTriangle size={12}/> {seedError}</div>}
        <div style={{marginTop: 8}}>
          <button type="button" className="btn btn-sm" onClick={downloadSeed}><Icons.Download size={12}/> Download first-boot configuration</button>
        </div>
      </div>

      <div>
        <div className="card-title" style={{fontSize: 13}}>Docker on an existing VM</div>
        <div className="form-help" style={{marginBottom: 8}}>
          In <span className="mono">deploy/probe</span> (see its README), run:
        </div>
        <pre className="mono" style={codeStyle}>{command}</pre>
        <div style={{marginTop: 8}}>
          <button type="button" className="btn btn-sm" onClick={copy}>
            {copied ? <><Icons.Check size={12}/> Copied</> : <><Icons.Copy size={12}/> Copy</>}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function HistoryModal({ probe, close }) {
  const [events, setEvents] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    probesApi.events(probe.id).then(setEvents).catch(e => { setError(e.message); setEvents([]); });
  }, [probe.id]);
  return (
    <Modal title={`History of ${probe.name}`} icon={Icons.Clock} close={close} onSubmit={(e) => { e.preventDefault(); close(); }}
           submitLabel="Close" width={640} error={error}>
      {events === null ? <div className="muted">Loading…</div> : !events.length ? <div className="muted">Nothing recorded yet.</div> : (
        <table className="tbl" style={{fontSize: 12}}>
          <thead><tr><th style={{width: 150}}>When</th><th style={{width: 160}}>Event</th><th>Detail</th></tr></thead>
          <tbody>
            {events.map(e => (
              <tr key={e.id}>
                <td className="muted" title={e.at}>{e.at ? new Date(e.at).toLocaleString() : ""}</td>
                <td style={{color: isAlarmEvent(e.kind) ? "var(--err)" : "var(--text-0)"}}>{eventLabel(e.kind)}</td>
                <td className="mono" style={{fontSize: 11, wordBreak: "break-all"}}>
                  {e.job_id ? <span>job #{e.job_id} · </span> : null}{e.detail}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}

function ConfirmModal({ title, danger, submitLabel, close, action, onDone, children }) {
  const { submit, submitting, error } = useSubmit(action, onDone);
  return (
    <Modal title={title} icon={Icons.AlertTriangle} danger={danger} close={close} onSubmit={submit}
           submitting={submitting} error={error} submitLabel={submitLabel}>
      <div style={{fontSize: 13, color: "var(--text-1)"}}>{children}</div>
    </Modal>
  );
}
