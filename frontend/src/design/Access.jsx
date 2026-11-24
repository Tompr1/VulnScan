import React, { useCallback, useEffect, useState } from "react";
import { Icons } from "./icons.jsx";
import { accessApi, getUser, refreshSession } from "../api.js";
import { ClientBadge } from "./ClientPicker.jsx";
import {
  ROLES, ROLE_HELP, describeSource, grantsOf, namesOf, principalLabel, scopeLabel, toggleId,
} from "./accessModel.js";

// Access administration of the MSP (global admins): who opens which client,
// with which role — users and user groups, clients and client groups, and the
// grants tying them. "Why?" on a user explains its access client by client.

const TABS = [
  ["users", "Users"],
  ["user-groups", "User groups"],
  ["clients", "Clients"],
  ["client-groups", "Client groups"],
  ["grants", "Grants"],
];

export function Access() {
  const [tab, setTab] = useState("users");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [modal, setModal] = useState(null); // {kind, ...}
  const [explained, setExplained] = useState(null); // user id

  const refresh = useCallback(async () => {
    try {
      const [users, userGroups, clients, clientGroups, grants] = await Promise.all([
        accessApi.users(), accessApi.userGroups(), accessApi.clients(), accessApi.clientGroups(), accessApi.grants(),
      ]);
      setData({ users, userGroups, clients, clientGroups, grants });
      setError("");
    } catch (e) { setError(e.message); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Clients changed: the top bar's client list and the open client follow.
  const afterClientChange = async () => { await refresh(); await refreshSession(); };

  const run = async (action, after = refresh) => {
    try { await action(); await after(); }
    catch (e) { alert(e.message); }
  };

  const close = () => setModal(null);
  const saved = (after = refresh) => async () => { setModal(null); await after(); };

  if (!data) {
    return (
      <>
        <AccessHeader/>
        {error
          ? <div style={{color: "var(--err)", fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>
          : <div className="empty">Loading…</div>}
      </>
    );
  }

  const counts = {
    users: data.users.length, "user-groups": data.userGroups.length, clients: data.clients.length,
    "client-groups": data.clientGroups.length, grants: data.grants.length,
  };

  return (
    <>
      <AccessHeader/>
      {error && <div style={{color: "var(--err)", marginBottom: 14, fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}

      <div className="card">
        <div className="toolbar">
          <div className="tabs">
            {TABS.map(([key, label]) => (
              <button key={key} className={`tab ${tab === key ? "active" : ""}`} onClick={() => setTab(key)}>
                {label} <span className="badge">{counts[key]}</span>
              </button>
            ))}
          </div>
          <div className="right">
            {tab === "users" && <button className="btn btn-primary btn-sm" onClick={() => setModal({ kind: "user" })}><Icons.Plus size={11}/> Add user</button>}
            {tab === "user-groups" && <button className="btn btn-primary btn-sm" onClick={() => setModal({ kind: "user-group" })}><Icons.Plus size={11}/> New user group</button>}
            {tab === "clients" && <button className="btn btn-primary btn-sm" onClick={() => setModal({ kind: "client" })}><Icons.Plus size={11}/> New client</button>}
            {tab === "client-groups" && <button className="btn btn-primary btn-sm" onClick={() => setModal({ kind: "client-group" })}><Icons.Plus size={11}/> New client group</button>}
            {tab === "grants" && <button className="btn btn-primary btn-sm" onClick={() => setModal({ kind: "grant" })}><Icons.Plus size={11}/> Grant access</button>}
          </div>
        </div>

        <div className="card-body flush">
          {tab === "users" && (
            <UsersTable data={data} onExplain={setExplained}
                        onToggleGlobal={(u) => run(() => accessApi.updateUser(u.id, { is_global_admin: !u.is_global_admin }))}
                        onPassword={(u) => setModal({ kind: "password", user: u })}
                        onDelete={(u) => confirm(`Delete the account ${u.email}? Its grants go with it.`) && run(() => accessApi.deleteUser(u.id))}/>
          )}
          {tab === "user-groups" && (
            <GroupsTable rows={data.userGroups} memberKey="user_ids" members={data.users} memberLabel="email"
                         grantCount={(g) => grantsOf(data.grants, { userGroupId: g.id }).length}
                         empty="No user group yet. A group gives the same access to a whole team."
                         onEdit={(g) => setModal({ kind: "user-group", group: g })}
                         onDelete={(g) => confirm(`Delete the group ${g.name}? Its members stay; the grants given to the group go.`) && run(() => accessApi.deleteUserGroup(g.id))}/>
          )}
          {tab === "clients" && (
            <ClientsTable data={data}
                          onRename={(c) => setModal({ kind: "client", client: c })}
                          onDelete={(c) => confirm(`Delete the client ${c.name}? Only a client without data can be deleted.`) && run(() => accessApi.deleteClient(c.id), afterClientChange)}/>
          )}
          {tab === "client-groups" && (
            <GroupsTable rows={data.clientGroups} memberKey="client_ids" members={data.clients} memberLabel="name"
                         grantCount={(g) => grantsOf(data.grants, { clientGroupId: g.id }).length}
                         empty="No client group yet. A group opens several clients with one grant (a region, a sector…)."
                         onEdit={(g) => setModal({ kind: "client-group", group: g })}
                         onDelete={(g) => confirm(`Delete the client group ${g.name}? Its clients stay; the grants given on the group go.`) && run(() => accessApi.deleteClientGroup(g.id))}/>
          )}
          {tab === "grants" && (
            <GrantsTable grants={data.grants}
                         onRole={(g, role) => run(() => accessApi.updateGrant(g.id, { role }))}
                         onDelete={(g) => confirm(`Remove ${principalLabel(g)}'s access to ${scopeLabel(g)}?`) && run(() => accessApi.deleteGrant(g.id))}/>
          )}
        </div>
      </div>

      {modal?.kind === "user" && <UserModal close={close} onSaved={saved()}/>}
      {modal?.kind === "password" && <PasswordModal user={modal.user} close={close} onSaved={saved()}/>}
      {modal?.kind === "client" && <ClientModal client={modal.client} close={close} onSaved={saved(afterClientChange)}/>}
      {modal?.kind === "user-group" && (
        <GroupModal title="user group" group={modal.group} memberKey="user_ids" members={data.users} memberLabel="email"
                    save={(body) => modal.group ? accessApi.updateUserGroup(modal.group.id, body) : accessApi.createUserGroup(body)}
                    close={close} onSaved={saved()}/>
      )}
      {modal?.kind === "client-group" && (
        <GroupModal title="client group" group={modal.group} memberKey="client_ids" members={data.clients} memberLabel="name"
                    save={(body) => modal.group ? accessApi.updateClientGroup(modal.group.id, body) : accessApi.createClientGroup(body)}
                    close={close} onSaved={saved()}/>
      )}
      {modal?.kind === "grant" && <GrantModal data={data} preset={modal.preset} close={close} onSaved={saved()}/>}

      {explained != null && (
        <EffectiveAccessDrawer userId={explained} close={() => setExplained(null)}
                               onGrant={(user) => { setExplained(null); setModal({ kind: "grant", preset: { principal: "user", principalId: user.id } }); }}/>
      )}
    </>
  );
}

function AccessHeader() {
  return (
    <div className="ph">
      <div>
        <h1>Access</h1>
        <div className="sub">Who opens which client, and with which role. Global admins open every client.</div>
      </div>
    </div>
  );
}

function fmtDate(iso) {
  if (!iso) return "never";
  const d = new Date(iso);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function IconBtn({ title, onClick, children, danger }) {
  return (
    <button className="btn btn-icon btn-ghost btn-sm" title={title} aria-label={title} onClick={onClick}
            style={{color: danger ? "var(--sev-critical)" : "var(--text-3)"}}>{children}</button>
  );
}

function Empty({ children }) {
  return <div className="empty"><div className="empty-body" style={{margin: "0 auto"}}>{children}</div></div>;
}

function Chips({ names, max = 4 }) {
  if (!names.length) return <span className="muted">—</span>;
  return (
    <div className="access-chips">
      {names.slice(0, max).map(n => <span key={n} className="tag">{n}</span>)}
      {names.length > max && <span className="muted" style={{fontSize: 12}}>+{names.length - max}</span>}
    </div>
  );
}

// ── Tables ──────────────────────────────────────────────────────────────────

function UsersTable({ data, onExplain, onToggleGlobal, onPassword, onDelete }) {
  const me = getUser()?.email;
  return (
    <table className="tbl">
      <thead><tr><th>User</th><th>Groups</th><th>Clients</th><th>Last login</th><th style={{width: 190}}/></tr></thead>
      <tbody>
        {data.users.map(u => {
          const self = u.email === me;
          return (
            <tr key={u.id}>
              <td>
                <div style={{color: "var(--text-0)", fontSize: 13, fontWeight: 500, display: "flex", gap: 8, alignItems: "center"}}>
                  {u.email}
                  {u.is_global_admin && <span className="tag brand" style={{height: 18}}>global admin</span>}
                  {self && <span className="muted" style={{fontSize: 11}}>you</span>}
                </div>
              </td>
              <td><Chips names={namesOf(u.group_ids, data.userGroups)}/></td>
              <td className="num">{u.is_global_admin ? "all" : u.client_count}</td>
              <td className="muted" style={{fontSize: 12}}>{fmtDate(u.last_login_at)}</td>
              <td>
                <div style={{display: "flex", gap: 4, justifyContent: "flex-end"}}>
                  <button className="btn btn-sm" onClick={() => onExplain(u.id)} title="What this user opens, and why">
                    <Icons.Eye size={11}/> Why?
                  </button>
                  {!self && (
                    <IconBtn title={u.is_global_admin ? "Remove global admin" : "Make global admin"} onClick={() => onToggleGlobal(u)}>
                      <Icons.Shield size={13}/>
                    </IconBtn>
                  )}
                  <IconBtn title="Reset password" onClick={() => onPassword(u)}><Icons.Lock size={13}/></IconBtn>
                  {!self && <IconBtn title="Delete account" onClick={() => onDelete(u)}><Icons.Trash size={13}/></IconBtn>}
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function ClientsTable({ data, onRename, onDelete }) {
  return (
    <table className="tbl">
      <thead><tr><th>Client</th><th>Client groups</th><th>Direct grants</th><th style={{width: 90}}/></tr></thead>
      <tbody>
        {data.clients.map(c => (
          <tr key={c.id}>
            <td>
              <div style={{display: "flex", gap: 10, alignItems: "center"}}>
                <ClientBadge client={c} size={24}/>
                <span style={{color: "var(--text-0)", fontWeight: 500}}>{c.name}</span>
                <span className="muted mono" style={{fontSize: 11}}>#{c.id}</span>
              </div>
            </td>
            <td><Chips names={namesOf(c.group_ids, data.clientGroups)}/></td>
            <td className="num">{c.grant_count}</td>
            <td>
              <div style={{display: "flex", gap: 4, justifyContent: "flex-end"}}>
                <IconBtn title="Rename" onClick={() => onRename(c)}><Icons.Edit size={13}/></IconBtn>
                {data.clients.length > 1 && <IconBtn title="Delete client" onClick={() => onDelete(c)}><Icons.Trash size={13}/></IconBtn>}
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function GroupsTable({ rows, memberKey, members, memberLabel, grantCount, empty, onEdit, onDelete }) {
  if (!rows.length) return <Empty>{empty}</Empty>;
  return (
    <table className="tbl">
      <thead><tr><th>Group</th><th>Members</th><th>Grants</th><th style={{width: 90}}/></tr></thead>
      <tbody>
        {rows.map(g => (
          <tr key={g.id}>
            <td style={{color: "var(--text-0)", fontWeight: 500}}>{g.name}</td>
            <td><Chips names={namesOf(g[memberKey], members, memberLabel)} max={5}/></td>
            <td className="num">{grantCount(g)}</td>
            <td>
              <div style={{display: "flex", gap: 4, justifyContent: "flex-end"}}>
                <IconBtn title="Edit" onClick={() => onEdit(g)}><Icons.Edit size={13}/></IconBtn>
                <IconBtn title="Delete group" onClick={() => onDelete(g)}><Icons.Trash size={13}/></IconBtn>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function GrantsTable({ grants, onRole, onDelete }) {
  if (!grants.length) return <Empty>No grant yet. Grant a user or a user group a role on a client or a client group.</Empty>;
  return (
    <table className="tbl">
      <thead><tr><th>Given to</th><th>On</th><th style={{width: 150}}>Role</th><th style={{width: 50}}/></tr></thead>
      <tbody>
        {grants.map(g => (
          <tr key={g.id}>
            <td>
              <div style={{display: "flex", gap: 8, alignItems: "center", color: "var(--text-0)"}}>
                {g.user_group ? <Icons.Users size={13}/> : <Icons.User size={13}/>} {principalLabel(g)}
              </div>
            </td>
            <td>
              <div style={{display: "flex", gap: 8, alignItems: "center"}}>
                {g.client ? <ClientBadge client={g.client} size={20}/> : <Icons.Layers size={13}/>} {scopeLabel(g)}
              </div>
            </td>
            <td>
              <select className="form-input access-role" value={g.role} onChange={e => onRole(g, e.target.value)} aria-label="Role">
                {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            </td>
            <td><IconBtn title="Remove grant" onClick={() => onDelete(g)}><Icons.Trash size={13}/></IconBtn></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Effective access ────────────────────────────────────────────────────────

function EffectiveAccessDrawer({ userId, close, onGrant }) {
  const [access, setAccess] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    accessApi.effectiveAccess(userId).then(setAccess).catch(e => setError(e.message));
  }, [userId]);

  const user = access?.user;
  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="drawer" role="dialog" aria-label="Effective access">
        <div className="drawer-head">
          <Icons.Eye size={16} color="var(--brand)"/>
          <div style={{minWidth: 0}}>
            <div style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>Effective access</div>
            <div className="mono" style={{fontSize: 11.5, color: "var(--text-3)"}}>{user?.email || "…"}</div>
          </div>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}} aria-label="Close"><Icons.X size={14}/></button>
        </div>
        <div className="drawer-body">
          {error && <div style={{color: "var(--err)", fontSize: 13}}><Icons.AlertTriangle size={13}/> {error}</div>}
          {!access && !error && <div className="muted">Loading…</div>}
          {access && (
            <>
              {user.is_global_admin ? (
                <div className="access-note brand">
                  <Icons.Shield size={14}/>
                  <span>Global admin: admin of every client, present and future, whatever the grants below.</span>
                </div>
              ) : (
                <div className="access-note">
                  <Icons.Info size={14}/>
                  <span>
                    {access.clients.length
                      ? <>Opens {access.clients.length} client{access.clients.length > 1 ? "s" : ""}. When several grants reach a client, the highest role wins.</>
                      : <>Opens no client: this user cannot sign in until it is granted access.</>}
                  </span>
                </div>
              )}

              <div style={{display: "flex", flexDirection: "column", gap: 10, marginTop: 16}}>
                {access.clients.map(c => (
                  <div key={c.id} className="access-client">
                    <div className="access-client-head">
                      <ClientBadge client={c} size={26}/>
                      <span className="name">{c.name}</span>
                      <span className="tag brand">{c.role}</span>
                    </div>
                    {c.global_admin && (
                      <div className="access-source effective"><Icons.Check size={12}/> <span>Global admin</span></div>
                    )}
                    {c.via.map(v => (
                      <div key={v.grant_id} className={`access-source ${v.effective ? "effective" : ""}`}
                           title={v.effective ? "This grant sets the role" : "Another grant gives this client a higher or equal role"}>
                        {v.effective ? <Icons.Check size={12}/> : <span className="access-dot"/>}
                        <span className="role">{v.role}</span>
                        <span>{describeSource(v)}</span>
                        <span className="muted mono" style={{marginLeft: "auto", fontSize: 11}}>#{v.grant_id}</span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>

              <button className="btn btn-sm" style={{marginTop: 18}} onClick={() => onGrant(user)}>
                <Icons.Plus size={11}/> Grant access to {user.email}
              </button>
            </>
          )}
        </div>
      </div>
    </>
  );
}

// ── Modals ──────────────────────────────────────────────────────────────────

function Modal({ title, icon: I = Icons.Settings, close, onSubmit, submitting, error, submitLabel, children, width = 460 }) {
  return (
    <>
      <div className="drawer-backdrop" onClick={close}/>
      <div className="modal" style={{maxWidth: width}} role="dialog" aria-label={title}>
        <div className="drawer-head">
          <I size={16} color="var(--brand)"/>
          <span style={{fontSize: 14, fontWeight: 600, color: "var(--text-0)"}}>{title}</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={close} style={{marginLeft: "auto"}} aria-label="Close"><Icons.X size={14}/></button>
        </div>
        <form onSubmit={onSubmit} style={{padding: "20px 24px", display: "flex", flexDirection: "column", gap: 14, overflowY: "auto"}}>
          {children}
          {error && <div style={{color: "var(--err)", fontSize: 12.5}}><Icons.AlertTriangle size={12}/> {error}</div>}
          <div style={{display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 6}}>
            <button type="button" className="btn" onClick={close} disabled={submitting}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? <><Icons.Refresh size={12} className="spin"/> Saving…</> : submitLabel}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

function useSubmit(action, onSaved) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try { await action(); await onSaved(); }
    catch (err) { setError(err.message); setSubmitting(false); }
  };
  return { submit, submitting, error };
}

function UserModal({ close, onSaved }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [globalAdmin, setGlobalAdmin] = useState(false);
  const { submit, submitting, error } = useSubmit(
    () => accessApi.createUser({ email, password, is_global_admin: globalAdmin }), onSaved);
  return (
    <Modal title="Add user" icon={Icons.User} close={close} onSubmit={submit} submitting={submitting} error={error} submitLabel="Add user">
      <div>
        <label className="form-label">Email</label>
        <input className="form-input mono" type="email" required autoFocus value={email} onChange={e => setEmail(e.target.value)} placeholder="alice@msp.example"/>
      </div>
      <div>
        <label className="form-label">Initial password</label>
        <input className="form-input" type="password" required minLength={6} value={password} onChange={e => setPassword(e.target.value)}/>
      </div>
      <label className="login-check">
        <input type="checkbox" checked={globalAdmin} onChange={e => setGlobalAdmin(e.target.checked)}/>
        <span>Global admin — opens every client and administers access</span>
      </label>
      {!globalAdmin && <div className="form-help">The account opens no client until you grant it access.</div>}
    </Modal>
  );
}

function PasswordModal({ user, close, onSaved }) {
  const [password, setPassword] = useState("");
  const { submit, submitting, error } = useSubmit(() => accessApi.updateUser(user.id, { password }), onSaved);
  return (
    <Modal title={`Reset password — ${user.email}`} icon={Icons.Lock} close={close} onSubmit={submit} submitting={submitting} error={error} submitLabel="Reset password">
      <div>
        <label className="form-label">New password</label>
        <input className="form-input" type="password" required minLength={6} autoFocus value={password} onChange={e => setPassword(e.target.value)}/>
      </div>
    </Modal>
  );
}

function ClientModal({ client, close, onSaved }) {
  const [name, setName] = useState(client?.name || "");
  const { submit, submitting, error } = useSubmit(
    () => client ? accessApi.updateClient(client.id, { name }) : accessApi.createClient({ name }), onSaved);
  return (
    <Modal title={client ? "Rename client" : "New client"} icon={Icons.Folder} close={close} onSubmit={submit}
           submitting={submitting} error={error} submitLabel={client ? "Rename" : "Create client"}>
      <div>
        <label className="form-label">Name</label>
        <input className="form-input" required autoFocus maxLength={255} value={name} onChange={e => setName(e.target.value)} placeholder="Acme Corp"/>
        {!client && <div className="form-help">Global admins open it at once; grant access to the others.</div>}
      </div>
    </Modal>
  );
}

function GroupModal({ title, group, memberKey, members, memberLabel, save, close, onSaved }) {
  const [name, setName] = useState(group?.name || "");
  const [ids, setIds] = useState(group?.[memberKey] || []);
  const [query, setQuery] = useState("");
  const { submit, submitting, error } = useSubmit(() => save({ name, [memberKey]: ids }), onSaved);
  const q = query.trim().toLowerCase();
  const shown = q ? members.filter(m => String(m[memberLabel]).toLowerCase().includes(q)) : members;
  return (
    <Modal title={group ? `Edit ${title}` : `New ${title}`} icon={Icons.Users} close={close} onSubmit={submit}
           submitting={submitting} error={error} submitLabel={group ? "Save" : "Create"} width={520}>
      <div>
        <label className="form-label">Name</label>
        <input className="form-input" required autoFocus maxLength={255} value={name} onChange={e => setName(e.target.value)}/>
      </div>
      <div>
        <label className="form-label">Members <span className="muted">({ids.length})</span></label>
        {members.length > 8 && (
          <input className="form-input" placeholder="Filter…" value={query} onChange={e => setQuery(e.target.value)} style={{marginBottom: 8}}/>
        )}
        <div className="access-pick">
          {shown.map(m => (
            <label key={m.id} className="access-pick-row">
              <input type="checkbox" checked={ids.includes(m.id)} onChange={() => setIds(toggleId(ids, m.id))}/>
              {memberKey === "client_ids" && <ClientBadge client={m} size={18}/>}
              <span>{m[memberLabel]}</span>
            </label>
          ))}
          {!shown.length && <div className="muted" style={{padding: 10, fontSize: 12.5}}>Nothing matches.</div>}
        </div>
      </div>
    </Modal>
  );
}

function GrantModal({ data, preset, close, onSaved }) {
  const [principal, setPrincipal] = useState(preset?.principal || "user");
  const [principalId, setPrincipalId] = useState(preset?.principalId ?? "");
  const [scope, setScope] = useState("client");
  const [scopeId, setScopeId] = useState("");
  const [role, setRole] = useState("analyst");
  const body = () => ({
    role,
    [principal === "user" ? "user_id" : "user_group_id"]: Number(principalId),
    [scope === "client" ? "client_id" : "client_group_id"]: Number(scopeId),
  });
  const { submit, submitting, error } = useSubmit(() => accessApi.createGrant(body()), onSaved);
  const principals = principal === "user"
    ? data.users.filter(u => !u.is_global_admin).map(u => ({ id: u.id, label: u.email }))
    : data.userGroups.map(g => ({ id: g.id, label: g.name }));
  const scopes = scope === "client"
    ? data.clients.map(c => ({ id: c.id, label: c.name }))
    : data.clientGroups.map(g => ({ id: g.id, label: g.name }));

  return (
    <Modal title="Grant access" icon={Icons.Key} close={close} onSubmit={submit} submitting={submitting} error={error} submitLabel="Grant access" width={520}>
      <div>
        <label className="form-label">Given to</label>
        <div style={{display: "flex", gap: 8}}>
          <div className="tabs">
            {[["user", "User"], ["user-group", "User group"]].map(([k, l]) => (
              <button type="button" key={k} className={`tab ${principal === k ? "active" : ""}`}
                      onClick={() => { setPrincipal(k); setPrincipalId(""); }}>{l}</button>
            ))}
          </div>
          <select className="form-input" required value={principalId} onChange={e => setPrincipalId(e.target.value)} aria-label="Given to">
            <option value="" disabled>Choose…</option>
            {principals.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
          </select>
        </div>
        {principal === "user" && <div className="form-help">Global admins open every client already: they are not listed.</div>}
      </div>
      <div>
        <label className="form-label">On</label>
        <div style={{display: "flex", gap: 8}}>
          <div className="tabs">
            {[["client", "Client"], ["client-group", "Client group"]].map(([k, l]) => (
              <button type="button" key={k} className={`tab ${scope === k ? "active" : ""}`}
                      onClick={() => { setScope(k); setScopeId(""); }}>{l}</button>
            ))}
          </div>
          <select className="form-input" required value={scopeId} onChange={e => setScopeId(e.target.value)} aria-label="On">
            <option value="" disabled>Choose…</option>
            {scopes.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </div>
      </div>
      <div>
        <label className="form-label">Role</label>
        <select className="form-input" value={role} onChange={e => setRole(e.target.value)}>
          {ROLES.map(r => <option key={r} value={r}>{ROLE_HELP[r]}</option>)}
        </select>
      </div>
    </Modal>
  );
}
