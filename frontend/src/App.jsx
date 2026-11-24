import React, { useState, useEffect, useCallback, useRef } from "react";
import { Nav, Topbar } from "./design/Shell.jsx";
import { Dashboard } from "./design/Dashboard.jsx";
import { Jobs } from "./design/Jobs.jsx";
import { JobDetail, FindingDrawer } from "./design/JobDetail.jsx";
import { Assets, AssetDetail, Reports } from "./design/Assets.jsx";
import { Profiles, Credentials, Datasets, Settings } from "./design/PagesOther.jsx";
import { ThreatIntel } from "./design/ThreatIntel.jsx";
import { AttackGraph } from "./design/AttackGraph.jsx";
import { Analytics } from "./design/Analytics.jsx";
import { LoginPage } from "./design/Login.jsx";
import { Inventory } from "./design/Inventory.jsx";
import { ClientPicker } from "./design/ClientPicker.jsx";
import { Access } from "./design/Access.jsx";
import { Icons } from "./design/icons.jsx";
import { DEFAULT_PAGE, canOpenPage, parseRoute, resolveRoute, routeHash } from "./design/routes.js";
import {
  getToken, getUser, logout as apiLogout, selectClient, isGlobalAdmin,
  SESSION_ENDED_EVENT, CLIENT_LOST_EVENT, SESSION_UPDATED_EVENT,
  scanApi, credentialsApi, datasetsApi, assetsApi, reportsApi, threatIntelApi,
} from "./api.js";

// The URL names the client and the page ("#/c/<client>/<page>"): a link,
// a bookmark or the browser history reopen the same client. See routes.js.
function currentRoute() {
  return parseRoute(window.location.hash);
}

function setHash(hash, { replace = false } = {}) {
  if (replace) window.history.replaceState(null, "", window.location.pathname + window.location.search + hash);
  else if (window.location.hash !== hash) window.location.hash = hash;
}

export default function App() {
  const [authed, setAuthed] = useState(() => !!getToken());
  const [user, setUser] = useState(() => getUser());
  const [route, setRoute] = useState(currentRoute);
  const [picking, setPicking] = useState(false);
  const [notice, setNotice] = useState("");
  const [platformVersion, setPlatformVersion] = useState("");
  const opening = useRef(null);

  // Fetch version from backend (no auth needed) — single source of truth
  useEffect(() => {
    fetch("/healthz").then(r => r.json())
      .then(d => setPlatformVersion(d.version || ""))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const follow = () => setRoute(currentRoute());
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);

  const navigate = useCallback((hash, options) => {
    setHash(hash, options);
    setRoute(parseRoute(hash));
  }, []);

  // The session ended (401), or the open client is out of reach (access
  // removed meanwhile): back to sign-in, or to the client picker.
  useEffect(() => {
    const ended = () => { setAuthed(false); setUser(null); setPicking(false); };
    const updated = () => setUser(getUser());
    const lost = (e) => {
      setNotice(String(e.detail || "").startsWith("No access")
        ? "Your access to this client has changed. Choose a client to continue."
        : "Choose a client to continue.");
      setPicking(true);
    };
    window.addEventListener(SESSION_ENDED_EVENT, ended);
    window.addEventListener(CLIENT_LOST_EVENT, lost);
    window.addEventListener(SESSION_UPDATED_EVENT, updated);
    return () => {
      window.removeEventListener(SESSION_ENDED_EVENT, ended);
      window.removeEventListener(CLIENT_LOST_EVENT, lost);
      window.removeEventListener(SESSION_UPDATED_EVENT, updated);
    };
  }, []);

  // A link to another client: open it (new token), then show the page.
  const openLinkedClient = useCallback(async (clientId) => {
    if (opening.current === clientId) return;
    opening.current = clientId;
    try {
      await selectClient(clientId);
      setUser(getUser());
    } catch (e) {
      if (!getToken()) return; // session ended: the sign-in page takes over
      navigate("", { replace: true });
      setNotice(`Client #${clientId} is not available to your account.`);
      setPicking(true);
    } finally {
      opening.current = null;
    }
  }, [navigate]);

  useEffect(() => {
    if (!authed || picking) return;
    const decision = resolveRoute(route, user);
    if (decision.action === "pick") setPicking(true);
    else if (decision.action === "redirect") navigate(decision.hash, { replace: true });
    else if (decision.action === "switch") openLinkedClient(decision.clientId);
  }, [authed, picking, route, user, navigate, openLinkedClient]);

  const onLogin = () => {
    const signedIn = getUser();
    const linked = currentRoute()?.clientId != null;
    setUser(signedIn);
    setNotice("");
    setRoute(currentRoute());
    // One client: it is already open. Several: choose — unless a link names one.
    setPicking(!linked && ((signedIn?.clients || []).length > 1 || signedIn?.workspace_id == null));
    setAuthed(true);
  };

  const pickClient = async (clientId) => {
    await selectClient(clientId);
    const target = route?.clientId === clientId ? route : { clientId, page: DEFAULT_PAGE };
    setUser(getUser());
    setNotice("");
    setPicking(false);
    navigate(routeHash(target));
  };

  const signOut = () => {
    apiLogout();
    setAuthed(false);
    setUser(null);
    setPicking(false);
    setNotice("");
    navigate("", { replace: true });
  };

  if (!authed) {
    return <LoginPage onLogin={onLogin} version={platformVersion}/>;
  }
  if (picking) {
    return <ClientPicker onPick={pickClient} onSignOut={signOut} notice={notice} version={platformVersion}/>;
  }
  const ready = route && route.clientId != null && route.clientId === user?.workspace_id && canOpenPage(route.page, user);
  if (!ready) {
    return (
      <div className="login-shell-centered">
        <div className="switching"><Icons.Refresh size={14} className="spin"/> Opening client…</div>
      </div>
    );
  }

  return (
    // Keyed by client: switching remounts every page, so nothing of the
    // previous client stays on screen or in a component's state.
    <Workspace key={user.workspace_id} user={user} route={route} navigate={navigate}
               onAllClients={() => { setNotice(""); setPicking(true); }}
               onSignOut={signOut} version={platformVersion}/>
  );
}

function Workspace({ user, route, navigate, onAllClients, onSignOut, version }) {
  const clientId = user.workspace_id;
  const page = route.page;
  const openedDevice = route.deviceId;
  const [settingsTab, setSettingsTab] = useState(null);
  const [openedJob, setOpenedJob] = useState(null);
  const [openedAsset, setOpenedAsset] = useState(null);
  const [drawerFinding, setDrawerFinding] = useState(null);
  const [counts, setCounts] = useState({});

  const clients = user.clients || [];
  const client = clients.find(c => c.id === clientId) || { id: clientId, name: `Client #${clientId}`, role: user.role };

  const refreshCounts = useCallback(async () => {
    if (!getToken()) return;
    try {
      const [jobs, profiles, creds, datasets, assets, reports, ti] = await Promise.all([
        scanApi.listJobs().catch(() => []),
        scanApi.listProfiles().catch(() => []),
        credentialsApi.list().catch(() => []),
        isGlobalAdmin() ? datasetsApi.list().catch(() => []) : Promise.resolve(null),
        assetsApi.list().catch(() => []),
        reportsApi.list().catch(() => []),
        threatIntelApi.stats().catch(() => null),
      ]);
      setCounts(prev => ({
        jobs: jobs.length,
        profiles: profiles.length,
        credentials: creds.length,
        datasets: datasets?.length,
        assets: assets.length,
        reports: reports.length,
        threat_kev: ti?.kev_count ?? prev.threat_kev,
      }));
    } catch {}
  }, []);

  useEffect(() => {
    refreshCounts();
    const t = setInterval(refreshCounts, 12000);
    return () => clearInterval(t);
  }, [refreshCounts]);

  // Browser back/forward to another page closes what was open on this one.
  useEffect(() => { setOpenedJob(null); setOpenedAsset(null); }, [page]);

  const go = useCallback((target) => navigate(routeHash({ clientId, ...target })), [navigate, clientId]);
  const openDevice = useCallback((id) => go({ page: "inventory", deviceId: id }), [go]);
  const closeDevice = useCallback(() => go({ page: "inventory" }), [go]);

  function setPageWrap(p, tab) {
    setOpenedJob(null); setOpenedAsset(null);
    setSettingsTab(p === "settings" ? (tab || null) : null);
    go({ page: p });
  }

  // Same page in the other client; a device belongs to this client only.
  const switchClient = (id) => navigate(routeHash({ clientId: id, page }));

  const crumbs = ((p) => {
    if (p === "dashboard")    return ["Dashboard"];
    if (p === "assets")       return openedAsset ? ["Assets", openedAsset.name] : ["Assets"];
    if (p === "inventory")    return openedDevice != null ? ["Devices", `#${openedDevice}`] : ["Devices"];
    if (p === "jobs")         return openedJob ? ["Scans", `#${openedJob.id}`] : ["Scan jobs"];
    if (p === "profiles")     return ["Profiles"];
    if (p === "reports")      return ["Reports"];
    if (p === "credentials")  return ["Credentials"];
    if (p === "datasets")     return ["Datasets"];
    if (p === "threat-intel") return ["Threat Intel"];
    if (p === "attack-graph") return ["Attack Graph"];
    if (p === "analytics")    return ["Analytics"];
    if (p === "settings")     return ["Settings"];
    if (p === "access")       return ["Access"];
    return [];
  })(page);

  return (
    <div className="shell" data-screen-label={page}>
      <Nav page={page} setPage={setPageWrap} counts={counts} version={version} onSignOut={onSignOut}/>
      <div className="main">
        <Topbar crumbs={crumbs} setPage={setPageWrap}
                client={client} clients={clients} onSwitchClient={switchClient} onAllClients={onAllClients}/>
        <div className="page">
          {page === "dashboard"   && <Dashboard openDrawer={setDrawerFinding} setPage={setPageWrap}/>}
          {page === "assets" && !openedAsset && <Assets openAsset={setOpenedAsset}/>}
          {page === "assets" &&  openedAsset && <AssetDetail asset={openedAsset} back={() => setOpenedAsset(null)}/>}

          {page === "jobs" && !openedJob && <Jobs openJob={setOpenedJob}/>}
          {page === "jobs" &&  openedJob && <JobDetail job={openedJob} back={() => setOpenedJob(null)} openDrawer={setDrawerFinding}/>}
          {page === "inventory"   && <Inventory deviceId={openedDevice} openDevice={openDevice} closeDevice={closeDevice}/>}
          {page === "profiles"    && <Profiles/>}
          {page === "reports"     && <Reports/>}
          {page === "credentials" && <Credentials/>}
          {page === "datasets"    && <Datasets/>}
          {page === "threat-intel"&& <ThreatIntel/>}
          {page === "attack-graph"&& <AttackGraph/>}
          {page === "analytics"  && <Analytics/>}
          {page === "settings"    && <Settings initialTab={settingsTab}/>}
          {page === "access"      && <Access/>}
        </div>
      </div>
      {drawerFinding && <FindingDrawer finding={drawerFinding} close={() => setDrawerFinding(null)}
                                       openDevice={(id) => { setDrawerFinding(null); openDevice(id); }}/>}
    </div>
  );
}
