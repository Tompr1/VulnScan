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
import { ContextWindow } from "./design/ClientPicker.jsx";
import { Access } from "./design/Access.jsx";
import { RootOverview, RootPlatform } from "./design/Root.jsx";
import { Probes } from "./design/Probes.jsx";
import { Icons } from "./design/icons.jsx";
import { CLIENT_PAGES, DEFAULT_PAGE, isRootSession, parseRoute, resolveRoute, routeHash } from "./design/routes.js";
import {
  getToken, getUser, logout as apiLogout, selectClient, selectRoot,
  SESSION_ENDED_EVENT, CLIENT_LOST_EVENT, SESSION_UPDATED_EVENT,
  scanApi, credentialsApi, datasetsApi, assetsApi, reportsApi, threatIntelApi,
} from "./api.js";

// The URL names the context and the page — "#/c/<client>/<page>" or
// "#/root/<page>": a link, a bookmark or the browser history reopen the same
// context. See routes.js.
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
  // The selection window: "page" when a choice must be made (after sign-in,
  // context lost), "overlay" when opened from the top bar over the open context.
  const [selector, setSelector] = useState(null);
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

  // The session ended (401), or the open context is out of reach (access
  // removed meanwhile): back to sign-in, or to the selection window.
  useEffect(() => {
    const ended = () => { setAuthed(false); setUser(null); setSelector(null); };
    const updated = () => setUser(getUser());
    const lost = (e) => {
      const detail = String(e.detail || "");
      setNotice(detail.startsWith("No access") ? "Your access to this client has changed. Choose where to continue."
        : detail.startsWith("Requires a global admin") ? "Your account is no longer a super admin. Choose a client to continue."
        : "Choose where to continue.");
      setSelector("page");
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

  // A link to another context: open it (new token), then show the page.
  const openLinked = useCallback(async (target, open, unavailable) => {
    if (opening.current === target) return;
    opening.current = target;
    try {
      await open();
      setUser(getUser());
    } catch (e) {
      if (!getToken()) return; // session ended: the sign-in page takes over
      navigate("", { replace: true });
      setNotice(unavailable);
      setSelector("page");
    } finally {
      opening.current = null;
    }
  }, [navigate]);

  useEffect(() => {
    if (!authed || selector === "page") return;
    const decision = resolveRoute(route, user);
    if (decision.action === "pick") setSelector("page");
    else if (decision.action === "redirect") navigate(decision.hash, { replace: true });
    else if (decision.action === "show" && window.location.hash !== routeHash(decision.route)) {
      // An old or partial link ("#/c/3/datasets", "#/c/3/"): show its canonical address.
      navigate(routeHash(decision.route), { replace: true });
    }
    else if (decision.action === "switch") {
      openLinked(`client-${decision.clientId}`, () => selectClient(decision.clientId), `Client #${decision.clientId} is not available to your account.`);
    } else if (decision.action === "switch-root") {
      openLinked("root", selectRoot, "Root is for super admins.");
    }
  }, [authed, selector, route, user, navigate, openLinked]);

  const onLogin = () => {
    const signedIn = getUser();
    const linked = currentRoute() != null && (currentRoute().root || currentRoute().clientId != null);
    setUser(signedIn);
    setNotice("");
    setRoute(currentRoute());
    // Like FortiManager: choose where to work — unless there is a single
    // client and no Root (it is already open), or a link names the place.
    const choices = (signedIn?.clients || []).length + (signedIn?.is_global_admin ? 1 : 0);
    setSelector(!linked && (choices > 1 || signedIn?.workspace_id == null) ? "page" : null);
    setAuthed(true);
  };

  const pickClient = async (clientId) => {
    await selectClient(clientId);
    // Same page in the other client when switching from a client; else its dashboard.
    const samePage = route && !route.root && CLIENT_PAGES.includes(route.page) ? route.page : DEFAULT_PAGE;
    const target = route?.clientId === clientId ? route : { clientId, page: samePage };
    setUser(getUser());
    setNotice("");
    setSelector(null);
    navigate(routeHash(target));
  };

  const pickRoot = async () => {
    await selectRoot();
    setUser(getUser());
    setNotice("");
    setSelector(null);
    navigate(route?.root ? routeHash(route) : routeHash({ root: true }));
  };

  const signOut = () => {
    apiLogout();
    setAuthed(false);
    setUser(null);
    setSelector(null);
    setNotice("");
    navigate("", { replace: true });
  };

  if (!authed) {
    return <LoginPage onLogin={onLogin} version={platformVersion}/>;
  }
  const current = isRootSession(user) ? { root: true } : { clientId: user?.workspace_id };
  const window_ = (mode) => (
    // When a choice must be made, nothing is chosen yet: no tile is marked open.
    <ContextWindow onPickClient={pickClient} onPickRoot={pickRoot} onSignOut={signOut} current={mode === "overlay" ? current : null}
                   onClose={mode === "overlay" ? () => setSelector(null) : null} notice={notice} version={platformVersion}/>
  );
  if (selector === "page") return window_("page");

  const ready = route && (route.root ? isRootSession(user) : route.clientId != null && route.clientId === user?.workspace_id);
  if (!ready) {
    return (
      <div className="login-shell-centered">
        <div className="switching"><Icons.Refresh size={14} className="spin"/> Opening…</div>
      </div>
    );
  }

  return (
    <>
      {/* Keyed by context: switching remounts every page, so nothing of the
          previous client stays on screen or in a component's state. */}
      <Workspace key={route.root ? "root" : `client-${user.workspace_id}`} user={user} route={route} navigate={navigate}
                 onOpenSelector={() => { setNotice(""); setSelector("overlay"); }}
                 onSignOut={signOut} version={platformVersion}/>
      {selector === "overlay" && window_("overlay")}
    </>
  );
}

function Workspace(props) {
  return props.route.root ? <RootWorkspace {...props}/> : <ClientWorkspace {...props}/>;
}

/** Root: the platform, for super admins — no client open. */
function RootWorkspace({ user, route, navigate, onOpenSelector, onSignOut, version }) {
  const page = route.page;
  const [counts, setCounts] = useState({});

  useEffect(() => {
    let cancelled = false;
    Promise.all([datasetsApi.list().catch(() => null), threatIntelApi.stats().catch(() => null)]).then(([datasets, ti]) => {
      if (!cancelled) setCounts({ datasets: datasets?.length, threat_kev: ti?.kev_count, clients: (user.clients || []).length });
    });
    return () => { cancelled = true; };
  }, [user]);

  const setPage = (p) => navigate(routeHash({ root: true, page: p }));
  const openClient = (clientId) => navigate(routeHash({ clientId }));

  const crumbs = {
    overview: ["Overview"], access: ["Clients & access"], probes: ["Scan probes"], datasets: ["Reference data"],
    "threat-intel": ["Threat Intel"], platform: ["Updates & system"],
  }[page] || [];

  return (
    <div className="shell" data-screen-label={`root-${page}`} data-context="root">
      <Nav page={page} setPage={setPage} counts={counts} version={version} onSignOut={onSignOut} root/>
      <div className="main">
        <Topbar crumbs={crumbs} setPage={setPage} context={{ root: true }} onOpenSelector={onOpenSelector}/>
        <div className="page">
          {page === "overview"     && <RootOverview openClient={openClient} setPage={setPage}/>}
          {page === "access"       && <Access/>}
          {page === "probes"       && <Probes/>}
          {page === "datasets"     && <Datasets/>}
          {page === "threat-intel" && <ThreatIntel/>}
          {page === "platform"     && <RootPlatform version={version}/>}
        </div>
      </div>
    </div>
  );
}

/** One client: its assets, scans, devices, reports and settings. */
function ClientWorkspace({ user, route, navigate, onOpenSelector, onSignOut, version }) {
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
      const [jobs, profiles, creds, assets, reports, ti] = await Promise.all([
        scanApi.listJobs().catch(() => []),
        scanApi.listProfiles().catch(() => []),
        credentialsApi.list().catch(() => []),
        assetsApi.list().catch(() => []),
        reportsApi.list().catch(() => []),
        threatIntelApi.stats().catch(() => null),
      ]);
      setCounts(prev => ({
        jobs: jobs.length,
        profiles: profiles.length,
        credentials: creds.length,
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

  // Browser back/forward to another page closes what was open on this one
  // — except the scan another page asked to open (openJob).
  const pendingJob = useRef(null);
  useEffect(() => { setOpenedJob(pendingJob.current); pendingJob.current = null; setOpenedAsset(null); }, [page]);

  const go = useCallback((target) => navigate(routeHash({ clientId, ...target })), [navigate, clientId]);
  const openDevice = useCallback((id) => go({ page: "inventory", deviceId: id }), [go]);
  const closeDevice = useCallback(() => go({ page: "inventory" }), [go]);
  const openJob = useCallback(async (id) => {
    try {
      const r = await scanApi.getJob(id);
      if (page === "jobs") { setOpenedJob(r.job); return; }
      pendingJob.current = r.job;
      go({ page: "jobs" });
    } catch {}
  }, [go, page]);

  function setPageWrap(p, tab) {
    setOpenedJob(null); setOpenedAsset(null);
    setSettingsTab(p === "settings" ? (tab || null) : null);
    go({ page: p });
  }

  const crumbs = ((p) => {
    if (p === "dashboard")    return ["Dashboard"];
    if (p === "assets")       return openedAsset ? ["Assets", openedAsset.name] : ["Assets"];
    if (p === "inventory")    return openedDevice != null ? ["Devices", `#${openedDevice}`] : ["Devices"];
    if (p === "jobs")         return openedJob ? ["Scans", `#${openedJob.id}`] : ["Scan jobs"];
    if (p === "profiles")     return ["Profiles"];
    if (p === "reports")      return ["Reports"];
    if (p === "credentials")  return ["Credentials"];
    if (p === "threat-intel") return ["Threat Intel"];
    if (p === "attack-graph") return ["Attack Graph"];
    if (p === "analytics")    return ["Analytics"];
    if (p === "settings")     return ["Settings"];
    return [];
  })(page);

  return (
    <div className="shell" data-screen-label={page} data-context="client">
      <Nav page={page} setPage={setPageWrap} counts={counts} version={version} onSignOut={onSignOut}/>
      <div className="main">
        <Topbar crumbs={crumbs} setPage={setPageWrap} context={{ client }} onOpenSelector={onOpenSelector}/>
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
          {page === "threat-intel"&& <ThreatIntel client openDevice={openDevice} openJob={openJob}/>}
          {page === "attack-graph"&& <AttackGraph/>}
          {page === "analytics"  && <Analytics/>}
          {page === "settings"    && <Settings initialTab={settingsTab}/>}
        </div>
      </div>
      {drawerFinding && <FindingDrawer finding={drawerFinding} close={() => setDrawerFinding(null)}
                                       openDevice={(id) => { setDrawerFinding(null); openDevice(id); }}/>}
    </div>
  );
}
