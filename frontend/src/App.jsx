import React, { useState, useEffect, useCallback } from "react";
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
import { INVENTORY_HASH, deviceHash, parseInventoryHash } from "./design/inventoryModel.js";
import {
  getToken, logout as apiLogout,
  scanApi, credentialsApi, datasetsApi, assetsApi, reportsApi, threatIntelApi,
} from "./api.js";

export default function App() {
  const [authed, setAuthed] = useState(() => !!getToken());
  // Inventory pages live in the URL hash, so alert links (#/inventory/devices/<id>)
  // open the device page, also after signing in.
  const initialRoute = parseInventoryHash(window.location.hash);
  const [page, setPage] = useState(initialRoute ? initialRoute.page : "dashboard");
  const [openedDevice, setOpenedDevice] = useState(initialRoute ? initialRoute.deviceId : null);
  const [settingsTab, setSettingsTab] = useState(null);
  const [openedJob, setOpenedJob] = useState(null);
  const [openedAsset, setOpenedAsset] = useState(null);
  const [drawerFinding, setDrawerFinding] = useState(null);
  const [counts, setCounts] = useState({});
  const [platformVersion, setPlatformVersion] = useState("");

  // Fetch version from backend (no auth needed) — single source of truth
  useEffect(() => {
    fetch("/healthz").then(r => r.json())
      .then(d => setPlatformVersion(d.version || ""))
      .catch(() => {});
  }, []);

  const refreshCounts = useCallback(async () => {
    if (!getToken()) return;
    try {
      const [jobs, profiles, creds, datasets, assets, reports, ti] = await Promise.all([
        scanApi.listJobs().catch(() => []),
        scanApi.listProfiles().catch(() => []),
        credentialsApi.list().catch(() => []),
        datasetsApi.list().catch(() => []),
        assetsApi.list().catch(() => []),
        reportsApi.list().catch(() => []),
        threatIntelApi.stats().catch(() => null),
      ]);
      setCounts(prev => ({
        jobs: jobs.length,
        profiles: profiles.length,
        credentials: creds.length,
        datasets: datasets.length,
        assets: assets.length,
        reports: reports.length,
        threat_kev: ti?.kev_count ?? prev.threat_kev,
      }));
    } catch {}
  }, []);

  useEffect(() => {
    const follow = () => {
      const route = parseInventoryHash(window.location.hash);
      if (!route) return;
      setOpenedJob(null); setOpenedAsset(null);
      setPage(route.page);
      setOpenedDevice(route.deviceId);
    };
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);

  const openDevice = useCallback((id) => { window.location.hash = deviceHash(id); }, []);
  const closeDevice = useCallback(() => { window.location.hash = INVENTORY_HASH; }, []);

  useEffect(() => {
    if (!authed) return;
    refreshCounts();
    const t = setInterval(refreshCounts, 12000);
    return () => clearInterval(t);
  }, [authed, refreshCounts]);

  if (!authed) {
    return <LoginPage onLogin={() => setAuthed(true)} version={platformVersion}/>;
  }

  const crumbs = ((p) => {
    if (p === "dashboard")    return ["VulnScan", "Dashboard"];
    if (p === "assets")       return openedAsset ? ["VulnScan", "Assets", openedAsset.name] : ["VulnScan", "Assets"];
    if (p === "inventory")    return openedDevice != null ? ["VulnScan", "Devices", `#${openedDevice}`] : ["VulnScan", "Devices"];
    if (p === "jobs")         return openedJob ? ["VulnScan", "Scans", `#${openedJob.id}`] : ["VulnScan", "Scan jobs"];
    if (p === "profiles")     return ["VulnScan", "Profiles"];
    if (p === "reports")      return ["VulnScan", "Reports"];
    if (p === "credentials")  return ["VulnScan", "Credentials"];
    if (p === "datasets")     return ["VulnScan", "Datasets"];
    if (p === "threat-intel") return ["VulnScan", "Threat Intel"];
    if (p === "attack-graph") return ["VulnScan", "Attack Graph"];
    if (p === "analytics")    return ["VulnScan", "Analytics"];
    if (p === "settings")     return ["VulnScan", "Settings"];
    return ["VulnScan"];
  })(page);

  function setPageWrap(p, tab) {
    setOpenedJob(null); setOpenedAsset(null); setOpenedDevice(null);
    setSettingsTab(p === "settings" ? (tab || null) : null);
    setPage(p);
    if (p === "inventory") {
      if (window.location.hash !== INVENTORY_HASH) window.location.hash = INVENTORY_HASH;
    } else if (parseInventoryHash(window.location.hash)) {
      // Leaving the inventory: drop its hash without adding a history entry.
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }

  return (
    <div className="shell" data-screen-label={page}>
      <Nav page={page} setPage={setPageWrap} counts={counts} version={platformVersion} onSignOut={() => {
        apiLogout();
        setAuthed(false);
      }}/>
      <div className="main">
        <Topbar crumbs={crumbs} setPage={setPageWrap}/>
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
        </div>
      </div>
      {drawerFinding && <FindingDrawer finding={drawerFinding} close={() => setDrawerFinding(null)}
                                       openDevice={(id) => { setDrawerFinding(null); openDevice(id); }}/>}
    </div>
  );
}
