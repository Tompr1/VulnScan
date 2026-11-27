import { test } from "node:test";
import assert from "node:assert/strict";

import {
  applianceHostname, canUpdate, clientsWithoutProbe, codeCounts, cloudInitUserData, codeStatus, enrollCommand, eventLabel, imageStatus,
  isAlarmEvent, probeCounts, probeStatus, seenText, shortBuild, shortImage, toggledScanTypes, updateSummary,
} from "../src/design/probesModel.js";

const DELEGABLE = ["internal", "external", "api"];

test("chaque statut de sonde a son libellé et sa couleur", () => {
  assert.deepEqual(probeStatus("online"), { label: "online", pill: "done" });
  assert.deepEqual(probeStatus("pending"), { label: "waiting for enrollment", pill: "queued" });
  assert.equal(probeStatus("bizarre").label, "bizarre");
});

test("cocher un type de scan l'ajoute dans l'ordre de l'API", () => {
  assert.deepEqual(toggledScanTypes(["api"], "internal", true, DELEGABLE), ["internal", "api"]);
  assert.deepEqual(toggledScanTypes(["internal", "api"], "internal", false, DELEGABLE), ["api"]);
  assert.deepEqual(toggledScanTypes(undefined, "external", true, DELEGABLE), ["external"]);
});

test("la commande d'enrôlement nomme la plateforme sans barre finale", () => {
  assert.equal(enrollCommand("https://soc.example/", "tok"),
               "docker compose run --rm probe enroll --platform https://soc.example --token=tok");
  assert.match(enrollCommand("https://soc.example", "-abc"), / --token=-abc$/);
});

test("un client qui confie des scans sans sonde enrôlée est signalé", () => {
  const clients = [
    { id: 1, probe_scan_types: ["internal"] },
    { id: 2, probe_scan_types: ["internal"] },
    { id: 3, probe_scan_types: [] },
  ];
  const probes = [{ workspace_id: 1, status: "offline" }, { workspace_id: 2, status: "pending" }];

  assert.deepEqual(clientsWithoutProbe(clients, probes).map(c => c.id), [2]);
});

test("la dernière nouvelle d'une sonde se compte en minutes", () => {
  const now = Date.parse("2026-11-26T12:00:00Z");
  const ago = (s) => new Date(now - s * 1000).toISOString();

  assert.deepEqual(
    [null, ago(20), ago(150), ago(3 * 3600 + 5), ago(2 * 86400)].map(iso => seenText(iso, now)),
    ["never", "just now", "2 min ago", "3 h ago", "2 d ago"],
  );
});

const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcd";

test("la configuration de premier démarrage porte la graine que l'appliance attend", () => {
  const yaml = cloudInitUserData({
    platformUrl: "https://soc.example/", token: TOKEN, probeName: "Paris HQ", localAllowlist: "10.0.0.0/8, .corp.local",
  });

  assert.equal(yaml.split("\n")[0], "#cloud-config");
  assert.match(yaml, /^hostname: v0cday-probe-paris-hq$/m);
  assert.match(yaml, /^ {2}- path: \/etc\/v0cday-probe\/seed\.env$/m);
  assert.match(yaml, /^ {4}permissions: '0600'$/m);
  assert.match(yaml, /^ {6}V0CDAY_PLATFORM=https:\/\/soc\.example$/m);
  assert.match(yaml, new RegExp(`^ {6}V0CDAY_TOKEN=${TOKEN}$`, "m"));
  assert.match(yaml, /^ {6}V0CDAY_LOCAL_ALLOWLIST=10\.0\.0\.0\/8,\.corp\.local$/m);
  assert.doesNotMatch(yaml, /ALLOW_HTTP|ca\.pem/);
});

test("le certificat d'autorité de la plateforme est déposé à côté de la graine", () => {
  const pem = "-----BEGIN CERTIFICATE-----\nMIIBabc\n-----END CERTIFICATE-----";

  const yaml = cloudInitUserData({ platformUrl: "https://10.0.0.2", token: TOKEN, probeName: "Lab", caPem: pem });

  assert.match(yaml, /^ {2}- path: \/etc\/v0cday-probe\/ca\.pem$/m);
  assert.match(yaml, /^ {6}-----BEGIN CERTIFICATE-----\n {6}MIIBabc\n {6}-----END CERTIFICATE-----$/m);
});

test("une valeur qui sortirait de la graine est refusée", () => {
  const base = { platformUrl: "https://soc.example", token: TOKEN, probeName: "x" };
  assert.throws(() => cloudInitUserData({ ...base, platformUrl: "http://soc.example" }), /https/);
  assert.throws(() => cloudInitUserData({ ...base, platformUrl: "https://soc.example\nV0CDAY_TOKEN=autre" }), /https/);
  assert.throws(() => cloudInitUserData({ ...base, token: "abc\nV0CDAY_PLATFORM=x" }), /token/);
  assert.throws(() => cloudInitUserData({ ...base, localAllowlist: "10.0.0.0/8\nV0CDAY_ALLOW_HTTP=1" }), /allowlist/);
  assert.throws(() => cloudInitUserData({ ...base, localAllowlist: "$(reboot)" }), /allowlist/);
  assert.throws(() => cloudInitUserData({ ...base, caPem: "pas un certificat" }), /PEM/);
});

test("le http n'est admis qu'explicitement, pour un labo", () => {
  const yaml = cloudInitUserData({ platformUrl: "http://192.168.2.11", token: TOKEN, probeName: "lab", allowHttp: true });

  assert.match(yaml, /^ {6}V0CDAY_ALLOW_HTTP=1$/m);
});

test("le nom d'hôte de l'appliance vient du nom de la sonde", () => {
  assert.equal(applianceHostname("Siège Lyon / DC-2"), "v0cday-probe-siege-lyon-dc-2");
  assert.equal(applianceHostname(""), "v0cday-probe");
  assert.ok(applianceHostname("x".repeat(100)).length <= 63);
});

test("l'état de l'image dit si la sonde est à jour", () => {
  assert.deepEqual(imageStatus("current"), { label: "up to date", pill: "done" });
  assert.equal(imageStatus("update_pending").label, "update pending");
  assert.equal(imageStatus("unmanaged").label, "");
  assert.equal(imageStatus("inattendu").label, "image not reported");
});

test("une image épinglée s'affiche en court", () => {
  assert.equal(shortImage("ghcr.io/msp/v0cday-probe@sha256:" + "abcdef123456" + "0".repeat(52)), "v0cday-probe@abcdef123456");
  assert.equal(shortImage("v0cday-probe:appliance"), "v0cday-probe:appliance");
  assert.equal(shortImage(null), "");
});

test("le journal se lit en mots, les alertes en rouge", () => {
  assert.equal(eventLabel("job_claimed"), "Took a scan");
  assert.equal(eventLabel("nouveau"), "nouveau");
  assert.deepEqual(["offline", "online", "revoked", "job_refused"].map(isAlarmEvent), [true, false, true, true]);
});

test("la vue d'ensemble compte les sondes par état", () => {
  const probes = [{ status: "online" }, { status: "online" }, { status: "offline" }, { status: "pending" }, { status: "revoked" }];

  assert.deepEqual(probeCounts(probes), { online: 2, offline: 1, pending: 1 });
});

// ── Mises à jour des sondes installées depuis les sources ────────────────────

const sonde = (extra) => ({ status: "online", code_status: "outdated", update_status: null, ...extra });

test("l'état du code d'une sonde suit la demande de mise à jour", () => {
  assert.equal(codeStatus(sonde({ code_status: "current" })).label, "code up to date");
  assert.equal(codeStatus(sonde()).label, "update available");
  assert.equal(codeStatus(sonde({ update_status: "requested", code_status: "updating" })).label, "update asked");
  assert.equal(codeStatus(sonde({ update_status: "running", code_status: "updating" })).label, "updating…");
  assert.deepEqual(codeStatus(sonde({ update_status: "failed" })), { label: "update failed", pill: "failed" });
  assert.equal(codeStatus(sonde({ code_status: "unknown" })).label, "code not reported");
  assert.equal(codeStatus(sonde({ code_status: "appliance" })).label, "", "une appliance suit son image");
});

test("on ne demande une mise à jour qu'à une sonde enrôlée, en retard, sans mise à jour en cours", () => {
  assert.equal(canUpdate(sonde(), "abc1234"), true);
  assert.equal(canUpdate(sonde({ code_status: "unknown", status: "offline" }), "abc1234"), true);
  assert.equal(canUpdate(sonde(), null), false, "commit de la plateforme inconnu");
  assert.equal(canUpdate(sonde({ code_status: "current" }), "abc1234"), false);
  assert.equal(canUpdate(sonde({ code_status: "appliance" }), "abc1234"), false);
  assert.equal(canUpdate(sonde({ status: "pending" }), "abc1234"), false);
  assert.equal(canUpdate(sonde({ update_status: "running" }), "abc1234"), false);
});

test("le résultat de la vérification tient en une phrase", () => {
  assert.equal(shortBuild("0123456789abcdef"), "0123456");
  assert.equal(updateSummary({ platform_build: "0123456789", counts: { outdated: 2, current: 1 } }),
    "Platform code 0123456: 2 can be updated, 1 up to date.");
  assert.match(updateSummary({ platform_build: null, counts: {} }), /does not know which commit/);
  assert.equal(updateSummary({ platform_build: "0123456789", counts: {} }), "Platform code 0123456: no enrolled probe.");
});

test("un échec de mise à jour apparaît en rouge dans l'historique", () => {
  assert.equal(eventLabel("update_done"), "Updated");
  assert.equal(isAlarmEvent("update_failed"), true);
});

test("les compteurs de code ne comptent que les sondes enrôlées", () => {
  assert.deepEqual(codeCounts([
    { status: "online", code_status: "outdated" }, { status: "offline", code_status: "outdated" },
    { status: "online", code_status: "current" }, { status: "pending", code_status: "unknown" },
    { status: "revoked", code_status: "outdated" },
  ]), { outdated: 2, current: 1 });
});
