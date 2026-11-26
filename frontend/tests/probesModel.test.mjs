import { test } from "node:test";
import assert from "node:assert/strict";

import {
  applianceHostname, clientsWithoutProbe, cloudInitUserData, enrollCommand, probeStatus, seenText, toggledScanTypes,
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
               "docker compose run --rm probe enroll --platform https://soc.example --token tok");
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
