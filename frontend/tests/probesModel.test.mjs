import { test } from "node:test";
import assert from "node:assert/strict";

import { clientsWithoutProbe, enrollCommand, probeStatus, seenText, toggledScanTypes } from "../src/design/probesModel.js";

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
