// Run with: node --test tests/   (from frontend/)
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ageText,
  compareDevices,
  compareIssues,
  describeChange,
  deviceHash,
  evidencePairs,
  filterBySeverity,
  parseInventoryHash,
  platformLabel,
  ruleLabel,
  summarizeFleet,
} from "../src/design/inventoryModel.js";

test("le lien d'une alerte ouvre la fiche de l'appareil", () => {
  assert.deepEqual(parseInventoryHash(deviceHash(42)), { page: "inventory", deviceId: 42 });
  assert.deepEqual(parseInventoryHash("#/inventory/devices/7/"), { page: "inventory", deviceId: 7 });
  assert.deepEqual(parseInventoryHash("#/inventory"), { page: "inventory", deviceId: null });
});

test("un lien étranger à l'inventaire est ignoré", () => {
  for (const hash of ["", "#", "#/jobs", "#/inventory/devices/abc", "#/inventory/devices/", null]) {
    assert.equal(parseInventoryHash(hash), null, String(hash));
  }
});

const devices = [
  { name: "PC-B", highest_severity: "high", issue_count: 1 },
  { name: "PC-A", highest_severity: null, issue_count: 0 },
  { name: "PC-C", highest_severity: "critical", issue_count: 1 },
  { name: "PC-D", highest_severity: "high", issue_count: 4 },
  { name: "PC-E", highest_severity: "low", issue_count: 2 },
];

test("les appareils les plus exposés passent en premier", () => {
  assert.deepEqual([...devices].sort(compareDevices).map(d => d.name), ["PC-C", "PC-D", "PC-B", "PC-E", "PC-A"]);
});

test("le filtre de gravité garde les appareils dont le pire problème atteint le seuil", () => {
  assert.deepEqual(filterBySeverity(devices, "high").map(d => d.name), ["PC-B", "PC-C", "PC-D"]);
  assert.deepEqual(filterBySeverity(devices, "none").map(d => d.name), ["PC-A"]);
  assert.equal(filterBySeverity(devices, "").length, 5);
});

test("le résumé du parc compte les appareils exposés", () => {
  assert.deepEqual(summarizeFleet(devices), { total: 5, withIssues: 4, critical: 1, high: 2, issues: 8 });
});

test("les problèmes exploités passent avant les plus graves", () => {
  const issues = [
    { title: "high", severity: "high", risk_score: 8 },
    { title: "kev", severity: "medium", is_kev: true },
    { title: "crit", severity: "critical", risk_score: 9.5 },
    { title: "crit-plus", severity: "critical", risk_score: 9.9 },
  ];
  assert.deepEqual(issues.sort(compareIssues).map(i => i.title), ["kev", "crit-plus", "crit", "high"]);
});

test("chaque changement du journal a une phrase lisible", () => {
  assert.equal(describeChange({ kind: "app_updated", subject: "Google Chrome", before: "130.0", after: "131.0" }),
    "Google Chrome updated: 130.0 → 131.0");
  assert.equal(describeChange({ kind: "app_installed", subject: "7-Zip", after: null }), "7-Zip installed");
  assert.equal(describeChange({ kind: "device_enrolled", subject: "PC-04" }), "Device enrolled");
  assert.equal(describeChange({ kind: "nouveau", subject: "x" }), "nouveau: x");
});

test("la preuve d'un constat se lit en paires libellé / valeur", () => {
  assert.deepEqual(evidencePairs("Device: PC-04\nUser: j.martin@corp\nligne sans séparateur\nReference: 24.08 (fleet: 2)"), [
    ["Device", "PC-04"], ["User", "j.martin@corp"], ["Reference", "24.08 (fleet: 2)"],
  ]);
  assert.deepEqual(evidencePairs(null), []);
});

test("les libellés connus sont traduits, les inconnus restent visibles", () => {
  assert.equal(ruleLabel("os_unsupported"), "OS out of support");
  assert.equal(ruleLabel("future_rule"), "future_rule");
  assert.equal(platformLabel("ios"), "iOS / iPadOS");
  assert.equal(platformLabel(undefined), "—");
});

test("l'ancienneté d'une date est donnée en jours", () => {
  const now = new Date("2026-11-21T12:00:00Z");
  assert.equal(ageText("2026-11-21T08:00:00Z", now), "today");
  assert.equal(ageText("2026-11-20T08:00:00Z", now), "yesterday");
  assert.equal(ageText("2026-11-01T12:00:00Z", now), "20 days ago");
  assert.equal(ageText(null, now), "never");
});
