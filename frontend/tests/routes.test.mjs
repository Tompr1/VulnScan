// Run with: node --test tests/   (from frontend/)
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  canOpenPage,
  clientHue,
  clientInitials,
  filterClients,
  parseRoute,
  resolveRoute,
  routeHash,
} from "../src/design/routes.js";

const TECH = { workspace_id: 2, is_global_admin: false };
const ADMIN_GLOBAL = { workspace_id: 2, is_global_admin: true };

// ── Lecture et écriture des URL ──────────────────────────────────────────

test("chaque page vit sous son client", () => {
  assert.equal(routeHash({ clientId: 3, page: "jobs" }), "#/c/3/jobs");
  assert.deepEqual(parseRoute("#/c/3/jobs"), { clientId: 3, page: "jobs", deviceId: null });
});

test("le lien d'une alerte ouvre la fiche de l'appareil chez son client", () => {
  const hash = routeHash({ clientId: 4, page: "inventory", deviceId: 42 });

  assert.equal(hash, "#/c/4/inventory/devices/42");
  assert.deepEqual(parseRoute(hash), { clientId: 4, page: "inventory", deviceId: 42 });
  assert.deepEqual(parseRoute("#/c/4/inventory/devices/42/"), { clientId: 4, page: "inventory", deviceId: 42 });
});

test("seul l'inventaire a des sous-pages d'appareil", () => {
  assert.equal(routeHash({ clientId: 4, page: "jobs", deviceId: 42 }), "#/c/4/jobs");
  assert.deepEqual(parseRoute("#/c/4/inventory/devices/abc"), { clientId: 4, page: "inventory", deviceId: null });
});

test("un client sans page, ou avec une page inconnue, ouvre son tableau de bord", () => {
  for (const hash of ["#/c/5", "#/c/5/", "#/c/5/nimporte-quoi"]) {
    assert.deepEqual(parseRoute(hash), { clientId: 5, page: "dashboard", deviceId: null }, hash);
  }
});

test("un ancien lien sans client est reconnu", () => {
  assert.deepEqual(parseRoute("#/inventory/devices/7"), { clientId: null, page: "inventory", deviceId: 7 });
  assert.deepEqual(parseRoute("#/inventory"), { clientId: null, page: "inventory", deviceId: null });
  assert.deepEqual(parseRoute("#/jobs"), { clientId: null, page: "jobs", deviceId: null });
});

test("un lien qui ne désigne aucune route est ignoré", () => {
  for (const hash of ["", "#", "#/", "#/inconnu", "#/c", "#/c/abc/jobs", "#/c/-1/jobs", null, undefined]) {
    assert.equal(parseRoute(hash), null, String(hash));
  }
});

// ── Décision à l'ouverture ───────────────────────────────────────────────

test("la page du client ouvert s'affiche", () => {
  const route = parseRoute("#/c/2/jobs");

  assert.deepEqual(resolveRoute(route, TECH), { action: "show", route });
});

test("un lien vers un autre client ouvre ce client", () => {
  assert.deepEqual(resolveRoute(parseRoute("#/c/7/inventory/devices/3"), TECH), { action: "switch", clientId: 7 });
});

test("un lien vers un client ouvre ce client même quand aucun n'est encore ouvert", () => {
  assert.deepEqual(resolveRoute(parseRoute("#/c/7/jobs"), { workspace_id: null }), { action: "switch", clientId: 7 });
});

test("sans client ouvert ni lien vers un client, on choisit son client", () => {
  for (const hash of ["", "#/jobs"]) {
    assert.deepEqual(resolveRoute(parseRoute(hash), { workspace_id: null, is_global_admin: true }), { action: "pick" }, hash);
  }
});

test("un ancien lien est redirigé vers la même page du client ouvert", () => {
  assert.deepEqual(resolveRoute(parseRoute("#/inventory/devices/7"), TECH), { action: "redirect", hash: "#/c/2/inventory/devices/7" });
});

test("sans route, on arrive sur le tableau de bord du client ouvert", () => {
  assert.deepEqual(resolveRoute(parseRoute(""), TECH), { action: "redirect", hash: "#/c/2/dashboard" });
});

test("la page Datasets n'est ouverte qu'à l'admin global", () => {
  assert.equal(canOpenPage("datasets", TECH), false);
  assert.equal(canOpenPage("datasets", ADMIN_GLOBAL), true);
  assert.equal(canOpenPage("datasets", null), false);
  assert.equal(canOpenPage("jobs", TECH), true);
  assert.deepEqual(resolveRoute(parseRoute("#/c/2/datasets"), TECH), { action: "redirect", hash: "#/c/2/dashboard" });
  assert.equal(resolveRoute(parseRoute("#/c/2/datasets"), ADMIN_GLOBAL).action, "show");
});

// ── Affichage des clients ────────────────────────────────────────────────

test("les initiales d'un client viennent de ses deux premiers mots", () => {
  assert.equal(clientInitials("Acme Corp"), "AC");
  assert.equal(clientInitials("globex"), "GL");
  assert.equal(clientInitials("hôpital-saint_louis"), "HS");
  assert.equal(clientInitials(""), "?");
});

test("chaque client garde sa couleur", () => {
  assert.equal(clientHue(3), clientHue(3));
  assert.notEqual(clientHue(1), clientHue(2));
  assert.ok(clientHue(12345) >= 0 && clientHue(12345) < 360);
});

test("la recherche filtre les clients par nom, sans tenir compte de la casse", () => {
  const clients = [{ id: 1, name: "Acme" }, { id: 2, name: "Globex" }, { id: 3, name: "ACME Lab" }];

  assert.deepEqual(filterClients(clients, " acme ").map(c => c.id), [1, 3]);
  assert.equal(filterClients(clients, "").length, 3);
});
