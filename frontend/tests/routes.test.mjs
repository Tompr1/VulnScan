// Run with: node --test tests/   (from frontend/)
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  clientHue,
  clientInitials,
  filterClients,
  canOpenPage,
  isRootSession,
  parseRoute,
  resolveRoute,
  routeHash,
} from "../src/design/routes.js";

const TECH = { workspace_id: 2, is_global_admin: false };
const ADMIN_SUR_CLIENT = { workspace_id: 2, is_global_admin: true };
const ADMIN_SUR_ROOT = { workspace_id: null, is_global_admin: true };
const client = (clientId, page, deviceId = null) => ({ root: false, clientId, page, deviceId });
const root = (page) => ({ root: true, clientId: null, page, deviceId: null });

// ── Lecture et écriture des URL ──────────────────────────────────────────

test("chaque page vit sous son client", () => {
  assert.equal(routeHash({ clientId: 3, page: "jobs" }), "#/c/3/jobs");
  assert.deepEqual(parseRoute("#/c/3/jobs"), client(3, "jobs"));
});

test("Root a ses propres pages", () => {
  assert.equal(routeHash({ root: true, page: "access" }), "#/root/access");
  assert.equal(routeHash({ root: true }), "#/root/overview");
  assert.deepEqual(parseRoute("#/root/datasets"), root("datasets"));
  for (const hash of ["#/root", "#/root/", "#/root/inconnue", "#/root/dashboard"]) {
    assert.deepEqual(parseRoute(hash), root("overview"), hash);
  }
});

test("le lien d'une alerte ouvre la fiche de l'appareil chez son client", () => {
  const hash = routeHash({ clientId: 4, page: "inventory", deviceId: 42 });

  assert.equal(hash, "#/c/4/inventory/devices/42");
  assert.deepEqual(parseRoute(hash), client(4, "inventory", 42));
  assert.deepEqual(parseRoute("#/c/4/inventory/devices/42/"), client(4, "inventory", 42));
});

test("seul l'inventaire a des sous-pages d'appareil", () => {
  assert.equal(routeHash({ clientId: 4, page: "jobs", deviceId: 42 }), "#/c/4/jobs");
  assert.deepEqual(parseRoute("#/c/4/inventory/devices/abc"), client(4, "inventory"));
});

test("un client sans page, ou avec une page inconnue, ouvre son tableau de bord", () => {
  for (const hash of ["#/c/5", "#/c/5/", "#/c/5/nimporte-quoi", "#/c/5/overview"]) {
    assert.deepEqual(parseRoute(hash), client(5, "dashboard"), hash);
  }
});

test("Datasets et Accès d'un client, d'avant Root, s'ouvrent dans Root", () => {
  assert.deepEqual(parseRoute("#/c/2/datasets"), root("datasets"));
  assert.deepEqual(parseRoute("#/c/2/access"), root("access"));
  assert.deepEqual(parseRoute("#/datasets"), root("datasets"));
});

test("un ancien lien sans client est reconnu", () => {
  assert.deepEqual(parseRoute("#/inventory/devices/7"), client(null, "inventory", 7));
  assert.deepEqual(parseRoute("#/jobs"), client(null, "jobs"));
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

test("un lien vers un autre client ouvre ce client, depuis un client ou depuis Root", () => {
  assert.deepEqual(resolveRoute(parseRoute("#/c/7/inventory/devices/3"), TECH), { action: "switch", clientId: 7 });
  assert.deepEqual(resolveRoute(parseRoute("#/c/7/jobs"), ADMIN_SUR_ROOT), { action: "switch", clientId: 7 });
  assert.deepEqual(resolveRoute(parseRoute("#/c/7/jobs"), { workspace_id: null }), { action: "switch", clientId: 7 });
});

test("Root s'affiche pour une session Root", () => {
  const route = parseRoute("#/root/access");

  assert.deepEqual(resolveRoute(route, ADMIN_SUR_ROOT), { action: "show", route });
});

test("un lien vers Root ouvre Root quand un client est ouvert", () => {
  assert.deepEqual(resolveRoute(parseRoute("#/root/platform"), ADMIN_SUR_CLIENT), { action: "switch-root" });
});

test("Root n'est jamais ouvert à un compte qui n'est pas admin global", () => {
  assert.deepEqual(resolveRoute(parseRoute("#/root/access"), TECH), { action: "redirect", hash: "#/c/2/dashboard" });
  assert.deepEqual(resolveRoute(parseRoute("#/c/2/datasets"), TECH), { action: "redirect", hash: "#/c/2/dashboard" });
  assert.deepEqual(resolveRoute(parseRoute("#/root"), { workspace_id: null, is_global_admin: false }), { action: "pick" });
});

test("sur Root sans lien, on arrive sur la vue d'ensemble ; un ancien lien sans client fait choisir", () => {
  assert.deepEqual(resolveRoute(parseRoute(""), ADMIN_SUR_ROOT), { action: "redirect", hash: "#/root/overview" });
  assert.deepEqual(resolveRoute(parseRoute("#/inventory/devices/7"), ADMIN_SUR_ROOT), { action: "pick" });
});

test("sans rien d'ouvert, un compte ordinaire choisit son client", () => {
  for (const hash of ["", "#/jobs"]) {
    assert.deepEqual(resolveRoute(parseRoute(hash), { workspace_id: null, is_global_admin: false }), { action: "pick" }, hash);
  }
});

test("un ancien lien est redirigé vers la même page du client ouvert", () => {
  assert.deepEqual(resolveRoute(parseRoute("#/inventory/devices/7"), TECH), { action: "redirect", hash: "#/c/2/inventory/devices/7" });
});

test("sans route, on arrive sur le tableau de bord du client ouvert", () => {
  assert.deepEqual(resolveRoute(parseRoute(""), TECH), { action: "redirect", hash: "#/c/2/dashboard" });
});

test("une session Root est celle d'un admin global sans client ouvert", () => {
  assert.equal(isRootSession(ADMIN_SUR_ROOT), true);
  assert.equal(isRootSession(ADMIN_SUR_CLIENT), false);
  assert.equal(isRootSession({ workspace_id: null, is_global_admin: false }), false);
  assert.equal(isRootSession(null), false);
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

test("les paramètres d'un client sont réservés à son admin", () => {
  for (const role of ["analyst", "viewer"]) {
    const user = { workspace_id: 2, role };
    assert.equal(canOpenPage(user, "settings"), false, role);
    assert.deepEqual(resolveRoute(parseRoute("#/c/2/settings"), user), { action: "redirect", hash: "#/c/2/dashboard" });
    assert.equal(canOpenPage(user, "jobs"), true);
  }
  const route = parseRoute("#/c/2/settings");
  assert.deepEqual(resolveRoute(route, { workspace_id: 2, role: "admin" }), { action: "show", route });
  assert.deepEqual(resolveRoute(route, { workspace_id: 2, role: "viewer", is_global_admin: true }), { action: "show", route });
});
