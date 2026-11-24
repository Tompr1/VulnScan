// Run with: node --test tests/   (from frontend/)
import { test } from "node:test";
import assert from "node:assert/strict";

import { describeSource, grantsOf, namesOf, principalLabel, scopeLabel, toggleId } from "../src/design/accessModel.js";

const DIRECT = { id: 1, role: "viewer", user: { id: 2, email: "tech@msp.example" }, user_group: null, client: { id: 1, name: "Acme" }, client_group: null };
const PAR_GROUPE = { id: 3, role: "admin", user: null, user_group: { id: 20, name: "Niveau 1" }, client: null, client_group: { id: 10, name: "Santé" } };

test("une attribution nomme son bénéficiaire et sa cible", () => {
  assert.equal(principalLabel(DIRECT), "tech@msp.example");
  assert.equal(principalLabel(PAR_GROUPE), "Group Niveau 1");
  assert.equal(scopeLabel(DIRECT), "Acme");
  assert.equal(scopeLabel(PAR_GROUPE), "Client group Santé");
});

test("la source d'un droit se lit en une phrase", () => {
  assert.equal(describeSource({ user_group: null, client_group: null }), "Direct grant, on the client");
  assert.equal(
    describeSource({ user_group: { name: "Niveau 1" }, client_group: { name: "Santé" } }),
    "Through group Niveau 1, on client group Santé",
  );
});

test("cocher puis décocher un membre", () => {
  assert.deepEqual(toggleId([3, 1], 2), [1, 2, 3]);
  assert.deepEqual(toggleId([1, 2, 3], 2), [1, 3]);
});

test("les noms des membres suivent l'ordre de la liste", () => {
  const clients = [{ id: 1, name: "Acme" }, { id: 2, name: "Globex" }, { id: 3, name: "Hôpital" }];

  assert.deepEqual(namesOf([3, 1], clients), ["Acme", "Hôpital"]);
  assert.deepEqual(namesOf([2], [{ id: 2, email: "lea@acme.example" }], "email"), ["lea@acme.example"]);
});

test("on retrouve les attributions d'un compte, d'un groupe ou d'un client", () => {
  const grants = [DIRECT, PAR_GROUPE];

  assert.deepEqual(grantsOf(grants, { userId: 2 }).map(g => g.id), [1]);
  assert.deepEqual(grantsOf(grants, { userGroupId: 20 }).map(g => g.id), [3]);
  assert.deepEqual(grantsOf(grants, { clientId: 1 }).map(g => g.id), [1]);
  assert.deepEqual(grantsOf(grants, { clientGroupId: 10 }).map(g => g.id), [3]);
  assert.deepEqual(grantsOf(grants, {}), []);
});
