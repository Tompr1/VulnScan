import { test } from "node:test";
import assert from "node:assert/strict";

import { assetCounts, folderChoices, isHost, targetLabel, treeRows } from "../src/design/assetsModel.js";

const ASSETS = [
  { id: 1, name: "VM UBUNTU", parent_id: null, target_list: [] },
  { id: 2, name: "FW", parent_id: null, target_list: [] },
  { id: 3, name: "Sophos", parent_id: 2, target_list: ["192.168.3.1"] },
  { id: 4, name: "ERP", parent_id: 1, target_list: ["192.168.3.20"] },
  { id: 5, name: "dmz", parent_id: 2, target_list: [] },
];

test("l'arbre range chaque asset sous son parent", () => {
  assert.deepEqual(treeRows(ASSETS).map(r => [r.asset.name, r.depth]), [
    ["FW", 0], ["dmz", 1], ["Sophos", 1], ["VM UBUNTU", 0], ["ERP", 1],
  ]);
});

test("un asset dont le parent n'existe plus remonte au premier niveau", () => {
  const rows = treeRows([{ id: 7, name: "orphelin", parent_id: 99 }, { id: 8, name: "A", parent_id: null }]);
  assert.deepEqual(rows.map(r => [r.asset.name, r.depth]), [["A", 0], ["orphelin", 0]]);
});

test("une boucle de parents ne fait pas disparaître d'asset", () => {
  const rows = treeRows([{ id: 1, name: "a", parent_id: 2 }, { id: 2, name: "b", parent_id: 1 }]);
  assert.equal(rows.length, 2);
});

test("un hôte n'est pas un dossier où ajouter des hôtes", () => {
  assert.equal(isHost(ASSETS[2]), true);
  assert.equal(isHost(ASSETS[0]), false);
  assert.deepEqual(folderChoices(ASSETS), [
    { id: 2, label: "FW" }, { id: 5, label: "FW / dmz" }, { id: 1, label: "VM UBUNTU" },
  ]);
});

test("les compteurs séparent dossiers, sous-dossiers et hôtes", () => {
  assert.deepEqual(assetCounts(ASSETS), { folders: 2, subFolders: 1, hosts: 2 });
});

test("une cible s'affiche sous son alias", () => {
  assert.equal(targetLabel({ target: "10.0.0.1", name: "ERP" }), "ERP (10.0.0.1)");
  assert.equal(targetLabel({ target: "10.0.0.1", name: null }), "10.0.0.1");
});
