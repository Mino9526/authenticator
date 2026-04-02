import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { EntryStore } from "../db.js";

test("EntryStore persists entries in sqlite", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "totp-authenticator-"));
  const dbPath = path.join(tempDir, "authenticator.sqlite");
  const store = new EntryStore(dbPath);

  const savedEntries = store.replaceEntries([
    {
      label: "GitHub",
      account: "demo@example.com",
      issuer: "GitHub",
      secret: "JBSWY3DPEHPK3PXP",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      notes: "security",
      website: "https://github.com",
    },
  ]);

  assert.equal(savedEntries.length, 1);
  assert.equal(savedEntries[0].issuer, "GitHub");

  const reopenedStore = new EntryStore(dbPath);
  const loadedEntries = reopenedStore.listEntries();

  assert.equal(loadedEntries.length, 1);
  assert.equal(loadedEntries[0].account, "demo@example.com");
  assert.equal("tags" in loadedEntries[0], false);

  store.close();
  reopenedStore.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});
