import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { resolveFilePath } from "../server.js";

test("resolveFilePath only allows application assets", () => {
  const root = path.join(path.sep, "tmp", "totp-authenticator");

  assert.equal(resolveFilePath(root, "/"), path.join(root, "index.html"));
  assert.equal(resolveFilePath(root, "/styles.css"), path.join(root, "styles.css"));
  assert.equal(resolveFilePath(root, "/src/app.js"), path.join(root, "src", "app.js"));

  assert.equal(resolveFilePath(root, "/data/authenticator.sqlite"), null);
  assert.equal(resolveFilePath(root, "/server.js"), null);
  assert.equal(resolveFilePath(root, "/../authenticator.sqlite"), null);
});
