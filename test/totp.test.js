import test from "node:test";
import assert from "node:assert/strict";

test("placeholder for ESM bootstrap", async () => {
  const {
    base32ToBytes,
    generateTotp,
    isSafeHttpUrl,
    mergeImportedEntries,
    normalizeSecret,
    parseEntryKey,
    parseOtpauthUri,
    sanitizeEntry,
    validateEntry,
  } = await import("../src/totp.js");

  assert.equal(Buffer.from(base32ToBytes("MZXW6===")).toString("utf8"), "foo");

  const entry = {
    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    digits: 8,
    period: 30,
    algorithm: "SHA1",
  };
  const code = await generateTotp(entry, 59000);
  assert.equal(code, "94287082");

  const parsed = parseOtpauthUri(
    "otpauth://totp/GitHub:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30",
  );
  assert.equal(parsed.issuer, "GitHub");
  assert.equal(parsed.account, "demo@example.com");
  assert.equal(parsed.label, "demo@example.com");

  const parsedFromKey = parseEntryKey(
    "otpauth://totp/GitHub:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30",
  );
  assert.equal(parsedFromKey.secret, "JBSWY3DPEHPK3PXP");

  const parsedSecretOnly = parseEntryKey("JBSWY3DPEHPK3PXP");
  assert.equal(parsedSecretOnly.secret, "JBSWY3DPEHPK3PXP");
  assert.equal(parsedSecretOnly.algorithm, "SHA1");

  assert.equal(normalizeSecret("jbsw y3dp ehpk 3pxp==="), "JBSWY3DPEHPK3PXP");
  assert.throws(() => normalizeSecret("JBSW0Y3D"), /Base32/);
  assert.equal(isSafeHttpUrl("https://github.com/settings/security"), true);
  assert.equal(isSafeHttpUrl("file:///C:/Windows/System32"), false);
  assert.throws(
    () =>
      validateEntry({
        label: "GitHub",
        secret: "JBSWY3DPEHPK3PXP",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        website: "file:///C:/Windows/System32",
      }),
    /http 或 https/,
  );

  const originalNow = Date.now;
  Date.now = () => 1_700_000_000_000;

  try {
    const first = sanitizeEntry({ label: "GitHub", issuer: "GitHub", secret: "JBSWY3DPEHPK3PXP" });
    const second = sanitizeEntry({ label: "GitHub", issuer: "GitHub", secret: "JBSWY3DPEHPK3PXP" });
    assert.notEqual(first.id, second.id);

    const existingEntry = sanitizeEntry({
      id: "github-fixed-id",
      label: "demo@example.com",
      account: "demo@example.com",
      issuer: "GitHub",
      secret: "JBSWY3DPEHPK3PXP",
      notes: "old",
    });

    const mergeBySecret = mergeImportedEntries([existingEntry], [
      {
        id: "another-id",
        label: "demo@example.com",
        account: "demo@example.com",
        issuer: "GitHub",
        secret: "JBSWY3DPEHPK3PXP",
        notes: "secret-replaced",
      },
    ]);
    assert.equal(mergeBySecret.entries.length, 1);
    assert.equal(mergeBySecret.replaced, 1);
    assert.equal(mergeBySecret.entries[0].id, "github-fixed-id");
    assert.equal(mergeBySecret.entries[0].notes, "secret-replaced");

    const mergeWithDifferentSecret = mergeImportedEntries([existingEntry], [
      {
        id: "different-secret-id",
        label: "demo@example.com",
        account: "demo@example.com",
        issuer: "GitHub",
        secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        notes: "new-entry",
      },
    ]);
    assert.equal(mergeWithDifferentSecret.entries.length, 2);
    assert.equal(mergeWithDifferentSecret.added, 1);
  } finally {
    Date.now = originalNow;
  }
});
