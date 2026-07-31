import test from "node:test";
import assert from "node:assert/strict";
import {
  base32ToBytes,
  formatOtp,
  isEncryptedBackupText,
  isSafeHttpUrl,
  normalizeSecret,
  parseEntryKey,
  parseOtpauthUri,
  sanitizePublicEntry,
  validateEntry,
} from "./totp.js";

test("normalizeSecret and base32ToBytes normalize base32 input", () => {
  assert.equal(normalizeSecret("jbsw y3dp ehpk 3pxp==="), "JBSWY3DPEHPK3PXP");
  assert.equal(Buffer.from(base32ToBytes("MZXW6===")).toString("utf8"), "foo");
  assert.throws(() => normalizeSecret("JBSW0Y3D"), /Base32/);
  assert.throws(() => base32ToBytes("A"), /长度不足/);
});

test("parseOtpauthUri and parseEntryKey parse valid secrets", () => {
  const uri = "otpauth://totp/GitHub:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30";
  const parsed = parseOtpauthUri(uri);
  assert.equal(parsed.issuer, "GitHub");
  assert.equal(parsed.account, "demo@example.com");
  assert.equal(parsed.label, "demo@example.com");
  assert.equal(parseEntryKey(uri).secret, "JBSWY3DPEHPK3PXP");
  assert.equal(parseEntryKey("JBSWY3DPEHPK3PXP").algorithm, "SHA1");
});

test("validateEntry only allows supported values and safe websites", () => {
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
});

test("public entries never retain a secret field", () => {
  const publicEntry = sanitizePublicEntry({
    id: "github",
    label: "GitHub",
    secret: "JBSWY3DPEHPK3PXP",
    createdAt: 1,
  });
  assert.equal(Object.hasOwn(publicEntry, "secret"), false);
  assert.equal(publicEntry.label, "GitHub");
});

test("backup format detection and OTP display formatting", () => {
  assert.equal(
    isEncryptedBackupText('{"format":"totp-authenticator-backup","version":1}'),
    true,
  );
  assert.equal(isEncryptedBackupText('{"version":1,"entries":[]}'), false);
  assert.equal(formatOtp("123456"), "123 456");
  assert.equal(formatOtp("12345678"), "1234 5678");
});
