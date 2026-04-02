const DEFAULT_PERIOD = 30;
const DEFAULT_DIGITS = 6;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HASH_ALGORITHM_MAP = {
  SHA1: "SHA-1",
  SHA256: "SHA-256",
  SHA512: "SHA-512",
};

export function normalizeSecret(secret) {
  const normalized = String(secret || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");

  if (!normalized) {
    return "";
  }

  if (!/^[A-Z2-7]+=*$/.test(normalized) || /=+[A-Z2-7]/.test(normalized)) {
    throw new Error("密钥包含无效的 Base32 字符。");
  }

  return normalized.replace(/=+$/g, "");
}

export function base32ToBytes(secret) {
  const normalized = normalizeSecret(secret);

  if (!normalized) {
    throw new Error("密钥不能为空。");
  }

  let bits = "";
  for (const char of normalized) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value < 0) {
      throw new Error(`无效的 Base32 字符: ${char}`);
    }
    bits += value.toString(2).padStart(5, "0");
  }

  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2);
  }

  return bytes;
}

function counterToBytes(counter) {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  const high = Math.floor(counter / 2 ** 32);
  const low = counter >>> 0;
  view.setUint32(0, high);
  view.setUint32(4, low);
  return new Uint8Array(buffer);
}

async function signHmac(secretBytes, counterBytes, algorithm) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("当前环境不支持 Web Crypto。");
  }

  const hashName = HASH_ALGORITHM_MAP[String(algorithm).toUpperCase()];
  if (!hashName) {
    throw new Error(`不支持的算法：${algorithm}`);
  }

  const key = await subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: { name: hashName } },
    false,
    ["sign"],
  );

  const signature = await subtle.sign("HMAC", key, counterBytes);
  return new Uint8Array(signature);
}

export async function generateTotp(entry, at = Date.now()) {
  const period = Number(entry.period || DEFAULT_PERIOD);
  const digits = Number(entry.digits || DEFAULT_DIGITS);
  const algorithm = String(entry.algorithm || "SHA1").toUpperCase();
  const counter = Math.floor(Math.floor(at / 1000) / period);
  const secretBytes = base32ToBytes(entry.secret);
  const hmac = await signHmac(secretBytes, counterToBytes(counter), algorithm);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = String(binary % 10 ** digits).padStart(digits, "0");

  return otp;
}

export function formatOtp(code) {
  const chunkSize = code.length === 8 ? 4 : 3;
  return code.match(new RegExp(`.{1,${chunkSize}}`, "g"))?.join(" ") || code;
}

export function secondsRemaining(entry, at = Date.now()) {
  const period = Number(entry.period || DEFAULT_PERIOD);
  const currentSecond = Math.floor(at / 1000);
  return period - (currentSecond % period);
}

function parseLabel(labelText) {
  const decoded = decodeURIComponent(labelText || "");
  const dividerIndex = decoded.indexOf(":");

  if (dividerIndex === -1) {
    return { issuer: "", label: decoded.trim(), account: "" };
  }

  const issuer = decoded.slice(0, dividerIndex).trim();
  const account = decoded.slice(dividerIndex + 1).trim();
  return {
    issuer,
    label: account || issuer,
    account,
  };
}

export function parseOtpauthUri(uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error("无效的 otpauth URI。");
  }

  if (parsed.protocol !== "otpauth:" || parsed.hostname !== "totp") {
    throw new Error("仅支持 otpauth://totp 类型。");
  }

  const labelData = parseLabel(parsed.pathname.replace(/^\//, ""));
  const secret = parsed.searchParams.get("secret");
  if (!secret) {
    throw new Error("otpauth URI 缺少 secret 参数。");
  }

  return sanitizeEntry({
    label: labelData.label,
    account: labelData.account,
    issuer: parsed.searchParams.get("issuer") || labelData.issuer,
    secret,
    algorithm: (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase(),
    digits: Number(parsed.searchParams.get("digits") || DEFAULT_DIGITS),
    period: Number(parsed.searchParams.get("period") || DEFAULT_PERIOD),
    notes: "",
    website: "",
  });
}

export function parseEntryKey(input) {
  const trimmed = String(input || "").trim();

  if (!trimmed) {
    throw new Error("请先输入要解析的 Key。");
  }

  if (trimmed.startsWith("otpauth://")) {
    return parseOtpauthUri(trimmed);
  }

  base32ToBytes(trimmed);
  return sanitizeEntry({
    label: "",
    account: "",
    issuer: "",
    secret: trimmed,
    algorithm: "SHA1",
    digits: DEFAULT_DIGITS,
    period: DEFAULT_PERIOD,
    notes: "",
    website: "",
  });
}

function slugify(text) {
  return String(text || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, "-")
    .replace(/^-+|-+$/g, "") || "entry";
}

function createRandomIdSuffix() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  }

  if (globalThis.crypto?.getRandomValues) {
    const values = new Uint32Array(2);
    globalThis.crypto.getRandomValues(values);
    return Array.from(values, (value) => value.toString(36)).join("").slice(0, 12);
  }

  return `${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`.slice(0, 12);
}

function createEntryId(seed) {
  return `${slugify(seed)}-${Date.now()}-${createRandomIdSuffix()}`;
}

export function isSafeHttpUrl(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return false;
  }

  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export function sanitizeEntry(input) {
  const now = Date.now();
  return {
    id: input.id || createEntryId(input.issuer || input.label),
    label: String(input.label || "").trim(),
    account: String(input.account || "").trim(),
    issuer: String(input.issuer || "").trim(),
    secret: normalizeSecret(input.secret),
    algorithm: String(input.algorithm || "SHA1").toUpperCase(),
    digits: Number(input.digits || DEFAULT_DIGITS),
    period: Number(input.period || DEFAULT_PERIOD),
    notes: String(input.notes || "").trim(),
    website: String(input.website || "").trim(),
    createdAt: Number(input.createdAt || now),
    updatedAt: Number(input.updatedAt || now),
  };
}

function normalizeFingerprintText(value) {
  return String(value || "").trim().toLowerCase();
}

export function getEntryFingerprint(entry) {
  return normalizeSecret(entry.secret);
}

export function mergeImportedEntries(existingEntries, importedEntries) {
  const merged = new Map();
  const fingerprintIndex = new Map();

  function addIndexedEntry(rawEntry) {
    const entry = sanitizeEntry(rawEntry);
    merged.set(entry.id, entry);
    fingerprintIndex.set(getEntryFingerprint(entry), entry.id);
    return entry;
  }

  function removeIndexedEntry(entry) {
    merged.delete(entry.id);
    fingerprintIndex.delete(getEntryFingerprint(entry));
  }

  existingEntries.forEach((entry) => addIndexedEntry(entry));

  let added = 0;
  let replaced = 0;

  for (const rawImportedEntry of importedEntries) {
    const importedEntry = sanitizeEntry(rawImportedEntry);
    const targetId = fingerprintIndex.get(getEntryFingerprint(importedEntry));

    if (!targetId) {
      addIndexedEntry(importedEntry);
      added += 1;
      continue;
    }

    const currentEntry = merged.get(targetId);
    removeIndexedEntry(currentEntry);
    addIndexedEntry({
      ...importedEntry,
      id: currentEntry.id,
      createdAt: currentEntry.createdAt,
    });
    replaced += 1;
  }

  return {
    entries: [...merged.values()],
    added,
    replaced,
  };
}

export function validateEntry(entry) {
  if (!entry.label) {
    throw new Error("条目名称不能为空。");
  }
  if (!entry.secret) {
    throw new Error("密钥不能为空。");
  }
  if (![6, 8].includes(Number(entry.digits))) {
    throw new Error("位数只支持 6 或 8。");
  }
  if (![15, 30, 45, 60].includes(Number(entry.period))) {
    throw new Error("周期建议为 15 / 30 / 45 / 60 秒。");
  }
  if (!["SHA1", "SHA256", "SHA512"].includes(String(entry.algorithm).toUpperCase())) {
    throw new Error("算法只支持 SHA1 / SHA256 / SHA512。");
  }
  if (entry.website && !isSafeHttpUrl(entry.website)) {
    throw new Error("网址只支持 http 或 https。");
  }
  base32ToBytes(entry.secret);
}

export function createSnapshot(entries) {
  return {
    version: 1,
    updatedAt: Date.now(),
    entries: entries.map((entry) => sanitizeEntry(entry)),
  };
}

export function parseImportText(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed) {
    throw new Error("导入内容为空。");
  }

  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed.entries)) {
      throw new Error("JSON 备份缺少 entries 数组。");
    }
    return parsed.entries.map((entry) => sanitizeEntry(entry));
  }

  return trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => parseOtpauthUri(line));
}
