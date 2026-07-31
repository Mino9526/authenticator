const DEFAULT_PERIOD = 30;
const DEFAULT_DIGITS = 6;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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
  if (!bytes.length) {
    throw new Error("Base32 密钥长度不足。");
  }
  return bytes;
}

export function formatOtp(code) {
  const normalized = String(code || "");
  const chunkSize = normalized.length === 8 ? 4 : 3;
  return normalized.match(new RegExp(`.{1,${chunkSize}}`, "g"))?.join(" ") || normalized;
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
  return {
    id: String(input.id || "").trim(),
    label: String(input.label || "").trim(),
    account: String(input.account || "").trim(),
    issuer: String(input.issuer || "").trim(),
    secret: normalizeSecret(input.secret),
    algorithm: String(input.algorithm || "SHA1").toUpperCase(),
    digits: Number(input.digits || DEFAULT_DIGITS),
    period: Number(input.period || DEFAULT_PERIOD),
    notes: String(input.notes || "").trim(),
    website: String(input.website || "").trim(),
  };
}

export function sanitizePublicEntry(input) {
  return {
    id: String(input.id || "").trim(),
    label: String(input.label || "").trim(),
    account: String(input.account || "").trim(),
    issuer: String(input.issuer || "").trim(),
    algorithm: String(input.algorithm || "SHA1").toUpperCase(),
    digits: Number(input.digits || DEFAULT_DIGITS),
    period: Number(input.period || DEFAULT_PERIOD),
    notes: String(input.notes || "").trim(),
    website: String(input.website || "").trim(),
    createdAt: Number(input.createdAt || 0),
    updatedAt: Number(input.updatedAt || 0),
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
    throw new Error("周期只支持 15 / 30 / 45 / 60 秒。");
  }
  if (!["SHA1", "SHA256", "SHA512"].includes(String(entry.algorithm).toUpperCase())) {
    throw new Error("算法只支持 SHA1 / SHA256 / SHA512。");
  }
  if (entry.website && !isSafeHttpUrl(entry.website)) {
    throw new Error("网址只支持 http 或 https。");
  }
  base32ToBytes(entry.secret);
}

export function isEncryptedBackupText(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed.startsWith("{")) {
    return false;
  }
  try {
    const parsed = JSON.parse(trimmed);
    return parsed?.format === "totp-authenticator-backup";
  } catch {
    return false;
  }
}
