import { sanitizeEntry } from "./totp.js";

async function readApiResponse(response) {
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "请求失败。");
  }
  return payload;
}

export async function loadEntries() {
  const response = await fetch("/api/entries");
  const payload = await readApiResponse(response);
  return Array.isArray(payload.entries) ? payload.entries.map((entry) => sanitizeEntry(entry)) : [];
}

export async function saveEntries(entries) {
  const response = await fetch("/api/entries", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ entries }),
  });
  const payload = await readApiResponse(response);
  return Array.isArray(payload.entries) ? payload.entries.map((entry) => sanitizeEntry(entry)) : [];
}
