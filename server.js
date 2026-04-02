import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { EntryStore } from "./db.js";

export const DEFAULT_HOST = "127.0.0.1";
export const DEFAULT_PORT = 4173;

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const STATIC_FILES = new Set(["index.html", "styles.css"]);
const STATIC_DIRECTORIES = new Set(["src"]);

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}

async function readJsonBody(req) {
  const rawBody = await readRequestBody(req);
  try {
    return JSON.parse(rawBody || "{}");
  } catch {
    throw new Error("Invalid JSON payload.");
  }
}

export function resolveFilePath(root, urlPath) {
  const pathname = decodeURIComponent(urlPath.split("?")[0]);
  const relativePath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const filePath = path.resolve(root, relativePath);
  const relativeToRoot = path.relative(root, filePath);
  const normalizedRelativePath = relativeToRoot.replace(/\\/g, "/");

  if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)) {
    return null;
  }

  if (
    !STATIC_FILES.has(normalizedRelativePath) &&
    !STATIC_DIRECTORIES.has(normalizedRelativePath.split("/")[0])
  ) {
    return null;
  }

  return filePath;
}

function serveStatic(root, req, res) {
  const filePath = resolveFilePath(root, req.url);

  if (!filePath) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.stat(filePath, (statError, stats) => {
    if (statError || !stats.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }

    const extname = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[extname] || "application/octet-stream";

    res.writeHead(200, { "Content-Type": contentType });
    fs.createReadStream(filePath).pipe(res);
  });
}

async function handleEntriesApi(store, req, res) {
  if (req.method === "GET") {
    sendJson(res, 200, { entries: store.listEntries() });
    return;
  }

  if (req.method === "PUT") {
    const payload = await readJsonBody(req);
    if (!Array.isArray(payload.entries)) {
      sendJson(res, 400, { error: "entries must be an array." });
      return;
    }

    const entries = store.replaceEntries(payload.entries);
    sendJson(res, 200, { entries });
    return;
  }

  res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Method not allowed");
}

export async function startServer({
  host = DEFAULT_HOST,
  port = DEFAULT_PORT,
  root = ROOT,
  databasePath = path.join(ROOT, "data", "authenticator.sqlite"),
} = {}) {
  const store = new EntryStore(databasePath);

  const server = http.createServer(async (req, res) => {
    try {
      if (req.url === "/api/entries") {
        await handleEntriesApi(store, req, res);
        return;
      }

      if (req.method !== "GET") {
        res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Method not allowed");
        return;
      }

      serveStatic(root, req, res);
    } catch (error) {
      sendJson(res, 500, { error: error.message });
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });

  server.on("close", () => {
    store.close();
  });

  const address = server.address();
  const actualPort = typeof address === "object" && address ? address.port : port;
  const url = `http://${host}:${actualPort}`;

  return {
    host,
    port: actualPort,
    url,
    server,
    async stop() {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || DEFAULT_PORT);
  startServer({ port })
    .then(({ url }) => {
      console.log(`TOTP Authenticator running at ${url}`);
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
}
