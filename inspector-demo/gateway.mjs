import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  PolicyError,
  buildConnectPayload,
  isSafeEventPath,
  sanitizeDisconnectPayload,
  sanitizeSendPayload,
} from "./policy.mjs";

const directory = dirname(fileURLToPath(import.meta.url));
const publicPort = Number.parseInt(process.env.PORT || "10000", 10);
const inspectorPort = 6274;
const remoteUrl = process.env.SATURNX_REMOTE_MCP_URL || "https://saturnx-mcp.onrender.com/mcp";
const bearerToken = process.env.SATURNX_DEMO_BEARER_TOKEN || "";
const maxBodyBytes = 64 * 1024;
let inspectorReady = false;

if (!Number.isInteger(publicPort) || publicPort < 1 || publicPort > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}
buildConnectPayload(remoteUrl, bearerToken);

const inspector = spawn(
  process.execPath,
  [
    join(directory, "node_modules", "@modelcontextprotocol", "inspector", "clients", "launcher", "build", "index.js"),
    "--web",
    "--config",
    join(directory, "inspector.json"),
  ],
  {
    cwd: directory,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      CLIENT_PORT: String(inspectorPort),
      MCP_AUTO_OPEN_ENABLED: "false",
      ALLOWED_ORIGINS: `http://127.0.0.1:${inspectorPort}`,
      // The Inspector binds to the loopback interface only (HOST=127.0.0.1),
      // so it is unreachable from outside this container/instance — this
      // gateway process is its only possible caller. Its own per-process
      // session-token auth exists to stop arbitrary web pages from reaching
      // a developer's local Inspector; it is redundant (and, without the
      // gateway forwarding the token, actively breaks every proxied route)
      // in this deployment, where the real access control is enforced
      // independently by this gateway's read-only policy and by
      // SaturnX's own ReadOnlyInspectorMiddleware.
      DANGEROUSLY_OMIT_AUTH: "true",
    },
    stdio: ["ignore", "pipe", "pipe"],
  }
);

inspector.stdout.on("data", (chunk) => process.stdout.write(`[inspector] ${chunk}`));
inspector.stderr.on("data", (chunk) => process.stderr.write(`[inspector] ${chunk}`));
inspector.on("exit", (code, signal) => {
  inspectorReady = false;
  console.error(`[gateway] Inspector exited (code=${code}, signal=${signal}).`);
  if (!server.listening) process.exit(code || 1);
});

function probeInspector() {
  const request = http.get(
    { hostname: "127.0.0.1", port: inspectorPort, path: "/", timeout: 1000 },
    (response) => {
      response.resume();
      inspectorReady = response.statusCode === 200;
      if (!inspectorReady) setTimeout(probeInspector, 500);
    }
  );
  request.on("timeout", () => request.destroy());
  request.on("error", () => setTimeout(probeInspector, 500));
}
probeInspector();

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBodyBytes) throw new PolicyError("Request body is too large.", 413);
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new PolicyError("Invalid JSON body.", 400);
  }
}

function jsonResponse(response, status, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": body.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function proxyRequest(request, response, bodyOverride) {
  const headers = { ...request.headers };
  delete headers.connection;
  delete headers["content-length"];
  delete headers["transfer-encoding"];
  headers.host = `127.0.0.1:${inspectorPort}`;
  if (headers.origin) headers.origin = `http://127.0.0.1:${inspectorPort}`;

  const body = bodyOverride === undefined ? undefined : Buffer.from(JSON.stringify(bodyOverride));
  if (body) {
    headers["content-type"] = "application/json";
    headers["content-length"] = String(body.length);
  }

  const upstream = http.request(
    {
      hostname: "127.0.0.1",
      port: inspectorPort,
      method: request.method,
      path: request.url,
      headers,
    },
    (upstreamResponse) => {
      const responseHeaders = { ...upstreamResponse.headers };
      delete responseHeaders.connection;
      delete responseHeaders["transfer-encoding"];
      responseHeaders["x-content-type-options"] = "nosniff";
      responseHeaders["referrer-policy"] = "no-referrer";
      response.writeHead(upstreamResponse.statusCode || 502, responseHeaders);
      upstreamResponse.pipe(response);
    }
  );
  upstream.on("error", (error) => {
    if (!response.headersSent) jsonResponse(response, 502, { error: "Inspector is unavailable." });
    else response.destroy(error);
  });
  if (body) upstream.end(body);
  else request.pipe(upstream);
}

const safeGetPaths = new Set([
  "/api/config",
  "/api/servers",
  "/api/servers/events",
  "/api/storage/client",
]);

const server = http.createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
    const pathname = requestUrl.pathname;

    if (pathname === "/healthz") {
      return jsonResponse(response, inspectorReady ? 200 : 503, {
        status: inspectorReady ? "ok" : "starting",
        service: "saturnx-inspector-demo",
        access: "read-only",
      });
    }
    if (!inspectorReady) return jsonResponse(response, 503, { error: "Inspector is starting." });

    if (!pathname.startsWith("/api/")) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return jsonResponse(response, 405, { error: "Method not allowed." });
      }
      return proxyRequest(request, response);
    }

    if (request.method === "GET" && safeGetPaths.has(pathname)) {
      return proxyRequest(request, response);
    }
    if (request.method === "GET" && isSafeEventPath(pathname, requestUrl.searchParams)) {
      return proxyRequest(request, response);
    }
    if (request.method === "POST" && pathname === "/api/mcp/connect") {
      await readJson(request);
      return proxyRequest(request, response, buildConnectPayload(remoteUrl, bearerToken));
    }
    if (request.method === "POST" && pathname === "/api/mcp/send") {
      const body = sanitizeSendPayload(await readJson(request));
      return proxyRequest(request, response, body);
    }
    if (request.method === "POST" && pathname === "/api/mcp/disconnect") {
      const body = sanitizeDisconnectPayload(await readJson(request));
      return proxyRequest(request, response, body);
    }
    return jsonResponse(response, 403, { error: "Disabled in the public read-only demo." });
  } catch (error) {
    if (error instanceof PolicyError) return jsonResponse(response, error.status, { error: error.message });
    console.error("[gateway] Request failed:", error);
    return jsonResponse(response, 500, { error: "Internal gateway error." });
  }
});

server.listen(publicPort, "0.0.0.0", () => {
  console.log(`[gateway] Read-only Inspector listening on port ${publicPort}.`);
});

function shutdown(signal) {
  console.log(`[gateway] Received ${signal}; shutting down.`);
  server.close(() => process.exit(0));
  inspector.kill("SIGTERM");
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
