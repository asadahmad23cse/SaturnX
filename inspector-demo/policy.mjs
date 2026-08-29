const READ_ONLY_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "ping",
  "tools/list",
  "resources/list",
  "resources/templates/list",
  "prompts/list",
]);

const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class PolicyError extends Error {
  constructor(message, status = 403) {
    super(message);
    this.name = "PolicyError";
    this.status = status;
  }
}

export function buildConnectPayload(remoteUrl, bearerToken) {
  const target = new URL(remoteUrl);
  if (target.protocol !== "https:" || target.pathname !== "/mcp") {
    throw new PolicyError("The configured MCP target must be an HTTPS /mcp endpoint.", 500);
  }
  if (!bearerToken || /[\r\n]/.test(bearerToken)) {
    throw new PolicyError("The read-only MCP credential is unavailable.", 503);
  }
  // Matches core/mcp/types.ts's InspectorServerSettings (Inspector 2.4.0):
  // every field below is required by that interface, and the bearer token
  // is read from settings.headers (an array of {key,value} pairs) — NOT
  // from config.headers, which StreamableHttpServerConfig doesn't define.
  return {
    config: {
      type: "streamable-http",
      url: target.toString(),
    },
    settings: {
      headers: [{ key: "Authorization", value: `Bearer ${bearerToken}` }],
      env: [],
      metadata: {},
      connectionTimeout: 60000,
      requestTimeout: 60000,
      taskTtl: 60000,
      autoRefreshOnListChanged: false,
      paginatedLists: false,
      maxFetchRequests: 1000,
      roots: [],
    },
  };
}

export function sanitizeSendPayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new PolicyError("Invalid Inspector request body.", 400);
  }
  const { sessionId, message, protocolVersion } = body;
  if (typeof sessionId !== "string" || !SESSION_ID.test(sessionId)) {
    throw new PolicyError("Invalid Inspector session.", 400);
  }
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    throw new PolicyError("Invalid MCP message.", 400);
  }
  if (message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    throw new PolicyError("Only MCP JSON-RPC requests are accepted.", 400);
  }
  if (!READ_ONLY_METHODS.has(message.method)) {
    throw new PolicyError(
      `MCP method '${message.method}' is disabled in the public read-only demo.`
    );
  }
  const sanitized = { sessionId, message };
  if (typeof protocolVersion === "string" && protocolVersion.length <= 64) {
    sanitized.protocolVersion = protocolVersion;
  }
  return sanitized;
}

export function sanitizeDisconnectPayload(body) {
  if (!body || typeof body.sessionId !== "string" || !SESSION_ID.test(body.sessionId)) {
    throw new PolicyError("Invalid Inspector session.", 400);
  }
  return { sessionId: body.sessionId };
}

export function isSafeEventPath(pathname, searchParams) {
  if (pathname !== "/api/mcp/events") return false;
  const sessionId = searchParams.get("sessionId") || "";
  return SESSION_ID.test(sessionId) && [...searchParams.keys()].every((key) => key === "sessionId");
}
