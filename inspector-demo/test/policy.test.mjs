import assert from "node:assert/strict";
import test from "node:test";

import {
  PolicyError,
  buildConnectPayload,
  isSafeEventPath,
  sanitizeDisconnectPayload,
  sanitizeSendPayload,
} from "../policy.mjs";

const sessionId = "123e4567-e89b-42d3-a456-426614174000";

test("connect configuration is fixed and receives the server-side token", () => {
  const payload = buildConnectPayload("https://saturnx-mcp.onrender.com/mcp", "demo-token");
  assert.equal(payload.config.type, "streamable-http");
  assert.equal(payload.config.url, "https://saturnx-mcp.onrender.com/mcp");
  assert.equal(payload.config.headers, undefined);
  assert.deepEqual(payload.settings.headers, [
    { key: "Authorization", value: "Bearer demo-token" },
  ]);
  // Every field InspectorServerSettings requires (2.4.0) must be present,
  // or the real Inspector's /api/mcp/connect throws before ever reaching
  // our target server.
  for (const key of [
    "headers", "env", "metadata", "connectionTimeout", "requestTimeout",
    "taskTtl", "autoRefreshOnListChanged", "paginatedLists",
    "maxFetchRequests", "roots",
  ]) {
    assert.ok(key in payload.settings, `settings.${key} must be present`);
  }
});

test("metadata requests pass without client-controlled headers", () => {
  const payload = sanitizeSendPayload({
    sessionId,
    message: { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    headers: { Authorization: "attacker" },
    relatedRequestId: "attacker",
  });
  assert.deepEqual(payload, {
    sessionId,
    message: { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  });
});

test("tool execution and JSON-RPC batches are blocked", () => {
  assert.throws(
    () => sanitizeSendPayload({
      sessionId,
      message: { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "shell_exec" } },
    }),
    PolicyError
  );
  assert.throws(() => sanitizeSendPayload([{}]), PolicyError);
});

test("event and disconnect requests require a UUID session", () => {
  assert.deepEqual(sanitizeDisconnectPayload({ sessionId }), { sessionId });
  assert.equal(
    isSafeEventPath("/api/mcp/events", new URLSearchParams({ sessionId })),
    true
  );
  assert.equal(
    isSafeEventPath("/api/mcp/events", new URLSearchParams({ sessionId: "bad" })),
    false
  );
});
