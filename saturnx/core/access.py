"""Request-level access controls for hosted SaturnX clients."""

from __future__ import annotations

from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

INSPECTOR_ACCESS_CLAIM = "saturnx_access"
INSPECTOR_READ_ONLY_VALUE = "inspect"


def is_read_only_inspector_request() -> bool:
    """Return whether the active bearer token is limited to metadata inspection."""
    token = get_access_token()
    return bool(
        token
        and token.claims.get(INSPECTOR_ACCESS_CLAIM) == INSPECTOR_READ_ONLY_VALUE
    )


class ReadOnlyInspectorMiddleware(Middleware):
    """Prevent the public Inspector token from executing any SaturnX tool."""

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> ToolResult:
        if not is_read_only_inspector_request():
            return await call_next(context)

        message = getattr(context, "message", None)
        tool_name = getattr(message, "name", "<unknown>")
        return ToolResult(
            structured_content={
                "tool": tool_name,
                "status": "blocked",
                "error_type": "read_only_demo",
                "recoverable": False,
                "message": (
                    "This public MCP Inspector session is read-only. "
                    "Tool execution requires a private SaturnX bearer token."
                ),
            },
            is_error=True,
        )
