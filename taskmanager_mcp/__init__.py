"""TaskManager MCP Server Package.

OAuth-protected MCP server for TaskManager integration.
"""

from taskmanager_sdk import (
    ApiResponse,
    TaskManagerClient,
    create_authenticated_client,
)

from taskmanager_mcp.token_verifier import IntrospectionTokenVerifier

# Backwards compatibility alias
TaskManagerAPI = TaskManagerClient

__all__ = [
    "ApiResponse",
    "TaskManagerAPI",
    "TaskManagerClient",
    "create_authenticated_client",
    "IntrospectionTokenVerifier",
]

__version__ = "0.1.0"
