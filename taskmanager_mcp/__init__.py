"""TaskManager MCP Server Package.

OAuth-protected MCP server for TaskManager integration.
"""

from taskmanager_mcp.task_api import ApiResponse, TaskManagerAPI, create_authenticated_client
from taskmanager_mcp.token_verifier import IntrospectionTokenVerifier

__all__ = [
    "ApiResponse",
    "TaskManagerAPI",
    "create_authenticated_client",
    "IntrospectionTokenVerifier",
]

__version__ = "0.1.0"
