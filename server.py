import datetime
import json
import logging
import os
from typing import Any

import click
from dotenv import load_dotenv
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp.server import FastMCP
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse

from task_api import TaskManagerAPI
from token_verifier import IntrospectionTokenVerifier

logger = logging.getLogger(__name__)

DEFAULT_SCOPE = ["read"]

load_dotenv()
CLIENT_ID = os.environ["TASKMANAGER_CLIENT_ID"]
CLIENT_SECRET = os.environ["TASKMANAGER_CLIENT_SECRET"]


def get_api_client() -> TaskManagerAPI:
    """Get API client for authenticated user.
    
    Currently uses server credentials for all requests.
    In a production system, this should be modified to use
    user-specific authentication tokens.
    
    Returns:
        TaskManagerAPI: Authenticated API client
    """
    task_manager = TaskManagerAPI()
    # For now, use the server credentials
    # TODO: Implement user-specific authentication
    task_manager.login(CLIENT_ID, CLIENT_SECRET)
    return task_manager


def create_resource_server(
    host: str, port: int, server_url: str, auth_server_url: str, oauth_strict: bool
) -> FastMCP:
    """
    Create MCP Resource Server with token introspection.

    This server:
    1. Provides public MCP transport endpoint (/mcp) for discovery
    2. Validates tokens via Authorization Server introspection for tools
    3. Serves protected MCP tools and resources
    """
    # Create token verifier for introspection with RFC 8707 resource validation
    token_verifier = IntrospectionTokenVerifier(
        introspection_endpoint=f"{auth_server_url}/introspect",
        server_url=str(server_url),
        validate_resource=oauth_strict,  # Enable RFC 8707 resource validation when --oauth-strict is set
    )

    # Create FastMCP server with OAuth-protected endpoints
    app = FastMCP(
        name="TaskManager MCP Server",
        instructions="TaskManager MCP Server with OAuth-protected tools and resources",
        host=host,
        port=port,
        debug=True,
        token_verifier=token_verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(auth_server_url),
            required_scopes=DEFAULT_SCOPE,
            resource_server_url=AnyHttpUrl(server_url),
        ),
    )

    # Add OAuth 2.0 discovery endpoints for client auto-configuration
    # These endpoints allow MCP clients to discover OAuth configuration automatically
    @app.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def oauth_authorization_server_metadata(request: Request) -> JSONResponse:
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        auth_base = str(auth_server_url).rstrip("/")
        return JSONResponse(
            {
                "issuer": auth_base,
                "authorization_endpoint": f"{auth_base}/authorize",
                "token_endpoint": f"{auth_base}/token",
                "introspection_endpoint": f"{auth_base}/introspect",
                "registration_endpoint": f"{auth_base}/register",
                "scopes_supported": DEFAULT_SCOPE,
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
                "code_challenge_methods_supported": ["S256"],
            }
        )

    @app.custom_route("/mcp/.well-known/oauth-protected-resource", methods=["GET"])
    async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
        """OAuth 2.0 Protected Resource Metadata (RFC 9908)"""
        return JSONResponse(
            {
                "resource": str(server_url),
                "authorization_servers": [str(auth_server_url)],
                "scopes_supported": DEFAULT_SCOPE,
                "bearer_methods_supported": ["header"],
                "resource_documentation": f"{server_url}/docs",
            }
        )

    @app.custom_route("/.well-known/oauth-authorization-server/mcp", methods=["GET"])
    async def oauth_authorization_server_metadata_for_mcp(
        request: Request,
    ) -> JSONResponse:
        """Resource-specific OAuth 2.0 Authorization Server Metadata for /mcp resource"""
        auth_base = str(auth_server_url).rstrip("/")
        return JSONResponse(
            {
                "issuer": auth_base,
                "authorization_endpoint": f"{auth_base}/authorize",
                "token_endpoint": f"{auth_base}/token",
                "introspection_endpoint": f"{auth_base}/introspect",
                "registration_endpoint": f"{auth_base}/register",
                "scopes_supported": DEFAULT_SCOPE,
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
                "code_challenge_methods_supported": ["S256"],
                "resource": str(server_url),  # Resource-specific binding
            }
        )

    @app.tool()
    async def get_time() -> dict[str, Any]:
        """
        Get the current server time.

        This tool demonstrates that system information can be protected
        by OAuth authentication. User must be authenticated to access it.
        """
        # This tool is protected by OAuth authentication at the transport level
        # All requests to /mcp require a valid Bearer token

        now = datetime.datetime.now()

        return {
            "current_time": now.isoformat(),
            "timezone": "UTC",  # Simplified for demo
            "timestamp": now.timestamp(),
            "formatted": now.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @app.tool()
    async def get_all_projects() -> str:
        """
        Get all projects from the task manager.

        Returns a list of all projects that the authenticated user has access to.
        Each project includes its ID, name, description, and other metadata.
        
        Returns:
            JSON string containing list of project objects with fields like id, name, description, created_at, etc.
        """
        projects = get_api_client().get_projects().data
        if projects is None:
            return ""
        return json.dumps(projects)

    @app.tool()
    async def get_all_tasks() -> str:
        """
        Get all tasks (todos) from the task manager.

        Returns a list of all tasks that the authenticated user has access to.
        Each task includes its ID, title, description, status, priority, project assignment,
        and other metadata.

        Returns:
            JSON string containing list of task objects with fields like id, title, description, status,

            priority, project_id, due_date, created_at, etc.
        """
        tasks = get_api_client().get_todos().data
        if tasks is None:
            return ""
        return json.dumps(tasks)

    @app.tool()
    async def create_task(
        title: str,
        project_id: int | None = None,
        description: str | None = None,
        priority: str = "medium",
        due_date: str | None = None,
    ) -> str:
        """
        Create a new task in the task manager.

        Creates a new task with the specified title and optional metadata.
        The task will be assigned to the authenticated user and can optionally
        be associated with a project.

        Args:
            title: The title/name of the task (required)
            project_id: Optional ID of the project to assign this task to
            description: Optional detailed description of the task
            priority: Priority level - one of "low", "medium", "high" (default: "medium")
            due_date: Optional due date in ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)

        Returns:
            The created task object with generated ID and other metadata
        """
        response = get_api_client().create_todo(

            title=title,
            project_id=project_id,
            description=description,
            priority=priority,
            due_date=due_date,
        )
        return json.dumps(response.data)

    return app


@click.command()
@click.option("--port", default=8001, help="Port to listen on")
@click.option(
    "--auth-server",
    default="https://mcp-auth.brooksmcmillin.com",
    help="Authorization Server URL",
)
@click.option(
    "--server-url",
    help="External server URL (for OAuth). Defaults to https://localhost:PORT",
)
@click.option(
    "--oauth-strict",
    is_flag=True,
    help="Enable RFC 8707 resource validation",
)
def main(port: int, auth_server: str, server_url: str | None = None, oauth_strict: bool = False) -> int:
    """
    Run the TaskManager MCP server.

    Args:
        port: Port to bind the server to
        auth_server: URL of the OAuth authorization server
        server_url: Public URL of this server (for OAuth callbacks)
        oauth_strict: Enable RFC 8707 resource validation

    Returns:
        Exit code (0 for success, 1 for error)
    """

    logging.basicConfig(level=logging.INFO)

    try:
        # Create settings
        host = "0.0.0.0"  # Bind to all interfaces for reverse proxy

        # If no server specified, callback to binding address
        if server_url is None:
            server_url = f"https://{host}:{port}"
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Make sure to provide a valid Authorization Server URL")
        return 1

    try:
        mcp_server = create_resource_server(
            host, port, server_url, auth_server, oauth_strict
        )

        logger.info(f"🚀 MCP Resource Server running on {server_url}")
        logger.info(f"🔑 Using Authorization Server: {auth_server}")

        # Run the server - this should block and keep running
        mcp_server.run(transport="streamable-http")
        logger.info("Server stopped")
        return 0
    except Exception as e:
        logger.error(f"Server error: {e}")
        logger.exception("Exception details:")
        return 1


if __name__ == "__main__":
    main()
