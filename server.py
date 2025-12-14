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
# OAuth client credentials (for MCP OAuth flow)
CLIENT_ID = os.environ["TASKMANAGER_CLIENT_ID"]
CLIENT_SECRET = os.environ["TASKMANAGER_CLIENT_SECRET"]
MCP_AUTH_SERVER = os.environ["MCP_AUTH_SERVER"]

# TaskManager API URL
TASKMANAGER_URL = os.environ.get("TASKMANAGER_OAUTH_HOST", "http://localhost:4321")

# User credentials for API access
USERNAME = os.environ.get("TASKMANAGER_USERNAME", CLIENT_ID)
PASSWORD = os.environ.get("TASKMANAGER_PASSWORD", CLIENT_SECRET)


def get_api_client() -> TaskManagerAPI:
    """Get API client for authenticated user.

    Currently uses server credentials for all requests.
    In a production system, this should be modified to use
    user-specific authentication tokens.

    Returns:
        TaskManagerAPI: Authenticated API client
    """

    # Use the public TaskManager URL for API calls
    task_manager = TaskManagerAPI(base_url=f"{TASKMANAGER_URL}/api")

    # Use username/password for API authentication
    response = task_manager.login(USERNAME, PASSWORD)
    if not response.success:
        logger.error(f"Failed to authenticate with TaskManager API: {response.error}")
        raise Exception(f"API authentication failed: {response.error}")
    logger.debug("Successfully authenticated with TaskManager API")
    return task_manager


def create_resource_server(
    port: int,
    server_url: str,
    auth_server_url: str,
    auth_server_public_url: str,
    oauth_strict: bool,
) -> FastMCP:
    """
    Create MCP Resource Server with token introspection.

    This server:
    1. Provides public MCP transport endpoint (/mcp) for discovery
    2. Validates tokens via Authorization Server introspection for tools
    3. Serves protected MCP tools and resources

    Args:
        port: Port to listen on
        server_url: Public URL of this server
        auth_server_url: Internal auth server URL (for introspection)
        auth_server_public_url: Public auth server URL (for OAuth metadata)
        oauth_strict: Enable RFC 8707 resource validation
    """
    # Create token verifier for introspection with RFC 8707 resource validation
    # Use internal URL for introspection (server-to-server communication)
    token_verifier = IntrospectionTokenVerifier(
        introspection_endpoint=f"{auth_server_url}/introspect",
        server_url=str(server_url),
        validate_resource=oauth_strict,  # Enable RFC 8707 resource validation when --oauth-strict is set
    )

    # Create FastMCP server with OAuth-protected endpoints
    # Don't specify host - let it default and use resource_server_url for OAuth
    # Use public auth server URL for OAuth flows
    app = FastMCP(
        name="TaskManager MCP Server",
        instructions="TaskManager MCP Server with OAuth-protected tools and resources",
        port=port,
        debug=True,
        token_verifier=token_verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(auth_server_public_url),
            required_scopes=DEFAULT_SCOPE,
            resource_server_url=AnyHttpUrl(server_url),
        ),
    )

    # CORS middleware will be added when we run the server with uvicorn

    # Add OAuth 2.0 discovery endpoints for client auto-configuration
    # These endpoints allow MCP clients to discover OAuth configuration automatically

    @app.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
    async def oauth_protected_resource_main(request: Request) -> JSONResponse:
        """OAuth 2.0 Protected Resource Metadata (RFC 9908) - Main endpoint"""
        logger.info("=== OAuth Protected Resource Metadata Request (Main) ===")
        logger.info(f"Request URL: {request.url}")
        logger.info(f"Host header: {request.headers.get('host')}")

        # Remove trailing slashes for OAuth spec compliance
        resource_url = str(server_url).rstrip("/")
        auth_server_url_no_slash = str(auth_server_public_url).rstrip("/")

        logger.info(f"Returning resource: {resource_url}")
        logger.info(f"Returning auth_servers: {auth_server_url_no_slash}")

        return JSONResponse(
            {
                "resource": resource_url,
                "authorization_servers": [auth_server_url_no_slash],
                "scopes_supported": DEFAULT_SCOPE,
                "bearer_methods_supported": ["header"],
            }
        )

    @app.custom_route("/.well-known/openid-configuration", methods=["GET", "OPTIONS"])
    async def openid_configuration(request: Request) -> JSONResponse:
        """OpenID Connect Discovery (aliases to OAuth Authorization Server Metadata)"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return JSONResponse(
                {},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                },
            )

        # OpenID Connect discovery - return same metadata as OAuth
        auth_base = str(auth_server_public_url).rstrip("/")

        logger.info("=== OpenID Configuration Request ===")
        logger.info(f"Request URL: {request.url}")
        logger.info(f"Host header: {request.headers.get('host')}")
        logger.info(f"Returning issuer: {auth_base}")

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
            },
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            },
        )

    @app.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
    async def oauth_authorization_server_metadata(request: Request) -> JSONResponse:
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return JSONResponse(
                {},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                },
            )

        # Use public auth server URL for client-facing OAuth metadata
        # Remove trailing slash for OAuth spec compliance
        auth_base = str(auth_server_public_url).rstrip("/")

        logger.info("=== OAuth Authorization Server Metadata Request ===")
        logger.info(f"Request URL: {request.url}")
        logger.info(f"Host header: {request.headers.get('host')}")
        logger.info(f"X-Forwarded-Proto: {request.headers.get('x-forwarded-proto')}")
        logger.info(f"X-Forwarded-For: {request.headers.get('x-forwarded-for')}")
        logger.info(f"Returning auth_base: {auth_base}")

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
            },
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            },
        )

    @app.custom_route("/mcp/.well-known/oauth-protected-resource", methods=["GET"])
    async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
        """OAuth 2.0 Protected Resource Metadata (RFC 9908)"""
        logger.info("=== OAuth Protected Resource Metadata Request (MCP-specific) ===")
        logger.info(f"Request URL: {request.url}")
        logger.info(f"Host header: {request.headers.get('host')}")
        logger.info(f"Returning resource: {server_url}")
        logger.info(f"Returning auth_servers: {auth_server_public_url}")

        # Remove trailing slashes for OAuth spec compliance
        resource_url = str(server_url).rstrip("/")
        auth_server_url_no_slash = str(auth_server_public_url).rstrip("/")

        return JSONResponse(
            {
                "resource": resource_url,
                "authorization_servers": [auth_server_url_no_slash],
                "scopes_supported": DEFAULT_SCOPE,
                "bearer_methods_supported": ["header"],
                "resource_documentation": f"{resource_url}/docs",
            }
        )

    @app.custom_route("/.well-known/oauth-authorization-server/mcp", methods=["GET"])
    async def oauth_authorization_server_metadata_for_mcp(
        request: Request,
    ) -> JSONResponse:
        """Resource-specific OAuth 2.0 Authorization Server Metadata for /mcp resource"""
        # Use public auth server URL for client-facing OAuth metadata
        # Remove trailing slash for OAuth spec compliance
        auth_base = str(auth_server_public_url).rstrip("/")
        resource_url = str(server_url).rstrip("/")

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
                "resource": resource_url,  # Resource-specific binding
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
        logger.info("=== get_all_projects called ===")
        try:
            api_client = get_api_client()
            logger.debug("API client created successfully")

            response = api_client.get_projects()
            logger.info(
                f"get_projects response: success={response.success}, status={response.status_code}"
            )

            if not response.success:
                logger.error(f"Failed to get projects: {response.error}")
                return json.dumps({"error": response.error})

            projects = response.data
            logger.info(f"Retrieved {len(projects) if projects else 0} projects")

            if projects is None:
                logger.warning("Projects data is None")
                return json.dumps([])

            result = json.dumps(projects)
            logger.debug(f"Returning projects JSON: {result[:200]}...")
            return result
        except Exception as e:
            logger.error(f"Exception in get_all_projects: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

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
        logger.info("=== get_all_tasks called ===")
        try:
            api_client = get_api_client()
            logger.debug("API client created successfully")

            response = api_client.get_todos()
            logger.info(
                f"get_todos response: success={response.success}, status={response.status_code}"
            )

            if not response.success:
                logger.error(f"Failed to get tasks: {response.error}")
                return json.dumps({"error": response.error})

            tasks = response.data
            logger.info(f"Retrieved {len(tasks) if tasks else 0} tasks")

            if tasks is None:
                logger.warning("Tasks data is None")
                return json.dumps([])

            result = json.dumps(tasks)
            logger.debug(f"Returning tasks JSON: {result[:200]}...")
            return result
        except Exception as e:
            logger.error(f"Exception in get_all_tasks: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

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
        logger.info(f"=== create_task called: title='{title}', project_id={project_id} ===")
        try:
            api_client = get_api_client()
            logger.debug("API client created successfully")

            response = api_client.create_todo(
                title=title,
                project_id=project_id,
                description=description,
                priority=priority,
                due_date=due_date,
            )
            logger.info(
                f"create_todo response: success={response.success}, status={response.status_code}"
            )

            if not response.success:
                logger.error(f"Failed to create task: {response.error}")
                return json.dumps({"error": response.error})

            task = response.data
            logger.info(f"Created task: {task}")

            if task is None:
                logger.warning("Task data is None")
                return json.dumps({"error": "No data returned from create_todo"})

            result = json.dumps(task)
            logger.debug(f"Returning task JSON: {result}")
            return result
        except Exception as e:
            logger.error(f"Exception in create_task: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

    return app


@click.command()
@click.option("--port", default=8001, help="Port to listen on")
@click.option(
    "--auth-server",
    default=MCP_AUTH_SERVER,
    help="Authorization Server URL (internal, for introspection)",
)
@click.option(
    "--auth-server-public-url",
    help="Public Authorization Server URL (for OAuth metadata). Defaults to --auth-server value",
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
def main(
    port: int,
    auth_server: str,
    auth_server_public_url: str | None = None,
    server_url: str | None = None,
    oauth_strict: bool = False,
) -> int:
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

    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    try:
        # If no server specified, use environment variable or default
        if server_url is None:
            server_url = os.getenv("MCP_SERVER_URL", f"https://localhost:{port}")

        # If no public auth server URL specified, use environment variable or default to internal URL
        if auth_server_public_url is None:
            auth_server_public_url = os.getenv("MCP_AUTH_SERVER_PUBLIC_URL", auth_server)

        # Remove trailing slashes from URLs (OAuth spec compliance)
        server_url = server_url.rstrip("/")
        auth_server_public_url = auth_server_public_url.rstrip("/")

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Make sure to provide a valid Authorization Server URL")
        return 1

    try:
        mcp_server = create_resource_server(
            port, server_url, auth_server, auth_server_public_url, oauth_strict
        )

        logger.info("=" * 60)
        logger.info(f"🚀 MCP Resource Server running on {server_url}")
        logger.info(f"🔑 Using Authorization Server (internal): {auth_server}")
        logger.info(f"🌐 Using Authorization Server (public): {auth_server_public_url}")
        logger.info(f"📍 Resource Server URL (for OAuth): {server_url}")
        logger.info("=" * 60)

        # Run the server - bind to 0.0.0.0 for Docker networking
        # FastMCP handles CORS internally for discovery endpoints
        import uvicorn

        # Configure uvicorn to handle proxy headers properly
        uvicorn.run(
            mcp_server.streamable_http_app,
            host="0.0.0.0",  # noqa: S104
            port=port,
            log_level="info",
            proxy_headers=True,
            forwarded_allow_ips="*",
        )
        logger.info("Server stopped")
        return 0
    except Exception as e:
        logger.error(f"Server error: {e}")
        logger.exception("Exception details:")
        return 1


if __name__ == "__main__":
    main()
