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
    async def get_tasks(
        status: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        category: str | None = None,
        limit: int | None = None,
    ) -> str:
        """
        Retrieve tasks with filtering options.

        Args:
            status: Filter by status - one of "pending", "completed", "overdue", or "all"
            start_date: Filter tasks with due date on or after this date (ISO format, e.g., "2025-12-14")
            end_date: Filter tasks with due date on or before this date (ISO format, e.g., "2025-12-20")
            category: Filter by category/project name
            limit: Maximum number of tasks to return

        Returns:
            JSON object with "tasks" array containing task objects with fields:
            id, title, description, due_date, status, category, priority, tags, created_at, updated_at
        """
        logger.info(
            f"=== get_tasks called: status={status}, start_date={start_date}, "
            f"end_date={end_date}, category={category}, limit={limit} ==="
        )
        try:
            api_client = get_api_client()
            logger.debug("API client created successfully")

            # Get projects to map category names to IDs and for task category lookup
            projects_response = api_client.get_projects()
            projects_map: dict[int, str] = {}
            category_to_project_id: dict[str, int] = {}
            if projects_response.success and projects_response.data:
                for project in projects_response.data:
                    projects_map[project["id"]] = project["name"]
                    category_to_project_id[project["name"].lower()] = project["id"]

            # Build query params for API call
            project_id = None
            if category:
                project_id = category_to_project_id.get(category.lower())
                if project_id is None:
                    logger.warning(f"Category '{category}' not found")

            # Map status for API (handle "overdue" and "all" specially)
            api_status = None
            if status and status.lower() not in ("all", "overdue"):
                api_status = status.lower()

            response = api_client.get_todos(project_id=project_id, status=api_status)
            logger.info(
                f"get_todos response: success={response.success}, status={response.status_code}"
            )

            if not response.success:
                logger.error(f"Failed to get tasks: {response.error}")
                return json.dumps({"error": response.error})

            tasks = response.data or []
            logger.info(f"Retrieved {len(tasks)} tasks before filtering")

            # Apply date filtering
            filtered_tasks = []
            now = datetime.datetime.now().date()
            for task in tasks:
                task_due_date = task.get("due_date")
                if task_due_date:
                    try:
                        due_date = datetime.datetime.fromisoformat(
                            task_due_date.replace("Z", "+00:00")
                        ).date()

                        # Filter by start_date
                        if start_date:
                            start = datetime.datetime.fromisoformat(start_date).date()
                            if due_date < start:
                                continue

                        # Filter by end_date
                        if end_date:
                            end = datetime.datetime.fromisoformat(end_date).date()
                            if due_date > end:
                                continue

                        # Filter overdue tasks
                        if (
                            status
                            and status.lower() == "overdue"
                            and (due_date >= now or task.get("status") == "completed")
                        ):
                            continue
                    except ValueError:
                        pass  # Skip date filtering if date parsing fails
                elif status and status.lower() == "overdue":
                    # Tasks without due dates can't be overdue
                    continue

                filtered_tasks.append(task)

            # Apply limit
            if limit and limit > 0:
                filtered_tasks = filtered_tasks[:limit]

            # Transform tasks to match expected output format
            result_tasks = []
            for task in filtered_tasks:
                result_tasks.append(
                    {
                        "id": f"task_{task['id']}",
                        "title": task.get("title", ""),
                        "description": task.get("description"),
                        "due_date": task.get("due_date"),
                        "status": task.get("status", "pending"),
                        "category": (
                            projects_map.get(task.get("project_id"))
                            if task.get("project_id")
                            else None
                        ),
                        "priority": task.get("priority", "medium"),
                        "tags": task.get("tags") or [],
                        "created_at": task.get("created_at"),
                        "updated_at": task.get("updated_at"),
                    }
                )

            logger.info(f"Returning {len(result_tasks)} tasks after filtering")
            return json.dumps({"tasks": result_tasks})
        except Exception as e:
            logger.error(f"Exception in get_tasks: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

    @app.tool()
    async def create_task(
        title: str,
        description: str | None = None,
        due_date: str | None = None,
        category: str | None = None,
        priority: str = "medium",
        tags: list[str] | None = None,
    ) -> str:
        """
        Create a new task.

        Args:
            title: Task title (required)
            description: Task details (optional)
            due_date: Due date in ISO format, e.g., "2025-12-20" (optional)
            category: Task category/project name (optional)
            priority: Priority level - one of "low", "medium", "high", "urgent" (default: "medium")
            tags: List of task tags (optional)

        Returns:
            JSON object with id, title, and status fields confirming task creation
        """
        logger.info(
            f"=== create_task called: title='{title}', category={category}, priority={priority} ==="
        )
        try:
            api_client = get_api_client()
            logger.debug("API client created successfully")

            # Map category name to project_id
            project_id = None
            if category:
                projects_response = api_client.get_projects()
                if projects_response.success and projects_response.data:
                    for project in projects_response.data:
                        if project["name"].lower() == category.lower():
                            project_id = project["id"]
                            break
                if project_id is None:
                    logger.warning(f"Category '{category}' not found, task will have no category")

            response = api_client.create_todo(
                title=title,
                project_id=project_id,
                description=description,
                priority=priority,
                due_date=due_date,
                tags=tags,
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

            # Return response in expected format
            result = {
                "id": f"task_{task['id']}",
                "title": task.get("title", title),
                "status": "created",
            }
            return json.dumps(result)
        except Exception as e:
            logger.error(f"Exception in create_task: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

    @app.tool()
    async def update_task(
        task_id: str,
        title: str | None = None,
        description: str | None = None,
        due_date: str | None = None,
        status: str | None = None,
        category: str | None = None,
        priority: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """
        Update an existing task.

        Args:
            task_id: Task ID (required) - format "task_123" or just "123"
            title: New title (optional)
            description: New description (optional)
            due_date: New due date in ISO format for rescheduling (optional)
            status: New status - one of "pending", "in_progress", "completed", "cancelled" (optional)
            category: New category/project name (optional)
            priority: New priority - one of "low", "medium", "high", "urgent" (optional)
            tags: New list of tags (optional)

        Returns:
            JSON object with id, updated_fields list, and status confirming update
        """
        logger.info(f"=== update_task called: task_id='{task_id}' ===")
        try:
            api_client = get_api_client()
            logger.debug("API client created successfully")

            # Extract numeric ID from task_id (handle both "task_123" and "123" formats)
            numeric_id = task_id.replace("task_", "") if task_id.startswith("task_") else task_id
            try:
                todo_id = int(numeric_id)
            except ValueError:
                return json.dumps({"error": f"Invalid task_id format: {task_id}"})

            # Map category name to project_id if provided
            project_id = None
            if category:
                projects_response = api_client.get_projects()
                if projects_response.success and projects_response.data:
                    for project in projects_response.data:
                        if project["name"].lower() == category.lower():
                            project_id = project["id"]
                            break
                if project_id is None:
                    logger.warning(f"Category '{category}' not found")

            # Track which fields are being updated
            updated_fields = []
            if title is not None:
                updated_fields.append("title")
            if description is not None:
                updated_fields.append("description")
            if due_date is not None:
                updated_fields.append("due_date")
            if status is not None:
                updated_fields.append("status")
            if category is not None:
                updated_fields.append("category")
            if priority is not None:
                updated_fields.append("priority")
            if tags is not None:
                updated_fields.append("tags")

            response = api_client.update_todo(
                todo_id=todo_id,
                title=title,
                description=description,
                priority=priority,
                status=status,
                due_date=due_date,
                tags=tags,
                project_id=project_id,
            )
            logger.info(
                f"update_todo response: success={response.success}, status={response.status_code}"
            )

            if not response.success:
                logger.error(f"Failed to update task: {response.error}")
                return json.dumps({"error": response.error})

            # Return response in expected format
            result = {
                "id": f"task_{todo_id}",
                "updated_fields": updated_fields,
                "status": "updated",
            }
            return json.dumps(result)
        except Exception as e:
            logger.error(f"Exception in update_task: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

    @app.tool()
    async def get_categories() -> str:
        """
        List all available task categories.

        Returns a list of all categories (projects) with the count of tasks in each.

        Returns:
            JSON object with "categories" array containing objects with name and task_count fields
        """
        logger.info("=== get_categories called ===")
        try:
            api_client = get_api_client()
            logger.debug("API client created successfully")

            # Get all projects
            projects_response = api_client.get_projects()
            if not projects_response.success:
                logger.error(f"Failed to get projects: {projects_response.error}")
                return json.dumps({"error": projects_response.error})

            projects = projects_response.data or []

            # Get all tasks to count per category
            todos_response = api_client.get_todos()
            tasks = todos_response.data or [] if todos_response.success else []

            # Count tasks per project
            task_counts: dict[int, int] = {}
            for task in tasks:
                project_id = task.get("project_id")
                if project_id:
                    task_counts[project_id] = task_counts.get(project_id, 0) + 1

            # Build categories list
            categories = []
            for project in projects:
                categories.append(
                    {
                        "name": project["name"],
                        "task_count": task_counts.get(project["id"], 0),
                    }
                )

            logger.info(f"Returning {len(categories)} categories")
            return json.dumps({"categories": categories})
        except Exception as e:
            logger.error(f"Exception in get_categories: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

    @app.tool()
    async def search_tasks(
        query: str,
        category: str | None = None,
    ) -> str:
        """
        Search tasks by keyword.

        Searches task titles and descriptions for the given query string.

        Args:
            query: Search query string (required)
            category: Filter by category/project name (optional)

        Returns:
            JSON object with "tasks" array (same format as get_tasks) and "count" field
        """
        logger.info(f"=== search_tasks called: query='{query}', category={category} ===")
        try:
            api_client = get_api_client()
            logger.debug("API client created successfully")

            # Get projects for category mapping
            projects_response = api_client.get_projects()
            projects_map: dict[int, str] = {}
            category_to_project_id: dict[str, int] = {}
            if projects_response.success and projects_response.data:
                for project in projects_response.data:
                    projects_map[project["id"]] = project["name"]
                    category_to_project_id[project["name"].lower()] = project["id"]

            # Filter by category if provided
            project_id = None
            if category:
                project_id = category_to_project_id.get(category.lower())

            response = api_client.get_todos(project_id=project_id)
            if not response.success:
                logger.error(f"Failed to get tasks: {response.error}")
                return json.dumps({"error": response.error})

            tasks = response.data or []

            # Search in title and description
            query_lower = query.lower()
            matching_tasks = []
            for task in tasks:
                title = task.get("title", "").lower()
                description = (task.get("description") or "").lower()
                tags = task.get("tags") or []
                tags_text = " ".join(tags).lower()

                if query_lower in title or query_lower in description or query_lower in tags_text:
                    matching_tasks.append(
                        {
                            "id": f"task_{task['id']}",
                            "title": task.get("title", ""),
                            "description": task.get("description"),
                            "due_date": task.get("due_date"),
                            "status": task.get("status", "pending"),
                            "category": (
                                projects_map.get(task.get("project_id"))
                                if task.get("project_id")
                                else None
                            ),
                            "priority": task.get("priority", "medium"),
                            "tags": task.get("tags") or [],
                            "created_at": task.get("created_at"),
                            "updated_at": task.get("updated_at"),
                        }
                    )

            logger.info(f"Found {len(matching_tasks)} tasks matching query '{query}'")
            return json.dumps({"tasks": matching_tasks, "count": len(matching_tasks)})
        except Exception as e:
            logger.error(f"Exception in search_tasks: {e}", exc_info=True)
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
