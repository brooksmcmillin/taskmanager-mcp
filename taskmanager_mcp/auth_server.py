import asyncio
import json
import logging
import os
import secrets
import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, cast

import click
from dotenv import load_dotenv
from mcp.server.auth.provider import AccessTokenT, AuthorizationCodeT, RefreshTokenT
from mcp.server.auth.routes import cors_middleware, create_auth_routes
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from uvicorn import Config, Server

from .task_api import TaskManagerAPI
from .taskmanager_oauth_provider import TaskManagerAuthSettings, TaskManagerOAuthProvider
from .token_storage import TokenStorage

load_dotenv()
logger = logging.getLogger(__name__)


class TaskManagerAuthProvider(
    TaskManagerOAuthProvider[AuthorizationCodeT, RefreshTokenT, AccessTokenT]
):
    """
    Authorization Server provider that integrates with TaskManager OAuth.

    This provider:
    1. Delegates OAuth authentication to TaskManager endpoints
    2. Issues MCP tokens after TaskManager authentication
    3. Stores token state for introspection by Resource Servers
    """

    def __init__(
        self,
        auth_settings: TaskManagerAuthSettings,
        server_url: str,
        token_storage: TokenStorage | None = None,
    ):
        super().__init__(auth_settings, server_url, token_storage=token_storage)
        self.registered_clients: dict[str, Any] = {}


# API client for backend database operations
api_client: TaskManagerAPI | None = None


def load_registered_clients() -> dict[str, Any]:
    """Load registered clients from backend database."""
    global api_client
    if not api_client:
        return {}

    response = api_client.get_oauth_clients()
    if not response.success:
        logging.warning(f"Could not load clients from backend: {response.error}")
        return {}

    # Convert API response to the format expected by auth server
    clients = {}
    if response.data:
        logger.info(f"Loaded {len(response.data)} clients from backend database")
        for client_data in response.data:
            logger.debug(f"Processing client data: {client_data}")
            client_id = client_data.get("client_id") or client_data.get("clientId")
            if client_id:
                # Parse JSON strings back to lists if needed
                redirect_uris = client_data.get("redirect_uris") or client_data.get(
                    "redirectUris", []
                )
                if isinstance(redirect_uris, str):
                    try:
                        redirect_uris = json.loads(redirect_uris)
                    except json.JSONDecodeError:
                        redirect_uris = []

                grant_types = client_data.get("grant_types") or client_data.get(
                    "grantTypes", ["authorization_code", "refresh_token"]
                )
                if isinstance(grant_types, str):
                    try:
                        grant_types = json.loads(grant_types)
                    except json.JSONDecodeError:
                        grant_types = ["authorization_code", "refresh_token"]

                response_types = client_data.get("response_types") or ["code"]
                if isinstance(response_types, str):
                    try:
                        response_types = json.loads(response_types)
                    except json.JSONDecodeError:
                        response_types = ["code"]

                # Handle scopes - could be a string, list, or JSON string
                scopes = client_data.get("scope") or client_data.get("scopes", "read")
                if isinstance(scopes, list):
                    # If it's a list, join with spaces (OAuth standard)
                    scope_string = " ".join(scopes)
                elif isinstance(scopes, str) and scopes.startswith("["):
                    # If it's a JSON string array, parse it
                    try:
                        parsed_scopes = json.loads(scopes)
                        scope_string = (
                            " ".join(parsed_scopes) if isinstance(parsed_scopes, list) else scopes
                        )
                    except json.JSONDecodeError:
                        scope_string = scopes
                else:
                    scope_string = scopes

                # Determine auth method based on client name
                # Clients with "claude-code" in their name are public clients (no secret)
                client_name = client_data.get("name", "")
                auth_method = "none" if "claude-code" in client_name else "client_secret_post"

                # Don't set client_secret for public clients
                client_secret = (
                    None
                    if auth_method == "none"
                    else (
                        client_data.get("client_secret")
                        or client_data.get("clientSecret", "dummy-secret")
                    )
                )

                processed_client = {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uris": redirect_uris,
                    "response_types": response_types,
                    "grant_types": grant_types,
                    "token_endpoint_auth_method": auth_method,
                    "scope": scope_string,
                    "created_at": client_data.get("created_at") or int(time.time()),
                }
                logger.info(
                    f"Processed client {client_id} with scope: '{scope_string}', auth_method: '{auth_method}'"
                )
                clients[client_id] = processed_client

    return clients


# Load persisted client storage
registered_clients = {}


def create_authorization_server(
    host: str,
    port: int,
    server_url: AnyHttpUrl,
    auth_settings: TaskManagerAuthSettings,
    token_storage: TokenStorage | None = None,
) -> Starlette:
    """Create the Authorization Server application."""
    oauth_provider = TaskManagerAuthProvider(  # type: ignore[var-annotated]
        auth_settings, str(server_url), token_storage=token_storage
    )

    # Load and share registered clients with OAuth provider
    global registered_clients
    registered_clients = load_registered_clients()
    oauth_provider.registered_clients = registered_clients

    mcp_auth_settings = AuthSettings(
        issuer_url=server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[auth_settings.mcp_scope],
            default_scopes=[auth_settings.mcp_scope],
        ),
        required_scopes=[auth_settings.mcp_scope],
        resource_server_url=None,
    )

    # Create OAuth routes without built-in registration
    routes = create_auth_routes(
        provider=oauth_provider,
        issuer_url=mcp_auth_settings.issuer_url,
        service_documentation_url=mcp_auth_settings.service_documentation_url,
        client_registration_options=None,  # Disable built-in registration
        revocation_options=mcp_auth_settings.revocation_options,
    )

    # Add debug wrapper for token endpoint
    original_token_route = None
    for i, route in enumerate(routes):
        if route.path == "/token" and route.methods is not None and "POST" in route.methods:
            original_token_route = route

            # Create debug wrapper
            async def debug_token_handler(request: Request) -> Response:
                logger.info("=== TOKEN ENDPOINT DEBUG ===")
                logger.info(f"Method: {request.method}")
                logger.info(f"URL: {request.url}")
                logger.info(f"Headers: {dict(request.headers)}")

                try:
                    # Read the raw body
                    body = await request.body()
                    logger.info(f"Raw body: {body.decode()}")

                    # Try to parse form data
                    if request.headers.get("content-type", "").startswith(
                        "application/x-www-form-urlencoded"
                    ):
                        # Reconstruct request with body

                        scope = dict(request.scope).copy()

                        async def url_encode_receive() -> dict[str, str | bytes]:
                            return {"type": "http.request", "body": body}

                        new_request = Request(scope, url_encode_receive)
                        form_data = await new_request.form()
                        logger.info(f"Form data: {dict(form_data)}")

                    # Call original handler - handle ASGI interface properly
                    logger.info("Calling original token endpoint")

                    # Create a new scope and receive callable with fresh body
                    scope = dict(request.scope).copy()

                    async def receive() -> dict[str, str | bytes | bool]:
                        return {
                            "type": "http.request",
                            "body": body,
                            "more_body": False,
                        }

                    # Create response handler
                    response_started = False
                    response_data = {"status": 500, "headers": [], "body": b""}

                    async def send(message: MutableMapping[str, Any]) -> None:
                        nonlocal response_started, response_data
                        if message["type"] == "http.response.start":
                            response_started = True
                            response_data["status"] = message["status"]
                            response_data["headers"] = message.get("headers", [])
                        elif message["type"] == "http.response.body":
                            response_data["body"] += message.get("body", b"")

                    # Call the endpoint as ASGI app
                    await original_token_route.app(scope, receive, send)  # noqa: B023

                    logger.info(f"Token endpoint result: {response_data['status']}")

                    # Log response body for debugging
                    if response_data["body"]:
                        try:
                            response_text = cast(bytes, response_data["body"]).decode("utf-8")
                            logger.info(f"Token endpoint response body: {response_text}")
                        except Exception:
                            logger.info(
                                f"Token endpoint response body (raw): {response_data['body']}"
                            )

                    # Convert headers back to dict format for Response
                    headers_dict = {}
                    for name, value in response_data["headers"]:  # type: ignore
                        headers_dict[name.decode()] = value.decode()

                    return Response(
                        content=response_data["body"],
                        status_code=cast(int, response_data["status"]),
                        headers=headers_dict,
                    )

                except Exception as e:
                    logger.error(f"Token endpoint error: {e}")
                    logger.error("Traceback: ", exc_info=True)
                    return JSONResponse(
                        {"error": "server_error", "error_description": str(e)},
                        status_code=500,
                    )

            # Replace the route with debug wrapper
            routes[i] = Route(route.path, debug_token_handler, methods=route.methods)
            break

    # Add OAuth callback route (GET) - receives callback from TaskManager
    async def oauth_callback_handler(request: Request) -> Response:
        """Handle OAuth callback from TaskManager."""
        return await oauth_provider.handle_oauth_callback(request)

    routes.append(Route("/oauth/callback", endpoint=oauth_callback_handler, methods=["GET"]))

    # Add MCP client callback route
    async def mcp_client_callback_handler(request: Request) -> Response:
        """Handle callback from MCP client OAuth flow."""
        from starlette.responses import HTMLResponse

        # Extract auth code and state from query params
        code = request.query_params.get("code")
        error = request.query_params.get("error")

        if error:
            return HTMLResponse(
                f"""
            <html>
            <body>
                <h1>Authorization Failed</h1>
                <p>Error: {error}</p>
                <p>You can close this window and return to the terminal.</p>
            </body>
            </html>
            """,
                status_code=400,
            )

        if code:
            return HTMLResponse(
                """
            <html>
            <body>
                <h1>Authorization Successful!</h1>
                <p>You can close this window and return to the terminal.</p>
                <script>setTimeout(() => window.close(), 2000);</script>
            </body>
            </html>
            """
            )

        return HTMLResponse("Invalid callback", status_code=400)

    routes.append(Route("/callback", endpoint=mcp_client_callback_handler, methods=["GET"]))

    # Add token introspection endpoint (RFC 7662) for Resource Servers
    async def introspect_handler(request: Request) -> Response:
        """
        Token introspection endpoint for Resource Servers.

        Resource Servers call this endpoint to validate tokens without
        needing direct access to token storage.
        """
        form = await request.form()
        token = form.get("token")
        logger.info("=== INTROSPECT HANDLER ===")

        if isinstance(token, str):
            logger.info(
                f"Token from request: {token[:20]}...{token[-10:]}"
                if token and len(token) > 30
                else f"Token: {token}"
            )

        if not token or not isinstance(token, str):
            logger.warning("No token or invalid token type in request")
            return JSONResponse({"active": False}, status_code=400)

        # Use provider's introspection method
        introspection_result = await oauth_provider.introspect_token(token)
        logger.info(f"Introspection result: {introspection_result}")

        if not introspection_result:
            return JSONResponse({"active": False})

        return JSONResponse(introspection_result)

    routes.append(
        Route(
            "/introspect",
            endpoint=cors_middleware(introspect_handler, ["POST", "OPTIONS"]),
            methods=["POST", "OPTIONS"],
        )
    )

    # Add dynamic client registration endpoint (RFC 7591)
    async def register_handler(request: Request) -> Response:
        """
        Dynamic Client Registration endpoint (RFC 7591).

        Allows Claude Code to register itself as an OAuth client.
        """
        try:
            # Log the raw request for debugging
            body = await request.body()
            logger.warning(f"Registration request body: {body.decode()}")
            logger.warning(f"Registration request headers: {dict(request.headers)}")

            # Try to parse as JSON
            registration_data = json.loads(body) if body else {}
            logger.warning(f"Parsed registration data: {registration_data}")
        except Exception as e:
            logger.error(f"Failed to parse registration request: {e}")
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid JSON"},
                status_code=400,
            )

        # Set default redirect URIs if not provided
        redirect_uris = registration_data.get("redirect_uris", [])

        # If redirect URIs were provided, also add the non-debug variant
        if redirect_uris:
            # Add both /debug and non-debug variants for MCP Inspector
            additional_uris = []
            for uri in redirect_uris:
                if "/oauth/callback/debug" in uri:
                    # Add the non-debug variant
                    non_debug_uri = uri.replace("/oauth/callback/debug", "/oauth/callback")
                    if non_debug_uri not in redirect_uris:
                        additional_uris.append(non_debug_uri)
                elif "/oauth/callback" in uri and "/debug" not in uri:
                    # Add the debug variant
                    debug_uri = uri.replace("/oauth/callback", "/oauth/callback/debug")
                    if debug_uri not in redirect_uris:
                        additional_uris.append(debug_uri)
            redirect_uris.extend(additional_uris)

        if not redirect_uris:
            redirect_uris = [
                "http://localhost:3000/callback",  # Common local development
                "https://claude.ai/callback",  # Claude Web callback
            ]

        # Create OAuth client via backend API
        global api_client
        if not api_client:
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": "Backend API not available",
                },
                status_code=500,
            )

        client_name = f"claude-code-{secrets.token_hex(4)}"

        # Create client in backend database
        api_response = api_client.create_oauth_client(
            name=client_name,
            redirect_uris=redirect_uris,
            grant_types=["authorization_code", "refresh_token"],
            scopes=[auth_settings.mcp_scope],
        )

        logger.info(f"API response status: {api_response.success}")
        logger.info(f"API response status_code: {api_response.status_code}")
        logger.info(f"API response data: {api_response.data}")
        logger.info(f"API response error: {api_response.error}")

        if not api_response.success:
            logger.error(f"Failed to create OAuth client: {api_response.error}")
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": f"Failed to create client: {api_response.error}",
                },
                status_code=500,
            )

        # Extract client credentials from API response
        client_data = api_response.data
        if client_data is None:
            logger.error("No client data returned from API - got None")
            logger.error(
                f"Full API response: success={api_response.success}, status={api_response.status_code}, error={api_response.error}"
            )
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": "No client data returned from backend",
                },
                status_code=500,
            )

        client_id = client_data.get("client_id") or client_data.get("clientId")
        client_secret = client_data.get("client_secret") or client_data.get("clientSecret")

        if not client_id or not client_secret:
            logger.error(f"Invalid client data returned from API: {client_data}")
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": "Invalid client data from backend",
                },
                status_code=500,
            )

        # Store in local cache for immediate use
        # Respect the requested auth method (e.g., "none" for public clients like MCP Inspector)
        requested_auth_method = registration_data.get(
            "token_endpoint_auth_method", "client_secret_post"
        )

        client_info = {
            "client_id": client_id,
            "client_secret": client_secret if requested_auth_method != "none" else None,
            "redirect_uris": redirect_uris,
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": requested_auth_method,
            "scope": auth_settings.mcp_scope,
            "created_at": int(time.time()),
        }
        registered_clients[client_id] = client_info

        # RFC 7591 client registration response
        registration_response = {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "redirect_uris": redirect_uris,
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": requested_auth_method,
            "scope": auth_settings.mcp_scope,
        }

        # Only include client_secret for clients that use client authentication
        if requested_auth_method != "none":
            registration_response["client_secret"] = client_secret
            registration_response["client_secret_expires_at"] = 0  # Never expires

        # Log for debugging
        logger.info(f"Registered new OAuth client: {client_id}")

        return JSONResponse(registration_response, status_code=201)

    routes.append(
        Route(
            "/register",
            endpoint=cors_middleware(register_handler, ["POST", "OPTIONS"]),
            methods=["POST", "OPTIONS"],
        )
    )

    # Add custom OAuth metadata endpoint to advertise registration support
    async def oauth_metadata_handler(request: Request) -> JSONResponse:
        """OAuth 2.0 Authorization Server Metadata with registration endpoint"""
        server_url_str = str(server_url).rstrip("/")

        return JSONResponse(
            {
                "issuer": server_url_str,
                "authorization_endpoint": f"{server_url_str}/authorize",
                "token_endpoint": f"{server_url_str}/token",
                "registration_endpoint": f"{server_url_str}/register",  # Advertise registration
                "introspection_endpoint": f"{server_url_str}/introspect",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": [auth_settings.mcp_scope],
            },
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            },
        )

    # Add OAuth metadata routes - insert at beginning to override MCP defaults
    routes.insert(
        0,
        Route(
            "/.well-known/oauth-authorization-server",
            endpoint=cors_middleware(oauth_metadata_handler, ["GET", "OPTIONS"]),
            methods=["GET", "OPTIONS"],
        ),
    )

    routes.insert(
        1,
        Route(
            "/.well-known/openid-configuration",
            endpoint=cors_middleware(oauth_metadata_handler, ["GET", "OPTIONS"]),
            methods=["GET", "OPTIONS"],
        ),
    )

    # Add logging middleware
    async def log_requests(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        logger.info("=== Incoming Request to Auth Server ===")
        logger.info(f"Method: {request.method}")
        logger.info(f"URL: {request.url}")
        logger.info(f"Path: {request.url.path}")
        logger.info(f"Host header: {request.headers.get('host')}")
        logger.info(f"X-Forwarded-Proto: {request.headers.get('x-forwarded-proto')}")
        logger.info(f"X-Forwarded-For: {request.headers.get('x-forwarded-for')}")
        logger.info(f"User-Agent: {request.headers.get('user-agent')}")

        response = await call_next(request)

        logger.info(f"Response status: {response.status_code}")
        return response

    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware

    class LoggingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            return await log_requests(request, call_next)

    return Starlette(routes=routes, middleware=[Middleware(LoggingMiddleware)])


async def run_server(
    host: str, port: int, server_url: AnyHttpUrl, auth_settings: TaskManagerAuthSettings
) -> None:
    """Run the Authorization Server."""
    # Initialize persistent token storage if DATABASE_URL is configured
    token_storage: TokenStorage | None = None
    database_url = os.environ.get("DATABASE_URL")

    if database_url:
        logger.info("Initializing database token storage...")
        token_storage = TokenStorage(database_url)
        try:
            await token_storage.initialize()
            logger.info("Database token storage initialized successfully")

            # Clean up any expired tokens on startup
            cleaned = await token_storage.cleanup_expired_tokens()
            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} expired tokens on startup")
        except Exception as e:
            logger.error(f"Failed to initialize database token storage: {e}")
            logger.warning("Falling back to in-memory token storage")
            token_storage = None
    else:
        logger.warning(
            "DATABASE_URL not configured - using in-memory token storage. "
            "Tokens will be lost on server restart!"
        )

    auth_server = create_authorization_server(
        host, port, server_url, auth_settings, token_storage=token_storage
    )

    config = Config(
        auth_server,
        host=host,
        port=port,
        log_level="info",
    )
    server = Server(config)

    # Remove trailing slash from server_url if present (required for OAuth spec)
    server_url_str = str(server_url).rstrip("/")
    server_url = AnyHttpUrl(server_url_str)

    storage_type = "database" if token_storage else "in-memory"
    logger.info("=" * 60)
    logger.info(f"🚀 MCP Authorization Server running on {server_url}")
    logger.info(f"📍 Public URL: {server_url}")
    logger.info(f"🔌 Binding to: {host}:{port}")
    logger.info(f"💾 Token storage: {storage_type}")
    logger.info("=" * 60)

    try:
        await server.serve()
    finally:
        # Clean up token storage on shutdown
        if token_storage:
            await token_storage.close()


@click.command()
@click.option("--port", default=9000, help="Port to listen on")
@click.option("--taskmanager-url", default="localhost:4321", help="TaskManager base URL")
@click.option(
    "--server-url",
    help="Auth server URL (for redirect URIs). Defaults to http://localhost:PORT",
)
# @click.option("--client-id", help="OAuth client ID (if already registered)")
# @click.option("--client-secret", help="OAuth client secret (if already registered)")
def main(port: int, taskmanager_url: str, server_url: str | None = None) -> int:
    """
    Run the MCP Authorization Server with TaskManager OAuth integration.

    This server handles OAuth flows by delegating authentication to your
    existing TaskManager OAuth endpoints.
    """
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Get OAuth client credentials for OAuth flow
    oauth_client_id = os.environ["TASKMANAGER_CLIENT_ID"]
    oauth_client_secret = os.environ["TASKMANAGER_CLIENT_SECRET"]

    # Get user credentials for API access
    username = os.environ.get("TASKMANAGER_USERNAME", oauth_client_id)
    password = os.environ.get("TASKMANAGER_PASSWORD", oauth_client_secret)

    # Initialize API client for backend database operations
    global api_client
    from .task_api import create_authenticated_client

    api_client = create_authenticated_client(username, password, f"{taskmanager_url}/api")

    if not api_client:
        logger.error("Failed to authenticate with backend API")
        return 1

    # Verify the API client can make authenticated requests
    # We'll verify by trying to load OAuth clients (which requires auth)
    logger.info("Verifying API client authentication...")
    test_response = api_client.get_oauth_clients()
    if test_response.success:
        logger.info("API client authenticated successfully - able to access protected endpoints")
    else:
        logger.warning(f"API client authentication verification failed: {test_response.error}")
        logger.warning("Will attempt to continue, but authentication may not work properly")

    # Load TaskManager auth settings with OAuth client credentials
    auth_settings = TaskManagerAuthSettings(
        base_url=taskmanager_url,
        client_id=oauth_client_id,
        client_secret=oauth_client_secret,
    )

    # Bind to 0.0.0.0 for Docker networking
    host = "0.0.0.0"  # noqa: S104

    # Use environment variable for public server URL, or default to localhost
    if server_url is None:
        server_url = os.getenv("MCP_AUTH_SERVER_URL", f"http://localhost:{port}")
    """
    server_settings = AuthServerSettings(
        host=host,
        port=port,
        server_url=AnyHttpUrl(server_url),
        auth_callback_path=f"{server_url}/oauth/callback",
    )
    """

    logger.info(f"TaskManager URL: {taskmanager_url}")

    asyncio.run(run_server(host, port, AnyHttpUrl(server_url), auth_settings))
    return 0


if __name__ == "__main__":
    main()
