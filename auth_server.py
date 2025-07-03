import asyncio
import json
import logging
import os
import time
from pathlib import Path

import click
from dotenv import load_dotenv
from mcp.server.auth.routes import cors_middleware, create_auth_routes
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from pydantic import AnyHttpUrl, BaseModel
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from uvicorn import Config, Server

from taskmanager_oauth_provider import TaskManagerAuthSettings, TaskManagerOAuthProvider
from task_api import TaskManagerAPI

load_dotenv()
logger = logging.getLogger(__name__)


class AuthServerSettings(BaseModel):
    """Settings for the Authorization Server."""

    # Server settings
    host: str = "localhost"
    port: int = 9000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")
    auth_callback_path: str = "https://mcp-auth.brooksmcmillin.com/login/callback"


class TaskManagerAuthProvider(TaskManagerOAuthProvider):
    """
    Authorization Server provider that integrates with TaskManager OAuth.

    This provider:
    1. Delegates OAuth authentication to TaskManager endpoints
    2. Issues MCP tokens after TaskManager authentication
    3. Stores token state for introspection by Resource Servers
    """

    def __init__(self, auth_settings: TaskManagerAuthSettings, server_url: str):
        super().__init__(auth_settings, server_url)


# API client for backend database operations
api_client = None

def load_registered_clients():
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
            client_id = client_data.get('client_id') or client_data.get('clientId')
            if client_id:
                # Parse JSON strings back to lists if needed
                redirect_uris = client_data.get('redirect_uris') or client_data.get('redirectUris', [])
                if isinstance(redirect_uris, str):
                    try:
                        redirect_uris = json.loads(redirect_uris)
                    except json.JSONDecodeError:
                        redirect_uris = []
                
                grant_types = client_data.get('grant_types') or client_data.get('grantTypes', ["authorization_code", "refresh_token"])
                if isinstance(grant_types, str):
                    try:
                        grant_types = json.loads(grant_types)
                    except json.JSONDecodeError:
                        grant_types = ["authorization_code", "refresh_token"]
                
                response_types = client_data.get('response_types') or ["code"]
                if isinstance(response_types, str):
                    try:
                        response_types = json.loads(response_types)
                    except json.JSONDecodeError:
                        response_types = ["code"]
                
                # Handle scopes - could be a string, list, or JSON string
                scopes = client_data.get('scope') or client_data.get('scopes', "read")
                if isinstance(scopes, list):
                    # If it's a list, join with spaces (OAuth standard)
                    scope_string = " ".join(scopes)
                elif isinstance(scopes, str) and scopes.startswith('['):
                    # If it's a JSON string array, parse it
                    try:
                        parsed_scopes = json.loads(scopes)
                        scope_string = " ".join(parsed_scopes) if isinstance(parsed_scopes, list) else scopes
                    except json.JSONDecodeError:
                        scope_string = scopes
                else:
                    scope_string = scopes
                
                # Determine auth method - Claude uses "none", others use "client_secret_post"
                auth_method = "none" if client_id == "claude-code-a6386c3617660a19" else "client_secret_post"
                
                processed_client = {
                    "client_id": client_id,
                    "client_secret": client_data.get('client_secret') or client_data.get('clientSecret', 'dummy-secret'),
                    "redirect_uris": redirect_uris,
                    "response_types": response_types,
                    "grant_types": grant_types,
                    "token_endpoint_auth_method": auth_method,
                    "scope": scope_string,
                    "created_at": client_data.get('created_at') or int(time.time())
                }
                logger.info(f"Processed client {client_id} with scope: '{scope_string}', auth_method: '{auth_method}'")
                clients[client_id] = processed_client
    
    return clients

def save_registered_clients(clients):
    """Save registered clients to backend database."""
    # This function is now handled by create_oauth_client calls
    # Individual client creation is done via the API in the register handler
    pass

# Load persisted client storage
registered_clients = {}

def create_authorization_server(server_settings: AuthServerSettings, auth_settings: TaskManagerAuthSettings) -> Starlette:
    """Create the Authorization Server application."""
    oauth_provider = TaskManagerAuthProvider(
        auth_settings, str(server_settings.server_url)
    )
    
    # Load and share registered clients with OAuth provider
    global registered_clients
    registered_clients = load_registered_clients()
    oauth_provider.registered_clients = registered_clients

    mcp_auth_settings = AuthSettings(
        issuer_url=server_settings.server_url,
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
        if route.path == "/token" and "POST" in route.methods:
            original_token_route = route
            # Create debug wrapper
            async def debug_token_handler(request: Request) -> Response:
                logger.info(f"=== TOKEN ENDPOINT DEBUG ===")
                logger.info(f"Method: {request.method}")
                logger.info(f"URL: {request.url}")
                logger.info(f"Headers: {dict(request.headers)}")
                
                try:
                    # Read the raw body
                    body = await request.body()
                    logger.info(f"Raw body: {body}")
                    
                    # Try to parse form data
                    if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                        # Reconstruct request with body
                        from starlette.requests import Request as StarletteRequest
                        scope = request.scope.copy()
                        
                        async def receive():
                            return {"type": "http.request", "body": body}
                        
                        new_request = StarletteRequest(scope, receive)
                        form_data = await new_request.form()
                        logger.info(f"Form data: {dict(form_data)}")
                    
                    # Call original handler - handle ASGI interface properly
                    logger.info("Calling original token endpoint")
                    
                    # Create a new scope and receive callable with fresh body
                    scope = request.scope.copy()
                    
                    async def receive():
                        return {"type": "http.request", "body": body, "more_body": False}
                    
                    # Create response handler
                    response_started = False
                    response_data = {"status": 500, "headers": [], "body": b""}
                    
                    async def send(message):
                        nonlocal response_started, response_data
                        if message["type"] == "http.response.start":
                            response_started = True
                            response_data["status"] = message["status"]
                            response_data["headers"] = message.get("headers", [])
                        elif message["type"] == "http.response.body":
                            response_data["body"] += message.get("body", b"")
                    
                    # Call the endpoint as ASGI app
                    await original_token_route.app(scope, receive, send)
                    
                    logger.info(f"Token endpoint result: {response_data['status']}")
                    
                    # Log response body for debugging
                    if response_data["body"]:
                        try:
                            response_text = response_data["body"].decode('utf-8')
                            logger.info(f"Token endpoint response body: {response_text}")
                        except:
                            logger.info(f"Token endpoint response body (raw): {response_data['body']}")
                    
                    # Convert headers back to dict format for Response
                    headers_dict = {}
                    for name, value in response_data["headers"]:
                        headers_dict[name.decode()] = value.decode()
                    
                    return Response(
                        content=response_data["body"],
                        status_code=response_data["status"],
                        headers=headers_dict
                    )
                    
                except Exception as e:
                    logger.error(f"Token endpoint error: {e}")
                    logger.error(f"Traceback: ", exc_info=True)
                    return JSONResponse({"error": "server_error", "error_description": str(e)}, status_code=500)
            
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
        state = request.query_params.get("state")
        error = request.query_params.get("error")
        
        if error:
            return HTMLResponse(f"""
            <html>
            <body>
                <h1>Authorization Failed</h1>
                <p>Error: {error}</p>
                <p>You can close this window and return to the terminal.</p>
            </body>
            </html>
            """, status_code=400)
        
        if code:
            return HTMLResponse("""
            <html>
            <body>
                <h1>Authorization Successful!</h1>
                <p>You can close this window and return to the terminal.</p>
                <script>setTimeout(() => window.close(), 2000);</script>
            </body>
            </html>
            """)
        
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
        if not token or not isinstance(token, str):
            return JSONResponse({"active": False}, status_code=400)

        # Use provider's introspection method
        introspection_result = await oauth_provider.introspect_token(token)
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
            print(f"[DEBUG] Registration request body: {body}")
            print(f"[DEBUG] Registration request headers: {dict(request.headers)}")
            logger.warning(f"Registration request body: {body}")
            logger.warning(f"Registration request headers: {dict(request.headers)}")
            
            # Try to parse as JSON
            registration_data = json.loads(body) if body else {}
            print(f"[DEBUG] Parsed registration data: {registration_data}")
            logger.warning(f"Parsed registration data: {registration_data}")
        except Exception as e:
            print(f"[DEBUG] Failed to parse registration request: {e}")
            logger.error(f"Failed to parse registration request: {e}")
            return JSONResponse({"error": "invalid_request", "error_description": "Invalid JSON"}, status_code=400)
        
        # Set default redirect URIs if not provided
        redirect_uris = registration_data.get("redirect_uris", [
            "http://localhost:3000/callback",  # Common local development
            "https://claude.ai/callback",      # Claude Web callback
        ])
        
        # Create OAuth client via backend API
        global api_client
        if not api_client:
            return JSONResponse({"error": "server_error", "error_description": "Backend API not available"}, status_code=500)
        
        # Generate client name
        import secrets
        client_name = f"claude-code-{secrets.token_hex(4)}"
        
        # Create client in backend database
        api_response = api_client.create_oauth_client(
            name=client_name,
            redirect_uris=redirect_uris,
            grant_types=["authorization_code", "refresh_token"],
            scopes=[auth_settings.mcp_scope]
        )
        
        if not api_response.success:
            logger.error(f"Failed to create OAuth client: {api_response.error}")
            return JSONResponse({"error": "server_error", "error_description": f"Failed to create client: {api_response.error}"}, status_code=500)
        
        # Extract client credentials from API response
        client_data = api_response.data
        client_id = client_data.get('client_id') or client_data.get('clientId')
        client_secret = client_data.get('client_secret') or client_data.get('clientSecret')
        
        if not client_id or not client_secret:
            logger.error(f"Invalid client data returned from API: {client_data}")
            return JSONResponse({"error": "server_error", "error_description": "Invalid client data from backend"}, status_code=500)
        
        # Store in local cache for immediate use
        client_info = {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": redirect_uris,
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": auth_settings.mcp_scope,
            "created_at": int(time.time())
        }
        registered_clients[client_id] = client_info
        
        # RFC 7591 client registration response
        registration_response = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,  # Never expires
            "redirect_uris": redirect_uris,
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": auth_settings.mcp_scope,
        }
        
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

    return Starlette(routes=routes)


async def run_server(server_settings: AuthServerSettings, auth_settings: TaskManagerAuthSettings):
    """Run the Authorization Server."""
    auth_server = create_authorization_server(server_settings, auth_settings)

    config = Config(
        auth_server,
        host=server_settings.host,
        port=server_settings.port,
        log_level="info",
    )
    server = Server(config)

    logger.info(f"🚀 MCP Authorization Server running on {server_settings.server_url}")

    await server.serve()


@click.command()
@click.option("--port", default=9000, help="Port to listen on")
@click.option("--taskmanager-url", default="localhost:4321", help="TaskManager base URL")
@click.option("--server-url", help="Auth server URL (for redirect URIs). Defaults to http://localhost:PORT")
# @click.option("--client-id", help="OAuth client ID (if already registered)")
# @click.option("--client-secret", help="OAuth client secret (if already registered)")
def main(port: int, taskmanager_url: str, server_url: str = None) -> int:
    """
    Run the MCP Authorization Server with TaskManager OAuth integration.

    This server handles OAuth flows by delegating authentication to your
    existing TaskManager OAuth endpoints.
    """
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    client_id = os.environ["TASKMANAGER_CLIENT_ID"]
    client_secret = os.environ["TASKMANAGER_CLIENT_SECRET"]
    
    # Initialize API client for backend database operations
    global api_client
    from task_api import create_authenticated_client
    api_client = create_authenticated_client(client_id, client_secret, f"{taskmanager_url}/api")
    
    if not api_client:
        logger.error("Failed to authenticate with backend API")
        return 1
   
    print(f"Taskmanager URL: {taskmanager_url}")
    # Load TaskManager auth settings
    auth_settings = TaskManagerAuthSettings(
        base_url=taskmanager_url,
        client_id=client_id,
        client_secret=client_secret,
    )

    # Create server settings
    host = "localhost"
    if server_url is None:
        server_url = f"http://{host}:{port}"
    server_settings = AuthServerSettings(
        host=host,
        port=port,
        server_url=AnyHttpUrl(server_url),
        auth_callback_path=f"{server_url}/oauth/callback",
    )

    logger.info(f"TaskManager URL: {taskmanager_url}")
    if client_id:
        logger.info(f"Using OAuth client ID: {client_id}")
    else:
        logger.warning("No client ID provided - you'll need to register an OAuth client in TaskManager")

    asyncio.run(run_server(server_settings, auth_settings))
    return 0


if __name__ == "__main__":
    main()  # type: ignore[call-arg]
