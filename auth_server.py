import asyncio
import logging
import os

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

load_dotenv()
logger = logging.getLogger(__name__)


class AuthServerSettings(BaseModel):
    """Settings for the Authorization Server."""

    # Server settings
    host: str = "localhost"
    port: int = 9000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")
    auth_callback_path: str = "http://localhost:9000/login/callback"


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


def create_authorization_server(server_settings: AuthServerSettings, auth_settings: TaskManagerAuthSettings) -> Starlette:
    """Create the Authorization Server application."""
    oauth_provider = TaskManagerAuthProvider(
        auth_settings, str(server_settings.server_url)
    )

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

    # Create OAuth routes
    routes = create_auth_routes(
        provider=oauth_provider,
        issuer_url=mcp_auth_settings.issuer_url,
        service_documentation_url=mcp_auth_settings.service_documentation_url,
        client_registration_options=mcp_auth_settings.client_registration_options,
        revocation_options=mcp_auth_settings.revocation_options,
    )

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
    logging.basicConfig(level=logging.INFO)

    client_id = os.environ["TASKMANAGER_CLIENT_ID"]
    client_secret = os.environ["TASKMANAGER_CLIENT_SECRET"]

   
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
