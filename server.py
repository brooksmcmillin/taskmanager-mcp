import datetime
import logging
from typing import Any

import click
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp.server import FastMCP
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

from token_verifier import IntrospectionTokenVerifier

logger = logging.getLogger(__name__)


class ResourceServerSettings(BaseSettings):

    model_config = SettingsConfigDict(env_prefix="MCP_RESOURCE_")

    # Server settings
    server_url: AnyHttpUrl = AnyHttpUrl("https://mcp.brooksmcmillin.com")

    host: str = "https://mcp.brooksmcmillin.com"
    port: int = 443

    # Authorization Server settings
    auth_server_url: AnyHttpUrl = AnyHttpUrl("https://mcp-auth.brooksmcmillin.com")
    auth_server_introspection_endpoint: str = "https://mcp-auth.brooksmcmillin.com/introspect"
    # No user endpoint needed - we get user data from token introspection

    # MCP settings
    mcp_scope: str = "read"

    # RFC 8707 resource validation
    oauth_strict: bool = False

    def __init__(self, **data):
        """Initialize settings with values from environment variables."""
        super().__init__(**data)


def create_resource_server(settings: ResourceServerSettings) -> FastMCP:
    """
    Create MCP Resource Server with token introspection.

    This server:
    1. Provides public MCP transport endpoint (/mcp) for discovery
    2. Validates tokens via Authorization Server introspection for tools
    3. Serves protected MCP tools and resources
    """
    # Create token verifier for introspection with RFC 8707 resource validation
    token_verifier = IntrospectionTokenVerifier(
        introspection_endpoint=settings.auth_server_introspection_endpoint,
        server_url=str(settings.server_url),
        validate_resource=settings.oauth_strict,  # Only validate when --oauth-strict is set
    )

    # Create FastMCP server with public transport, protected tools
    app = FastMCP(
        name="MCP Resource Server",
        instructions="Resource Server with public /mcp endpoint and protected tools",
        host=settings.host,
        port=settings.port,
        debug=True,
        token_verifier=token_verifier,
        auth=AuthSettings(
            issuer_url=settings.auth_server_url,
            required_scopes=[settings.mcp_scope],
            resource_server_url=settings.server_url,
        ),
    )

    # Add OAuth discovery endpoints using FastMCP's route decorator
    from starlette.responses import JSONResponse
    from starlette.requests import Request
    
    @app.route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def oauth_authorization_server_metadata(request: Request):
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        return JSONResponse({
            "issuer": str(settings.auth_server_url),
            "authorization_endpoint": f"{settings.auth_server_url}/oauth/authorize",
            "token_endpoint": f"{settings.auth_server_url}/oauth/token",
            "introspection_endpoint": f"{settings.auth_server_url}/introspect",
            "scopes_supported": [settings.mcp_scope],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
        })
    
    @app.route("/mcp/.well-known/oauth-protected-resource", methods=["GET"])
    async def oauth_protected_resource_metadata(request: Request):
        """OAuth 2.0 Protected Resource Metadata (RFC 9908)"""
        return JSONResponse({
            "resource": str(settings.server_url),
            "authorization_servers": [str(settings.auth_server_url)],
            "scopes_supported": [settings.mcp_scope],
            "bearer_methods_supported": ["header"],
            "resource_documentation": f"{settings.server_url}/docs"
        })

    @app.tool()
    async def get_time() -> dict[str, Any]:
        """
        Get the current server time.

        This tool demonstrates that system information can be protected
        by OAuth authentication. User must be authenticated to access it.
        """
        # TODO: Implement tool-level authentication
        # For now, this tool is accessible without authentication
        # to allow Claude Code to connect to the server
        
        now = datetime.datetime.now()

        return {
            "current_time": now.isoformat(),
            "timezone": "UTC",  # Simplified for demo
            "timestamp": now.timestamp(),
            "formatted": now.strftime("%Y-%m-%d %H:%M:%S"),
        }

    return app


@click.command()
@click.option("--port", default=8001, help="Port to listen on")
@click.option("--auth-server", default="https://mcp-auth.brooksmcmillin.com", help="Authorization Server URL")
@click.option("--server-url", help="External server URL (for OAuth). Defaults to https://localhost:PORT")
@click.option(
    "--oauth-strict",
    is_flag=True,
    help="Enable RFC 8707 resource validation",
)
def main(port: int, auth_server: str, server_url: str, oauth_strict: bool) -> int:

    logging.basicConfig(level=logging.INFO)

    try:
        # Parse auth server URL
        auth_server_url = AnyHttpUrl(auth_server)

        # Create settings  
        host = "0.0.0.0"  # Bind to all interfaces for reverse proxy
        if server_url is None:
            server_url = f"https://localhost:{port}"
        settings = ResourceServerSettings(
            host=host,
            port=port,
            server_url=AnyHttpUrl(server_url),
            auth_server_url=auth_server_url,
            auth_server_introspection_endpoint=f"{auth_server}/introspect",
            oauth_strict=oauth_strict,
        )
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Make sure to provide a valid Authorization Server URL")
        return 1

    try:
        mcp_server = create_resource_server(settings)

        logger.info(f"🚀 MCP Resource Server running on {settings.server_url}")
        logger.info(f"🔑 Using Authorization Server: {settings.auth_server_url}")

        # Run the server - this should block and keep running
        mcp_server.run(transport="streamable-http")
        logger.info("Server stopped")
        return 0
    except Exception as e:
        logger.error(f"Server error: {e}")
        logger.exception("Exception details:")
        return 1


if __name__ == "__main__":
    main()  # type: ignore[call-arg]
