"""
TaskManager OAuth Provider for MCP Server

This provider integrates with the existing OAuth endpoints in the taskmanager application
to provide authentication for MCP (Model Context Protocol) servers.

OAuth 2.0 Flow Overview:
1. Authorization Request: Client redirects user to /oauth/authorize
2. User Login: User authenticates with taskmanager credentials  
3. Authorization Grant: User consents, server creates authorization code
4. Access Token Request: Client exchanges code for access token at /oauth/token
5. Resource Access: Client uses access token to access protected MCP resources

This implementation handles the MCP-specific parts of the OAuth flow while
delegating the actual OAuth logic to your existing taskmanager endpoints.
"""

import logging
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlencode

import aiohttp
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

logger = logging.getLogger(__name__)


class TaskManagerAuthSettings(BaseSettings):
    """
    Settings for TaskManager OAuth integration.
    
    These settings configure how the MCP server connects to your taskmanager
    OAuth endpoints for authentication.
    """
    
    model_config = SettingsConfigDict(env_prefix="TASKMANAGER_")

    # TaskManager OAuth endpoints
    base_url: str = "http://localhost:4321"
    authorize_endpoint: str = "/api/oauth/authorize"
    token_endpoint: str = "/api/oauth/token"
    clients_endpoint: str = "/api/oauth/clients"
    
    # OAuth client credentials (will be auto-registered if not provided)
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    client_name: str = "MCP Server"
    
    # MCP-specific settings
    mcp_scope: str = "read"  # Default scope for MCP access
    
    # Session settings for admin operations (if needed)
    admin_session_cookie: Optional[str] = None  # For auto-registering clients


class TaskManagerOAuthProvider(OAuthAuthorizationServerProvider):
    """
    OAuth provider that integrates with TaskManager's existing OAuth endpoints.
    
    This provider acts as a bridge between the MCP server authentication system
    and your existing taskmanager OAuth implementation. It handles:
    
    1. Client registration with taskmanager
    2. OAuth authorization flow delegation
    3. Token exchange and validation
    4. User information retrieval
    
    The actual OAuth logic is handled by your taskmanager endpoints, while this
    provider manages the MCP-specific integration details.
    """

    def __init__(self, settings: TaskManagerAuthSettings, server_url: str):
        """
        Initialize the TaskManager OAuth provider.
        
        Args:
            settings: Configuration for connecting to taskmanager
            server_url: The URL of this MCP server (for redirect URIs)
        """
        self.settings = settings
        print(f"Setting up for {server_url}")
        self.server_url = server_url
        
        # In-memory storage for this demo
        # In production, you might want to use persistent storage
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str | None]] = {}
        
        # HTTP session for making requests to taskmanager
        self._session: Optional[aiohttp.ClientSession] = None
        
        logger.info(f"Initialized TaskManager OAuth provider for {settings.base_url}")

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session for taskmanager API calls."""
        if self._session is None:
            # Create session with headers that bypass CSRF for API calls
            headers = {
                "X-Requested-With": "XMLHttpRequest",  # Often bypasses CSRF
                "Accept": "application/json",
            }
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def close(self):
        """Clean up HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """
        Get OAuth client information.
        
        This first checks our local cache, then attempts to retrieve from
        taskmanager if not found locally.
        """
        # Check local cache first
        if client_id in self.clients:
            return self.clients[client_id]
            
        # Check registered clients from auth server
        if hasattr(self, 'registered_clients') and client_id in self.registered_clients:
            client_data = self.registered_clients[client_id]
            # Convert to OAuthClientInformationFull format
            client_info = OAuthClientInformationFull(
                client_id=client_data["client_id"],
                client_secret=client_data["client_secret"],
                redirect_uris=client_data["redirect_uris"],
                response_types=client_data["response_types"],
                grant_types=client_data["grant_types"],
                token_endpoint_auth_method=client_data["token_endpoint_auth_method"],
                scope=client_data["scope"]
            )
            # Cache it locally for future use
            self.clients[client_id] = client_info
            logger.info(f"Found client {client_id} in registered clients")
            return client_info
            
        # TODO: Add endpoint to taskmanager to retrieve client info by ID
        # For now, return None if not found locally
        logger.warning(f"Client {client_id} not found in local cache or registered clients")
        return None

    async def register_client(self, client_info: OAuthClientInformationFull):
        """
        Register a new OAuth client.
        
        This stores the client information locally and optionally registers
        it with the taskmanager system if admin credentials are available.
        """
        self.clients[client_info.client_id] = client_info
        logger.info(f"Registered OAuth client: {client_info.client_id}")
        
        # TODO: Optionally register with taskmanager if admin session available
        if self.settings.admin_session_cookie:
            await self._register_with_taskmanager(client_info)

    async def _register_with_taskmanager(self, client_info: OAuthClientInformationFull):
        """
        Register client with taskmanager (requires admin session).
        
        This is a stub for automatically registering MCP clients with your
        taskmanager system. You'll need to implement the admin authentication
        part based on your needs.
        """
        # TODO: Implement client registration with taskmanager
        # This would POST to /api/oauth/clients with admin credentials
        logger.info("Auto-registration with taskmanager not yet implemented")
        pass

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """
        Generate authorization URL that redirects to taskmanager's OAuth flow.
        
        This creates the authorization URL that will redirect users to your
        taskmanager's OAuth consent page. The user will authenticate there
        and then be redirected back to complete the MCP authentication.
        """
        state = params.state or secrets.token_hex(16)

        # Store state mapping for callback processing
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,  # RFC 8707 resource parameter
        }

        # Build authorization URL pointing to taskmanager
        # Use the original client_id (Claude's) for the TaskManager OAuth flow
        auth_params = {
            "client_id": client.client_id,  # Use the actual client ID (claude-code-a6386c3617660a19)
            "redirect_uri": f"{self.server_url.rstrip('/')}/oauth/callback",  # This server handles callback
            "response_type": "code",
            "scope": self.settings.mcp_scope,
            "state": state,
        }
        
        # Note: We intentionally do NOT forward PKCE parameters to TaskManager
        # because we're acting as a proxy. The MCP client's PKCE verification
        # will be handled by the MCP auth server directly.

        auth_url = (
            f"{self.settings.base_url}{self.settings.authorize_endpoint}?"
            f"{urlencode(auth_params)}"
        )

        logger.info(f"Generated authorization URL: {auth_url}")
        return auth_url

    async def handle_oauth_callback(self, request: Request) -> Response:
        """
        Handle OAuth callback from taskmanager.
        
        This processes the authorization code received from taskmanager's
        OAuth flow and exchanges it for an access token, then creates
        an MCP authorization code for the original client.
        """
        # Get parameters from callback
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")

        if error:
            logger.error(f"OAuth callback error: {error}")
            raise HTTPException(400, f"OAuth error: {error}")

        if not code or not state:
            logger.error("Missing code or state in OAuth callback")
            raise HTTPException(400, "Missing code or state parameter")

        # Retrieve state mapping
        state_data = self.state_mapping.get(state)
        if not state_data:
            logger.error(f"Invalid state parameter: {state}")
            raise HTTPException(400, "Invalid state parameter")

        try:
            # Exchange authorization code with taskmanager for access token
            access_token = await self._exchange_code_with_taskmanager(code, state)
            
            # Create MCP authorization code for the original client
            mcp_code = f"mcp_{secrets.token_hex(16)}"
            auth_code = AuthorizationCode(
                code=mcp_code,
                client_id=state_data["client_id"],
                redirect_uri=AnyHttpUrl(state_data["redirect_uri"]),
                redirect_uri_provided_explicitly=state_data["redirect_uri_provided_explicitly"] == "True",
                expires_at=time.time() + 300,  # 5 minutes
                scopes=[self.settings.mcp_scope],
                code_challenge=state_data["code_challenge"],
                resource=state_data.get("resource"),
            )
            self.auth_codes[mcp_code] = auth_code

            # Store the taskmanager access token for later use
            # TODO: You might want to validate/introspect the token here
            self.tokens[f"tm_{access_token}"] = AccessToken(
                token=f"tm_{access_token}",
                client_id=state_data["client_id"],
                scopes=[self.settings.mcp_scope],
                expires_at=int(time.time()) + 3600,  # 1 hour
                resource=state_data.get("resource"),
            )

            # Clean up state
            del self.state_mapping[state]

            # Redirect back to original client
            redirect_uri = construct_redirect_uri(
                state_data["redirect_uri"], 
                code=mcp_code, 
                state=state
            )
            return RedirectResponse(url=redirect_uri, status_code=302)

        except Exception as e:
            logger.error(f"Error handling OAuth callback: {e}")
            raise HTTPException(500, "Internal server error during OAuth callback")

    async def _exchange_code_with_taskmanager(self, code: str, state: str) -> str:
        """
        Exchange authorization code with taskmanager for access token.
        
        This makes a request to your taskmanager's token endpoint to
        exchange the authorization code for an access token.
        """
        session = await self._get_session()
        
        # Get the state data that matches this callback
        state_data = self.state_mapping.get(state)
        
        if not state_data:
            logger.error(f"No state data found for state: {state}")
            # Fallback to TaskManager credentials
            client_id = self.settings.client_id or "mcp-server-default"
            client_secret = self.settings.client_secret or "REPLACE_WITH_CLIENT_SECRET"
        else:
            # Use the client credentials from the original request
            client_id = state_data["client_id"]
            client_secret = "dummy-secret"  # Default for Claude client
            
            # Look up the actual client secret from registered clients
            if hasattr(self, 'registered_clients') and client_id in self.registered_clients:
                client_info = self.registered_clients[client_id]
                client_secret = client_info.get("client_secret", "dummy-secret")
                logger.info(f"Found client secret for {client_id}: {client_secret}")
            else:
                logger.warning(f"Client {client_id} not found in registered clients")
        
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": f"{self.server_url.rstrip('/')}/oauth/callback",
        }

        token_url = f"{self.settings.base_url}{self.settings.token_endpoint}"
        
        logger.info(f"Exchanging token at {token_url} with data: {token_data}")
        
        async with session.post(token_url, data=token_data) as response:
            if response.status != 200:
                error_text = await response.text()
                logger.error(f"Token exchange failed: {response.status} - {error_text}")
                logger.error(f"Request data was: {token_data}")
                raise HTTPException(400, f"Token exchange failed: {response.status}")
            
            token_response = await response.json()
            logger.info(f"Token response from TaskManager: {token_response}")
            access_token = token_response.get("access_token")
            
            if not access_token:
                logger.error(f"No access token in response. Full response: {token_response}")
                raise HTTPException(400, "No access token received")
            
            logger.info("Successfully exchanged code for access token")
            return access_token

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code from storage."""
        logger.info(f"Loading authorization code: {authorization_code}")
        logger.info(f"Available auth codes: {list(self.auth_codes.keys())}")
        auth_code = self.auth_codes.get(authorization_code)
        if auth_code:
            logger.info(f"Found auth code for client: {auth_code.client_id}")
        else:
            logger.error(f"Auth code not found: {authorization_code}")
        return auth_code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """
        Exchange MCP authorization code for MCP access token.
        
        This creates the final MCP access token that will be used by
        the MCP client to access protected resources.
        """
        logger.info(f"Exchanging MCP authorization code: {authorization_code.code}")
        logger.info(f"For client: {client.client_id}")
        logger.info(f"Code challenge: {authorization_code.code_challenge}")
        
        if authorization_code.code not in self.auth_codes:
            logger.error(f"Authorization code {authorization_code.code} not found in auth_codes")
            logger.error(f"Available codes: {list(self.auth_codes.keys())}")
            raise ValueError("Invalid authorization code")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token (linked to taskmanager token if needed)
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,  # 1 hour
            resource=authorization_code.resource,
        )

        # Clean up authorization code
        del self.auth_codes[authorization_code.code]

        logger.info(f"Issued MCP access token for client {client.client_id}")

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """
        Load and validate an access token.
        
        This checks if the token exists and hasn't expired. For tokens
        that were issued based on taskmanager authentication, you might
        want to add additional validation here.
        """
        print(f"DEBUG: Looking for token: {token}")
        print(f"DEBUG: Available tokens: {list(self.tokens.keys())}")
        access_token = self.tokens.get(token)
        if not access_token:
            print("DEBUG: Token not found in storage")
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        """Load a refresh token - implement if refresh tokens are needed."""
        # TODO: Implement refresh token support if needed
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token - implement if refresh tokens are needed."""
        # TODO: Implement refresh token exchange if needed
        raise NotImplementedError("Refresh tokens not yet implemented")

    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:
        """
        Revoke a token.
        
        This removes the token from local storage. You might also want to
        notify the taskmanager system about token revocation.
        """
        if token in self.tokens:
            del self.tokens[token]
            logger.info(f"Revoked token: {token[:10]}...")

    async def introspect_token(self, token: str) -> dict[str, Any] | None:
        """
        Introspect a token for Resource Server validation.
        
        This is used by MCP Resource Servers to validate tokens without
        direct access to token storage. Returns token metadata if valid.
        """
        access_token = await self.load_access_token(token)
        if not access_token:
            return {"active": False}

        return {
            "active": True,
            "client_id": access_token.client_id,
            "scope": " ".join(access_token.scopes),
            "exp": access_token.expires_at,
            "iat": int(time.time()),
            "token_type": "Bearer",
            "aud": access_token.resource,  # RFC 8707 audience claim
        }


# Helper function to create provider instance
def create_taskmanager_oauth_provider(
    taskmanager_base_url: str = "https://todo.brooksmcmillin.com",
    server_url: str = "https://mcp.brooksmcmillin.com",
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> TaskManagerOAuthProvider:
    """
    Convenience function to create a TaskManager OAuth provider.
    
    Args:
        taskmanager_base_url: Base URL of your taskmanager application
        server_url: URL of this MCP server
        client_id: OAuth client ID (if already registered)
        client_secret: OAuth client secret (if already registered)
    
    Returns:
        Configured TaskManagerOAuthProvider instance
    """
    settings = TaskManagerAuthSettings(
        base_url=taskmanager_base_url,
        client_id=client_id,
        client_secret=client_secret,
    )
    
    return TaskManagerOAuthProvider(settings, server_url)
