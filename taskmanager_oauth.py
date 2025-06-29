"""
WIP, please ignore
"""

from mcp.server.auth.provider import AccessToken, AuthorizationCode, AuthorizationParams, OAuthAuthorizationServerProvider
from mcp.shared.auth import OAuthClientInformationFull
from pydantic_settings import BaseSettings
from typing import Optional


class AuthSettings(BaseSettings):
    pass

class TaskManagerOAuthProvider(OAuthAuthorizationServerProvider):

    def __init__(self, settings: AuthSettings, auth_callback_url: str, server_url: str):
        self.settings = settings
        self.auth_callback_url = auth_callback_url
        self.server_url = server_url
        self.clients: dict[str, OAuthClientInformationFull]= {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {} 
        self.state_mapping: dict[str, dict[str, Optional[str]]] = {}

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        return self.clients.get(client_id)
    
    async def register_client(self, client_info: OAuthClientInformationFull):
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = "" # Get client ID from OAuth server

        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,  # RFC 8707
        }

        auth_url = f"{self.auth_callback_url}?state={state}&client_id={client.client_id}"
        return auth_url
