"""Example token verifier implementation using OAuth 2.0 Token Introspection (RFC 7662)."""

import logging
from typing import Any

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.shared.auth_utils import check_resource_allowed, resource_url_from_server_url

logger = logging.getLogger(__name__)


class IntrospectionTokenVerifier(TokenVerifier):
    """Example token verifier that uses OAuth 2.0 Token Introspection (RFC 7662).

    This is a simple example implementation for demonstration purposes.
    Production implementations should consider:
    - Connection pooling and reuse
    - More sophisticated error handling
    - Rate limiting and retry logic
    - Comprehensive configuration options
    """

    def __init__(
        self,
        introspection_endpoint: str,
        server_url: str,
        validate_resource: bool = False,
    ):
        self.introspection_endpoint = introspection_endpoint
        self.server_url = server_url
        self.validate_resource = validate_resource
        self.resource_url = resource_url_from_server_url(server_url)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify token via introspection endpoint."""
        import httpx

        # Validate URL to prevent SSRF attacks
        if not self.introspection_endpoint.startswith(
            ("https://", "http://localhost", "http://127.0.0.1")
        ):
            logger.warning(
                f"Rejecting introspection endpoint with unsafe scheme: {self.introspection_endpoint}"
            )
            return None

        # Configure secure HTTP client
        timeout = httpx.Timeout(10.0, connect=5.0)
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            verify=True,  # Enforce SSL verification
        ) as client:
            try:
                print(f"Connectiong to {self.introspection_endpoint}")
                response = await client.post(
                    self.introspection_endpoint,
                    data={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code != 200:
                    logger.debug(
                        f"Token introspection returned status {response.status_code}"
                    )
                    return None

                data = response.json()
                print(f"DEBUG: Introspection response: {data}")
                if not data.get("active", False):
                    print("DEBUG: Token marked as inactive")
                    return None

                # RFC 8707 resource validation (only when --oauth-strict is set)
                if self.validate_resource and not self._validate_resource(data):
                    logger.warning(
                        f"Token resource validation failed. Expected: {self.resource_url}"
                    )
                    return None

                access_token = AccessToken(
                    token=token,
                    client_id=data.get("client_id", "unknown"),
                    scopes=data.get("scope", "").split() if data.get("scope") else [],
                    expires_at=data.get("exp"),
                    resource=data.get("aud"),  # Include resource in token
                )
                print(f"DEBUG: Created AccessToken: {access_token}")
                return access_token
            except Exception as e:
                logger.warning(f"Token introspection failed: {e}")
                return None

    def _validate_resource(self, token_data: dict[str, Any]) -> bool:
        """Validate token was issued for this resource server."""
        print("Validating Resource")
        if not self.server_url or not self.resource_url:
            return False  # Fail if strict validation requested but URLs missing

        # Check 'aud' claim first (standard JWT audience)
        aud = token_data.get("aud")
        if isinstance(aud, list):
            for audience in aud:
                if self._is_valid_resource(audience):
                    return True
            return False
        elif aud:
            return self._is_valid_resource(aud)

        # No resource binding - invalid per RFC 8707
        return False

    def _is_valid_resource(self, resource: str) -> bool:
        """Check if resource matches this server using hierarchical matching."""
        print("Checking if valid resource")
        if not self.resource_url:
            return False

        return check_resource_allowed(
            requested_resource=self.resource_url, configured_resource=resource
        )
