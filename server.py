"""MCP Resource Server with Token Introspection.

This server validates tokens via Authorization Server introspection and serves MCP resources.
Demonstrates RFC 9728 Protected Resource Metadata for AS/RS separation.

NOTE: this is a simplified example for demonstration purposes.
This is not a production-ready implementation.
"""

import datetime
import logging
from typing import Any

import click
import httpx2
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.server import MCPServer
from mcp.shared.auth_utils import check_resource_allowed, resource_url_from_server_url
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

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
        # Validate URL to prevent SSRF attacks
        if not self.introspection_endpoint.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            logger.warning(f"Rejecting introspection endpoint with unsafe scheme: {self.introspection_endpoint}")
            return None

        # Configure secure HTTP client
        timeout = httpx2.Timeout(10.0, connect=5.0)
        limits = httpx2.Limits(max_connections=10, max_keepalive_connections=5)

        async with httpx2.AsyncClient(
            timeout=timeout,
            limits=limits,
            verify=True,  # Enforce SSL verification
        ) as client:
            try:
                response = await client.post(
                    self.introspection_endpoint,
                    data={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code != 200:
                    logger.debug(f"Token introspection returned status {response.status_code}")
                    return None

                data = response.json()
                if not data.get("active", False):
                    return None

                # RFC 8707 resource validation (only when --oauth-strict is set)
                if self.validate_resource and not self._validate_resource(data):
                    logger.warning(f"Token resource validation failed. Expected: {self.resource_url}")
                    return None

                # `aud` may be a string or a list; report the entry naming this server when there is
                # one, otherwise what the token was issued for, so the server can compare it.
                aud: str | list[str] | None = data.get("aud")
                audiences = aud if isinstance(aud, list) else [aud] if aud else []
                own = self.resource_url.rstrip("/")
                resource = next((a for a in audiences if a.rstrip("/") == own), audiences[0] if audiences else None)

                return AccessToken(
                    token=token,
                    client_id=data.get("client_id", "unknown"),
                    scopes=data.get("scope", "").split() if data.get("scope") else [],
                    expires_at=data.get("exp"),
                    resource=resource,
                    subject=data.get("sub"),  # RFC 7662 subject (resource owner)
                    claims=data,
                )
            except Exception as e:
                logger.warning(f"Token introspection failed: {e}")
                return None

    def _validate_resource(self, token_data: dict[str, Any]) -> bool:
        """Validate token was issued for this resource server."""
        if not self.server_url or not self.resource_url:
            return False  # Fail if strict validation requested but URLs missing

        # Check 'aud' claim first (standard JWT audience)
        aud: list[str] | str | None = token_data.get("aud")
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
        if not self.resource_url:
            return False

        return check_resource_allowed(requested_resource=self.resource_url, configured_resource=resource)


class ResourceServerSettings(BaseSettings):
    """Settings for the MCP Resource Server."""

    model_config = SettingsConfigDict(env_prefix="MCP_RESOURCE_")

    # Server settings
    host: str = "localhost"
    port: int = 8001
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8001/mcp")

    # Authorization Server settings
    auth_server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")
    auth_server_introspection_endpoint: str = "http://localhost:9000/introspect"
    # No user endpoint needed - we get user data from token introspection

    # MCP settings
    mcp_scope: str = "user"

    # RFC 8707 resource validation
    oauth_strict: bool = False


def create_resource_server(settings: ResourceServerSettings) -> MCPServer:
    """
    Create MCP Resource Server with token introspection.

    This server:
    1. Provides protected resource metadata (RFC 9728)
    2. Validates tokens via Authorization Server introspection
    3. Serves MCP tools and resources
    """
    # Create token verifier for introspection with RFC 8707 resource validation
    token_verifier = IntrospectionTokenVerifier(
        introspection_endpoint=settings.auth_server_introspection_endpoint,
        server_url=str(settings.server_url),
        validate_resource=settings.oauth_strict,  # Only validate when --oauth-strict is set
    )

    # Create MCPServer server as a Resource Server
    app = MCPServer(
        name="MCP Resource Server",
        instructions="Resource Server that validates tokens via Authorization Server introspection",
        debug=True,
        # Auth configuration for RS mode
        token_verifier=token_verifier,
        auth=AuthSettings(
            issuer_url=settings.auth_server_url,
            required_scopes=[settings.mcp_scope],
            resource_server_url=settings.server_url,
            validate_token_resource=True,  # tokens must be reported as issued for server_url
        ),
    )
    # Store settings for later use in run()
    app._resource_server_settings = settings  # type: ignore[attr-defined]

    @app.tool()
    async def get_time() -> dict[str, Any]:
        """Get the current server time.

        This tool demonstrates that system information can be protected
        by OAuth authentication. User must be authenticated to access it.
        """

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
@click.option("--auth-server", default="http://localhost:9000", help="Authorization Server URL")
@click.option(
    "--oauth-strict",
    is_flag=True,
    help="Enable RFC 8707 resource validation",
)
def main(port: int, auth_server: str, oauth_strict: bool) -> int:
    """Run the MCP Resource Server.

    This server:
    - Provides RFC 9728 Protected Resource Metadata
    - Validates tokens via Authorization Server introspection
    - Serves MCP tools requiring authentication

    Must be used with a running Authorization Server.
    """
    logging.basicConfig(level=logging.INFO)

    try:
        # Parse auth server URL
        auth_server_url = AnyHttpUrl(auth_server)

        # Create settings
        host = "localhost"
        server_url = (
            f"http://{host}:{port}/mcp"  # curl -v http://localhost:8001/.well-known/oauth-protected-resource/mcp
        )
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
        mcp_server.run(transport="streamable-http", host=host, port=port)
        logger.info("Server stopped")
        return 0
    except Exception:
        logger.exception("Server error")
        return 1


if __name__ == "__main__":
    main()  # type: ignore[call-arg]
