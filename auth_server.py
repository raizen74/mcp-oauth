"""Authorization Server for MCP Split Demo.

This server handles OAuth flows, client registration, and token issuance.
Can be replaced with enterprise authorization servers like Auth0, Entra ID, etc.

NOTE: this is a simplified example for demonstration purposes.
This is not a production-ready implementation.

"""

import asyncio
import logging
import secrets
import time
from typing import Any

import click
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.routes import cors_middleware, create_auth_routes
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl, BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from uvicorn import Config, Server

logger = logging.getLogger(__name__)


class SimpleAuthSettings(BaseSettings):
    """Simple OAuth settings for demo purposes."""

    model_config = SettingsConfigDict(env_prefix="MCP_")

    # Demo user credentials
    demo_username: str = "demo_user"
    demo_password: str = "demo_password"

    # MCP OAuth scope
    mcp_scope: str = "user"


class SimpleOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """Simple OAuth provider for demo purposes.

    This provider handles the OAuth flow by:
    1. Providing a simple login form for demo credentials
    2. Issuing MCP tokens after successful authentication
    3. Maintaining token state for introspection
    """

    def __init__(self, settings: SimpleAuthSettings, auth_callback_url: str, server_url: str):
        self.settings = settings
        self.auth_callback_url = auth_callback_url
        self.server_url = server_url
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str | None]] = {}
        # Store authenticated user information
        self.user_data: dict[str, dict[str, Any]] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        if not client_info.client_id:
            raise ValueError("No client_id provided")
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Generate an authorization URL for simple login flow."""
        state = params.state or secrets.token_hex(16)

        # Store state mapping for callback
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,  # RFC 8707
        }

        # Build simple login URL that points to login page
        auth_url = f"{self.auth_callback_url}?state={state}&client_id={client.client_id}"

        return auth_url

    async def get_login_page(self, state: str) -> HTMLResponse:
        """Generate login page HTML for the given state."""
        if not state:
            raise HTTPException(400, "Missing state parameter")

        # Create simple login form HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MCP Demo Authentication</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }}
                .form-group {{ margin-bottom: 15px; }}
                input {{ width: 100%; padding: 8px; margin-top: 5px; }}
                button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }}
            </style>
        </head>
        <body>
            <h2>MCP Demo Authentication</h2>
            <p>This is a simplified authentication demo. Use the demo credentials below:</p>
            <p><strong>Username:</strong> demo_user<br>
            <strong>Password:</strong> demo_password</p>

            <form action="{self.server_url.rstrip("/")}/login/callback" method="post">
                <input type="hidden" name="state" value="{state}">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" value="demo_user" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" value="demo_password" required>
                </div>
                <button type="submit">Sign In</button>
            </form>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    async def handle_login_callback(self, request: Request) -> Response:
        """Handle login form submission callback."""
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        state = form.get("state")

        if not username or not password or not state:
            raise HTTPException(400, "Missing username, password, or state parameter")

        # Ensure we have strings, not UploadFile objects
        if not isinstance(username, str) or not isinstance(password, str) or not isinstance(state, str):
            raise HTTPException(400, "Invalid parameter types")

        redirect_uri = await self.handle_simple_callback(username, password, state)
        return RedirectResponse(url=redirect_uri, status_code=302)

    async def handle_simple_callback(self, username: str, password: str, state: str) -> str:
        """Handle simple authentication callback and return redirect URI."""
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
        client_id = state_data["client_id"]
        resource = state_data.get("resource")  # RFC 8707

        # These are required values from our own state mapping
        assert redirect_uri is not None
        assert code_challenge is not None
        assert client_id is not None

        # Validate demo credentials
        if username != self.settings.demo_username or password != self.settings.demo_password:
            raise HTTPException(401, "Invalid credentials")

        # Create MCP authorization code
        new_code = f"mcp_{secrets.token_hex(16)}"
        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=[self.settings.mcp_scope],
            code_challenge=code_challenge,
            resource=resource,  # RFC 8707
            subject=username,
        )
        self.auth_codes[new_code] = auth_code

        # Store user data
        self.user_data[username] = {
            "username": username,
            "user_id": f"user_{secrets.token_hex(8)}",
            "authenticated_at": time.time(),
        }

        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")
        if not client.client_id:
            raise ValueError("No client_id provided")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
            resource=authorization_code.resource,  # RFC 8707
            subject=authorization_code.subject,
        )

        # Store user data mapping for this token
        self.user_data[mcp_token] = {
            "username": self.settings.demo_username,
            "user_id": f"user_{secrets.token_hex(8)}",
            "authenticated_at": time.time(),
        }

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        """Load a refresh token - not supported in this example."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token - not supported in this example."""
        raise NotImplementedError("Refresh tokens not supported")

    # TODO(Marcelo): The type hint is wrong. We need to fix, and test to check if it works.
    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:  # type: ignore
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]


class AuthServerSettings(BaseModel):
    """Settings for the Authorization Server."""

    # Server settings
    host: str = "localhost"
    port: int = 9000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")
    auth_callback_path: str = "http://localhost:9000/login/callback"


class SimpleAuthProvider(SimpleOAuthProvider):
    """Authorization Server provider with simple demo authentication.

    This provider:
    1. Issues MCP tokens after simple credential authentication
    2. Stores token state for introspection by Resource Servers
    """

    def __init__(self, auth_settings: SimpleAuthSettings, auth_callback_path: str, server_url: str):
        super().__init__(auth_settings, auth_callback_path, server_url)


def create_authorization_server(server_settings: AuthServerSettings, auth_settings: SimpleAuthSettings) -> Starlette:
    """Create the Authorization Server application."""
    oauth_provider = SimpleAuthProvider(
        auth_settings, server_settings.auth_callback_path, str(server_settings.server_url)
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

    # Add login page route (GET)
    async def login_page_handler(request: Request) -> Response:
        """Show login form."""
        state = request.query_params.get("state")
        if not state:
            raise HTTPException(400, "Missing state parameter")
        return await oauth_provider.get_login_page(state)

    routes.append(Route("/login", endpoint=login_page_handler, methods=["GET"]))

    # Add login callback route (POST)
    async def login_callback_handler(request: Request) -> Response:
        """Handle simple authentication callback."""
        return await oauth_provider.handle_login_callback(request)

    routes.append(Route("/login/callback", endpoint=login_callback_handler, methods=["POST"]))

    # Add token introspection endpoint (RFC 7662) for Resource Servers
    async def introspect_handler(request: Request) -> Response:
        """Token introspection endpoint for Resource Servers.

        Resource Servers call this endpoint to validate tokens without
        needing direct access to token storage.
        """
        form = await request.form()
        print(f"{form = }")
        token = form.get("token")
        if not token or not isinstance(token, str):
            return JSONResponse({"active": False}, status_code=400)

        # Look up token in provider
        access_token = await oauth_provider.load_access_token(token)
        if not access_token:
            return JSONResponse({"active": False})

        return JSONResponse(
            {
                "active": True,
                "client_id": access_token.client_id,
                "scope": " ".join(access_token.scopes),
                "exp": access_token.expires_at,
                "iat": int(time.time()),
                "token_type": "Bearer",
                "aud": access_token.resource,  # RFC 8707 audience claim
                "sub": access_token.subject,  # RFC 7662 subject
                "iss": str(server_settings.server_url),
            }
        )

    routes.append(
        Route(
            "/introspect",
            endpoint=cors_middleware(introspect_handler, ["POST", "OPTIONS"]),
            methods=["POST", "OPTIONS"],
        )
    )

    return Starlette(routes=routes)


async def run_server(server_settings: AuthServerSettings, auth_settings: SimpleAuthSettings):
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
def main(port: int) -> int:
    """Run the MCP Authorization Server.

    This server handles OAuth flows and can be used by multiple Resource Servers.

    Uses simple hardcoded credentials for demo purposes.
    """
    logging.basicConfig(level=logging.INFO)

    # Load simple auth settings
    auth_settings = SimpleAuthSettings()

    # Create server settings
    host = "localhost"
    server_url = f"http://{host}:{port}"
    server_settings = AuthServerSettings(
        host=host,
        port=port,
        server_url=AnyHttpUrl(server_url),
        auth_callback_path=f"{server_url}/login",
    )

    asyncio.run(run_server(server_settings, auth_settings))
    return 0


if __name__ == "__main__":
    main()  # type: ignore[call-arg]
