# MCP OAuth Authentication Demo

This example demonstrates OAuth 2.0 authentication with the Model Context Protocol using **separate Authorization Server (AS) and Resource Server (RS)** to comply with the new RFC 9728 specification.

---

## Running the Servers

### Step 1: Start Authorization Server

```bash
# Start Authorization Server on port 9000
uv run auth_server.py --port=9000
```

**What it provides:**

- OAuth 2.0 flows (registration, authorization, token exchange)
- Simple credential-based authentication (no external provider needed)  
- Token introspection endpoint for Resource Servers (`/introspect`)

---

### Step 2: Start Resource Server (MCP Server)

```bash
# Start Resource Server on port 8001, connected to Authorization Server
uv run server.py --port=8001 --auth-server=http://localhost:9000

# With RFC 8707 strict resource validation (recommended for production)
uv run server.py --port=8001 --auth-server=http://localhost:9000 --oauth-strict

```

### Step 3: Test with Client

```bash
# Start client with streamable HTTP
MCP_SERVER_PORT=8001 MCP_TRANSPORT_TYPE=streamable-http uv run client.py
```

## How It Works

### RFC 9728 Discovery

**Client → Resource Server:**

```bash
curl http://localhost:8001/.well-known/oauth-protected-resource/mcp
```

```json
{
  "resource": "http://localhost:8001",
  "authorization_servers": ["http://localhost:9000"]
}
```

**Client → Authorization Server:**

```bash
curl http://localhost:9000/.well-known/oauth-authorization-server
```

```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/authorize",
  "token_endpoint": "http://localhost:9000/token"
}
```

### Testing with Legacy Server

```bash
# Test with client (will automatically fall back to legacy discovery)
MCP_SERVER_PORT=8001 MCP_TRANSPORT_TYPE=streamable-http uv run client.py
```

The client will:

1. Try RFC 9728 discovery at `/.well-known/oauth-protected-resource` (404 on legacy server)
2. Fall back to direct OAuth discovery at `/.well-known/oauth-authorization-server`
3. Complete authentication with the MCP server acting as its own AS

This ensures existing MCP servers (which could optionally act as Authorization Servers under the old spec) continue to work while the ecosystem transitions to the new architecture where MCP servers are Resource Servers only.

## Manual Testing

### Test Discovery

```bash
# Test Resource Server discovery endpoint (new architecture)
curl -v http://localhost:8001/.well-known/oauth-protected-resource

# Test Authorization Server metadata
curl -v http://localhost:9000/.well-known/oauth-authorization-server
```

### Test Token Introspection

```bash
# After getting a token through OAuth flow:
curl -X POST http://localhost:9000/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=mcp_df065182f68fb49cc7bff5d980342441fcd97d69f01e1c8f7dd6c2b4c22141df"
```
