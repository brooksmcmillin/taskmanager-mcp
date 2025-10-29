# TaskManager MCP Server

A Model Context Protocol (MCP) server that provides secure, OAuth-protected access to TaskManager's task and project management functionality. This server integrates with Claude Code and other MCP clients to enable AI-powered task management workflows.

## Security Notice

**Important**: This application is designed for educational and development use. While it implements OAuth 2.0 standards and security best practices, it has not undergone comprehensive security auditing or hardening for production environments handling sensitive data. The server includes features like in-memory token storage and debug logging that are not suitable for production use. Use appropriate caution and implement additional security measures (persistent storage, security headers, rate limiting, etc.) if deploying publicly or in production environments.

## Features

- **OAuth 2.0 Authentication**: Secure authentication using your existing TaskManager OAuth setup
- **Task Management**: Create, read, and manage tasks through MCP tools
- **Project Management**: Access and organize projects
- **RFC-Compliant OAuth**: Supports OAuth 2.0 with PKCE, dynamic client registration (RFC 7591), and token introspection (RFC 7662)
- **Resource Validation**: Optional RFC 8707 resource parameter validation
- **Auto-Discovery**: OAuth 2.0 Authorization Server Metadata (RFC 8414) for client auto-configuration

## Quick Start

1. Register an OAuth client in TaskManager named "brooks" with redirect URI: `https://your-auth-server.com/oauth/callback`
2. Create `.env` file with your TaskManager OAuth credentials and server URLs (see Environment Variables section)
3. Run `docker-compose up -d --build`
4. Configure nginx reverse proxy with SSL (see example configs in repo)
5. Connect with MCP Inspector at `https://your-resource-server.com/mcp/` (note trailing slash!)

See detailed setup instructions below for production deployment and local development.

## Architecture

The server uses a two-layer OAuth architecture with Docker containers and nginx reverse proxy:

1. **Authorization Server** (`auth_server.py`) - Handles OAuth flows, dynamic client registration, and token management
   - Delegates authentication to TaskManager's OAuth server
   - Issues MCP-specific access tokens after successful TaskManager authentication
   - Provides token introspection for resource server validation

2. **Resource Server** (`server.py`) - Provides MCP tools protected by OAuth authentication
   - Validates tokens via introspection endpoint
   - Serves OAuth discovery metadata for MCP clients
   - Exposes protected MCP tools and resources

3. **Nginx Reverse Proxy** - Handles SSL termination and CORS headers
   - Proxies requests to appropriate Docker containers
   - Exposes custom headers (like session IDs) for MCP protocol

### OAuth Flow

```
MCP Client → Auth Server → TaskManager OAuth → Auth Server → MCP Client
                ↓
            (issues token)
                ↓
MCP Client → Resource Server (validates token via introspection)
```

The auth server uses the "brooks" OAuth client registered in TaskManager to delegate authentication, then issues its own tokens for accessing MCP resources.

## MCP Tools

- `get_time()` - Get current server time (demo tool)
- `get_all_projects()` - Retrieve all projects from TaskManager
- `get_all_tasks()` - Retrieve all tasks from TaskManager  
- `create_task(title, project_id, description, priority, due_date)` - Create new tasks

## Setup

### Prerequisites

- Docker and Docker Compose
- TaskManager application with OAuth endpoints
- Nginx with SSL certificates (for production deployment)
- An OAuth client registered in TaskManager (see below)

### TaskManager OAuth Client Setup

Before running the servers, register an OAuth client in TaskManager with these settings:

- **Client ID**: `brooks` (or update `.env` with your client ID)
- **Redirect URI**: `https://your-auth-server-domain/oauth/callback`
- **Grant Types**: `authorization_code`, `refresh_token`
- **Scopes**: `read`, `write`

This client is used by the auth server to delegate authentication to TaskManager.

### Docker Deployment

1. Build and start the containers:
```bash
docker-compose up -d --build
```

2. Check logs:
```bash
docker-compose logs -f
```

3. Stop the servers:
```bash
docker-compose down
```

The `docker-compose.yml` configures:
- **auth-server**: Port 9000 (OAuth authorization server)
- **resource-server**: Port 8001 (MCP resource server)
- Both containers use Python 3.13 with `uv` for fast dependency installation

### Local Development

For local development without Docker:

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Update `.env` to use localhost URLs:
```env
MCP_AUTH_SERVER=http://localhost:9000
TASKMANAGER_OAUTH_HOST=http://localhost:4321
MCP_AUTH_SERVER_PUBLIC_URL=http://localhost:9000
MCP_SERVER_URL=http://localhost:8001
```

3. Start the Authorization Server:
```bash
python auth_server.py --port 9000 --taskmanager-url http://localhost:4321
```

4. Start the Resource Server:
```bash
python server.py --port 8001 --auth-server http://localhost:9000
```

### Usage with MCP Clients

#### MCP Inspector

For testing and debugging, use [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

1. Open MCP Inspector in your browser
2. Connect to the resource server using the **full URL with trailing slash**:
3. The inspector will automatically discover OAuth configuration
4. Click "Connect" to start the OAuth flow
5. Authenticate via TaskManager
6. Use the tools and resources

**Important**: The trailing slash is required for MCP Streamable HTTP transport. Without it, requests will get 307 redirects that lose the POST body.

#### Claude Code / Claude Desktop

Configure your MCP client to use the server:

```json
{
  "mcpServers": {
    "taskmanager": {
      "url": "",
      "transport": "streamable-http"
    }
  }
}
```

The client will:
1. Discover OAuth configuration via `.well-known` endpoints
2. Initiate OAuth flow when tools are first accessed
3. Store and reuse tokens for subsequent requests

## Development

### Running Tests

```bash
pytest
```

### Type Checking

```bash
mypy .
```

### Project Structure

- `server.py` - Main MCP resource server with OAuth-protected tools
- `auth_server.py` - OAuth authorization server with dynamic client registration
- `taskmanager_oauth_provider.py` - OAuth provider that delegates to TaskManager
- `task_api.py` - TaskManager API client for backend communication
- `token_verifier.py` - Token introspection with HTTP/HTTPS support
- `docker-compose.yml` - Docker orchestration for both servers
- `Dockerfile` - Python 3.13 container with uv package manager
- `.env` - Environment variables (create from template above)
- `tests/` - Test suite

## Detailed OAuth Flow

### Client Registration (Dynamic)

1. MCP client (e.g., Inspector) sends registration request to auth server
2. Auth server creates client credentials and stores configuration
3. Auth server supports both public clients (`token_endpoint_auth_method: "none"`) and confidential clients
4. Both `/oauth/callback` and `/oauth/callback/debug` redirect URIs are registered automatically

### Authentication Flow

1. **Client initiates OAuth**: MCP client discovers OAuth config via `.well-known/oauth-protected-resource`
2. **Authorization request**: Client redirects user to auth server's `/authorize` endpoint
3. **Delegate to TaskManager**: Auth server redirects to TaskManager OAuth with "brooks" client credentials
4. **User authenticates**: User logs in via TaskManager's OAuth consent screen
5. **TaskManager callback**: TaskManager redirects back to auth server's `/oauth/callback` with auth code
6. **Exchange code**: Auth server exchanges code with TaskManager for TaskManager access token
7. **Issue MCP token**: Auth server issues its own access token for MCP resources
8. **Return to client**: Auth server redirects to client with MCP access token
9. **Access resources**: Client uses token to call MCP tools on resource server
10. **Token validation**: Resource server validates token via introspection endpoint

### Token Introspection

- Resource server validates tokens by calling auth server's `/introspect` endpoint
- Uses HTTP for internal Docker communication, HTTPS for public endpoints
- Optional RFC 8707 resource validation (enable with `--oauth-strict` flag)
- Tokens include scope and expiration metadata

## Security Features

- **PKCE (Proof Key for Code Exchange)**: Protects authorization code from interception
- **Token introspection**: Resource server validates tokens in real-time
- **Scope-based access control**: Configurable scope requirements for tools
- **Optional RFC 8707 validation**: Strict resource parameter validation when enabled
- **Dynamic client registration (RFC 7591)**: Secure client registration with automatic credential generation
- **Public client support**: Supports clients without secrets (e.g., browser-based apps)
- **CORS security**: Properly configured headers for cross-origin requests
- **SSL/TLS**: Production deployment uses HTTPS with valid certificates

## Troubleshooting

### "Missing session ID" Error

- **Cause**: nginx not exposing custom response headers
- **Fix**: Add `Access-Control-Expose-Headers: *` to nginx CORS configuration

### 307 Redirect on POST /mcp

- **Cause**: Missing trailing slash in URL
- **Fix**: Use `https://your-server.com/mcp/` (with trailing slash)

### Token Introspection Failing

- **Cause**: SSL verification failing for internal Docker HTTP communication
- **Fix**: Ensure `token_verifier.py` allows HTTP for Docker internal hostnames like `http://auth-server:9000`

### OAuth Loop (Keeps Re-authorizing)

- **Cause**: Token validation failing, causing 401 errors that trigger new OAuth flows
- **Debug**: Check auth server and resource server logs for introspection errors
- **Fix**: Verify internal URLs are accessible between containers

### Invalid redirect_uri Error

- **Cause**: Redirect URI mismatch between registered client and callback
- **Fix**: Ensure the "brooks" OAuth client in TaskManager has correct redirect URI: `https://your-auth-server.com/oauth/callback`
