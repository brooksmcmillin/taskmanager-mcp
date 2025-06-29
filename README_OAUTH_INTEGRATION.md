# TaskManager OAuth Integration for MCP Server

This document explains how the MCP (Model Context Protocol) server integrates with your existing TaskManager OAuth endpoints for authentication.

## 🔄 OAuth 2.0 Flow Overview

The OAuth 2.0 Authorization Code flow is used to authenticate MCP clients. Here's how it works:

```
┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ MCP Client  │    │ MCP Auth Server │    │ TaskManager     │    │ MCP Resource    │
│             │    │ (Port 9000)     │    │ OAuth Endpoints │    │ Server (8001)   │
└─────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
       │                    │                        │                        │
       │ 1. Request Auth    │                        │                        │
       ├───────────────────>│                        │                        │
       │                    │                        │                        │
       │ 2. Redirect to     │ 3. Redirect to         │                        │
       │    Auth Server     │    TaskManager         │                        │
       │<───────────────────┤───────────────────────>│                        │
       │                    │                        │                        │
       │ 4. User Login & Consent                     │                        │
       ├─────────────────────────────────────────────>│                        │
       │                    │                        │                        │
       │ 5. Auth Code       │ 6. Auth Code           │                        │
       │<───────────────────┤<───────────────────────┤                        │
       │                    │                        │                        │
       │ 7. Exchange Code   │ 8. Exchange Code       │                        │
       ├───────────────────>├───────────────────────>│                        │
       │                    │                        │                        │
       │ 9. Access Token    │ 10. Access Token       │                        │
       │<───────────────────┤<───────────────────────┤                        │
       │                    │                        │                        │
       │ 11. MCP Request with Token                   │                        │
       ├─────────────────────────────────────────────────────────────────────>│
       │                    │                        │                        │
       │                    │ 12. Token Introspection│                        │
       │                    │<───────────────────────┤                        │
       │                    │                        │                        │
       │ 13. MCP Response   │                        │                        │
       │<─────────────────────────────────────────────────────────────────────┤
```

### Step-by-Step Breakdown:

1. **Authorization Request**: MCP client requests authorization from MCP Auth Server
2. **Redirect Chain**: Auth server redirects to TaskManager OAuth authorize endpoint
3. **User Authentication**: User logs in to TaskManager and grants consent
4. **Authorization Grant**: TaskManager returns authorization code to MCP Auth Server
5. **Token Exchange**: MCP Auth Server exchanges code for access token with TaskManager
6. **MCP Token Issuance**: MCP Auth Server issues MCP-specific access token to client
7. **Resource Access**: Client uses MCP token to access protected MCP resources
8. **Token Validation**: MCP Resource Server validates tokens via introspection

## 🏗️ Architecture Components

### 1. TaskManager OAuth Provider (`taskmanager_oauth_provider.py`)

This is the core integration component that bridges MCP authentication with your TaskManager OAuth endpoints.

**Key Features:**
- Delegates OAuth authentication to TaskManager
- Handles OAuth callback processing
- Manages MCP token lifecycle
- Provides token introspection for resource servers

**Configuration:**
```python
class TaskManagerAuthSettings(BaseSettings):
    base_url: str = "http://localhost:4321"           # TaskManager base URL
    authorize_endpoint: str = "/api/oauth/authorize"   # OAuth authorize endpoint
    token_endpoint: str = "/api/oauth/token"          # OAuth token endpoint
    client_id: Optional[str] = None                   # OAuth client ID
    client_secret: Optional[str] = None               # OAuth client secret
    mcp_scope: str = "read"                          # Default MCP scope
```

### 2. MCP Auth Server (`auth_server.py`)

The OAuth Authorization Server that handles MCP client authentication requests.

**Endpoints:**
- `/oauth/authorize` - OAuth authorization endpoint (from MCP library)
- `/oauth/token` - OAuth token endpoint (from MCP library)  
- `/oauth/callback` - Callback from TaskManager OAuth flow
- `/introspect` - Token introspection for resource servers

**Usage:**
```bash
python auth_server.py \
  --port 9000 \
  --taskmanager-url http://localhost:4321 \
  --client-id your-client-id \
  --client-secret your-client-secret
```

### 3. MCP Resource Server (`server.py`)

The server that provides protected MCP resources and validates tokens.

**Features:**
- Token validation via introspection
- Protected MCP tools and resources
- RFC 9728 Protected Resource Metadata support

### 4. OAuth Client Setup (`setup_oauth_client.py`)

Helper script to register OAuth clients with TaskManager.

**Usage:**
```bash
# Register new OAuth client
python setup_oauth_client.py \
  --taskmanager-url http://localhost:4321 \
  --session-cookie "your-session-cookie" \
  --client-name "MCP Server"

# List existing clients
python setup_oauth_client.py \
  --taskmanager-url http://localhost:4321 \
  --session-cookie "your-session-cookie" \
  --list-only
```

## 🚀 Setup Instructions

### 1. Prerequisites

Ensure your TaskManager application is running with OAuth endpoints available:
- `GET/POST /api/oauth/authorize` - Authorization endpoint
- `POST /api/oauth/token` - Token endpoint
- `GET/POST /api/oauth/clients` - Client management endpoint
- `GET /api/oauth/jwks` - JSON Web Key Set endpoint (if using JWT tokens)

### 2. Register OAuth Client

First, register an OAuth client with your TaskManager application:

```bash
# Get session cookie from browser after logging into TaskManager
# Then register the client
python setup_oauth_client.py \
  --taskmanager-url http://localhost:4321 \
  --session-cookie "your-session-cookie-value" \
  --client-name "MCP Server"
```

This will output the client credentials you need for the next step.

### 3. Start MCP Auth Server

Start the MCP Authorization Server with your TaskManager integration:

```bash
python auth_server.py \
  --port 9000 \
  --taskmanager-url http://localhost:4321 \
  --client-id "client-id-from-step-2" \
  --client-secret "client-secret-from-step-2"
```

### 4. Start MCP Resource Server

Start the MCP Resource Server that provides protected resources:

```bash
python server.py \
  --port 8001 \
  --auth-server http://localhost:9000
```

### 5. Test with MCP Client

Test the integration with the provided test client:

```bash
# Set environment variables
export MCP_SERVER_PORT=8001
export MCP_TRANSPORT_TYPE=streamable_http

# Run test client
python test_client.py
```

## 🔧 Configuration Options

### Environment Variables

You can configure the integration using environment variables:

```bash
# TaskManager OAuth Provider Settings
export TASKMANAGER_BASE_URL=http://localhost:4321
export TASKMANAGER_CLIENT_ID=your-client-id
export TASKMANAGER_CLIENT_SECRET=your-client-secret
export TASKMANAGER_MCP_SCOPE=read,write

# MCP Server Settings  
export MCP_RESOURCE_HOST=localhost
export MCP_RESOURCE_PORT=8001
export MCP_RESOURCE_AUTH_SERVER_URL=http://localhost:9000

# JWT Settings (if using JWT tokens in TaskManager)
export JWT_PRIVATE_KEY=path-to-private-key.pem
export JWT_ISSUER=http://localhost:4321
```

### OAuth Scopes

The integration supports flexible OAuth scopes. Configure scopes in your TaskManager OAuth client registration:

- `read` - Read access to MCP resources
- `write` - Write access to MCP resources  
- `admin` - Administrative access (if needed)

## 🔍 Troubleshooting

### Common Issues

1. **"Invalid client" errors**
   - Ensure OAuth client is registered in TaskManager
   - Verify client_id and client_secret are correct
   - Check that redirect URIs match exactly

2. **"Invalid redirect URI" errors**
   - Verify redirect URIs in OAuth client registration include:
     - `http://localhost:9000/oauth/callback` (MCP auth server)
     - `http://localhost:3030/callback` (test client)

3. **Token validation failures**
   - Check that TaskManager token endpoint is accessible
   - Verify token introspection is working
   - Ensure clocks are synchronized between servers

4. **CORS issues**
   - Configure CORS settings in TaskManager if needed
   - Ensure OAuth endpoints allow cross-origin requests

### Debug Logging

Enable debug logging to troubleshoot issues:

```bash
# Set log level to DEBUG
export PYTHONPATH=/path/to/mcp-server
python -c "import logging; logging.basicConfig(level=logging.DEBUG)" auth_server.py --port 9000
```

### Testing OAuth Flow Manually

You can test the OAuth flow manually using curl:

```bash
# 1. Get authorization URL
curl "http://localhost:9000/oauth/authorize?client_id=test&redirect_uri=http://localhost:3030/callback&response_type=code&scope=read"

# 2. Follow browser redirect to TaskManager, complete login

# 3. Exchange authorization code for token
curl -X POST http://localhost:9000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=YOUR_AUTH_CODE&client_id=test&client_secret=YOUR_SECRET&redirect_uri=http://localhost:3030/callback"

# 4. Test token with MCP resource server
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" http://localhost:8001/mcp
```

## 🔐 Security Considerations

1. **Use HTTPS in production** - All OAuth flows should use HTTPS
2. **Secure client credentials** - Store client secrets securely
3. **Token expiration** - Configure appropriate token lifetimes
4. **Scope limitation** - Use minimal scopes required for functionality
5. **PKCE support** - The integration supports PKCE for enhanced security

## 📝 TODO Items for Production

The current implementation includes several TODOs for production deployment:

1. **JWT Token Validation**: Implement proper JWT token validation if TaskManager uses JWT
2. **Persistent Storage**: Replace in-memory storage with persistent storage (Redis, database)
3. **Client Registration API**: Add endpoint to retrieve client info by ID from TaskManager
4. **Refresh Token Support**: Implement refresh token handling if needed
5. **Rate Limiting**: Add rate limiting for OAuth endpoints
6. **Admin Authentication**: Implement admin session handling for automatic client registration
7. **Error Handling**: Enhance error handling and user feedback
8. **Monitoring**: Add metrics and monitoring for OAuth flows

## 🤝 Integration Points

### TaskManager Requirements

Your TaskManager application needs to support:

1. **OAuth 2.0 Authorization Code Flow**
2. **PKCE (Proof Key for Code Exchange)** - Optional but recommended
3. **Client Credentials Authentication**
4. **Token Introspection** - For resource server validation
5. **CORS Support** - For cross-origin OAuth requests

### MCP Integration

The MCP server integration provides:

1. **Standards-compliant OAuth 2.0** - Follows RFC 6749
2. **RFC 9728 Protected Resource Metadata** - For authorization server discovery
3. **Token Introspection (RFC 7662)** - For distributed token validation
4. **PKCE Support (RFC 7636)** - For enhanced security

This integration allows your existing TaskManager OAuth system to authenticate MCP clients without requiring changes to your core authentication logic.