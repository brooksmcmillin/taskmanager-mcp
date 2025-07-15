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

## Architecture

The server consists of two main components:

1. **Authorization Server** (`auth_server.py`) - Handles OAuth flows and token management
2. **Resource Server** (`server.py`) - Provides MCP tools protected by OAuth authentication

## MCP Tools

- `get_time()` - Get current server time (demo tool)
- `get_all_projects()` - Retrieve all projects from TaskManager
- `get_all_tasks()` - Retrieve all tasks from TaskManager  
- `create_task(title, project_id, description, priority, due_date)` - Create new tasks

## Setup

### Prerequisites

- Python 3.8+
- TaskManager application with OAuth endpoints
- Environment variables configured

### Environment Variables

Create a `.env` file with:

```env
TASKMANAGER_CLIENT_ID=your_oauth_client_id
TASKMANAGER_CLIENT_SECRET=your_oauth_client_secret
MCP_AUTH_SERVER=http://localhost:9000
TASKMANAGER_OAUTH_HOST=http://localhost:4321
MCP_SERVER=http://localhost:8001
```

### Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Start the Authorization Server:
```bash
python auth_server.py --port 9000 --taskmanager-url localhost:4321
```

3. Start the Resource Server:
```bash
python server.py --port 8001 --auth-server http://localhost:9000
```

### Usage with Claude Code

Configure Claude Code to use this MCP server:

```json
{
  "mcpServers": {
    "taskmanager": {
      "command": "python",
      "args": ["server.py"],
      "env": {
        "MCP_AUTH_SERVER": "http://localhost:9000"
      }
    }
  }
}
```

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

- `server.py` - Main MCP resource server
- `auth_server.py` - OAuth authorization server  
- `taskmanager_oauth_provider.py` - OAuth provider implementation
- `task_api.py` - TaskManager API client
- `token_verifier.py` - Token introspection utilities
- `tests/` - Test suite

## OAuth Flow

1. Client initiates OAuth flow
2. User redirected to TaskManager for authentication
3. TaskManager redirects back with authorization code
4. Authorization server exchanges code for access token
5. Client uses token to access MCP tools

## Security Features

- PKCE (Proof Key for Code Exchange) support
- Token introspection for resource validation
- Configurable scope requirements
- Optional strict resource validation (RFC 8707)
