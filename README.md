# TaskManager MCP

A Model Context Protocol (MCP) server implementation with OAuth 2.0 authentication integration for TaskManager.

## Overview

This project provides an MCP-compliant server that integrates with a TaskManager application via OAuth 2.0. It consists of:

- **Resource Server** (`server.py`) - MCP server with OAuth-protected tools
- **Authorization Server** (`auth_server.py`) - OAuth 2.0 authorization server
- **TaskManager API Client** (`task_api.py`) - Python client for TaskManager API
- **Token Verification** (`token_verifier.py`) - Token introspection utilities

## Features

- OAuth 2.0 Authorization Code flow with PKCE
- Token introspection (RFC 7662)
- Protected resource metadata (RFC 9908)
- MCP tool integration with time utilities
- Dynamic client registration
- Resource server validation (RFC 8707)

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

The servers can be configured via environment variables:

### Resource Server
- `MCP_RESOURCE_SERVER_URL` - External server URL (default: https://mcp.brooksmcmillin.com)
- `MCP_RESOURCE_AUTH_SERVER_URL` - Authorization server URL
- `MCP_RESOURCE_MCP_SCOPE` - Required OAuth scope (default: read)

### Authorization Server
- Server settings configurable via command line options

## Usage

### Start the Authorization Server

```bash
python auth_server.py --port 9000
```

### Start the Resource Server

```bash
python server.py --port 8001 --auth-server https://mcp-auth.brooksmcmillin.com
```

Options:
- `--oauth-strict` - Enable RFC 8707 resource validation
- `--server-url` - Override external server URL

### Test the Integration

```bash
python test_client.py
```

## API Endpoints

### Resource Server
- `GET /mcp` - MCP transport endpoint
- `GET /.well-known/oauth-authorization-server` - OAuth metadata
- `GET /mcp/.well-known/oauth-protected-resource` - Protected resource metadata

### Authorization Server
- `POST /authorize` - OAuth authorization endpoint
- `POST /token` - Token exchange endpoint
- `POST /introspect` - Token introspection endpoint
- `POST /register` - Dynamic client registration

## Tools Available

- `get_time` - Returns current server time (OAuth protected)

## Architecture

The system follows OAuth 2.0 best practices:

1. **Authorization Server** handles user authentication via TaskManager
2. **Resource Server** validates tokens via introspection
3. **MCP Integration** provides secure tool access to authenticated clients
4. **Token Verification** ensures proper scope and resource validation

## Development

Run tests:
```bash
python test_setup.py
```

## License

This project integrates with TaskManager and follows MCP specifications.