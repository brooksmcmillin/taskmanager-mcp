"""Pytest configuration and fixtures for tests."""

import os

# Set required environment variables before any imports
# These are needed by taskmanager_mcp.server module at import time
os.environ.setdefault("TASKMANAGER_CLIENT_ID", "test-client-id")
os.environ.setdefault("TASKMANAGER_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("MCP_AUTH_SERVER", "http://localhost:9000")
