#!/usr/bin/env python3
"""
Script to upload the hardcoded Claude client data to the backend database.

This script extracts the Claude client configuration that was previously
hardcoded in auth_server.py and uploads it to the backend database via
the task_api.py interface.
"""

import os
import sys
from dotenv import load_dotenv
from task_api import create_authenticated_client

# Load environment variables
load_dotenv()

# Hardcoded Claude client data (extracted from auth_server.py)
CLAUDE_CLIENT_DATA = {
    "name": "Claude Web Client",
    "client_id": "claude-code-a6386c3617660a19",
    "client_secret": "dummy-secret",  # Claude Web uses "none" auth method
    "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
    "response_types": ["code"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "none",  # Claude Web uses no client authentication
    "scopes": ["read"],
    "created_at": 1751347844
}

def main():
    """Upload the Claude client data to the backend database."""
    # Get credentials from environment
    client_id = os.environ.get("TASKMANAGER_CLIENT_ID")
    client_secret = os.environ.get("TASKMANAGER_CLIENT_SECRET")
    taskmanager_url = os.environ.get("TASKMANAGER_URL", "localhost:4321")
    
    if not client_id or not client_secret:
        print("Error: TASKMANAGER_CLIENT_ID and TASKMANAGER_CLIENT_SECRET environment variables must be set")
        return 1
    
    # Create authenticated API client
    api_client = create_authenticated_client(
        client_id, 
        client_secret, 
        f"{taskmanager_url}/api"
    )
    
    if not api_client:
        print("Error: Failed to authenticate with backend API")
        return 1
    
    print("Successfully authenticated with backend API")
    
    # Check if the Claude client already exists
    print("Checking for existing OAuth clients...")
    response = api_client.get_oauth_clients()
    
    if not response.success:
        print(f"Error: Failed to get OAuth clients: {response.error}")
        return 1
    
    # Check if Claude client already exists
    existing_clients = response.data or []
    claude_client_exists = False
    
    for client in existing_clients:
        if client.get('client_id') == CLAUDE_CLIENT_DATA['client_id'] or \
           client.get('clientId') == CLAUDE_CLIENT_DATA['client_id']:
            claude_client_exists = True
            print(f"Claude client already exists: {CLAUDE_CLIENT_DATA['client_id']}")
            break
    
    if claude_client_exists:
        print("Claude client is already registered in the backend database")
        return 0
    
    # Create the Claude client
    print(f"Creating Claude client: {CLAUDE_CLIENT_DATA['client_id']}")
    
    response = api_client.create_oauth_client(
        name=CLAUDE_CLIENT_DATA['name'],
        redirect_uris=CLAUDE_CLIENT_DATA['redirect_uris'],
        grant_types=CLAUDE_CLIENT_DATA['grant_types'],
        scopes=CLAUDE_CLIENT_DATA['scopes']
    )
    
    if not response.success:
        print(f"Error: Failed to create Claude client: {response.error}")
        return 1
    
    created_client = response.data
    print("Successfully created Claude client in backend database:")
    print(f"  Client ID: {created_client.get('client_id') or created_client.get('clientId')}")
    print(f"  Client Secret: {created_client.get('client_secret') or created_client.get('clientSecret')}")
    
    # Note about client ID mismatch
    created_client_id = created_client.get('client_id') or created_client.get('clientId')
    if created_client_id != CLAUDE_CLIENT_DATA['client_id']:
        print("\nWarning: The created client ID differs from the hardcoded one.")
        print(f"  Expected: {CLAUDE_CLIENT_DATA['client_id']}")
        print(f"  Created:  {created_client_id}")
        print("You may need to update Claude's configuration to use the new client ID.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
