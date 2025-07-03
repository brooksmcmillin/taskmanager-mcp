#!/usr/bin/env python3
"""
Script to fix the redirect URI for the Claude OAuth client in the database.

This script connects directly to the PostgreSQL database and updates the
redirect_uris field for the claude-code-a6386c3617660a19 client to include
the correct MCP auth server callback URL.
"""

import json
import os
import sys
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

# Load environment variables from taskmanager .env file
taskmanager_env = Path("../taskmanager/.env")
if taskmanager_env.exists():
    load_dotenv(taskmanager_env)
else:
    print("Error: Could not find ../taskmanager/.env file")
    sys.exit(1)

# Database connection settings
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("POSTGRES_DB", "taskmanager")
DB_USER = os.environ.get("POSTGRES_USER", "taskmanager")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD")

if not DB_PASSWORD:
    print("Error: POSTGRES_PASSWORD not found in environment variables")
    sys.exit(1)

CLAUDE_CLIENT_ID = "claude-code-a6386c3617660a19"
MCP_AUTH_SERVER_URL = "https://mcp-auth.brooksmcmillin.com"

def main():
    """Fix the redirect URI for the Claude client."""
    connection = None
    try:
        # Connect to the database
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        
        cursor = connection.cursor()
        
        print(f"Connected to database {DB_NAME}@{DB_HOST}:{DB_PORT}")
        
        # Check if Claude client exists
        cursor.execute(
            "SELECT client_id, name, redirect_uris, scopes FROM oauth_clients WHERE client_id = %s",
            (CLAUDE_CLIENT_ID,)
        )
        
        client_row = cursor.fetchone()
        
        if not client_row:
            print(f"Error: Claude client {CLAUDE_CLIENT_ID} not found in database")
            print("Available clients:")
            cursor.execute("SELECT client_id, name FROM oauth_clients ORDER BY created_at DESC")
            for row in cursor.fetchall():
                print(f"  - {row[0]}: {row[1]}")
            return 1
        
        client_id, name, current_redirect_uris, current_scopes = client_row
        print(f"Found client: {name} (ID: {client_id})")
        print(f"Current redirect URIs: {current_redirect_uris}")
        print(f"Current scopes: {current_scopes}")
        
        # Parse current redirect URIs
        try:
            redirect_uris_list = json.loads(current_redirect_uris) if isinstance(current_redirect_uris, str) else current_redirect_uris
        except json.JSONDecodeError:
            print("Error: Could not parse current redirect URIs as JSON")
            redirect_uris_list = []
        
        # Add the MCP auth server callback URL if not already present
        mcp_callback_url = f"{MCP_AUTH_SERVER_URL}/oauth/callback"
        claude_callback_url = "https://claude.ai/api/mcp/auth_callback"
        
        updated_redirect_uris = list(redirect_uris_list) if redirect_uris_list else []
        
        # Ensure both URLs are in the list
        urls_to_add = [mcp_callback_url, claude_callback_url]
        for url in urls_to_add:
            if url not in updated_redirect_uris:
                updated_redirect_uris.append(url)
                print(f"Adding redirect URI: {url}")
            else:
                print(f"Redirect URI already present: {url}")
        
        # Update the database
        updated_redirect_uris_json = json.dumps(updated_redirect_uris)
        
        cursor.execute(
            "UPDATE oauth_clients SET redirect_uris = %s WHERE client_id = %s",
            (updated_redirect_uris_json, CLAUDE_CLIENT_ID)
        )
        
        connection.commit()
        
        print(f"\nSuccessfully updated redirect URIs for client {CLAUDE_CLIENT_ID}")
        print(f"New redirect URIs: {updated_redirect_uris_json}")
        
        # Verify the update
        cursor.execute(
            "SELECT redirect_uris FROM oauth_clients WHERE client_id = %s",
            (CLAUDE_CLIENT_ID,)
        )
        
        new_redirect_uris = cursor.fetchone()[0]
        print(f"Verified redirect URIs in database: {new_redirect_uris}")
        
        return 0
        
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        if connection:
            connection.close()
            print("Database connection closed")

if __name__ == "__main__":
    sys.exit(main())