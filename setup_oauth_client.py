"""
OAuth Client Setup Script for TaskManager Integration

This script helps you register OAuth clients with your TaskManager application
for use with the MCP server authentication system.

Usage:
    python setup_oauth_client.py --help
    python setup_oauth_client.py --taskmanager-url http://localhost:4321 --session-cookie "your-session-cookie"

You can get the session cookie from your browser after logging into TaskManager.
"""

import asyncio
import json
import sys
from typing import Any, Optional

import aiohttp
import click
import os
from dotenv import load_dotenv

load_dotenv()
MCP_AUTH_SERVER = os.environ["MCP_AUTH_SERVER"]


async def register_oauth_client(
    taskmanager_url: str,
    session_cookie: str,
    client_name: str = "MCP Server",
    redirect_uris: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Register an OAuth client with TaskManager.

    Args:
        taskmanager_url: Base URL of TaskManager application
        session_cookie: Session cookie for authentication
        client_name: Name for the OAuth client
        redirect_uris: List of allowed redirect URIs

    Returns:
        OAuth client information including client_id and client_secret
    """
    if redirect_uris is None:
        redirect_uris = [f"{MCP_AUTH_SERVER}/oauth/callback"]

    client_data = {
        "name": client_name,
        "redirectUris": redirect_uris,
        "grantTypes": ["authorization_code", "refresh_token"],
        "scopes": ["read", "write"],  # Adjust scopes as needed
    }

    headers = {
        "Content-Type": "application/json",
        "Cookie": f"session={session_cookie}",
    }

    async with aiohttp.ClientSession() as session:
        url = f"{taskmanager_url}/api/oauth/clients"

        async with session.post(url, json=client_data, headers=headers) as response:
            if response.status == 201:
                client_info = await response.json()
                return client_info  # type: ignore
            else:
                error_text = await response.text()
                raise Exception(f"Failed to register client: {response.status} - {error_text}")


async def list_oauth_clients(taskmanager_url: str, session_cookie: str) -> list[dict[str, Any]]:
    """
    List existing OAuth clients in TaskManager.

    Args:
        taskmanager_url: Base URL of TaskManager application
        session_cookie: Session cookie for authentication

    Returns:
        List of OAuth client information
    """
    headers = {
        "Cookie": f"session={session_cookie}",
    }

    async with aiohttp.ClientSession() as session:
        url = f"{taskmanager_url}/api/oauth/clients"

        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                clients = await response.json()
                return clients  # type: ignore
            else:
                error_text = await response.text()
                raise Exception(f"Failed to list clients: {response.status} - {error_text}")


@click.command()
@click.option("--taskmanager-url", default="http://localhost:4321", help="TaskManager base URL")
@click.option("--session-cookie", help="Session cookie from TaskManager (required for auth)")
@click.option("--client-name", default="MCP Server", help="Name for the OAuth client")
@click.option("--list-only", is_flag=True, help="Only list existing clients, don't create new one")
@click.option("--output-env", is_flag=True, help="Output environment variables for .env file")
def main(
    taskmanager_url: str,
    session_cookie: Optional[str],
    client_name: str,
    list_only: bool,
    output_env: bool,
) -> None:
    """
    Set up OAuth client for TaskManager integration.

    This script helps you register OAuth clients with your TaskManager application.
    You'll need to provide a session cookie from your browser after logging in.

    To get the session cookie:
    1. Open TaskManager in your browser and log in
    2. Open browser dev tools (F12)
    3. Go to Application/Storage -> Cookies
    4. Copy the 'session' cookie value
    """

    if not session_cookie:
        print("❌ Session cookie is required for authentication")
        print("\nTo get the session cookie:")
        print("1. Open TaskManager in your browser and log in")
        print("2. Open browser dev tools (F12)")
        print("3. Go to Application/Storage -> Cookies")
        print("4. Copy the 'session' cookie value")
        print("5. Run this script with --session-cookie 'your-cookie-value'")
        sys.exit(1)

    async def run() -> None:
        try:
            print(f"🔗 Connecting to TaskManager at {taskmanager_url}")

            if list_only:
                print("📋 Listing existing OAuth clients...")
                clients = await list_oauth_clients(taskmanager_url, session_cookie)

                if not clients:
                    print("No OAuth clients found.")
                else:
                    print(f"\nFound {len(clients)} OAuth client(s):")
                    for i, client in enumerate(clients, 1):
                        print(f"\n{i}. {client.get('name', 'Unnamed')}")
                        print(f"   Client ID: {client.get('client_id', 'N/A')}")
                        print(f"   Redirect URIs: {client.get('redirect_uris', 'N/A')}")
                        print(f"   Scopes: {client.get('scopes', 'N/A')}")
                        print(f"   Active: {client.get('is_active', 'N/A')}")
                return

            print(f"🔑 Registering OAuth client '{client_name}'...")
            client_info = await register_oauth_client(taskmanager_url, session_cookie, client_name)

            # Do not print the entire client_info dictionary as it may contain sensitive data.

            print("✅ OAuth client registered successfully!")
            print("\n📋 Client Information:")
            print(f"Client ID: {client_info['client_id']}")
            print(f"Client Secret: {client_info['client_secret']}")
            print(f"Name: {client_info['name']}")
            print(f"Redirect URIs: {json.dumps(client_info['redirect_uris'], indent=2)}")

            if output_env:
                print("\n🔧 Environment Variables (.env file):")
                print(f"TASKMANAGER_CLIENT_ID={client_info['client_id']}")
                print(f"TASKMANAGER_CLIENT_SECRET={client_info['client_secret']}")
                print(f"TASKMANAGER_BASE_URL={taskmanager_url}")

            print("\n💡 Usage:")
            print("Start the MCP auth server with:")
            print(
                f"python auth_server.py --taskmanager-url {taskmanager_url} --client-id {client_info['client_id']} --client-secret {client_info['client_secret']}"
            )

        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)

    asyncio.run(run())


if __name__ == "__main__":
    main()
