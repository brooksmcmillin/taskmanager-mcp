#!/usr/bin/env python3
"""
Test Setup for TaskManager OAuth Integration

This script validates that your TaskManager OAuth endpoints are accessible
and properly configured for MCP integration.
"""

import asyncio
import json
import sys
from typing import Optional

import aiohttp
import click


async def test_taskmanager_endpoints(base_url: str, session_cookie: Optional[str] = None):
    """Test TaskManager OAuth endpoints accessibility."""
    
    print(f"🔍 Testing TaskManager OAuth endpoints at {base_url}")
    
    async with aiohttp.ClientSession() as session:
        
        # Test 1: Authorization endpoint (should redirect to login)
        print("\n1. Testing authorization endpoint...")
        try:
            auth_url = f"{base_url}/api/oauth/authorize?client_id=test&redirect_uri=http://localhost:3030/callback&response_type=code"
            async with session.get(auth_url, allow_redirects=False) as response:
                if response.status in [302, 200]:
                    print(f"   ✅ Authorization endpoint accessible (status: {response.status})")
                    if response.status == 302:
                        location = response.headers.get('Location', '')
                        print(f"   📍 Redirects to: {location}")
                else:
                    print(f"   ❌ Authorization endpoint error (status: {response.status})")
        except Exception as e:
            print(f"   ❌ Authorization endpoint error: {e}")
        
        # Test 2: Token endpoint (should return method not allowed for GET)
        print("\n2. Testing token endpoint...")
        try:
            token_url = f"{base_url}/api/oauth/token"
            async with session.get(token_url) as response:
                if response.status == 405:  # Method not allowed for GET
                    print("   ✅ Token endpoint accessible (correctly rejects GET)")
                elif response.status == 400:  # Bad request due to missing parameters
                    print("   ✅ Token endpoint accessible (rejects invalid request)")
                else:
                    print(f"   ⚠️  Token endpoint status: {response.status}")
        except Exception as e:
            print(f"   ❌ Token endpoint error: {e}")
        
        # Test 3: JWKS endpoint
        print("\n3. Testing JWKS endpoint...")
        try:
            jwks_url = f"{base_url}/api/oauth/jwks"
            async with session.get(jwks_url) as response:
                if response.status == 200:
                    jwks = await response.json()
                    print("   ✅ JWKS endpoint accessible")
                    if 'keys' in jwks:
                        print(f"   📝 Found {len(jwks['keys'])} key(s)")
                    else:
                        print("   ⚠️  JWKS format may need updating")
                else:
                    print(f"   ❌ JWKS endpoint error (status: {response.status})")
        except Exception as e:
            print(f"   ❌ JWKS endpoint error: {e}")
        
        # Test 4: Clients endpoint (requires authentication)
        print("\n4. Testing clients endpoint...")
        try:
            clients_url = f"{base_url}/api/oauth/clients"
            headers = {}
            if session_cookie:
                headers["Cookie"] = f"session={session_cookie}"
            
            async with session.get(clients_url, headers=headers) as response:
                if response.status == 200:
                    clients = await response.json()
                    print(f"   ✅ Clients endpoint accessible")
                    print(f"   📋 Found {len(clients)} client(s)")
                elif response.status == 401:
                    print("   ⚠️  Clients endpoint requires authentication")
                    if not session_cookie:
                        print("   💡 Provide --session-cookie to test authenticated endpoints")
                else:
                    print(f"   ❌ Clients endpoint error (status: {response.status})")
        except Exception as e:
            print(f"   ❌ Clients endpoint error: {e}")


async def test_mcp_servers(auth_server_port: int = 9000, resource_server_port: int = 8001):
    """Test MCP server endpoints."""
    
    print(f"\n🔍 Testing MCP server endpoints")
    
    async with aiohttp.ClientSession() as session:
        
        # Test MCP Auth Server
        print("\n1. Testing MCP Auth Server...")
        try:
            auth_url = f"http://localhost:{auth_server_port}/.well-known/oauth-authorization-server"
            async with session.get(auth_url) as response:
                if response.status == 200:
                    metadata = await response.json()
                    print("   ✅ MCP Auth Server accessible")
                    print(f"   📝 Issuer: {metadata.get('issuer', 'N/A')}")
                else:
                    print(f"   ❌ MCP Auth Server not accessible (status: {response.status})")
        except Exception as e:
            print(f"   ❌ MCP Auth Server error: {e}")
            print("   💡 Make sure to start: python auth_server.py")
        
        # Test MCP Resource Server
        print("\n2. Testing MCP Resource Server...")
        try:
            resource_url = f"http://localhost:{resource_server_port}/.well-known/oauth-protected-resource"
            async with session.get(resource_url) as response:
                if response.status == 200:
                    metadata = await response.json()
                    print("   ✅ MCP Resource Server accessible")
                    print(f"   📝 Resource server: {metadata.get('resource_server', 'N/A')}")
                else:
                    print(f"   ❌ MCP Resource Server not accessible (status: {response.status})")
        except Exception as e:
            print(f"   ❌ MCP Resource Server error: {e}")
            print("   💡 Make sure to start: python server.py")


@click.command()
@click.option("--taskmanager-url", default="http://localhost:4321", help="TaskManager base URL")
@click.option("--session-cookie", help="Session cookie for authenticated tests")
@click.option("--auth-server-port", default=9000, help="MCP Auth Server port")
@click.option("--resource-server-port", default=8001, help="MCP Resource Server port")
@click.option("--skip-mcp", is_flag=True, help="Skip MCP server tests")
def main(
    taskmanager_url: str,
    session_cookie: Optional[str],
    auth_server_port: int,
    resource_server_port: int,
    skip_mcp: bool,
):
    """
    Test TaskManager OAuth integration setup.
    
    This script validates that your TaskManager OAuth endpoints are accessible
    and properly configured for MCP integration.
    
    For authenticated tests, provide a session cookie from your browser.
    """
    
    async def run():
        print("🧪 TaskManager OAuth Integration Test")
        print("=" * 50)
        
        # Test TaskManager endpoints
        await test_taskmanager_endpoints(taskmanager_url, session_cookie)
        
        # Test MCP servers if requested
        if not skip_mcp:
            await test_mcp_servers(auth_server_port, resource_server_port)
        
        print("\n" + "=" * 50)
        print("🎯 Test Summary:")
        print("\nNext steps:")
        print("1. If TaskManager endpoints failed, check that TaskManager is running")
        print("2. If OAuth endpoints are missing, ensure OAuth implementation is complete")
        print("3. Register OAuth client: python setup_oauth_client.py --session-cookie 'your-cookie'")
        print("4. Start MCP servers: python auth_server.py & python server.py")
        print("5. Test full flow: python test_client.py")
        
    asyncio.run(run())


if __name__ == "__main__":
    main()