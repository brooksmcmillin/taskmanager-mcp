#!/usr/bin/env python3
"""
Debug script to test the token endpoint with various request formats
to understand why Claude Web is getting 400 Bad Request errors.
"""

import asyncio
import json
from urllib.parse import urlencode

import aiohttp


async def test_token_endpoint():
    """Test token endpoint with different request formats that Claude Web might use."""
    
    base_url = "http://localhost:9000"
    token_url = f"{base_url}/token"
    
    # Test data that Claude Web would send
    test_cases = [
        {
            "name": "Claude Web typical request (form-encoded)",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": urlencode({
                "grant_type": "authorization_code",
                "code": "test_code_123",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback", 
                "client_id": "claude-code-a6386c3617660a19",
                "code_verifier": "test_code_verifier_123456789012345678901234567890"
            })
        },
        {
            "name": "Claude Web with client_secret=None (form-encoded)",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": urlencode({
                "grant_type": "authorization_code",
                "code": "test_code_123",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "client_id": "claude-code-a6386c3617660a19",
                "client_secret": "",  # Empty string
                "code_verifier": "test_code_verifier_123456789012345678901234567890"
            })
        },
        {
            "name": "Claude Web with missing client_secret (form-encoded)",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": urlencode({
                "grant_type": "authorization_code",
                "code": "test_code_123", 
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "client_id": "claude-code-a6386c3617660a19",
                "code_verifier": "test_code_verifier_123456789012345678901234567890"
                # No client_secret field at all
            })
        },
        {
            "name": "JSON request (not typical for OAuth)",
            "headers": {"Content-Type": "application/json"},
            "data": json.dumps({
                "grant_type": "authorization_code",
                "code": "test_code_123",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "client_id": "claude-code-a6386c3617660a19",
                "code_verifier": "test_code_verifier_123456789012345678901234567890"
            })
        },
        {
            "name": "Invalid grant_type",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": urlencode({
                "grant_type": "invalid_grant",
                "code": "test_code_123",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "client_id": "claude-code-a6386c3617660a19",
                "code_verifier": "test_code_verifier_123456789012345678901234567890"
            })
        }
    ]
    
    print("🔍 Testing token endpoint with various request formats...")
    print("=" * 70)
    
    async with aiohttp.ClientSession() as session:
        for test_case in test_cases:
            print(f"\n📋 Test: {test_case['name']}")
            print("-" * 50)
            
            try:
                async with session.post(
                    token_url,
                    headers=test_case['headers'],
                    data=test_case['data']
                ) as response:
                    print(f"Status: {response.status}")
                    print(f"Headers: {dict(response.headers)}")
                    
                    try:
                        if response.content_type == 'application/json':
                            body = await response.json()
                            print(f"Response body (JSON): {json.dumps(body, indent=2)}")
                        else:
                            body = await response.text()
                            print(f"Response body (text): {body}")
                    except Exception as e:
                        print(f"Could not parse response body: {e}")
                        raw_body = await response.read()
                        print(f"Raw response body: {raw_body}")
                        
            except Exception as e:
                print(f"❌ Request failed: {e}")
                
    print("\n" + "=" * 70)
    print("🎯 Summary:")
    print("- Check which request format returns 400 vs other status codes")
    print("- Look for validation error messages in the response bodies")
    print("- Compare with expected MCP token endpoint behavior")


if __name__ == "__main__":
    asyncio.run(test_token_endpoint())