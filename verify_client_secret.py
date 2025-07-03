#!/usr/bin/env python3
"""
Script to verify and fix the Claude client secret in the database.
"""

import hashlib
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

# Database connection settings
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("POSTGRES_DB", "taskmanager")
DB_USER = os.environ.get("POSTGRES_USER", "taskmanager")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD")

CLAUDE_CLIENT_ID = "claude-code-a6386c3617660a19"

def hash_secret(secret):
    """Hash a client secret using SHA-256 (same as TaskManager)."""
    return hashlib.sha256(secret.encode()).hexdigest()

def main():
    """Verify and potentially fix the Claude client secret."""
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
        
        # Get the current client secret hash
        cursor.execute(
            "SELECT client_secret_hash FROM oauth_clients WHERE client_id = %s",
            (CLAUDE_CLIENT_ID,)
        )
        
        result = cursor.fetchone()
        if not result:
            print(f"Error: Claude client {CLAUDE_CLIENT_ID} not found in database")
            return 1
        
        current_hash = result[0]
        print(f"Current client_secret_hash in database: {current_hash}")
        
        # Test various possible client secrets
        possible_secrets = [
            "dummy-secret",
            "",
            "REPLACE_WITH_CLIENT_SECRET",
            "none",
            "claude-secret"
        ]
        
        print("\nTesting possible client secrets:")
        for secret in possible_secrets:
            test_hash = hash_secret(secret)
            matches = test_hash == current_hash
            print(f"  '{secret}' -> {test_hash} {'✓ MATCH' if matches else '✗'}")
            
            if matches:
                print(f"\n✅ Found matching secret: '{secret}'")
                return 0
        
        print(f"\n❌ None of the tested secrets match the database hash")
        print(f"Current hash: {current_hash}")
        
        # Offer to update the client secret to "dummy-secret"
        dummy_secret_hash = hash_secret("dummy-secret")
        print(f"\nWould you like to update the client secret to 'dummy-secret'?")
        print(f"This will set the hash to: {dummy_secret_hash}")
        
        response = input("Update? (y/N): ").strip().lower()
        if response == 'y' or response == 'yes':
            cursor.execute(
                "UPDATE oauth_clients SET client_secret_hash = %s WHERE client_id = %s",
                (dummy_secret_hash, CLAUDE_CLIENT_ID)
            )
            connection.commit()
            print("✅ Client secret updated successfully!")
            return 0
        else:
            print("No changes made.")
            return 1
        
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        if connection:
            connection.close()

if __name__ == "__main__":
    sys.exit(main())