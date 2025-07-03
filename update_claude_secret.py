#!/usr/bin/env python3
"""
Script to update the Claude client secret to 'dummy-secret'.
"""

import hashlib
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
    """Update the Claude client secret to 'dummy-secret'."""
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
        
        # Update the client secret to "dummy-secret"
        dummy_secret_hash = hash_secret("dummy-secret")
        
        cursor.execute(
            "UPDATE oauth_clients SET client_secret_hash = %s WHERE client_id = %s",
            (dummy_secret_hash, CLAUDE_CLIENT_ID)
        )
        
        connection.commit()
        
        # Verify the update
        cursor.execute(
            "SELECT client_secret_hash FROM oauth_clients WHERE client_id = %s",
            (CLAUDE_CLIENT_ID,)
        )
        
        new_hash = cursor.fetchone()[0]
        
        print(f"✅ Updated Claude client secret hash to: {new_hash}")
        print(f"✅ This corresponds to client secret: 'dummy-secret'")
        
        # Verify it matches
        if new_hash == dummy_secret_hash:
            print("✅ Hash verification successful!")
            return 0
        else:
            print("❌ Hash verification failed!")
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