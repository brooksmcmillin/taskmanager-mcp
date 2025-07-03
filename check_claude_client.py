#!/usr/bin/env python3
"""
Script to check the Claude OAuth client configuration in the database.
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

CLAUDE_CLIENT_ID = "claude-code-a6386c3617660a19"

def main():
    """Check the Claude client configuration."""
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
        
        # Get all columns for the Claude client
        cursor.execute("SELECT * FROM oauth_clients WHERE client_id = %s", (CLAUDE_CLIENT_ID,))
        
        columns = [desc[0] for desc in cursor.description]
        client_row = cursor.fetchone()
        
        if not client_row:
            print(f"Error: Claude client {CLAUDE_CLIENT_ID} not found in database")
            return 1
        
        print(f"\nClaude Client Configuration:")
        print("=" * 40)
        
        for i, column in enumerate(columns):
            value = client_row[i]
            if column in ['redirect_uris', 'grant_types', 'scopes'] and isinstance(value, str):
                try:
                    value = json.loads(value)
                except:
                    pass
            print(f"{column}: {value}")
        
        print("\n" + "=" * 40)
        
        # Also check the table schema to see what columns are available
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'oauth_clients' 
            ORDER BY ordinal_position
        """)
        
        print("\nTable Schema:")
        print("-" * 20)
        for column_name, data_type in cursor.fetchall():
            print(f"{column_name}: {data_type}")
        
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

if __name__ == "__main__":
    sys.exit(main())