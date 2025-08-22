#!/usr/bin/env python3
"""
Migration script to move keys from SQLite to JSON storage.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime

def migrate_sqlite_to_json():
    """Migrate keys from SQLite database to JSON file."""
    
    sqlite_path = Path("data/sae_client.db")
    json_path = Path("data/keys.json")
    
    if not sqlite_path.exists():
        print("SQLite database not found. Nothing to migrate.")
        return
    
    print(f"Migrating keys from {sqlite_path} to {json_path}")
    
    try:
        # Connect to SQLite database
        conn = sqlite3.connect(str(sqlite_path))
        cursor = conn.cursor()
        
        # Get all keys from SQLite
        cursor.execute("SELECT * FROM keys")
        rows = cursor.fetchall()
        
        print(f"Found {len(rows)} keys in SQLite database")
        
        if not rows:
            print("No keys to migrate.")
            return
        
        # Get column names
        cursor.execute("PRAGMA table_info(keys)")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Convert rows to dictionary format
        keys_data = {}
        for row in rows:
            key_data = dict(zip(columns, row))
            key_id = key_data['key_id']
            
            # Convert to JSON-compatible format
            json_key_data = {
                "key_id": key_data["key_id"],
                "key_type": key_data["key_type"],
                "key_material": key_data["key_material"],
                "key_size": key_data["key_size"],
                "source": key_data["source"],
                "creation_time": key_data["creation_time"],
                "expiry_time": key_data["expiry_time"],
                "status": key_data["status"],
                "allowed_sae_id": key_data.get("allowed_sae_id"),
                "metadata": key_data.get("metadata")
            }
            
            keys_data[key_id] = json_key_data
            print(f"Migrated key: {key_id}")
        
        # Write to JSON file
        json_data = {"keys": keys_data}
        json_path.write_text(json.dumps(json_data, indent=2))
        
        print(f"Successfully migrated {len(keys_data)} keys to {json_path}")
        
        # Close SQLite connection
        conn.close()
        
        # Create backup of SQLite database
        backup_path = sqlite_path.with_suffix('.db.backup')
        import shutil
        shutil.copy2(sqlite_path, backup_path)
        print(f"Created backup of SQLite database: {backup_path}")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    migrate_sqlite_to_json()
