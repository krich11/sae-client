"""
Storage Backend Interface and Implementations.
Supports configurable storage backends (SQLite, JSON).
"""

import json
import logging
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from contextlib import contextmanager

from ..models.api_models import LocalKey


class StorageBackend(ABC):
    """Abstract storage backend interface."""
    
    @abstractmethod
    def save_key(self, key: LocalKey) -> bool:
        """Save a key to storage."""
        pass
    
    @abstractmethod
    def get_key(self, key_id: str) -> Optional[LocalKey]:
        """Get a key by ID."""
        pass
    
    @abstractmethod
    def get_all_keys(self) -> List[LocalKey]:
        """Get all keys."""
        pass
    
    @abstractmethod
    def delete_key(self, key_id: str) -> bool:
        """Delete a key by ID."""
        pass
    
    @abstractmethod
    def reset_database(self) -> bool:
        """Reset/clear all data."""
        pass


class SQLiteBackend(StorageBackend):
    """SQLite storage backend."""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if table exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
                table_exists = cursor.fetchone() is not None
                
                if not table_exists:
                    # Create new table with full schema
                    cursor.execute("""
                        CREATE TABLE keys (
                            key_id TEXT PRIMARY KEY,
                            key_type TEXT NOT NULL,
                            key_material TEXT NOT NULL,
                            key_size INTEGER NOT NULL,
                            source TEXT NOT NULL,
                            creation_time TEXT NOT NULL,
                            expiry_time TEXT,
                            status TEXT NOT NULL,
                            allowed_sae_id TEXT,
                            metadata TEXT,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                    """)
                    self.logger.info("Created new keys table with full schema")
                else:
                    # Check if allowed_sae_id column exists
                    cursor.execute("PRAGMA table_info(keys)")
                    columns = [col[1] for col in cursor.fetchall()]
                    
                    if 'allowed_sae_id' not in columns:
                        # Add the missing column
                        cursor.execute("ALTER TABLE keys ADD COLUMN allowed_sae_id TEXT")
                        self.logger.info("Added missing allowed_sae_id column to existing keys table")
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to initialize SQLite database: {e}")
            raise
    
    @contextmanager
    def _get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
    
    def save_key(self, key: LocalKey) -> bool:
        """Save key to SQLite."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO keys 
                    (key_id, key_type, key_material, key_size, source, creation_time, 
                     expiry_time, status, allowed_sae_id, metadata, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    key.key_id, key.key_type.value, key.key_material, key.key_size,
                    key.source, key.creation_time.isoformat(),
                    key.expiry_time.isoformat() if key.expiry_time else None,
                    key.status.value, key.allowed_sae_id,
                    json.dumps(key.metadata) if key.metadata else None,
                    datetime.now().isoformat(), datetime.now().isoformat()
                ))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to save key {key.key_id}: {e}")
            return False
    
    def get_key(self, key_id: str) -> Optional[LocalKey]:
        """Get key from SQLite."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_key(row)
                return None
        except Exception as e:
            self.logger.error(f"Failed to get key {key_id}: {e}")
            return None
    
    def get_all_keys(self) -> List[LocalKey]:
        """Get all keys from SQLite."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM keys")
                rows = cursor.fetchall()
                return [self._row_to_key(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Failed to get all keys: {e}")
            return []
    
    def delete_key(self, key_id: str) -> bool:
        """Delete key from SQLite."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM keys WHERE key_id = ?", (key_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            self.logger.error(f"Failed to delete key {key_id}: {e}")
            return False
    
    def reset_database(self) -> bool:
        """Reset SQLite database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM keys")
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to reset database: {e}")
            return False
    
    def _row_to_key(self, row) -> LocalKey:
        """Convert database row to LocalKey."""
        from ..models.api_models import KeyType, KeyStatus
        return LocalKey(
            key_id=row[0],
            key_type=KeyType(row[1]),
            key_material=row[2],
            key_size=row[3],
            source=row[4],
            creation_time=datetime.fromisoformat(row[5]),
            expiry_time=datetime.fromisoformat(row[6]) if row[6] else None,
            status=KeyStatus(row[7]),
            allowed_sae_id=row[8],
            metadata=json.loads(row[9]) if row[9] else None
        )


class JSONBackend(StorageBackend):
    """JSON file storage backend."""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.logger = logging.getLogger(__name__)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_file_exists()
    
    def _ensure_file_exists(self):
        """Ensure JSON file exists."""
        if not self.file_path.exists():
            self.file_path.write_text('{"keys": {}}')
    
    def _load_data(self) -> Dict[str, Any]:
        """Load data from JSON file."""
        try:
            if self.file_path.exists():
                content = self.file_path.read_text(encoding='utf-8')
                return json.loads(content)
            return {"keys": {}}
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.logger.error(f"Failed to load JSON data: {e}")
            self.logger.warning("Creating new JSON file due to corruption")
            # Backup corrupted file and create new one
            if self.file_path.exists():
                backup_path = self.file_path.with_suffix('.json.bak')
                self.file_path.rename(backup_path)
                self.logger.info(f"Backed up corrupted file to {backup_path}")
            return {"keys": {}}
        except Exception as e:
            self.logger.error(f"Failed to load JSON data: {e}")
            return {"keys": {}}
    
    def _save_data(self, data: Dict[str, Any]):
        """Save data to JSON file."""
        try:
            self.file_path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            self.logger.error(f"Failed to save JSON data: {e}")
            raise
    
    def save_key(self, key: LocalKey) -> bool:
        """Save key to JSON."""
        try:
            data = self._load_data()
            data["keys"][key.key_id] = {
                "key_id": key.key_id,
                "key_type": key.key_type.value,
                "key_material": key.key_material,
                "key_size": key.key_size,
                "source": key.source,
                "creation_time": key.creation_time.isoformat(),
                "expiry_time": key.expiry_time.isoformat() if key.expiry_time else None,
                "status": key.status.value,
                "allowed_sae_id": key.allowed_sae_id,
                "metadata": key.metadata
            }
            self._save_data(data)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save key {key.key_id}: {e}")
            return False
    
    def get_key(self, key_id: str) -> Optional[LocalKey]:
        """Get key from JSON."""
        try:
            data = self._load_data()
            key_data = data["keys"].get(key_id)
            if key_data:
                return self._dict_to_key(key_data)
            return None
        except Exception as e:
            self.logger.error(f"Failed to get key {key_id}: {e}")
            return None
    
    def get_all_keys(self) -> List[LocalKey]:
        """Get all keys from JSON."""
        try:
            data = self._load_data()
            return [self._dict_to_key(key_data) for key_data in data["keys"].values()]
        except Exception as e:
            self.logger.error(f"Failed to get all keys: {e}")
            return []
    
    def delete_key(self, key_id: str) -> bool:
        """Delete key from JSON."""
        try:
            data = self._load_data()
            if key_id in data["keys"]:
                del data["keys"][key_id]
                self._save_data(data)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to delete key {key_id}: {e}")
            return False
    
    def reset_database(self) -> bool:
        """Reset JSON storage."""
        try:
            self._save_data({"keys": {}})
            return True
        except Exception as e:
            self.logger.error(f"Failed to reset JSON storage: {e}")
            return False
    
    def _dict_to_key(self, key_data: Dict[str, Any]) -> LocalKey:
        """Convert dictionary to LocalKey."""
        from ..models.api_models import KeyType, KeyStatus
        return LocalKey(
            key_id=key_data["key_id"],
            key_type=KeyType(key_data["key_type"]),
            key_material=key_data["key_material"],
            key_size=key_data["key_size"],
            source=key_data["source"],
            creation_time=datetime.fromisoformat(key_data["creation_time"]),
            expiry_time=datetime.fromisoformat(key_data["expiry_time"]) if key_data.get("expiry_time") else None,
            status=KeyStatus(key_data["status"]),
            allowed_sae_id=key_data.get("allowed_sae_id"),
            metadata=key_data.get("metadata")
        )
