"""
Storage Service for SAE Client.
Handles local key storage, configuration persistence, and data management.
"""

import json
import logging
import os
import shutil
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

from ..config import config_manager, logger
from ..models.api_models import LocalKey
from .storage_backend import StorageBackend, SQLiteBackend, JSONBackend


class StorageService:
    """Comprehensive storage service for SAE client data."""
    
    def __init__(self):
        """Initialize storage service."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
        self.data_dir = Path(self.config.data_dir)
        self.keys_file = Path(self.config.keys_file)
        
        self._ensure_directories()
        self._init_storage_backend()
    
    def _init_storage_backend(self):
        """Initialize the appropriate storage backend."""
        backend_type = self.config.storage_backend.lower()
        storage_path = self.config.storage_path
        
        if backend_type == "json":
            self.backend = JSONBackend(storage_path)
            self.logger.info(f"Initialized JSON storage backend: {storage_path}")
        elif backend_type == "sqlite":
            self.backend = SQLiteBackend(storage_path)
            self.logger.info(f"Initialized SQLite storage backend: {storage_path}")
        else:
            raise ValueError(f"Unsupported storage backend: {backend_type}")
    
    def _ensure_directories(self):
        """Ensure all required directories exist."""
        directories = [
            self.data_dir,
            self.data_dir / "keys",
            self.data_dir / "backups",
            self.data_dir / "temp",
            Path(self.config.certs_dir) if hasattr(self.config, 'certs_dir') else Path("./certs"),
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Ensured directory exists: {directory}")
    
    def _init_database(self):
        """Initialize SQLite database for key storage (legacy method)."""
        # This method is kept for backward compatibility
        # The actual initialization is now handled by the storage backend
        pass
    
    @contextmanager
    def _get_db_connection(self):
        """Get database connection with proper error handling."""
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_file))
            conn.row_factory = sqlite3.Row
            yield conn
        except Exception as e:
            self.logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def save_key(self, key: LocalKey) -> bool:
        """
        Save a key to storage.
        
        Args:
            key: LocalKey object to save
            
        Returns:
            bool: True if saved successfully
        """
        try:
            success = self.backend.save_key(key)
            if success:
                self._log_audit("SAVE", "KEY", key.key_id, f"Saved key {key.key_id}")
                self.logger.debug(f"Saved key {key.key_id} to {self.config.storage_backend} storage")
            return success
        except Exception as e:
            self.logger.error(f"Failed to save key {key.key_id}: {e}")
            return False
    
    def load_key(self, key_id: str) -> Optional[LocalKey]:
        """
        Load a key from storage.
        
        Args:
            key_id: Key identifier
            
        Returns:
            LocalKey: Key object if found, None otherwise
        """
        try:
            return self.backend.get_key(key_id)
        except Exception as e:
            self.logger.error(f"Failed to load key {key_id}: {e}")
            return None
    
    def load_keys(self) -> Dict[str, LocalKey]:
        """
        Load all keys from storage.
        
        Returns:
            Dict[str, LocalKey]: Dictionary of key_id to LocalKey objects
        """
        try:
            keys_list = self.backend.get_all_keys()
            keys = {key.key_id: key for key in keys_list}
            self.logger.info(f"Loaded {len(keys)} keys from {self.config.storage_backend} storage")
            return keys
        except Exception as e:
            self.logger.error(f"Failed to load keys: {e}")
            return {}
    
    def _row_to_key(self, row) -> Optional[LocalKey]:
        """Convert database row to LocalKey object."""
        try:
            from ..models.api_models import KeyType, KeyStatus
            
            return LocalKey(
                key_id=row['key_id'],
                key_type=KeyType(row['key_type']),
                key_material=row['key_material'],
                key_size=row['key_size'],
                source=row['source'],
                creation_time=datetime.fromisoformat(row['creation_time']),
                expiry_time=datetime.fromisoformat(row['expiry_time']) if row['expiry_time'] else None,
                status=KeyStatus(row['status']),
                metadata=json.loads(row['metadata']) if row['metadata'] else {}
            )
        except Exception as e:
            self.logger.error(f"Failed to convert row to key: {e}")
            return None
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from storage.
        
        Args:
            key_id: Key identifier
            
        Returns:
            bool: True if deleted successfully
        """
        try:
            success = self.backend.delete_key(key_id)
            if success:
                self._log_audit("DELETE", "KEY", key_id, f"Deleted key {key_id}")
                self.logger.info(f"Deleted key {key_id} from {self.config.storage_backend} storage")
            return success
        except Exception as e:
            self.logger.error(f"Failed to delete key {key_id}: {e}")
            return False
    
    def update_key_status(self, key_id: str, status: str) -> bool:
        """
        Update key status.
        
        Args:
            key_id: Key identifier
            status: New status
            
        Returns:
            bool: True if updated successfully
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE keys 
                    SET status = ?, updated_at = ? 
                    WHERE key_id = ?
                """, (status, datetime.now().isoformat(), key_id))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    self._log_audit("UPDATE", "KEY", key_id, f"Updated status to {status}")
                    self.logger.info(f"Updated key {key_id} status to {status}")
                    return True
                else:
                    self.logger.warning(f"Key {key_id} not found for status update")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to update key {key_id} status: {e}")
            return False
    
    def save_configuration(self, key: str, value: Any) -> bool:
        """
        Save configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
            
        Returns:
            bool: True if saved successfully
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO configuration (key, value, updated_at)
                    VALUES (?, ?, ?)
                """, (key, json.dumps(value), datetime.now().isoformat()))
                
                conn.commit()
                self.logger.debug(f"Saved configuration {key}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save configuration {key}: {e}")
            return False
    
    def load_configuration(self, key: str, default: Any = None) -> Any:
        """
        Load configuration value.
        
        Args:
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Any: Configuration value or default
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT value FROM configuration WHERE key = ?", (key,))
                
                row = cursor.fetchone()
                if row:
                    return json.loads(row['value'])
                return default
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration {key}: {e}")
            return default
    
    def _log_audit(self, action: str, entity_type: str, entity_id: Optional[str], details: str):
        """Log audit entry."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO audit_log (timestamp, action, entity_type, entity_id, details, user_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    action,
                    entity_type,
                    entity_id,
                    details,
                    self.config.sae_id
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log audit entry: {e}")
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log entries.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List[Dict[str, Any]]: Audit log entries
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM audit_log 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
                
                entries = []
                for row in cursor.fetchall():
                    entries.append({
                        'id': row['id'],
                        'timestamp': row['timestamp'],
                        'action': row['action'],
                        'entity_type': row['entity_type'],
                        'entity_id': row['entity_id'],
                        'details': row['details'],
                        'user_id': row['user_id']
                    })
                
                return entries
                
        except Exception as e:
            self.logger.error(f"Failed to get audit log: {e}")
            return []
    
    def create_backup(self) -> Optional[str]:
        """
        Create a backup of the database.
        
        Returns:
            str: Backup file path if successful, None otherwise
        """
        try:
            backup_dir = self.data_dir / "backups"
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"sae_client_backup_{timestamp}.db"
            
            shutil.copy2(self.db_file, backup_file)
            
            self.logger.info(f"Created backup: {backup_file}")
            return str(backup_file)
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            return None
    
    def restore_backup(self, backup_file: str) -> bool:
        """
        Restore database from backup.
        
        Args:
            backup_file: Path to backup file
            
        Returns:
            bool: True if restored successfully
        """
        try:
            backup_path = Path(backup_file)
            if not backup_path.exists():
                self.logger.error(f"Backup file not found: {backup_file}")
                return False
            
            # Create backup of current database
            current_backup = self.create_backup()
            
            # Restore from backup
            shutil.copy2(backup_path, self.db_file)
            
            self.logger.info(f"Restored database from backup: {backup_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restore backup: {e}")
            return False
    
    def cleanup_old_backups(self, keep_days: int = 30) -> int:
        """
        Clean up old backup files.
        
        Args:
            keep_days: Number of days to keep backups
            
        Returns:
            int: Number of backups deleted
        """
        try:
            backup_dir = self.data_dir / "backups"
            if not backup_dir.exists():
                return 0
            
            cutoff_time = datetime.now().timestamp() - (keep_days * 24 * 3600)
            deleted_count = 0
            
            for backup_file in backup_dir.glob("sae_client_backup_*.db"):
                if backup_file.stat().st_mtime < cutoff_time:
                    backup_file.unlink()
                    deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} old backup files")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old backups: {e}")
            return 0
    
    def reset_database(self) -> bool:
        """
        Reset the database (delete all keys and recreate tables).
        
        Returns:
            bool: True if reset successfully
        """
        try:
            self.logger.warning(f"Resetting {self.config.storage_backend} storage - all keys will be deleted!")
            
            success = self.backend.reset_database()
            if success:
                self.logger.info(f"{self.config.storage_backend.capitalize()} storage reset completed successfully")
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to reset {self.config.storage_backend} storage: {e}")
            return False

    def get_storage_statistics(self) -> Dict[str, Any]:
        """
        Get storage statistics.
        
        Returns:
            Dict[str, Any]: Storage statistics
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Count keys
                cursor.execute("SELECT COUNT(*) as count FROM keys")
                total_keys = cursor.fetchone()['count']
                
                # Count by status
                cursor.execute("SELECT status, COUNT(*) as count FROM keys GROUP BY status")
                status_counts = {row['status']: row['count'] for row in cursor.fetchall()}
                
                # Count by type
                cursor.execute("SELECT key_type, COUNT(*) as count FROM keys GROUP BY key_type")
                type_counts = {row['key_type']: row['count'] for row in cursor.fetchall()}
                
                # Database size
                db_size = self.db_file.stat().st_size if self.db_file.exists() else 0
                
                return {
                    'total_keys': total_keys,
                    'status_counts': status_counts,
                    'type_counts': type_counts,
                    'database_size_bytes': db_size,
                    'database_size_mb': round(db_size / (1024 * 1024), 2)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get storage statistics: {e}")
            return {}


# Global storage service instance
storage_service = StorageService()
