"""
Key Management Service for SAE Client.
Handles key request/response, storage, lifecycle management, and cryptographic operations.
"""

import json
import logging
import base64
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

from ..config import config_manager, logger
from ..models.api_models import (
    KeyType, KeyStatus, LocalKey, ETSIKey, KeyRequest, KeyResponse
)
from .storage_service import StorageService


class KeyManagementService:
    """Comprehensive key management service for SAE operations."""
    
    def __init__(self):
        """Initialize key management service."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
        self.storage = StorageService()
        self._load_keys()
    
    def _load_keys(self):
        """Load existing keys from storage."""
        try:
            self.keys = self.storage.load_keys()
            self.logger.info(f"Loaded {len(self.keys)} existing keys from storage")
        except Exception as e:
            self.logger.warning(f"Could not load existing keys: {e}")
            self.keys = {}
    
    def request_keys_from_kme(self, key_type: KeyType, key_size: int, quantity: int = 1, slave_sae_id: str = None, master_sae_id: str = None, additional_slave_sae_ids: List[str] = None) -> KeyResponse:
        """
        Request keys from KME server.
        
        Args:
            key_type: Type of keys to request (ENCRYPTION/DECRYPTION)
            key_size: Key size in bits
            quantity: Number of keys to request
            slave_sae_id: Slave SAE ID for encryption keys
            master_sae_id: Master SAE ID for decryption keys
            additional_slave_sae_ids: Additional slave SAE IDs for key sharing (ETSI multicast)
            
        Returns:
            KeyResponse: Response containing requested keys
        """
        from ..api.client import kme_client
        
        try:
            self.logger.info(f"Requesting {quantity} {key_type.value} keys of size {key_size} from KME")
            
            if key_type == KeyType.ENCRYPTION:
                if not slave_sae_id:
                    slave_sae_id = "SLAVE_001"  # Default fallback
                response = kme_client.request_encryption_keys_for_slave(slave_sae_id, key_size, quantity, additional_slave_sae_ids)
            else:
                if not master_sae_id:
                    master_sae_id = "MASTER_001"  # Default fallback
                response = kme_client.request_decryption_keys_for_master(master_sae_id, key_size, quantity)
            
            # Store received keys locally
            stored_keys = []
            self.logger.info(f"Attempting to store {len(response.keys)} keys from KME response")
            for etsi_key in response.keys:
                try:
                    self.logger.info(f"Storing key {etsi_key.key_ID} from KME")
                    local_key = self._store_key_from_kme(etsi_key, key_type, slave_sae_id, master_sae_id)
                    stored_keys.append(local_key)
                    self.logger.info(f"Successfully stored key {etsi_key.key_ID}")
                except Exception as e:
                    self.logger.error(f"Failed to store key {etsi_key.key_ID}: {e}")
            
            self.logger.info(f"Successfully stored {len(stored_keys)} keys from KME")
            return response
            
        except Exception as e:
            self.logger.error(f"Failed to request keys from KME: {e}")
            raise
    
    def _store_key_from_kme(self, etsi_key: ETSIKey, key_type: KeyType, slave_sae_id: str = None, master_sae_id: str = None) -> LocalKey:
        """
        Store a key received from KME.
        
        Args:
            etsi_key: ETSI key from KME
            key_type: Type of key
            slave_sae_id: Slave SAE ID allowed to request this key (for encryption keys)
            master_sae_id: Master SAE ID that requested this key (for decryption keys)
            
        Returns:
            LocalKey: Stored key object
        """
        # Determine the source and allowed SAE based on key type
        if key_type == KeyType.ENCRYPTION:
            source = f"kme:encryption_for_slave_{slave_sae_id}"
            allowed_sae = slave_sae_id
        else:
            source = f"kme:decryption_from_master_{master_sae_id}"
            allowed_sae = master_sae_id
        
        # Calculate correct key size from base64 material
        import base64
        decoded_bytes = base64.b64decode(etsi_key.key)
        actual_key_size = len(decoded_bytes) * 8  # Convert bytes to bits
        
        local_key = LocalKey(
            key_id=etsi_key.key_ID,
            key_type=key_type,
            key_material=etsi_key.key,
            key_size=actual_key_size,  # Correctly calculated key size
            source=source,
            creation_time=datetime.now(),
            expiry_time=datetime.now() + timedelta(hours=24),
            status=KeyStatus.AVAILABLE,
            allowed_sae_id=allowed_sae,  # Set the allowed SAE ID
            metadata={
                'kme_response': etsi_key.dict(),
                'stored_at': datetime.now().isoformat(),
                'allowed_sae_id': allowed_sae,
                'key_type_context': 'encryption_for_slave' if key_type == KeyType.ENCRYPTION else 'decryption_from_master'
            }
        )
        
        self.logger.info(f"Adding key {etsi_key.key_ID} to memory")
        self.keys[etsi_key.key_ID] = local_key
        
        # Debug logging for key details
        if config_manager.config.debug_mode:
            import hashlib
            key_id_and_material = f"{etsi_key.key_ID}{etsi_key.key}"
            md5_hash = hashlib.md5(key_id_and_material.encode()).hexdigest()
            self.logger.info(f"DEBUG KEY DETAILS:")
            self.logger.info(f"  Key ID: {etsi_key.key_ID}")
            self.logger.info(f"  Key Material: {etsi_key.key}")
            self.logger.info(f"  Key Size: {actual_key_size} bits")
            self.logger.info(f"  Allowed SAE: {allowed_sae}")
            self.logger.info(f"  MD5 Hash (ID+Material): {md5_hash}")
        
        self.logger.info(f"Saving key {etsi_key.key_ID} to storage")
        save_result = self.storage.save_key(local_key)
        if save_result:
            self.logger.info(f"Successfully saved key {etsi_key.key_ID} to storage")
        else:
            self.logger.error(f"Failed to save key {etsi_key.key_ID} to storage")
        
        return local_key
    
    def store_key_from_master(self, key_id: str, key_data: Dict[str, Any], master_id: str) -> LocalKey:
        """
        Store a key received from a master SAE.
        
        Args:
            key_id: Key identifier
            key_data: Key data from master
            master_id: ID of the master SAE
            
        Returns:
            LocalKey: Stored key object
        """
        local_key = LocalKey(
            key_id=key_id,
            key_type=KeyType(key_data.get('key_type', KeyType.ENCRYPTION)),
            key_material=key_data.get('key_material', ''),
            key_size=key_data.get('key_size', 256),
            source=f"master:{master_id}",
            creation_time=datetime.fromisoformat(key_data.get('creation_time', datetime.now().isoformat())),
            expiry_time=datetime.fromisoformat(key_data.get('expiry_time', (datetime.now() + timedelta(hours=24)).isoformat())) if key_data.get('expiry_time') else None,
            status=KeyStatus.AVAILABLE,
            metadata={
                'master_id': master_id,
                'received_at': datetime.now().isoformat(),
                'master_data': key_data
            }
        )
        
        self.keys[key_id] = local_key
        self.storage.save_key(local_key)
        self.logger.info(f"Stored key {key_id} from master {master_id}")
        
        return local_key
    
    def store_key(self, local_key: LocalKey) -> LocalKey:
        """
        Store a LocalKey object directly.
        
        Args:
            local_key: LocalKey object to store
            
        Returns:
            LocalKey: Stored key object
        """
        self.keys[local_key.key_id] = local_key
        self.storage.save_key(local_key)
        self.logger.info(f"Stored key {local_key.key_id} directly")
        return local_key
    
    def get_key(self, key_id: str) -> Optional[LocalKey]:
        """
        Retrieve a key by ID.
        
        Args:
            key_id: Key identifier
            
        Returns:
            LocalKey: Key object if found, None otherwise
        """
        key = self.keys.get(key_id)
        if key and self._is_key_valid(key):
            return key
        elif key and not self._is_key_valid(key):
            self.logger.warning(f"Key {key_id} has expired or is invalid")
            self._mark_key_expired(key_id)
        return None
    
    def get_available_keys(self, key_type: Optional[KeyType] = None, allowed_sae_id: Optional[str] = None) -> List[LocalKey]:
        """
        Get all available keys, optionally filtered by type and allowed SAE.
        
        Args:
            key_type: Optional key type filter
            allowed_sae_id: Optional SAE ID filter (only return keys allowed for this SAE)
            
        Returns:
            List[LocalKey]: List of available keys
        """
        available_keys = []
        for key in self.keys.values():
            if self._is_key_valid(key) and key.status == KeyStatus.AVAILABLE:
                # Filter by key type
                if key_type is None or key.key_type == key_type:
                    # Filter by allowed SAE ID
                    if allowed_sae_id is None or key.allowed_sae_id == allowed_sae_id:
                        available_keys.append(key)
        
        return available_keys
    
    def use_key(self, key_id: str) -> Optional[LocalKey]:
        """
        Mark a key as used and return it.
        
        Args:
            key_id: Key identifier
            
        Returns:
            LocalKey: Used key object if found and valid
        """
        key = self.get_key(key_id)
        if key:
            key.status = KeyStatus.USED
            key.metadata['used_at'] = datetime.now().isoformat()
            self.storage.save_key(key)
            self.logger.info(f"Marked key {key_id} as used")
            return key
        return None
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from storage.
        
        Args:
            key_id: Key identifier
            
        Returns:
            bool: True if key was deleted, False otherwise
        """
        if key_id in self.keys:
            del self.keys[key_id]
            self.storage.delete_key(key_id)
            self.logger.info(f"Deleted key {key_id}")
            return True
        return False
    
    def _is_key_valid(self, key: LocalKey) -> bool:
        """
        Check if a key is valid and not expired.
        
        Args:
            key: Key to validate
            
        Returns:
            bool: True if key is valid, False otherwise
        """
        if key.status == KeyStatus.EXPIRED:
            return False
        
        if key.expiry_time and datetime.now() > key.expiry_time:
            self._mark_key_expired(key.key_id)
            return False
        
        return True
    
    def _mark_key_expired(self, key_id: str):
        """Mark a key as expired."""
        if key_id in self.keys:
            self.keys[key_id].status = KeyStatus.EXPIRED
            self.keys[key_id].metadata['expired_at'] = datetime.now().isoformat()
            self.storage.save_key(self.keys[key_id])
            self.logger.info(f"Marked key {key_id} as expired")
    
    def cleanup_expired_keys(self) -> int:
        """
        Clean up expired keys from storage.
        
        Returns:
            int: Number of keys cleaned up
        """
        expired_count = 0
        current_time = datetime.now()
        
        for key_id, key in list(self.keys.items()):
            if key.expiry_time and current_time > key.expiry_time:
                self.delete_key(key_id)
                expired_count += 1
        
        self.logger.info(f"Cleaned up {expired_count} expired keys")
        return expired_count
    
    def get_key_statistics(self) -> Dict[str, Any]:
        """
        Get key statistics.
        
        Returns:
            Dict[str, Any]: Key statistics
        """
        total_keys = len(self.keys)
        available_keys = len([k for k in self.keys.values() if k.status == KeyStatus.AVAILABLE])
        used_keys = len([k for k in self.keys.values() if k.status == KeyStatus.USED])
        expired_keys = len([k for k in self.keys.values() if k.status == KeyStatus.EXPIRED])
        
        encryption_keys = len([k for k in self.keys.values() if k.key_type == KeyType.ENCRYPTION])
        decryption_keys = len([k for k in self.keys.values() if k.key_type == KeyType.DECRYPTION])
        
        return {
            'total_keys': total_keys,
            'available_keys': available_keys,
            'used_keys': used_keys,
            'expired_keys': expired_keys,
            'encryption_keys': encryption_keys,
            'decryption_keys': decryption_keys,
            'kme_keys': len([k for k in self.keys.values() if k.source == 'kme']),
            'master_keys': len([k for k in self.keys.values() if k.source.startswith('master:')])
        }
    
    def export_key_data(self, key_id: str) -> Dict[str, Any]:
        """
        Export key data for sharing with other SAEs.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Dict[str, Any]: Key data for export
        """
        key = self.get_key(key_id)
        if not key:
            raise ValueError(f"Key {key_id} not found or invalid")
        
        return {
            'key_id': key.key_id,
            'key_type': key.key_type.value,
            'key_size': key.key_size,
            'key_material': key.key_material,
            'creation_time': key.creation_time.isoformat(),
            'expiry_time': key.expiry_time.isoformat() if key.expiry_time else None,
            'source': key.source,
            'status': key.status.value
        }


# Global key management service instance
key_service = KeyManagementService()
