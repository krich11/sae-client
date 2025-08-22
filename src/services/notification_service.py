"""
Notification Service for SAE Client.
Handles master/slave communication and key availability notifications.
"""

import logging
import json
import socket
import threading
import time
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime
from pathlib import Path

from ..config import config_manager, logger
from ..models.api_models import (
    NotificationMessage, KeyAvailabilityNotification, KeyRequestNotification,
    LocalKey, KeyType, KeyStatus
)


class NotificationService:
    """Service for handling master/slave notifications."""
    
    def __init__(self):
        """Initialize notification service."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        self.server_socket = None
        self.server_thread = None
        self.connected_slaves: List[str] = []
        self.connected_master: Optional[str] = None
        self.notification_callbacks: Dict[str, Callable] = {}
        
        # Register default callbacks
        self._register_default_callbacks()
    
    def _register_default_callbacks(self):
        """Register default notification callbacks."""
        self.register_callback('key_available', self._default_key_available_callback)
        self.register_callback('key_request', self._default_key_request_callback)
        self.register_callback('status_update', self._default_status_callback)
    
    def register_callback(self, event_type: str, callback: Callable):
        """Register a callback for a specific event type."""
        self.notification_callbacks[event_type] = callback
        self.logger.info(f"Registered callback for event: {event_type}")
    
    def _default_key_available_callback(self, notification: KeyAvailabilityNotification):
        """Default callback for key availability notifications."""
        self.logger.info(f"Key available notification received: {notification.key_id}")
        # This is a stub - in a real implementation, this would handle the key
        # For now, just log the notification
        return True
    
    def _default_key_request_callback(self, notification: KeyRequestNotification):
        """Default callback for key request notifications."""
        self.logger.info(f"Key request notification received from {notification.slave_id}")
        # This is a stub - in a real implementation, this would process the request
        # For now, just log the notification
        return True
    
    def _default_status_callback(self, notification: NotificationMessage):
        """Default callback for status update notifications."""
        self.logger.info(f"Status update received from {notification.sender_id}")
        # This is a stub - in a real implementation, this would update status
        # For now, just log the notification
        return True
    
    def start_server(self, port: Optional[int] = None):
        """Start the notification server."""
        if self.is_running:
            self.logger.warning("Notification server already running")
            return
        
        server_port = port or self.config.master_slave_port
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', server_port))
            self.server_socket.listen(5)
            
            self.is_running = True
            self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
            self.server_thread.start()
            
            self.logger.info(f"Notification server started on port {server_port}")
        except Exception as e:
            self.logger.error(f"Failed to start notification server: {e}")
            raise
    
    def stop_server(self):
        """Stop the notification server."""
        if not self.is_running:
            return
        
        self.is_running = False
        
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        
        if self.server_thread:
            self.server_thread.join(timeout=5)
        
        self.logger.info("Notification server stopped")
    
    def _server_loop(self):
        """Main server loop for handling incoming connections."""
        while self.is_running:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.is_running:
                    self.logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle individual client connection."""
        try:
            data = client_socket.recv(4096)
            if data:
                message = json.loads(data.decode('utf-8'))
                self._process_message(message)
        except Exception as e:
            self.logger.error(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()
    
    def _process_message(self, message_data: Dict[str, Any]):
        """Process incoming notification message."""
        try:
            message_type = message_data.get('message_type')
            
            if message_type == 'key_available':
                notification = KeyAvailabilityNotification(**message_data)
                self._handle_key_available(notification)
            elif message_type == 'key_request':
                notification = KeyRequestNotification(**message_data)
                self._handle_key_request(notification)
            elif message_type == 'status_update':
                notification = NotificationMessage(**message_data)
                self._handle_status_update(notification)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    def _handle_key_available(self, notification: KeyAvailabilityNotification):
        """Handle key availability notification."""
        callback = self.notification_callbacks.get('key_available')
        if callback:
            callback(notification)
    
    def _handle_key_request(self, notification: KeyRequestNotification):
        """Handle key request notification."""
        callback = self.notification_callbacks.get('key_request')
        if callback:
            callback(notification)
    
    def _handle_status_update(self, notification: NotificationMessage):
        """Handle status update notification."""
        callback = self.notification_callbacks.get('status_update')
        if callback:
            callback(notification)
    
    def send_notification(self, target_host: str, target_port: int, message: Dict[str, Any]) -> bool:
        """Send notification to a specific target."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.notification_timeout)
                sock.connect((target_host, target_port))
                sock.send(json.dumps(message).encode('utf-8'))
                self.logger.info(f"Notification sent to {target_host}:{target_port}")
                return True
        except Exception as e:
            self.logger.error(f"Failed to send notification to {target_host}:{target_port}: {e}")
            return False


class MasterNotificationService(NotificationService):
    """Master-specific notification service."""
    
    def notify_slave_available_key(self, slave_id: str, key_id: str, key_data: Dict[str, Any]) -> bool:
        """
        Notify a slave SAE of an available key.
        
        Args:
            slave_id: ID of the slave SAE to notify
            key_id: ID of the available key
            key_data: Key data to send to the slave
            
        Returns:
            bool: True if notification was sent successfully
        """
        self.logger.info(f"Notifying slave {slave_id} of available key {key_id}")
        
        # This is a stub implementation
        # In a real implementation, this would:
        # 1. Look up the slave's connection details
        # 2. Create a proper KeyAvailabilityNotification
        # 3. Send the notification via the network
        
        notification = KeyAvailabilityNotification(
            master_id=self.config.sae_id,
            slave_id=slave_id,
            key_id=key_id,
            key_type=key_data.get('key_type', KeyType.ENCRYPTION),
            key_size=key_data.get('key_size', 256),
            creation_time=datetime.now(),
            expiry_time=key_data.get('expiry_time')
        )
        
        # For now, just log the notification
        self.logger.info(f"Would send notification: {notification.dict()}")
        
        # TODO: Implement actual network communication
        # This would involve:
        # - Looking up slave connection details from a registry
        # - Sending the notification via TCP/UDP
        # - Handling acknowledgments and retries
        
        return True
    
    def broadcast_key_availability(self, key_id: str, key_data: Dict[str, Any]) -> bool:
        """Broadcast key availability to all connected slaves."""
        self.logger.info(f"Broadcasting key availability for key {key_id}")
        
        success_count = 0
        for slave_id in self.connected_slaves:
            if self.notify_slave_available_key(slave_id, key_id, key_data):
                success_count += 1
        
        self.logger.info(f"Broadcast completed: {success_count}/{len(self.connected_slaves)} successful")
        return success_count > 0


class SlaveNotificationService(NotificationService):
    """Slave-specific notification service."""
    
    def on_key_available_notification(self, master_id: str, key_id: str, key_data: Dict[str, Any]) -> bool:
        """
        Handle notification of available key from master.
        
        Args:
            master_id: ID of the master SAE
            key_id: ID of the available key
            key_data: Key data received from master
            
        Returns:
            bool: True if key was successfully processed
        """
        self.logger.info(f"Received key availability notification from {master_id} for key {key_id}")
        
        # This is a stub implementation
        # In a real implementation, this would:
        # 1. Validate the notification
        # 2. Store the key data locally
        # 3. Update internal state
        # 4. Trigger any registered callbacks
        
        # Create a local key record
        local_key = LocalKey(
            key_id=key_id,
            key_type=key_data.get('key_type', KeyType.ENCRYPTION),
            key_material=key_data.get('key_material', ''),
            key_size=key_data.get('key_size', 256),
            source=f"master:{master_id}",
            creation_time=datetime.now(),
            expiry_time=key_data.get('expiry_time'),
            status=KeyStatus.AVAILABLE,
            metadata={'master_id': master_id}
        )
        
        # For now, just log the key
        self.logger.info(f"Would store key: {local_key.dict()}")
        
        # TODO: Implement actual key storage
        # This would involve:
        # - Storing the key in local storage
        # - Updating key inventory
        # - Triggering any registered callbacks
        # - Sending acknowledgment to master
        
        return True
    
    def request_key_from_master(self, master_id: str, key_ids: List[str] = None, key_type: KeyType = None, key_size: int = None, quantity: int = 1) -> bool:
        """
        Request keys from a master SAE using ETSI "Get key with key IDs" method.
        
        Args:
            master_id: ID of the master SAE
            key_ids: List of key IDs to request (required for ETSI compliance)
            key_type: Key type (legacy parameter, not used in ETSI)
            key_size: Key size (legacy parameter, not used in ETSI)
            quantity: Number of keys (legacy parameter, not used in ETSI)
            
        Returns:
            bool: True if keys were successfully requested
        """
        self.logger.info(f"Requesting keys from master {master_id} using ETSI 'Get key with key IDs' method")
        
        if not key_ids:
            self.logger.error("Key IDs are required for ETSI 'Get key with key IDs' method")
            return False
        
        try:
            from ..api.client import kme_client
            from ..services.key_service import key_service
            
            # ETSI "Get key with key IDs" request format
            request_data = {
                "key_IDs": [{"key_ID": key_id} for key_id in key_ids]
            }
            
            # Make the ETSI-compliant API call
            # URL: https://{KME_hostname}/api/v1/keys/{master_SAE_ID}/dec_keys
            from ..config import config_manager
            kme_url = config_manager.get_kme_url(f"/api/v1/keys/{master_id}/dec_keys")
            
            # Debug logging for KME requests
            if config_manager.config.debug_mode:
                self.logger.info(f"KME REQUEST: POST {kme_url}")
                self.logger.info(f"KME REQUEST JSON: {json.dumps(request_data, indent=2)}")
            
            response = kme_client.session.post(
                kme_url,
                json=request_data,
                timeout=config_manager.config.timeout
            )
            
            # Debug logging for KME responses
            if config_manager.config.debug_mode:
                self.logger.info(f"KME RESPONSE: {response.status_code} {kme_url}")
                try:
                    response_json = response.json()
                    self.logger.info(f"KME RESPONSE JSON: {json.dumps(response_json, indent=2)}")
                except:
                    self.logger.info(f"KME RESPONSE TEXT: {response.text}")
            
            if response.status_code == 200:
                # Parse the ETSI Key container response
                key_container = response.json()
                keys = key_container.get('keys', [])
                
                self.logger.info(f"Successfully received {len(keys)} keys from master {master_id}")
                
                # Store the received keys locally
                for key_data in keys:
                    key_id = key_data.get('key_ID')
                    key_material = key_data.get('key')
                    
                    if key_id and key_material:
                        # Calculate correct key size from base64 material
                        import base64
                        decoded_bytes = base64.b64decode(key_material)
                        actual_key_size = len(decoded_bytes) * 8  # Convert bytes to bits
                        
                        # Create local key record
                        local_key = LocalKey(
                            key_id=key_id,
                            key_type=KeyType.DECRYPTION,  # Keys from master are for decryption
                            key_material=key_material,
                            key_size=actual_key_size,  # Correctly calculated key size
                            source=f"master:{master_id}",
                            creation_time=datetime.now(),
                            status=KeyStatus.AVAILABLE,
                            allowed_sae_id=self.config.sae_id,  # Current SAE is allowed to use this key
                            metadata={
                                'master_id': master_id,
                                'etsi_response': key_data,
                                'allowed_sae_id': self.config.sae_id
                            }
                        )
                        
                        # Debug logging for key details
                        if config_manager.config.debug_mode:
                            import hashlib
                            key_id_and_material = f"{key_id}{key_material}"
                            md5_hash = hashlib.md5(key_id_and_material.encode()).hexdigest()
                            self.logger.info(f"DEBUG SLAVE KEY DETAILS:")
                            self.logger.info(f"  Key ID: {key_id}")
                            self.logger.info(f"  Key Material: {key_material}")
                            self.logger.info(f"  Key Size: {actual_key_size} bits")
                            self.logger.info(f"  Allowed SAE: {self.config.sae_id}")
                            self.logger.info(f"  MD5 Hash (ID+Material): {md5_hash}")
                        
                        # Store the key
                        key_service.store_key(local_key)
                        self.logger.info(f"Stored key {key_id} from master {master_id}")
        
        return True
                
            elif response.status_code == 401:
                self.logger.error(f"Unauthorized: SAE {self.config.sae_id} was not authorized to request these keys")
                return False
                
            elif response.status_code == 400:
                error_data = response.json()
                error_msg = error_data.get('message', 'Unknown error')
                self.logger.error(f"Bad request: {error_msg}")
                return False
                
            else:
                self.logger.error(f"KME request failed with status {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error requesting keys from master {master_id}: {e}")
            return False


# Global notification service instances
master_notification_service = MasterNotificationService()
slave_notification_service = SlaveNotificationService()
