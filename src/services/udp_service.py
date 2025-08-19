"""
UDP Service for SAE Synchronization.
Handles UDP communication for SAE-to-SAE key synchronization.
"""

import socket
import json
import logging
import threading
import time
from typing import Optional, Callable, Dict, Any
from datetime import datetime
from pathlib import Path

from ..config import config_manager
from ..models.sync_models import (
    SignedMessage, BaseSyncMessage, SyncSession, SyncState,
    MessageType, SyncConfig
)
from ..utils.message_signer import message_signer


class UDPService:
    """UDP service for SAE synchronization messages."""
    
    def __init__(self):
        """Initialize UDP service."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
        self.sync_config = SyncConfig()
        self.socket = None
        self.is_running = False
        self.listener_thread = None
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.sessions: Dict[str, SyncSession] = {}
        self.processed_message_ids = set()
        
        # Register default message handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default message handlers."""
        self.register_handler(MessageType.KEY_NOTIFICATION, self._handle_key_notification)
        self.register_handler(MessageType.KEY_ACKNOWLEDGMENT, self._handle_key_acknowledgment)
        self.register_handler(MessageType.ROTATION_CONFIRMATION, self._handle_rotation_confirmation)
        self.register_handler(MessageType.ERROR, self._handle_error_message)
    
    def register_handler(self, message_type: MessageType, handler: Callable):
        """Register a message handler for a specific message type."""
        self.message_handlers[message_type] = handler
        self.logger.info(f"Registered handler for message type: {message_type}")
    
    def start_listener(self, port: Optional[int] = None) -> bool:
        """
        Start UDP listener.
        
        Args:
            port: UDP port to listen on (uses config default if None)
            
        Returns:
            bool: True if listener started successfully
        """
        if self.is_running:
            self.logger.warning("UDP listener already running")
            return True
        
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to port
            listen_port = port or self.sync_config.udp_port
            self.socket.bind(('0.0.0.0', listen_port))
            
            self.is_running = True
            self.listener_thread = threading.Thread(target=self._listener_loop, daemon=True)
            self.listener_thread.start()
            
            self.logger.info(f"UDP listener started on port {listen_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start UDP listener: {e}")
            return False
    
    def stop_listener(self):
        """Stop UDP listener."""
        if not self.is_running:
            return
        
        self.is_running = False
        
        if self.socket:
            self.socket.close()
            self.socket = None
        
        if self.listener_thread:
            self.listener_thread.join(timeout=5)
            self.listener_thread = None
        
        self.logger.info("UDP listener stopped")
    
    def _listener_loop(self):
        """Main listener loop."""
        self.logger.info("UDP listener loop started")
        
        while self.is_running:
            try:
                # Set socket timeout for clean shutdown
                self.socket.settimeout(1.0)
                
                # Receive message
                data, addr = self.socket.recvfrom(self.sync_config.max_message_size)
                
                # Process message in separate thread
                thread = threading.Thread(
                    target=self._process_message,
                    args=(data, addr),
                    daemon=True
                )
                thread.start()
                
            except socket.timeout:
                # Timeout is expected, continue loop
                continue
            except Exception as e:
                if self.is_running:
                    self.logger.error(f"Error in listener loop: {e}")
                break
        
        self.logger.info("UDP listener loop stopped")
    
    def _process_message(self, data: bytes, addr: tuple):
        """Process received UDP message."""
        try:
            # Debug logging for received message
            if self.config.debug_mode:
                self.logger.info(f"UDP MESSAGE RECEIVED: {addr}")
                self.logger.info(f"UDP MESSAGE SIZE: {len(data)} bytes")
                try:
                    message_json = data.decode('utf-8')
                    self.logger.info(f"UDP MESSAGE JSON: {json.dumps(json.loads(message_json), indent=2)}")
                    
                    # Decode and display the payload
                    try:
                        import base64
                        message_data = json.loads(message_json)
                        payload_bytes = base64.b64decode(message_data.get('payload', ''))
                        payload_json = json.loads(payload_bytes.decode('utf-8'))
                        self.logger.info(f"UDP MESSAGE PAYLOAD (DECODED): {json.dumps(payload_json, indent=2)}")
                    except Exception as e:
                        self.logger.warning(f"Failed to decode payload: {e}")
                        
                except:
                    self.logger.info(f"UDP MESSAGE RAW: {data}")
            
            # Parse message
            message_json = data.decode('utf-8')
            message_data = json.loads(message_json)
            
            # Create SignedMessage object
            signed_message = SignedMessage(**message_data)
            
            self.logger.debug(f"Received message from {addr}: {signed_message.sender_sae_id}")
            
            # Check for duplicate message
            if signed_message.payload in self.processed_message_ids:
                self.logger.warning(f"Duplicate message ignored: {signed_message.sender_sae_id}")
                if self.config.debug_mode:
                    self._print_console_notification("DUPLICATE MESSAGE", {
                        "From": signed_message.sender_sae_id,
                        "Address": f"{addr[0]}:{addr[1]}",
                        "Status": "⚠ IGNORED"
                    }, is_warning=True)
                return
            
            # Add to processed messages (with cleanup)
            self.processed_message_ids.add(signed_message.payload)
            if len(self.processed_message_ids) > 1000:
                # Clean up old message IDs
                self.processed_message_ids.clear()
            
            # Verify message
            message = message_signer.verify_message(signed_message, signed_message.sender_sae_id)
            if not message:
                self.logger.warning(f"Message verification failed from {signed_message.sender_sae_id}")
                if self.config.debug_mode:
                    self._print_console_notification("SIGNATURE VERIFICATION", {
                        "From": signed_message.sender_sae_id,
                        "Address": f"{addr[0]}:{addr[1]}",
                        "Status": "✗ FAILED",
                        "Reason": "Invalid signature or sender mismatch"
                    }, is_error=True)
                return
            
            # Console notification for signature verification success
            if self.config.debug_mode:
                self._print_console_notification("SIGNATURE VERIFICATION", {
                    "From": signed_message.sender_sae_id,
                    "Address": f"{addr[0]}:{addr[1]}",
                    "Status": "✓ VALID",
                    "Message Type": message.message_type,
                    "Message ID": message.message_id[:8] + "..."
                })
            
            # Debug logging for verified message
            if self.config.debug_mode:
                self.logger.info(f"UDP MESSAGE VERIFIED: {message.message_type}")
                self.logger.info(f"UDP MESSAGE SENDER: {signed_message.sender_sae_id}")
                self.logger.info(f"UDP MESSAGE ID: {message.message_id}")
                self.logger.info(f"UDP MESSAGE TIMESTAMP: {message.timestamp}")
            
            # Handle message based on type
            handler = self.message_handlers.get(message.message_type)
            if handler:
                handler(message, addr)
            else:
                self.logger.warning(f"No handler for message type: {message.message_type}")
                if self.config.debug_mode:
                    self._print_console_notification("UNKNOWN MESSAGE TYPE", {
                        "From": signed_message.sender_sae_id,
                        "Message Type": message.message_type,
                        "Status": "⚠ UNHANDLED"
                    }, is_warning=True)
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in message from {addr}: {e}")
            if self.config.debug_mode:
                self._print_console_notification("MESSAGE PARSE ERROR", {
                    "Address": f"{addr[0]}:{addr[1]}",
                    "Error": "Invalid JSON format",
                    "Status": "✗ FAILED"
                }, is_error=True)
        except Exception as e:
            self.logger.error(f"Error processing message from {addr}: {e}")
            if self.config.debug_mode:
                self._print_console_notification("MESSAGE PROCESSING ERROR", {
                    "Address": f"{addr[0]}:{addr[1]}",
                    "Error": str(e),
                    "Status": "✗ FAILED"
                }, is_error=True)
    
    def send_message(self, message: SignedMessage, host: str, port: int) -> bool:
        """
        Send a signed message via UDP.
        
        Args:
            message: The signed message to send
            host: Destination host
            port: Destination port
            
        Returns:
            bool: True if message sent successfully
        """
        try:
            # Debug logging for outgoing message
            if self.config.debug_mode:
                self.logger.info(f"UDP MESSAGE SEND: {host}:{port}")
                message_json = message.json()
                self.logger.info(f"UDP MESSAGE JSON: {json.dumps(json.loads(message_json), indent=2)}")
                
                # Decode and display the payload
                try:
                    import base64
                    payload_bytes = base64.b64decode(message.payload)
                    payload_json = json.loads(payload_bytes.decode('utf-8'))
                    self.logger.info(f"UDP MESSAGE PAYLOAD (DECODED): {json.dumps(payload_json, indent=2)}")
                except Exception as e:
                    self.logger.warning(f"Failed to decode payload: {e}")
                
                self.logger.info(f"UDP MESSAGE SIZE: {len(message_json.encode('utf-8'))} bytes")
            
            # Create temporary socket for sending
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_socket:
                # Serialize message
                message_json = message.json()
                message_bytes = message_json.encode('utf-8')
                
                # Send message
                send_socket.sendto(message_bytes, (host, port))
                
                self.logger.debug(f"Sent message to {host}:{port}: {message.sender_sae_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to send message to {host}:{port}: {e}")
            return False
    
    def _handle_key_notification(self, message: BaseSyncMessage, addr: tuple):
        """Handle key notification message."""
        from ..models.sync_models import KeyNotificationMessage
        
        if not isinstance(message, KeyNotificationMessage):
            self.logger.error("Invalid message type for key notification handler")
            return
        
        # Debug logging for key notification
        if self.config.debug_mode:
            self.logger.info(f"SYNC KEY NOTIFICATION RECEIVED:")
            self.logger.info(f"  Master SAE: {message.master_sae_id}")
            self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
            self.logger.info(f"  Message ID: {message.message_id}")
            self.logger.info(f"  Key IDs: {message.key_ids}")
            self.logger.info(f"  Rotation Timestamp: {message.rotation_timestamp}")
            self.logger.info(f"  Rotation Time: {time.ctime(message.rotation_timestamp)}")
        
        self.logger.info(f"Received key notification from {message.master_sae_id}")
        self.logger.info(f"Available keys: {message.key_ids}")
        self.logger.info(f"Rotation timestamp: {message.rotation_timestamp}")
        
        # Console notification for interactive mode
        if self.config.debug_mode:
            self._print_console_notification("KEY NOTIFICATION", {
                "From": message.master_sae_id,
                "To": message.slave_sae_id,
                "Key IDs": ", ".join(message.key_ids),
                "Rotation Time": time.ctime(message.rotation_timestamp),
                "Message ID": message.message_id[:8] + "...",
                "Signature": "✓ VALID",
                "Address": f"{addr[0]}:{addr[1]}"
            })
        
        # Create or update session
        session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.message_id}"
        session = SyncSession(
            session_id=session_id,
            master_sae_id=message.master_sae_id,
            slave_sae_id=message.slave_sae_id,
            state=SyncState.NOTIFIED,
            key_ids=message.key_ids,
            rotation_timestamp=message.rotation_timestamp
        )
        self.sessions[session_id] = session
        
        # Debug logging for session creation
        if self.config.debug_mode:
            self.logger.info(f"SYNC SESSION CREATED:")
            self.logger.info(f"  Session ID: {session_id}")
            self.logger.info(f"  State: {session.state}")
            self.logger.info(f"  Created: {session.created_at}")
        
        # Request keys from KME
        self._request_keys_from_kme(message)
        
        # Send acknowledgment
        self._send_key_acknowledgment(message, addr)
    
    def _handle_key_acknowledgment(self, message: BaseSyncMessage, addr: tuple):
        """Handle key acknowledgment message."""
        from ..models.sync_models import KeyAcknowledgmentMessage
        
        if not isinstance(message, KeyAcknowledgmentMessage):
            self.logger.error("Invalid message type for key acknowledgment handler")
            return
        
        # Debug logging for key acknowledgment
        if self.config.debug_mode:
            self.logger.info(f"SYNC KEY ACKNOWLEDGMENT RECEIVED:")
            self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
            self.logger.info(f"  Master SAE: {message.master_sae_id}")
            self.logger.info(f"  Original Message ID: {message.original_message_id}")
            self.logger.info(f"  Selected Key ID: {message.selected_key_id}")
            self.logger.info(f"  Status: {message.status}")
        
        self.logger.info(f"Received key acknowledgment from {message.slave_sae_id}")
        self.logger.info(f"Selected key: {message.selected_key_id}")
        
        # Enhanced debug logging for acknowledgment receipt
        if self.config.debug_mode:
            self.logger.info(f"SYNC KEY ACKNOWLEDGMENT PROCESSED:")
            self.logger.info(f"  From: {message.slave_sae_id}")
            self.logger.info(f"  To: {message.master_sae_id}")
            self.logger.info(f"  Original Message: {message.original_message_id}")
            self.logger.info(f"  Selected Key: {message.selected_key_id}")
            self.logger.info(f"  Status: {message.status}")
            self.logger.info(f"  Address: {addr[0]}:{addr[1]}")
        
        # Console notification for interactive mode
        if self.config.debug_mode:
            self._print_console_notification("KEY ACKNOWLEDGMENT", {
                "From": message.slave_sae_id,
                "To": message.master_sae_id,
                "Selected Key": message.selected_key_id or "None",
                "Status": message.status,
                "Original Message": message.original_message_id[:8] + "...",
                "Signature": "✓ VALID",
                "Address": f"{addr[0]}:{addr[1]}"
            })
        
        # Update session
        session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.state = SyncState.ACKNOWLEDGED
            session.selected_key_id = message.selected_key_id
            session.updated_at = datetime.now()
            
            # Debug logging for session update
            if self.config.debug_mode:
                self.logger.info(f"SYNC SESSION UPDATED:")
                self.logger.info(f"  Session ID: {session_id}")
                self.logger.info(f"  New State: {session.state}")
                self.logger.info(f"  Selected Key: {session.selected_key_id}")
                self.logger.info(f"  Updated: {session.updated_at}")
        
        # Send rotation confirmation
        self._send_rotation_confirmation(message, addr)
    
    def _handle_rotation_confirmation(self, message: BaseSyncMessage, addr: tuple):
        """Handle rotation confirmation message."""
        from ..models.sync_models import RotationConfirmationMessage
        
        if not isinstance(message, RotationConfirmationMessage):
            self.logger.error("Invalid message type for rotation confirmation handler")
            return
        
        # Debug logging for rotation confirmation
        if self.config.debug_mode:
            self.logger.info(f"SYNC ROTATION CONFIRMATION RECEIVED:")
            self.logger.info(f"  Master SAE: {message.master_sae_id}")
            self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
            self.logger.info(f"  Original Message ID: {message.original_message_id}")
            self.logger.info(f"  Rotation Timestamp: {message.rotation_timestamp}")
            self.logger.info(f"  Rotation Time: {time.ctime(message.rotation_timestamp)}")
        
        self.logger.info(f"Received rotation confirmation from {message.master_sae_id}")
        self.logger.info(f"Rotation timestamp: {message.rotation_timestamp}")
        
        # Console notification for interactive mode
        if self.config.debug_mode:
            self._print_console_notification("ROTATION CONFIRMATION", {
                "From": message.master_sae_id,
                "To": message.slave_sae_id,
                "Rotation Time": time.ctime(message.rotation_timestamp),
                "Original Message": message.original_message_id[:8] + "...",
                "Signature": "✓ VALID",
                "Address": f"{addr[0]}:{addr[1]}"
            })
        
        # Update session
        session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.state = SyncState.CONFIRMED
            session.updated_at = datetime.now()
            
            # Debug logging for session confirmation
            if self.config.debug_mode:
                self.logger.info(f"SYNC SESSION CONFIRMED:")
                self.logger.info(f"  Session ID: {session_id}")
                self.logger.info(f"  Final State: {session.state}")
                self.logger.info(f"  Rotation Time: {time.ctime(session.rotation_timestamp)}")
                self.logger.info(f"  Updated: {session.updated_at}")
        
        # Schedule key rotation
        self._schedule_key_rotation(message)
    
    def _handle_error_message(self, message: BaseSyncMessage, addr: tuple):
        """Handle error message."""
        from ..models.sync_models import ErrorMessage
        
        if not isinstance(message, ErrorMessage):
            self.logger.error("Invalid message type for error handler")
            return
        
        self.logger.error(f"Received error from {message.master_sae_id}: {message.error_message}")
        self.logger.error(f"Error code: {message.error_code}")
        
        # Console notification for interactive mode
        if self.config.debug_mode:
            self._print_console_notification("ERROR MESSAGE", {
                "From": message.master_sae_id,
                "To": message.slave_sae_id,
                "Error Code": message.error_code,
                "Error Message": message.error_message,
                "Original Message": message.original_message_id[:8] + "..." if message.original_message_id else "None",
                "Signature": "✓ VALID",
                "Address": f"{addr[0]}:{addr[1]}"
            }, is_error=True)
        
        # Update session
        session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.state = SyncState.ERROR
            session.error_message = message.error_message
            session.updated_at = datetime.now()
    
    def _request_keys_from_kme(self, message):
        """Request keys from KME using existing notification service."""
        try:
            from ..services.notification_service import slave_notification_service
            
            # Request keys from KME
            success = slave_notification_service.request_key_from_master(
                message.master_sae_id,
                key_ids=message.key_ids
            )
            
            if success:
                self.logger.info("Successfully requested keys from KME")
            else:
                self.logger.error("Failed to request keys from KME")
                
        except Exception as e:
            self.logger.error(f"Error requesting keys from KME: {e}")
    
    def _send_key_acknowledgment(self, message, addr):
        """Send key acknowledgment message."""
        try:
            # Debug logging for acknowledgment creation
            if self.config.debug_mode:
                self.logger.info(f"SYNC KEY ACKNOWLEDGMENT CREATION:")
                self.logger.info(f"  Original Message ID: {message.message_id}")
                self.logger.info(f"  Master SAE: {message.master_sae_id}")
                self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
                self.logger.info(f"  Selected Key ID: {message.key_ids[0] if message.key_ids else 'None'}")
            
            # Create acknowledgment message
            ack_message = message_signer.create_key_acknowledgment(
                original_message_id=message.message_id,
                master_sae_id=message.master_sae_id,
                slave_sae_id=message.slave_sae_id,
                selected_key_id=message.key_ids[0] if message.key_ids else None
            )
            
            # Send message
            host, port = addr
            success = self.send_message(ack_message, host, port)
            
            if success:
                self.logger.info("Sent key acknowledgment")
                # Debug logging for successful send
                if self.config.debug_mode:
                    self.logger.info(f"SYNC KEY ACKNOWLEDGMENT SENT:")
                    self.logger.info(f"  To: {host}:{port}")
                    self.logger.info(f"  Message Type: NOTIFY-ACK")
                    self.logger.info(f"  Original Message: {message.message_id}")
            else:
                self.logger.error("Failed to send key acknowledgment")
                
        except Exception as e:
            self.logger.error(f"Error sending key acknowledgment: {e}")
    
    def _send_rotation_confirmation(self, message, addr):
        """Send rotation confirmation message."""
        try:
            # Find session to get rotation timestamp
            session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
            session = self.sessions.get(session_id)
            
            if not session or not session.rotation_timestamp:
                self.logger.error("Session or rotation timestamp not found")
                return
            
            # Create confirmation message
            conf_message = message_signer.create_rotation_confirmation(
                original_message_id=message.original_message_id,
                rotation_timestamp=session.rotation_timestamp,
                master_sae_id=message.master_sae_id,
                slave_sae_id=message.slave_sae_id
            )
            
            # Send message
            host, port = addr
            success = self.send_message(conf_message, host, port)
            
            if success:
                self.logger.info("Sent rotation confirmation")
            else:
                self.logger.error("Failed to send rotation confirmation")
                
        except Exception as e:
            self.logger.error(f"Error sending rotation confirmation: {e}")
    
    def _schedule_key_rotation(self, message):
        """Schedule key rotation at the specified timestamp."""
        try:
            from ..models.sync_models import RotationConfirmationMessage
            
            if not isinstance(message, RotationConfirmationMessage):
                return
            
            # Calculate delay until rotation
            current_time = int(datetime.now().timestamp())
            delay = message.rotation_timestamp - current_time
            
            # Debug logging for rotation scheduling
            if self.config.debug_mode:
                self.logger.info(f"SYNC ROTATION SCHEDULING:")
                self.logger.info(f"  Current Time: {current_time} ({time.ctime(current_time)})")
                self.logger.info(f"  Rotation Time: {message.rotation_timestamp} ({time.ctime(message.rotation_timestamp)})")
                self.logger.info(f"  Delay: {delay} seconds")
                self.logger.info(f"  Delay: {delay/60:.1f} minutes")
            
            if delay <= 0:
                self.logger.warning("Rotation timestamp is in the past, rotating immediately")
                self._execute_key_rotation(message)
            else:
                self.logger.info(f"Scheduling key rotation in {delay} seconds")
                
                # Schedule rotation
                timer = threading.Timer(delay, self._execute_key_rotation, args=[message])
                timer.daemon = True
                timer.start()
                
                # Debug logging for timer creation
                if self.config.debug_mode:
                    self.logger.info(f"SYNC TIMER CREATED:")
                    self.logger.info(f"  Timer ID: {id(timer)}")
                    self.logger.info(f"  Scheduled: {time.ctime(time.time() + delay)}")
                    self.logger.info(f"  Daemon: {timer.daemon}")
                
        except Exception as e:
            self.logger.error(f"Error scheduling key rotation: {e}")
    
    def _execute_key_rotation(self, message):
        """Execute key rotation."""
        try:
            # Debug logging for key rotation execution
            if self.config.debug_mode:
                self.logger.info(f"SYNC KEY ROTATION EXECUTING:")
                self.logger.info(f"  Master SAE: {message.master_sae_id}")
                self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
                self.logger.info(f"  Original Message ID: {message.original_message_id}")
                self.logger.info(f"  Execution Time: {datetime.now()}")
                self.logger.info(f"  Scheduled Time: {time.ctime(message.rotation_timestamp)}")
            
            self.logger.info("Executing key rotation")
            
            # Update session state
            session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
            if session_id in self.sessions:
                session = self.sessions[session_id]
                session.state = SyncState.ROTATING
                session.updated_at = datetime.now()
                
                # Debug logging for session state update
                if self.config.debug_mode:
                    self.logger.info(f"SYNC SESSION ROTATING:")
                    self.logger.info(f"  Session ID: {session_id}")
                    self.logger.info(f"  State: {session.state}")
                    self.logger.info(f"  Key IDs: {session.key_ids}")
                    self.logger.info(f"  Selected Key: {session.selected_key_id}")
                    self.logger.info(f"  Updated: {session.updated_at}")
            
            # Execute device-specific key rotation
            self._execute_device_rotation(message)
            
            # Clean up session after rotation
            if session_id in self.sessions:
                del self.sessions[session_id]
                
                # Debug logging for session cleanup
                if self.config.debug_mode:
                    self.logger.info(f"SYNC SESSION CLEANED UP:")
                    self.logger.info(f"  Session ID: {session_id}")
                    self.logger.info(f"  Cleanup Time: {datetime.now()}")
                
        except Exception as e:
            self.logger.error(f"Error executing key rotation: {e}")
    
    def _execute_device_rotation(self, message):
        """Execute device-specific key rotation using persona plugin."""
        try:
            # Load persona plugin
            persona_name = self.sync_config.device_persona
            persona = self._load_persona_plugin(persona_name)
            
            if persona:
                # Execute rotation
                persona.rotate_key(message.original_message_id, message.rotation_timestamp)
                self.logger.info(f"Executed key rotation using {persona_name} persona")
            else:
                self.logger.warning(f"No persona plugin found for: {persona_name}")
                
        except Exception as e:
            self.logger.error(f"Error executing device rotation: {e}")
    
    def _load_persona_plugin(self, persona_name: str):
        """Load persona plugin."""
        try:
            # This will be implemented when we create the persona system
            # For now, return None
            return None
        except Exception as e:
            self.logger.error(f"Error loading persona plugin {persona_name}: {e}")
            return None
    
    def get_sessions(self) -> Dict[str, SyncSession]:
        """Get current synchronization sessions."""
        return self.sessions.copy()
    
    def get_session(self, session_id: str) -> Optional[SyncSession]:
        """Get a specific synchronization session."""
        return self.sessions.get(session_id)
    
    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Clean up old synchronization sessions."""
        try:
            current_time = datetime.now()
            sessions_to_remove = []
            
            for session_id, session in self.sessions.items():
                age = current_time - session.updated_at
                if age.total_seconds() > max_age_hours * 3600:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del self.sessions[session_id]
                self.logger.info(f"Cleaned up old session: {session_id}")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old sessions: {e}")


    def _print_console_notification(self, title: str, data: dict, is_error: bool = False, is_warning: bool = False):
        """
        Print a pretty console notification for interactive mode.
        
        Args:
            title: Notification title
            data: Dictionary of key-value pairs to display
            is_error: Whether this is an error notification
            is_warning: Whether this is a warning notification
        """
        try:
            # Import rich components
            from rich.console import Console
            from rich.panel import Panel
            from rich.text import Text
            from rich.table import Table
            from rich.align import Align
            
            console = Console()
            
            # Determine colors based on notification type
            if is_error:
                title_color = "red"
                border_color = "red"
                status_color = "red"
            elif is_warning:
                title_color = "yellow"
                border_color = "yellow"
                status_color = "yellow"
            else:
                title_color = "cyan"
                border_color = "green"
                status_color = "green"
            
            # Create notification table
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Key", style="bold white", width=15)
            table.add_column("Value", style="white")
            
            # Add data rows
            for key, value in data.items():
                if key == "Status" and "✓" in str(value):
                    table.add_row(key, f"[{status_color}]{value}[/{status_color}]")
                elif key == "Status" and "✗" in str(value):
                    table.add_row(key, f"[red]{value}[/red]")
                elif key == "Status" and "⚠" in str(value):
                    table.add_row(key, f"[yellow]{value}[/yellow]")
                else:
                    table.add_row(key, str(value))
            
            # Create the notification panel
            notification_text = Text(f"🔔 {title}", style=f"bold {title_color}")
            panel = Panel(
                Align.center(table),
                title=notification_text,
                border_style=border_color,
                padding=(0, 1)
            )
            
            # Print the notification
            console.print(panel)
            
        except Exception as e:
            # Fallback to simple print if rich is not available
            print(f"\n🔔 {title}")
            for key, value in data.items():
                print(f"  {key}: {value}")
            print()


# Global UDP service instance
udp_service = UDPService()
