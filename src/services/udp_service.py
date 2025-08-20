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
from .sync_state_machine import sync_state_machine, MessageType as StateMessageType


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
        self.register_handler(MessageType.SYNC_CONFIRMATION, self._handle_sync_confirmation)
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
            
            # State machine validation
            # For acknowledgments and sync confirmations, use the original_message_id to find the session
            if message.message_type == MessageType.KEY_ACKNOWLEDGMENT:
                from ..models.sync_models import KeyAcknowledgmentMessage
                if isinstance(message, KeyAcknowledgmentMessage):
                    session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
                else:
                    session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.message_id}"
            elif message.message_type == MessageType.SYNC_CONFIRMATION:
                from ..models.sync_models import SyncConfirmationMessage
                if isinstance(message, SyncConfirmationMessage):
                    session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
                else:
                    session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.message_id}"
            else:
                session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.message_id}"
            
            # Debug logging for session ID construction
            if self.config.debug_mode:
                self.logger.info(f"STATE MACHINE VALIDATION:")
                self.logger.info(f"  Message Type: {message.message_type}")
                self.logger.info(f"  Message ID: {message.message_id}")
                if message.message_type == MessageType.KEY_ACKNOWLEDGMENT:
                    from ..models.sync_models import KeyAcknowledgmentMessage
                    if isinstance(message, KeyAcknowledgmentMessage):
                        self.logger.info(f"  Original Message ID: {message.original_message_id}")
                elif message.message_type == MessageType.SYNC_CONFIRMATION:
                    from ..models.sync_models import SyncConfirmationMessage
                    if isinstance(message, SyncConfirmationMessage):
                        self.logger.info(f"  Original Message ID: {message.original_message_id}")
                self.logger.info(f"  Session ID: {session_id}")
                self.logger.info(f"  Master SAE: {message.master_sae_id}")
                self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
            
            # Map message type to state machine type
            state_message_type = self._map_message_type(message.message_type)
            
            # Check if message can be accepted
            can_accept, reason = sync_state_machine.can_accept_message(
                state_message_type,
                signed_message.sender_sae_id,
                self.config.sae_id,
                session_id
            )
            
            if not can_accept:
                self.logger.warning(f"State machine rejected message: {reason}")
                if self.config.debug_mode:
                    self._print_console_notification("STATE MACHINE REJECTION", {
                        "From": signed_message.sender_sae_id,
                        "Message Type": message.message_type,
                        "Reason": reason,
                        "Status": "✗ REJECTED"
                    }, is_error=True)
                return
            
            # Debug logging for state machine acceptance
            if self.config.debug_mode:
                self.logger.info(f"STATE MACHINE ACCEPTED: {reason}")
            
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
    
    def _map_message_type(self, message_type: MessageType) -> StateMessageType:
        """
        Map sync model message type to state machine message type.
        
        Args:
            message_type: Sync model message type
            
        Returns:
            StateMessageType: State machine message type
        """
        mapping = {
            MessageType.KEY_NOTIFICATION: StateMessageType.NOTIFY,
            MessageType.KEY_ACKNOWLEDGMENT: StateMessageType.NOTIFY_ACK,
            MessageType.SYNC_CONFIRMATION: StateMessageType.ACK,
            MessageType.ERROR: StateMessageType.ERROR
        }
        return mapping.get(message_type, StateMessageType.ERROR)
    
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
        
        # Calculate time until key roll
        current_time = time.time()
        time_until_roll = message.rotation_timestamp - current_time
        
        if time_until_roll > 0:
            hours = int(time_until_roll // 3600)
            minutes = int((time_until_roll % 3600) // 60)
            seconds = int(time_until_roll % 60)
            time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            self.logger.info(f"Proposed time for key roll is in {time_str} at {time.ctime(message.rotation_timestamp)}")
        else:
            self.logger.warning(f"Key roll time has already passed! Rotation was scheduled for {time.ctime(message.rotation_timestamp)}")
        
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
        
        # Create session in state machine
        session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.message_id}"
        
        # Debug logging for session creation
        if self.config.debug_mode:
            self.logger.info(f"STATE MACHINE SESSION CREATION:")
            self.logger.info(f"  Session ID: {session_id}")
            self.logger.info(f"  Master SAE: {message.master_sae_id}")
            self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
            self.logger.info(f"  Message ID: {message.message_id}")
            self.logger.info(f"  Key IDs: {message.key_ids}")
            self.logger.info(f"  Rotation Timestamp: {message.rotation_timestamp}")
        
        sync_state_machine.create_session(
            session_id=session_id,
            master_sae_id=message.master_sae_id,
            slave_sae_id=message.slave_sae_id,
            key_ids=message.key_ids,
            rotation_timestamp=message.rotation_timestamp
        )
        
        # Also create legacy session for backward compatibility
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
        
        # Update session in state machine
        session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
        
        # Debug logging for session lookup
        if self.config.debug_mode:
            self.logger.info(f"STATE MACHINE SESSION LOOKUP:")
            self.logger.info(f"  Session ID: {session_id}")
            self.logger.info(f"  Master SAE: {message.master_sae_id}")
            self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
            self.logger.info(f"  Original Message ID: {message.original_message_id}")
            self.logger.info(f"  Selected Key ID: {message.selected_key_id}")
            
            # Check if session exists
            existing_session = sync_state_machine.get_session(session_id)
            if existing_session:
                self.logger.info(f"  Session Found: {existing_session.state.value}")
            else:
                self.logger.info(f"  Session NOT FOUND!")
                # List all existing sessions for debugging
                all_sessions = sync_state_machine.sessions
                self.logger.info(f"  All Sessions: {list(all_sessions.keys())}")
                self.logger.info(f"  Expected Session ID: {session_id}")
                self.logger.info(f"  Session ID Length: {len(session_id)}")
                self.logger.info(f"  Session ID Characters: {[ord(c) for c in session_id[:20]]}...")
        
        # Update global state machine session
        sync_state_machine.update_session_state(
            session_id=session_id,
            new_state=SyncState.ACKNOWLEDGED,
            selected_key_id=message.selected_key_id
        )
        
        # Also update legacy session for backward compatibility
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
        
        # Send sync confirmation
        self._send_sync_confirmation(message, addr)
    
    def _handle_sync_confirmation(self, message: BaseSyncMessage, addr: tuple):
        """Handle sync confirmation message."""
        from ..models.sync_models import SyncConfirmationMessage
        
        if not isinstance(message, SyncConfirmationMessage):
            self.logger.error("Invalid message type for sync confirmation handler")
            return
        
        # Debug logging for sync confirmation
        if self.config.debug_mode:
            self.logger.info(f"SYNC CONFIRMATION RECEIVED:")
            self.logger.info(f"  Master SAE: {message.master_sae_id}")
            self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
            self.logger.info(f"  Original Message ID: {message.original_message_id}")
            self.logger.info(f"  Final Rotation Timestamp: {message.final_rotation_timestamp}")
            self.logger.info(f"  Final Rotation Time: {time.ctime(message.final_rotation_timestamp)}")
        
        self.logger.info(f"Received sync confirmation from {message.master_sae_id}")
        self.logger.info(f"Final rotation timestamp: {message.final_rotation_timestamp}")
        
        # Console notification for interactive mode
        if self.config.debug_mode:
            self._print_console_notification("SYNC CONFIRMATION", {
                "From": message.master_sae_id,
                "To": message.slave_sae_id,
                "Final Rotation Time": time.ctime(message.final_rotation_timestamp),
                "Original Message": message.original_message_id[:8] + "...",
                "Signature": "✓ VALID",
                "Address": f"{addr[0]}:{addr[1]}"
            })
        
        # Update session in global state machine
        session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
        
        # Update global state machine session
        sync_state_machine.update_session_state(
            session_id=session_id,
            new_state=SyncState.CONFIRMED
        )
        
        # Also update local session for backward compatibility
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
            
            # Check if we need more time for key roll using persona timing
            suggested_timestamp = None
            status = "ready"
            
            try:
                from src.personas.base_persona import persona_manager
                from src.config import config
                
                persona_name = config.device_persona
                persona_instance = persona_manager.load_persona(persona_name)
                
                if persona_instance:
                    # Check if the proposed rotation time gives us enough grace period
                    current_time = int(time.time())
                    time_until_rotation = message.rotation_timestamp - current_time
                    grace_period = persona_instance.get_grace_period()
                    
                    if time_until_rotation < grace_period:
                        # We need more time, suggest a later timestamp
                        suggested_timestamp = persona_instance.calculate_suggested_timestamp(message.rotation_timestamp)
                        status = "need_more_time"
                        
                        if self.config.debug_mode:
                            self.logger.info(f"SYNC TIMING ADJUSTMENT:")
                            self.logger.info(f"  Proposed rotation time: {time.ctime(message.rotation_timestamp)}")
                            self.logger.info(f"  Time until rotation: {time_until_rotation} seconds")
                            self.logger.info(f"  Grace period needed: {grace_period} seconds")
                            self.logger.info(f"  Suggested new time: {time.ctime(suggested_timestamp)}")
                            self.logger.info(f"  Status: {status}")
            except Exception as e:
                if self.config.debug_mode:
                    self.logger.warning(f"Could not check persona timing constraints: {e}")
            
            # Create acknowledgment message
            ack_message = message_signer.create_key_acknowledgment(
                original_message_id=message.message_id,
                master_sae_id=message.master_sae_id,
                slave_sae_id=message.slave_sae_id,
                selected_key_id=message.key_ids[0] if message.key_ids else None,
                status=status,
                suggested_rotation_timestamp=suggested_timestamp
            )
            
            # Look up master's configured address instead of using source address
            from .sae_peers import sae_peers
            master_address = sae_peers.get_peer_address(message.master_sae_id)
            
            if not master_address:
                self.logger.error(f"Master {message.master_sae_id} not found in known peers")
                return
            
            master_host, master_port = master_address
            
            # Debug logging for master address lookup
            if self.config.debug_mode:
                self.logger.info(f"SYNC MASTER ADDRESS LOOKUP:")
                self.logger.info(f"  Master SAE: {message.master_sae_id}")
                self.logger.info(f"  Found Address: {master_host}:{master_port}")
                self.logger.info(f"  Original Source Address: {addr[0]}:{addr[1]}")
            
            # Send message to master's configured port
            success = self.send_message(ack_message, master_host, master_port)
            
            if success:
                self.logger.info("Sent key acknowledgment")
                # Debug logging for successful send
                if self.config.debug_mode:
                    self.logger.info(f"SYNC KEY ACKNOWLEDGMENT SENT:")
                    self.logger.info(f"  To: {master_host}:{master_port}")
                    self.logger.info(f"  Message Type: NOTIFY-ACK")
                    self.logger.info(f"  Original Message: {message.message_id}")
                
                # Update slave's own state machine to ACKNOWLEDGED state
                session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.message_id}"
                sync_state_machine.update_session_state(
                    session_id=session_id,
                    new_state=SyncState.ACKNOWLEDGED,
                    selected_key_id=message.key_ids[0] if message.key_ids else None
                )
                
                # Debug logging for slave state update
                if self.config.debug_mode:
                    self.logger.info(f"SLAVE STATE MACHINE UPDATED:")
                    self.logger.info(f"  Session ID: {session_id}")
                    self.logger.info(f"  New State: ACKNOWLEDGED")
                    self.logger.info(f"  Selected Key: {message.key_ids[0] if message.key_ids else 'None'}")
            else:
                self.logger.error("Failed to send key acknowledgment")
                
        except Exception as e:
            self.logger.error(f"Error sending key acknowledgment: {e}")
    
    def _send_sync_confirmation(self, message, addr):
        """Send sync confirmation message."""
        try:
            # Find session to get rotation timestamp
            session_id = f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}"
            session = sync_state_machine.get_session(session_id)
            
            if not session or not session.rotation_timestamp:
                self.logger.error("Session or rotation timestamp not found")
                if self.config.debug_mode:
                    self.logger.info(f"ROTATION CONFIRMATION DEBUG:")
                    self.logger.info(f"  Session ID: {session_id}")
                    self.logger.info(f"  Session Found: {session is not None}")
                    if session:
                        self.logger.info(f"  Rotation Timestamp: {session.rotation_timestamp}")
                    # List all sessions in state machine
                    all_sessions = sync_state_machine.list_sessions()
                    self.logger.info(f"  All State Machine Sessions: {list(all_sessions.keys())}")
                return
            
            # Debug logging for sync confirmation creation
            if self.config.debug_mode:
                self.logger.info(f"SYNC CONFIRMATION CREATION:")
                self.logger.info(f"  Session ID: {session_id}")
                self.logger.info(f"  Original Message ID: {message.original_message_id}")
                self.logger.info(f"  Final Rotation Timestamp: {session.rotation_timestamp}")
                self.logger.info(f"  Master SAE: {message.master_sae_id}")
                self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
            
            # Create confirmation message
            conf_message = message_signer.create_sync_confirmation(
                original_message_id=message.original_message_id,
                final_rotation_timestamp=session.rotation_timestamp,
                master_sae_id=message.master_sae_id,
                slave_sae_id=message.slave_sae_id
            )
            
            # Look up slave's configured address instead of using source address
            from .sae_peers import sae_peers
            slave_address = sae_peers.get_peer_address(message.slave_sae_id)
            
            if not slave_address:
                self.logger.error(f"Slave {message.slave_sae_id} not found in known peers")
                return
            
            slave_host, slave_port = slave_address
            
            # Debug logging for slave address lookup
            if self.config.debug_mode:
                self.logger.info(f"SYNC SLAVE ADDRESS LOOKUP:")
                self.logger.info(f"  Slave SAE: {message.slave_sae_id}")
                self.logger.info(f"  Found Address: {slave_host}:{slave_port}")
                self.logger.info(f"  Original Source Address: {addr[0]}:{addr[1]}")
            
            # Send message to slave's configured port
            success = self.send_message(conf_message, slave_host, slave_port)
            
            if success:
                self.logger.info("Sent sync confirmation")
            else:
                self.logger.error("Failed to send sync confirmation")
                
        except Exception as e:
            self.logger.error(f"Error sending sync confirmation: {e}")
    
    def _schedule_key_rotation(self, message):
        """Schedule key rotation at the specified timestamp."""
        try:
            from ..models.sync_models import SyncConfirmationMessage
            
            if not isinstance(message, SyncConfirmationMessage):
                return
            
            # Calculate delay until rotation
            current_time = int(datetime.now().timestamp())
            delay = message.final_rotation_timestamp - current_time
            
            # Debug logging for rotation scheduling
            if self.config.debug_mode:
                self.logger.info(f"SYNC ROTATION SCHEDULING:")
                self.logger.info(f"  Current Time: {current_time} ({time.ctime(current_time)})")
                self.logger.info(f"  Final Rotation Time: {message.final_rotation_timestamp} ({time.ctime(message.final_rotation_timestamp)})")
                self.logger.info(f"  Delay: {delay} seconds")
                self.logger.info(f"  Delay: {delay/60:.1f} minutes")
            
            if delay <= 0:
                self.logger.warning("Final rotation timestamp is in the past, rotating immediately")
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
                self.logger.info(f"  Scheduled Time: {time.ctime(message.final_rotation_timestamp)}")
            
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
            # Load persona plugin using main configuration, not sync_config
            from src.config import config_manager
            persona_name = config_manager.config.device_persona
            persona = self._load_persona_plugin(persona_name)
            
            if persona:
                # Create rotation context with flexible parameters
                from src.personas.base_persona import RotationContext
                
                # Create rotation context with persona configuration
                persona_config = persona.config if hasattr(persona, 'config') else {}
                context = RotationContext(
                    key_id=message.original_message_id,
                    rotation_timestamp=message.final_rotation_timestamp,
                    device_interface=persona_config.get('device_interface'),
                    encryption_algorithm=persona_config.get('encryption_algorithm', 'AES-256'),
                    key_priority=persona_config.get('key_priority', 'normal'),
                    rollback_on_failure=persona_config.get('rollback_on_failure', True),
                    notification_url=persona_config.get('notification_url'),
                    notification_headers=persona_config.get('notification_headers', {}),
                    session_id=f"{message.master_sae_id}_{message.slave_sae_id}_{message.original_message_id}",
                    master_sae_id=message.master_sae_id,
                    slave_sae_id=message.slave_sae_id,
                    custom_metadata=persona_config.get('custom_metadata', {}),
                    advance_warning_seconds=persona_config.get('advance_warning_seconds', 30),
                    cleanup_delay_seconds=persona_config.get('cleanup_delay_seconds', 60),
                    validate_key_before_rotation=persona_config.get('validate_key_before_rotation', True),
                    validate_device_after_rotation=persona_config.get('validate_device_after_rotation', True)
                )
                
                # Execute rotation with context
                success = persona.rotate_key(context)
                if success:
                    self.logger.info(f"Executed key rotation using {persona_name} persona")
                else:
                    self.logger.error(f"Key rotation failed using {persona_name} persona")
            else:
                self.logger.warning(f"No persona plugin found for: {persona_name}")
                
        except Exception as e:
            self.logger.error(f"Error executing device rotation: {e}")
    
    def _load_persona_plugin(self, persona_name: str):
        """Load persona plugin."""
        try:
            from src.personas.base_persona import persona_manager
            
            # Use the configured persona from the main config
            from src.config import config_manager
            configured_persona_name = config_manager.config.device_persona
            
            # Load the configured persona
            persona = persona_manager.get_persona(configured_persona_name)
            if not persona:
                persona = persona_manager.load_persona(configured_persona_name)
            
            if persona:
                self.logger.info(f"Loaded persona plugin: {configured_persona_name}")
                return persona
            else:
                self.logger.warning(f"Could not load persona plugin: {configured_persona_name}")
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
    
    def cleanup_old_sessions(self):
        """Clean up expired synchronization sessions and revert keys based on scheduled rotation time."""
        try:
            import time
            current_time = int(time.time())
            sessions_to_remove = []
            
            for session_id, session in self.sessions.items():
                # Check if the scheduled rotation time has passed
                if session.rotation_timestamp and current_time > session.rotation_timestamp:
                    sessions_to_remove.append(session_id)
                    self.logger.info(f"Session {session_id} expired - rotation time {session.rotation_timestamp} has passed")
            
            # Clean up expired sessions and revert keys
            for session_id in sessions_to_remove:
                # Extract key IDs and slave SAE ID from session
                key_ids = session.key_ids if hasattr(session, 'key_ids') else []
                slave_sae_id = session.slave_sae_id if hasattr(session, 'slave_sae_id') else None
                
                # Revert keys back to available status (only if still in NOTIFIED/ASSIGNED state)
                if key_ids and slave_sae_id:
                    from src.services.key_service import key_service
                    for key_id in key_ids:
                        key_service.revert_notified_key_to_available(key_id, slave_sae_id)
                        self.logger.info(f"Reverted key {key_id} to available due to expired session {session_id}")
                
                # Remove the session
                del self.sessions[session_id]
                self.logger.info(f"Cleaned up expired session: {session_id}")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old sessions: {e}")
    
    def cleanup_expired_keys(self):
        """
        Clean up expired key notifications and revert keys to available status.
        
        This method should be called periodically to clean up keys that were
        notified but never completed the handshake process. Keys are reverted
        when their scheduled rotation time has passed.
        """
        try:
            from src.services.key_service import key_service
            cleaned_count = key_service.cleanup_expired_notifications()
            
            if cleaned_count > 0:
                self.logger.info(f"UDP Service: Cleaned up {cleaned_count} expired key notifications")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up expired keys: {e}")


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
