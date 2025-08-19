"""
SAE Synchronization State Machine.

Manages the state transitions for the SAE-to-SAE key synchronization protocol.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

from ..config import config_manager


class SyncState(Enum):
    """Synchronization states."""
    IDLE = "idle"
    NOTIFIED = "notified"  # Master has sent notification
    ACKNOWLEDGED = "acknowledged"  # Slave has sent acknowledgment
    CONFIRMED = "confirmed"  # Master has sent confirmation
    ROTATING = "rotating"  # Keys are being rotated
    ERROR = "error"


class MessageType(Enum):
    """Message types for state validation."""
    NOTIFY = "key_notification"
    NOTIFY_ACK = "key_acknowledgment"
    ACK = "sync_confirmation"
    ERROR = "error"


@dataclass
class SessionInfo:
    """Information about a synchronization session."""
    session_id: str
    master_sae_id: str
    slave_sae_id: str
    state: SyncState
    key_ids: list
    rotation_timestamp: Optional[int] = None
    created_at: datetime = None
    updated_at: datetime = None
    selected_key_id: Optional[str] = None
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()


class SyncStateMachine:
    """State machine for SAE synchronization protocol."""
    
    def __init__(self):
        """Initialize state machine."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
        self.sessions: Dict[str, SessionInfo] = {}
        self.session_timeout = 300  # 5 minutes
    
    def can_accept_message(self, message_type: MessageType, sender_sae_id: str, 
                          receiver_sae_id: str, session_id: str) -> Tuple[bool, str]:
        """
        Check if a message can be accepted based on current state.
        
        Args:
            message_type: Type of message being received
            sender_sae_id: SAE ID of the sender
            receiver_sae_id: SAE ID of the receiver
            session_id: Session identifier
            
        Returns:
            Tuple[bool, str]: (can_accept, reason)
        """
        try:
            # Get or create session
            session = self.sessions.get(session_id)
            
            # Clean up old sessions
            self._cleanup_expired_sessions()
            
            # Check if this is a new session
            if session is None:
                if message_type == MessageType.NOTIFY:
                    # Master can always send initial notification
                    return True, "New session, accepting initial notification"
                else:
                    return False, f"No active session for {message_type.value}"
            
            # Check session timeout
            if self._is_session_expired(session):
                self.logger.warning(f"Session {session_id} has expired")
                del self.sessions[session_id]
                if message_type == MessageType.NOTIFY:
                    return True, "Session expired, accepting new notification"
                else:
                    return False, "Session expired, rejecting non-notification message"
            
            # State-based validation
            return self._validate_state_transition(session, message_type, sender_sae_id, receiver_sae_id)
            
        except Exception as e:
            self.logger.error(f"Error in can_accept_message: {e}")
            return False, f"Internal error: {e}"
    
    def _validate_state_transition(self, session: SessionInfo, message_type: MessageType,
                                 sender_sae_id: str, receiver_sae_id: str) -> Tuple[bool, str]:
        """
        Validate state transition based on current state and message type.
        
        Args:
            session: Current session
            message_type: Type of message being received
            sender_sae_id: SAE ID of the sender
            receiver_sae_id: SAE ID of the receiver
            
        Returns:
            Tuple[bool, str]: (can_accept, reason)
        """
        current_state = session.state
        
        # Debug logging for state validation
        if self.config.debug_mode:
            self.logger.info(f"STATE MACHINE VALIDATION DEBUG:")
            self.logger.info(f"  Session ID: {session.session_id}")
            self.logger.info(f"  Current State Object: {current_state}")
            self.logger.info(f"  Current State Type: {type(current_state)}")
            self.logger.info(f"  Current State Value: {current_state.value if hasattr(current_state, 'value') else 'No value'}")
            self.logger.info(f"  SyncState.ACKNOWLEDGED: {SyncState.ACKNOWLEDGED}")
            self.logger.info(f"  SyncState.ACKNOWLEDGED Type: {type(SyncState.ACKNOWLEDGED)}")
            self.logger.info(f"  SyncState.ACKNOWLEDGED Value: {SyncState.ACKNOWLEDGED.value}")
            self.logger.info(f"  States Match: {current_state == SyncState.ACKNOWLEDGED}")
            self.logger.info(f"  Values Match: {current_state.value == SyncState.ACKNOWLEDGED.value if hasattr(current_state, 'value') else 'No value'}")
        
        # Determine if receiver is master or slave
        is_master = receiver_sae_id == session.master_sae_id
        is_slave = receiver_sae_id == session.slave_sae_id
        
        if not is_master and not is_slave:
            return False, f"Receiver {receiver_sae_id} is not part of session {session.session_id}"
        
        # State transition rules
        if current_state == SyncState.IDLE:
            if message_type == MessageType.NOTIFY and is_slave:
                return True, "Slave accepting initial notification"
            else:
                return False, f"Invalid message {message_type.value} in {current_state.value} state"
        
        elif current_state == SyncState.NOTIFIED:
            if message_type == MessageType.NOTIFY_ACK and is_master:
                return True, "Master accepting acknowledgment"
            elif message_type == MessageType.NOTIFY and is_slave:
                return True, "Slave accepting updated notification"
            else:
                return False, f"Invalid message {message_type.value} in {current_state.value} state"
        
        elif current_state == SyncState.ACKNOWLEDGED:
            if message_type == MessageType.ACK and is_slave:
                return True, "Slave accepting sync confirmation"
            elif message_type == MessageType.NOTIFY and is_slave:
                return True, "Slave accepting new notification"
            else:
                return False, f"Invalid message {message_type.value} in {current_state.value} state"
        
        elif current_state == SyncState.CONFIRMED:
            if message_type == MessageType.NOTIFY and is_slave:
                return True, "Slave accepting new notification"
            else:
                return False, f"Invalid message {message_type.value} in {current_state.value} state"
        
        elif current_state == SyncState.ROTATING:
            if message_type == MessageType.NOTIFY and is_slave:
                return True, "Slave accepting new notification during rotation"
            else:
                return False, f"Invalid message {message_type.value} in {current_state.value} state"
        
        elif current_state == SyncState.ERROR:
            if message_type == MessageType.NOTIFY and is_slave:
                return True, "Slave accepting new notification after error"
            else:
                return False, f"Invalid message {message_type.value} in {current_state.value} state"
        
        else:
            # Debug logging to see what state we actually have
            if self.config.debug_mode:
                self.logger.info(f"STATE MACHINE DEBUG - Unknown state:")
                self.logger.info(f"  Current State: {current_state}")
                self.logger.info(f"  Current State Type: {type(current_state)}")
                self.logger.info(f"  Current State Value: {current_state.value if hasattr(current_state, 'value') else 'No value'}")
                self.logger.info(f"  Expected States: {[state.value for state in SyncState]}")
                self.logger.info(f"  Message Type: {message_type}")
                self.logger.info(f"  Is Master: {is_master}")
                self.logger.info(f"  Is Slave: {is_slave}")
            return False, f"Unknown state: {current_state}"
    
    def update_session_state(self, session_id: str, new_state: SyncState, 
                           **kwargs) -> bool:
        """
        Update session state and metadata.
        
        Args:
            session_id: Session identifier
            new_state: New state to transition to
            **kwargs: Additional session data to update
            
        Returns:
            bool: True if update successful
        """
        try:
            session = self.sessions.get(session_id)
            if session is None:
                self.logger.warning(f"Session {session_id} not found for state update")
                return False
            
            # Update state
            old_state = session.state
            session.state = new_state
            session.updated_at = datetime.now()
            
            # Update additional fields
            for key, value in kwargs.items():
                if hasattr(session, key):
                    setattr(session, key, value)
            
            self.logger.info(f"Session {session_id} state transition: {old_state.value} -> {new_state.value}")
            
            # Debug logging
            if self.config.debug_mode:
                self.logger.info(f"STATE MACHINE UPDATE:")
                self.logger.info(f"  Session ID: {session_id}")
                self.logger.info(f"  Old State: {old_state.value}")
                self.logger.info(f"  New State: {new_state.value}")
                self.logger.info(f"  Master SAE: {session.master_sae_id}")
                self.logger.info(f"  Slave SAE: {session.slave_sae_id}")
                self.logger.info(f"  Updated: {session.updated_at}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating session state: {e}")
            return False
    
    def create_session(self, session_id: str, master_sae_id: str, slave_sae_id: str,
                      key_ids: list, rotation_timestamp: Optional[int] = None) -> bool:
        """
        Create a new synchronization session.
        
        Args:
            session_id: Session identifier
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            key_ids: List of key IDs
            rotation_timestamp: Optional rotation timestamp
            
        Returns:
            bool: True if session created successfully
        """
        try:
            session = SessionInfo(
                session_id=session_id,
                master_sae_id=master_sae_id,
                slave_sae_id=slave_sae_id,
                state=SyncState.NOTIFIED,  # Initial state after notification
                key_ids=key_ids,
                rotation_timestamp=rotation_timestamp
            )
            
            self.sessions[session_id] = session
            
            self.logger.info(f"Created session {session_id} for {master_sae_id} -> {slave_sae_id}")
            
            # Debug logging
            if self.config.debug_mode:
                self.logger.info(f"STATE MACHINE SESSION CREATED:")
                self.logger.info(f"  Session ID: {session_id}")
                self.logger.info(f"  Master SAE: {master_sae_id}")
                self.logger.info(f"  Slave SAE: {slave_sae_id}")
                self.logger.info(f"  Key IDs: {key_ids}")
                self.logger.info(f"  Rotation Timestamp: {rotation_timestamp}")
                self.logger.info(f"  Initial State: {session.state.value}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating session: {e}")
            return False
    
    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """
        Get session information.
        
        Args:
            session_id: Session identifier
            
        Returns:
            SessionInfo: Session information or None if not found
        """
        return self.sessions.get(session_id)
    
    def list_sessions(self) -> Dict[str, SessionInfo]:
        """
        Get all active sessions.
        
        Returns:
            Dict[str, SessionInfo]: All active sessions
        """
        return self.sessions.copy()
    
    def _is_session_expired(self, session: SessionInfo) -> bool:
        """Check if session has expired."""
        if session.updated_at is None:
            return True
        
        age = datetime.now() - session.updated_at
        return age.total_seconds() > self.session_timeout
    
    def _cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        expired_sessions = []
        for session_id, session in self.sessions.items():
            if self._is_session_expired(session):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
            self.logger.info(f"Cleaned up expired session: {session_id}")
        
        if expired_sessions and self.config.debug_mode:
            self.logger.info(f"STATE MACHINE CLEANUP: Removed {len(expired_sessions)} expired sessions")


# Global state machine instance
sync_state_machine = SyncStateMachine()
