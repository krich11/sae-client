"""
SAE Synchronization Message Models.
Defines the data structures for SAE-to-SAE key synchronization messages.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator
import uuid


class MessageType(str, Enum):
    """Types of synchronization messages."""
    KEY_NOTIFICATION = "key_notification"
    KEY_ACKNOWLEDGMENT = "key_acknowledgment"
    ROTATION_CONFIRMATION = "rotation_confirmation"
    ERROR = "error"


class SyncState(str, Enum):
    """Synchronization state machine states."""
    IDLE = "idle"
    NOTIFIED = "notified"
    KEYS_REQUESTED = "keys_requested"
    ACKNOWLEDGED = "acknowledged"
    CONFIRMED = "confirmed"
    ROTATING = "rotating"
    ERROR = "error"


class BaseSyncMessage(BaseModel):
    """Base class for all synchronization messages."""
    message_type: MessageType
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: int = Field(default_factory=lambda: int(datetime.now().timestamp()))
    master_sae_id: str
    slave_sae_id: str
    
    @validator('message_id')
    def validate_message_id(cls, v):
        """Validate message ID is a valid UUID."""
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError('message_id must be a valid UUID')
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        """Validate timestamp is reasonable."""
        current_time = int(datetime.now().timestamp())
        if v < current_time - 3600:  # More than 1 hour ago
            raise ValueError('timestamp is too old')
        if v > current_time + 3600:  # More than 1 hour in future
            raise ValueError('timestamp is too far in future')
        return v


class KeyNotificationMessage(BaseSyncMessage):
    """Message sent by master SAE to notify slave of available keys."""
    message_type: MessageType = MessageType.KEY_NOTIFICATION
    key_ids: List[str] = Field(..., min_items=1, description="List of available key IDs")
    rotation_timestamp: int = Field(..., description="Future timestamp when keys should be rotated")
    
    @validator('key_ids')
    def validate_key_ids(cls, v):
        """Validate key IDs are not empty."""
        if not v or any(not kid.strip() for kid in v):
            raise ValueError('key_ids must contain non-empty strings')
        return v
    
    @validator('rotation_timestamp')
    def validate_rotation_timestamp(cls, v, values):
        """Validate rotation timestamp is in the future."""
        current_time = int(datetime.now().timestamp())
        if v <= current_time:
            raise ValueError('rotation_timestamp must be in the future')
        if v > current_time + 3600:  # More than 1 hour in future
            raise ValueError('rotation_timestamp is too far in future')
        return v


class KeyAcknowledgmentMessage(BaseSyncMessage):
    """Message sent by slave SAE to acknowledge key notification."""
    message_type: MessageType = MessageType.KEY_ACKNOWLEDGMENT
    original_message_id: str = Field(..., description="ID of the original key notification message")
    selected_key_id: Optional[str] = Field(None, description="Optional key ID selected for use")
    status: str = Field(default="ready", description="Status of key preparation")
    
    @validator('original_message_id')
    def validate_original_message_id(cls, v):
        """Validate original message ID is a valid UUID."""
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError('original_message_id must be a valid UUID')


class RotationConfirmationMessage(BaseSyncMessage):
    """Message sent by master SAE to confirm key rotation."""
    message_type: MessageType = MessageType.ROTATION_CONFIRMATION
    original_message_id: str = Field(..., description="ID of the original key notification message")
    rotation_timestamp: int = Field(..., description="Timestamp when keys should be rotated")
    
    @validator('original_message_id')
    def validate_original_message_id(cls, v):
        """Validate original message ID is a valid UUID."""
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError('original_message_id must be a valid UUID')


class ErrorMessage(BaseSyncMessage):
    """Error message sent when synchronization fails."""
    message_type: MessageType = MessageType.ERROR
    original_message_id: Optional[str] = Field(None, description="ID of the message that caused the error")
    error_code: str = Field(..., description="Error code")
    error_message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")


class SignedMessage(BaseModel):
    """Wrapper for signed synchronization messages."""
    payload: str = Field(..., description="Base64-encoded JSON payload")
    signature: str = Field(..., description="Base64-encoded RSA-SHA256 signature")
    sender_sae_id: str = Field(..., description="SAE ID of the message sender")
    public_key: str = Field(..., description="PEM-encoded public key of the sender")
    type: str = Field(..., description="Message type: NOTIFY, NOTIFY-ACK, ACK")
    
    @validator('payload')
    def validate_payload(cls, v):
        """Validate payload is not empty."""
        if not v.strip():
            raise ValueError('payload cannot be empty')
        return v
    
    @validator('signature')
    def validate_signature(cls, v):
        """Validate signature is not empty."""
        if not v.strip():
            raise ValueError('signature cannot be empty')
        return v
    
    @validator('public_key')
    def validate_public_key(cls, v):
        """Validate public key is in PEM format."""
        if not v.strip():
            raise ValueError('public_key cannot be empty')
        if not v.startswith('-----BEGIN PUBLIC KEY-----'):
            raise ValueError('public_key must be in PEM format')
        return v


class SyncSession(BaseModel):
    """Represents a synchronization session between master and slave."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    master_sae_id: str
    slave_sae_id: str
    state: SyncState = SyncState.IDLE
    key_ids: List[str] = Field(default_factory=list)
    selected_key_id: Optional[str] = None
    rotation_timestamp: Optional[int] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    error_message: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SyncConfig(BaseModel):
    """Configuration for synchronization system."""
    udp_port: int = Field(default=5000, description="UDP port for synchronization messages")
    sync_timeout: int = Field(default=30, description="Timeout for synchronization operations (seconds)")
    rotation_advance_time: int = Field(default=300, description="Advance time for key rotation (seconds)")
    device_persona: str = Field(default="default", description="Device persona to use")
    max_message_size: int = Field(default=8192, description="Maximum UDP message size")
    signature_algorithm: str = Field(default="RSA-SHA256", description="Signature algorithm to use")
    
    @validator('udp_port')
    def validate_udp_port(cls, v):
        """Validate UDP port is in valid range."""
        if v < 1024 or v > 65535:
            raise ValueError('udp_port must be between 1024 and 65535')
        return v
    
    @validator('sync_timeout')
    def validate_sync_timeout(cls, v):
        """Validate sync timeout is reasonable."""
        if v < 5 or v > 300:
            raise ValueError('sync_timeout must be between 5 and 300 seconds')
        return v
    
    @validator('rotation_advance_time')
    def validate_rotation_advance_time(cls, v):
        """Validate rotation advance time is reasonable."""
        if v < 60 or v > 3600:
            raise ValueError('rotation_advance_time must be between 60 and 3600 seconds')
        return v
