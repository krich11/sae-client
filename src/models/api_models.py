"""
ETSI GS QKD 014 API Models for SAE Client.
Implements all data structures defined in the ETSI specification.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator
from enum import Enum


class KeyStatus(str, Enum):
    """Key status enumeration."""
    AVAILABLE = "available"
    USED = "used"
    EXPIRED = "expired"
    REVOKED = "revoked"


class KeyType(str, Enum):
    """Key type enumeration."""
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"


class ErrorCode(str, Enum):
    """Error code enumeration."""
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    INTERNAL_ERROR = "internal_error"
    SERVICE_UNAVAILABLE = "service_unavailable"


class CertificateExtension(BaseModel):
    """Certificate extension for debugging and auditing."""
    client_verified: str = Field(..., description="Client verification status")
    client_dn: str = Field(..., description="Client distinguished name")
    client_issuer: str = Field(..., description="Client certificate issuer")
    ssl_protocol: str = Field(..., description="SSL protocol version")
    ssl_cipher: str = Field(..., description="SSL cipher suite")


class KeyContainer(BaseModel):
    """Key container as defined in ETSI GS QKD 014."""
    key_id: str = Field(..., description="Unique key identifier")
    key_type: KeyType = Field(..., description="Type of key")
    key_material: str = Field(..., description="Base64 encoded key material")
    key_size: int = Field(..., description="Key size in bits")
    creation_time: datetime = Field(..., description="Key creation timestamp")
    expiry_time: Optional[datetime] = Field(None, description="Key expiry timestamp")
    status: KeyStatus = Field(default=KeyStatus.AVAILABLE, description="Key status")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class SpecKeyContainer(BaseModel):
    """Specification key container with ETSI extensions."""
    key_container: KeyContainer = Field(..., description="Key container")
    easy_kms_certificate_extension: Optional[CertificateExtension] = Field(
        None, description="Certificate extension for debugging"
    )


class StatusSpec(BaseModel):
    """Status specification response."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="Service version")
    timestamp: datetime = Field(..., description="Response timestamp")
    easy_kms_certificate_extension: Optional[CertificateExtension] = Field(
        None, description="Certificate extension for debugging"
    )


class KeyRequest(BaseModel):
    """Key request specification."""
    key_type: KeyType = Field(..., description="Requested key type")
    key_size: int = Field(..., description="Requested key size")
    quantity: int = Field(default=1, description="Number of keys requested")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Request metadata")


class KeyResponse(BaseModel):
    """Key response specification."""
    keys: List[SpecKeyContainer] = Field(..., description="List of key containers")
    total_keys: int = Field(..., description="Total number of keys")
    easy_kms_certificate_extension: Optional[CertificateExtension] = Field(
        None, description="Certificate extension for debugging"
    )


class ErrorResponse(BaseModel):
    """Error response specification."""
    error_code: ErrorCode = Field(..., description="Error code")
    error_message: str = Field(..., description="Error description")
    timestamp: datetime = Field(..., description="Error timestamp")
    easy_kms_certificate_extension: Optional[CertificateExtension] = Field(
        None, description="Certificate extension for debugging"
    )


class NotificationMessage(BaseModel):
    """Master/Slave notification message."""
    message_type: str = Field(..., description="Type of notification")
    sender_id: str = Field(..., description="Sender SAE ID")
    receiver_id: str = Field(..., description="Receiver SAE ID")
    key_id: Optional[str] = Field(None, description="Related key ID")
    key_data: Optional[Dict[str, Any]] = Field(None, description="Key data")
    timestamp: datetime = Field(default_factory=datetime.now, description="Message timestamp")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class KeyAvailabilityNotification(BaseModel):
    """Key availability notification from master to slave."""
    master_id: str = Field(..., description="Master SAE ID")
    slave_id: str = Field(..., description="Slave SAE ID")
    key_id: str = Field(..., description="Available key ID")
    key_type: KeyType = Field(..., description="Key type")
    key_size: int = Field(..., description="Key size")
    creation_time: datetime = Field(..., description="Key creation time")
    expiry_time: Optional[datetime] = Field(None, description="Key expiry time")


class KeyRequestNotification(BaseModel):
    """Key request notification from slave to master."""
    slave_id: str = Field(..., description="Slave SAE ID")
    master_id: str = Field(..., description="Master SAE ID")
    key_type: KeyType = Field(..., description="Requested key type")
    key_size: int = Field(..., description="Requested key size")
    quantity: int = Field(default=1, description="Number of keys requested")


class LocalKey(BaseModel):
    """Local key storage model."""
    key_id: str = Field(..., description="Key identifier")
    key_type: KeyType = Field(..., description="Key type")
    key_material: str = Field(..., description="Base64 encoded key material")
    key_size: int = Field(..., description="Key size in bits")
    source: str = Field(..., description="Key source (KME or master)")
    creation_time: datetime = Field(..., description="Creation timestamp")
    expiry_time: Optional[datetime] = Field(None, description="Expiry timestamp")
    status: KeyStatus = Field(default=KeyStatus.AVAILABLE, description="Key status")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

    @validator('key_material')
    def validate_key_material(cls, v):
        """Validate key material is base64 encoded."""
        import base64
        try:
            base64.b64decode(v)
            return v
        except Exception:
            raise ValueError("Key material must be base64 encoded")


class SAEStatus(BaseModel):
    """SAE status information."""
    sae_id: str = Field(..., description="SAE identifier")
    mode: str = Field(..., description="SAE mode (master/slave)")
    status: str = Field(..., description="SAE status")
    available_keys: int = Field(..., description="Number of available keys")
    total_keys: int = Field(..., description="Total number of keys")
    last_activity: datetime = Field(..., description="Last activity timestamp")
    connected_slaves: Optional[List[str]] = Field(None, description="Connected slave IDs")
    connected_master: Optional[str] = Field(None, description="Connected master ID")
