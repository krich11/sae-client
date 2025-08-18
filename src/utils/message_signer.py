"""
Message Signing and Verification Utilities.
Handles cryptographic signing and verification of SAE synchronization messages.
"""

import json
import base64
import hashlib
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from ..config import config_manager
from ..models.sync_models import SignedMessage, BaseSyncMessage


class MessageSigner:
    """Handles signing and verification of SAE synchronization messages."""
    
    def __init__(self):
        """Initialize message signer."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
        self._private_key = None
        self._public_key = None
        self._load_keys()
    
    def _load_keys(self):
        """Load SAE private and public keys."""
        try:
            # Load private key
            private_key_path = Path(self.config.sae_key_path)
            if private_key_path.exists():
                with open(private_key_path, 'rb') as f:
                    self._private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                self.logger.info("Loaded SAE private key")
            else:
                self.logger.warning(f"SAE private key not found: {private_key_path}")
            
            # Load public key (from certificate)
            cert_path = Path(self.config.sae_cert_path)
            if cert_path.exists():
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                    # Extract public key from certificate
                    from cryptography import x509
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    self._public_key = cert.public_key()
                self.logger.info("Loaded SAE public key from certificate")
            else:
                self.logger.warning(f"SAE certificate not found: {cert_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to load keys: {e}")
            raise
    
    def sign_message(self, message: BaseSyncMessage, sae_id: str) -> SignedMessage:
        """
        Sign a synchronization message.
        
        Args:
            message: The message to sign
            sae_id: SAE ID of the signer
            
        Returns:
            SignedMessage: The signed message
            
        Raises:
            ValueError: If private key is not available
        """
        if not self._private_key:
            raise ValueError("Private key not available for signing")
        
        try:
            # Convert message to JSON string
            message_json = message.json()
            
            # Create hash of the message
            message_hash = hashlib.sha256(message_json.encode('utf-8')).digest()
            
            # Sign the hash
            signature = self._private_key.sign(
                message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Encode payload and signature
            payload_b64 = base64.b64encode(message_json.encode('utf-8')).decode('utf-8')
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            signed_message = SignedMessage(
                payload=payload_b64,
                signature=signature_b64,
                sender_sae_id=sae_id
            )
            
            self.logger.debug(f"Signed message {message.message_id} for SAE {sae_id}")
            return signed_message
            
        except Exception as e:
            self.logger.error(f"Failed to sign message: {e}")
            raise
    
    def verify_message(self, signed_message: SignedMessage, expected_sender: str) -> Optional[BaseSyncMessage]:
        """
        Verify a signed message.
        
        Args:
            signed_message: The signed message to verify
            expected_sender: Expected SAE ID of the sender
            
        Returns:
            BaseSyncMessage: The verified message, or None if verification fails
        """
        try:
            # Verify sender SAE ID
            if signed_message.sender_sae_id != expected_sender:
                self.logger.warning(f"Sender SAE ID mismatch: expected {expected_sender}, got {signed_message.sender_sae_id}")
                return None
            
            # Decode payload and signature
            payload_bytes = base64.b64decode(signed_message.payload)
            signature_bytes = base64.b64decode(signed_message.signature)
            
            # Verify signature
            if not self._verify_signature(payload_bytes, signature_bytes, signed_message.sender_sae_id):
                self.logger.warning(f"Signature verification failed for message from {signed_message.sender_sae_id}")
                return None
            
            # Parse the message
            message_json = payload_bytes.decode('utf-8')
            message_data = json.loads(message_json)
            
            # Create appropriate message object based on type
            message_type = message_data.get('message_type')
            if message_type == 'key_notification':
                from ..models.sync_models import KeyNotificationMessage
                message = KeyNotificationMessage(**message_data)
            elif message_type == 'key_acknowledgment':
                from ..models.sync_models import KeyAcknowledgmentMessage
                message = KeyAcknowledgmentMessage(**message_data)
            elif message_type == 'rotation_confirmation':
                from ..models.sync_models import RotationConfirmationMessage
                message = RotationConfirmationMessage(**message_data)
            elif message_type == 'error':
                from ..models.sync_models import ErrorMessage
                message = ErrorMessage(**message_data)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                return None
            
            self.logger.debug(f"Verified message {message.message_id} from {signed_message.sender_sae_id}")
            return message
            
        except Exception as e:
            self.logger.error(f"Failed to verify message: {e}")
            return None
    
    def _verify_signature(self, payload: bytes, signature: bytes, sender_sae_id: str) -> bool:
        """
        Verify signature using sender's public key.
        
        Args:
            payload: The message payload
            signature: The signature to verify
            sender_sae_id: SAE ID of the sender
            
        Returns:
            bool: True if signature is valid
        """
        try:
            # For now, we'll use our own public key for verification
            # In a real implementation, you'd load the sender's public key
            # from a certificate store or PKI
            if not self._public_key:
                self.logger.warning("Public key not available for verification")
                return False
            
            # Create hash of the payload
            payload_hash = hashlib.sha256(payload).digest()
            
            # Verify signature
            self._public_key.verify(
                signature,
                payload_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except InvalidSignature:
            self.logger.warning(f"Invalid signature for message from {sender_sae_id}")
            return False
        except Exception as e:
            self.logger.error(f"Signature verification error: {e}")
            return False
    
    def create_key_notification(self, key_ids: list, rotation_timestamp: int, 
                              master_sae_id: str, slave_sae_id: str) -> SignedMessage:
        """
        Create a signed key notification message.
        
        Args:
            key_ids: List of available key IDs
            rotation_timestamp: Future timestamp for key rotation
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            
        Returns:
            SignedMessage: The signed key notification message
        """
        from ..models.sync_models import KeyNotificationMessage
        
        message = KeyNotificationMessage(
            key_ids=key_ids,
            rotation_timestamp=rotation_timestamp,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id
        )
        
        return self.sign_message(message, master_sae_id)
    
    def create_key_acknowledgment(self, original_message_id: str, 
                                master_sae_id: str, slave_sae_id: str,
                                selected_key_id: Optional[str] = None) -> SignedMessage:
        """
        Create a signed key acknowledgment message.
        
        Args:
            original_message_id: ID of the original key notification
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            selected_key_id: Optional selected key ID
            
        Returns:
            SignedMessage: The signed key acknowledgment message
        """
        from ..models.sync_models import KeyAcknowledgmentMessage
        
        message = KeyAcknowledgmentMessage(
            original_message_id=original_message_id,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id,
            selected_key_id=selected_key_id
        )
        
        return self.sign_message(message, slave_sae_id)
    
    def create_rotation_confirmation(self, original_message_id: str,
                                   rotation_timestamp: int,
                                   master_sae_id: str, slave_sae_id: str) -> SignedMessage:
        """
        Create a signed rotation confirmation message.
        
        Args:
            original_message_id: ID of the original key notification
            rotation_timestamp: Timestamp for key rotation
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            
        Returns:
            SignedMessage: The signed rotation confirmation message
        """
        from ..models.sync_models import RotationConfirmationMessage
        
        message = RotationConfirmationMessage(
            original_message_id=original_message_id,
            rotation_timestamp=rotation_timestamp,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id
        )
        
        return self.sign_message(message, master_sae_id)
    
    def create_error_message(self, error_code: str, error_message: str,
                           master_sae_id: str, slave_sae_id: str,
                           original_message_id: Optional[str] = None,
                           details: Optional[Dict[str, Any]] = None) -> SignedMessage:
        """
        Create a signed error message.
        
        Args:
            error_code: Error code
            error_message: Human-readable error message
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            original_message_id: ID of the message that caused the error
            details: Additional error details
            
        Returns:
            SignedMessage: The signed error message
        """
        from ..models.sync_models import ErrorMessage
        
        message = ErrorMessage(
            error_code=error_code,
            error_message=error_message,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id,
            original_message_id=original_message_id,
            details=details
        )
        
        return self.sign_message(message, master_sae_id)


# Global message signer instance
message_signer = MessageSigner()
