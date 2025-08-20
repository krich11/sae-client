"""
Message Signing and Verification Utilities.
Handles cryptographic signing and verification of SAE synchronization messages.
"""

import json
import base64
import hashlib
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from ..config import config_manager
from ..models.sync_models import SignedMessage, BaseSyncMessage, MessageType


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
            
            # Export public key to PEM format
            public_key_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Encode payload and signature
            payload_b64 = base64.b64encode(message_json.encode('utf-8')).decode('utf-8')
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # Determine message type based on message content
            message_type = self._get_message_type(message)
            
            signed_message = SignedMessage(
                payload=payload_b64,
                signature=signature_b64,
                sender_sae_id=sae_id,
                public_key=public_key_pem,
                type=message_type
            )
            
            # Debug logging for message signing
            if self.config.debug_mode:
                self.logger.info(f"MESSAGE SIGNING:")
                self.logger.info(f"  SAE ID: {sae_id}")
                self.logger.info(f"  Message Type: {message.message_type}")
                self.logger.info(f"  Message ID: {message.message_id}")
                self.logger.info(f"  Payload Size: {len(message_json)} bytes")
                self.logger.info(f"  Hash Size: {len(message_hash)} bytes")
                self.logger.info(f"  Signature Size: {len(signature)} bytes")
                self.logger.info(f"  Payload B64 Size: {len(payload_b64)} bytes")
                self.logger.info(f"  Signature B64 Size: {len(signature_b64)} bytes")
            
            self.logger.debug(f"Signed message {message.message_id} for SAE {sae_id}")
            return signed_message
            
        except Exception as e:
            self.logger.error(f"Failed to sign message: {e}")
            raise
    
    def _get_message_type(self, message: BaseSyncMessage) -> str:
        """
        Determine the message type for the SignedMessage type field.
        
        Args:
            message: The base sync message
            
        Returns:
            str: Message type (NOTIFY, NOTIFY-ACK, ACK)
        """
        if message.message_type == MessageType.KEY_NOTIFICATION:
            return "NOTIFY"
        elif message.message_type == MessageType.KEY_ACKNOWLEDGMENT:
            return "NOTIFY-ACK"
        elif message.message_type == MessageType.SYNC_CONFIRMATION:
            return "SYNC-CONFIRM"
        elif message.message_type == MessageType.ERROR:
            return "ERROR"
        else:
            return "UNKNOWN"
    
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
            # Debug logging for message verification
            if self.config.debug_mode:
                self.logger.info(f"MESSAGE VERIFICATION:")
                self.logger.info(f"  Expected Sender: {expected_sender}")
                self.logger.info(f"  Actual Sender: {signed_message.sender_sae_id}")
                self.logger.info(f"  Payload Size: {len(signed_message.payload)} bytes")
                self.logger.info(f"  Signature Size: {len(signed_message.signature)} bytes")
                self.logger.info(f"  Public Key Size: {len(signed_message.public_key)} bytes")
            
            # Verify sender SAE ID
            if signed_message.sender_sae_id != expected_sender:
                self.logger.warning(f"Sender SAE ID mismatch: expected {expected_sender}, got {signed_message.sender_sae_id}")
                return None
            
            # Decode payload and signature
            payload_bytes = base64.b64decode(signed_message.payload)
            signature_bytes = base64.b64decode(signed_message.signature)
            
            # Debug logging for decoded data
            if self.config.debug_mode:
                self.logger.info(f"MESSAGE DECODING:")
                self.logger.info(f"  Payload Bytes: {len(payload_bytes)} bytes")
                self.logger.info(f"  Signature Bytes: {len(signature_bytes)} bytes")
            
            # Verify signature using public key from message
            if not self._verify_signature_with_key(payload_bytes, signature_bytes, signed_message.public_key, signed_message.sender_sae_id):
                self.logger.warning(f"Signature verification failed for message from {signed_message.sender_sae_id}")
                return None
            
            # Parse the message
            message_json = payload_bytes.decode('utf-8')
            message_data = json.loads(message_json)
            
            # Debug logging for message parsing
            if self.config.debug_mode:
                self.logger.info(f"MESSAGE PARSING:")
                self.logger.info(f"  Message Type: {message_data.get('message_type')}")
                self.logger.info(f"  Message ID: {message_data.get('message_id')}")
                self.logger.info(f"  Timestamp: {message_data.get('timestamp')}")
            
            # Create appropriate message object based on type
            message_type = message_data.get('message_type')
            if message_type == 'key_notification':
                from ..models.sync_models import KeyNotificationMessage
                message = KeyNotificationMessage(**message_data)
            elif message_type == 'key_acknowledgment':
                from ..models.sync_models import KeyAcknowledgmentMessage
                message = KeyAcknowledgmentMessage(**message_data)
            elif message_type == 'sync_confirmation':
                from ..models.sync_models import SyncConfirmationMessage
                message = SyncConfirmationMessage(**message_data)
            elif message_type == 'cleanup_status_request':
                from ..models.sync_models import CleanupStatusRequestMessage
                message = CleanupStatusRequestMessage(**message_data)
            elif message_type == 'cleanup_status_response':
                from ..models.sync_models import CleanupStatusResponseMessage
                message = CleanupStatusResponseMessage(**message_data)
            elif message_type == 'cleanup_delete_request':
                from ..models.sync_models import CleanupDeleteRequestMessage
                message = CleanupDeleteRequestMessage(**message_data)
            elif message_type == 'cleanup_delete_response':
                from ..models.sync_models import CleanupDeleteResponseMessage
                message = CleanupDeleteResponseMessage(**message_data)
            elif message_type == 'cleanup_acknowledgment':
                from ..models.sync_models import CleanupAcknowledgmentMessage
                message = CleanupAcknowledgmentMessage(**message_data)
            elif message_type == 'rotation_completed':
                from ..models.sync_models import RotationCompletedMessage
                message = RotationCompletedMessage(**message_data)
            elif message_type == 'error':
                from ..models.sync_models import ErrorMessage
                message = ErrorMessage(**message_data)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                return None
            
            # Debug logging for successful verification
            if self.config.debug_mode:
                self.logger.info(f"MESSAGE VERIFICATION SUCCESS:")
                self.logger.info(f"  Message ID: {message.message_id}")
                self.logger.info(f"  Sender: {signed_message.sender_sae_id}")
                self.logger.info(f"  Type: {message.message_type}")
            
            self.logger.debug(f"Verified message {message.message_id} from {signed_message.sender_sae_id}")
            return message
            
        except Exception as e:
            self.logger.error(f"Failed to verify message: {e}")
            return None
    
    def _verify_signature_with_key(self, payload: bytes, signature: bytes, public_key_pem: str, sender_sae_id: str) -> bool:
        """
        Verify signature using the public key provided in the message.
        
        Args:
            payload: The message payload
            signature: The signature to verify
            public_key_pem: PEM-encoded public key from the message
            sender_sae_id: SAE ID of the sender (for logging)
            
        Returns:
            bool: True if signature is valid
        """
        try:
            # Load public key from PEM string
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Create hash of the payload
            payload_hash = hashlib.sha256(payload).digest()
            
            # Debug logging for signature verification
            if self.config.debug_mode:
                self.logger.info(f"SIGNATURE VERIFICATION DETAILS:")
                self.logger.info(f"  Sender SAE ID: {sender_sae_id}")
                self.logger.info(f"  Payload hash: {payload_hash.hex()}")
                self.logger.info(f"  Signature: {signature.hex()}")
                self.logger.info(f"  Public key loaded from message")
            
            # Verify signature
            public_key.verify(
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
    
    def _verify_signature(self, payload: bytes, signature: bytes, sender_sae_id: str) -> bool:
        """
        Verify signature using sender's public key (legacy method).
        
        Args:
            payload: The message payload
            signature: The signature to verify
            sender_sae_id: SAE ID of the sender
            
        Returns:
            bool: True if signature is valid
        """
        try:
            # Load the sender's public key
            sender_public_key = self._load_sender_public_key(sender_sae_id)
            if not sender_public_key:
                self.logger.warning(f"Public key not available for sender {sender_sae_id}")
                return False
            
            # Create hash of the payload
            payload_hash = hashlib.sha256(payload).digest()
            
            # Debug logging for signature verification
            if self.config.debug_mode:
                self.logger.info(f"SIGNATURE VERIFICATION DETAILS:")
                self.logger.info(f"  Sender SAE ID: {sender_sae_id}")
                self.logger.info(f"  Payload hash: {payload_hash.hex()}")
                self.logger.info(f"  Signature: {signature.hex()}")
            
            # Verify signature
            sender_public_key.verify(
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
    
    def _load_sender_public_key(self, sender_sae_id: str):
        """
        Load the public key for a specific sender SAE.
        
        Args:
            sender_sae_id: SAE ID of the sender
            
        Returns:
            Public key object or None if not found
        """
        try:
            # For now, we'll use a simple approach: look for certificates in a certs directory
            # In a real implementation, this would use a proper PKI or certificate store
            
            # Try to load from a certs directory structure
            cert_dir = Path("certs")
            if cert_dir.exists():
                # Look for sender's certificate
                sender_cert_path = cert_dir / sender_sae_id.lower() / f"{sender_sae_id.lower()}.crt"
                if sender_cert_path.exists():
                    with open(sender_cert_path, 'rb') as f:
                        cert_data = f.read()
                        from cryptography import x509
                        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                        public_key = cert.public_key()
                        self.logger.info(f"Loaded public key for {sender_sae_id} from {sender_cert_path}")
                        return public_key
                
                # If not found, try alternative naming
                sender_cert_path = cert_dir / "sae" / f"{sender_sae_id.lower()}.crt"
                if sender_cert_path.exists():
                    with open(sender_cert_path, 'rb') as f:
                        cert_data = f.read()
                        from cryptography import x509
                        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                        public_key = cert.public_key()
                        self.logger.info(f"Loaded public key for {sender_sae_id} from {sender_cert_path}")
                        return public_key
            
            # If we can't find the sender's certificate, for testing purposes,
            # we'll use our own public key (this is NOT secure for production!)
            if self.config.debug_mode:
                self.logger.warning(f"Could not find certificate for {sender_sae_id}, using own public key for testing")
            return self._public_key
            
        except Exception as e:
            self.logger.error(f"Failed to load public key for {sender_sae_id}: {e}")
            return None
    
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
                                selected_key_id: Optional[str] = None,
                                status: str = "ready",
                                suggested_rotation_timestamp: Optional[int] = None) -> SignedMessage:
        """
        Create a signed key acknowledgment message.
        
        Args:
            original_message_id: ID of the original key notification
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            selected_key_id: Optional selected key ID
            status: Status of key preparation ('ready' or 'need_more_time')
            suggested_rotation_timestamp: Optional suggested rotation timestamp
            
        Returns:
            SignedMessage: The signed key acknowledgment message
        """
        from ..models.sync_models import KeyAcknowledgmentMessage
        
        message = KeyAcknowledgmentMessage(
            original_message_id=original_message_id,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id,
            selected_key_id=selected_key_id,
            status=status,
            suggested_rotation_timestamp=suggested_rotation_timestamp
        )
        
        return self.sign_message(message, slave_sae_id)
    
    def create_sync_confirmation(self, original_message_id: str,
                               final_rotation_timestamp: int,
                               master_sae_id: str, slave_sae_id: str) -> SignedMessage:
        """
        Create a signed sync confirmation message.
        
        Args:
            original_message_id: ID of the original key notification
            final_rotation_timestamp: Final agreed timestamp for key rotation
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            
        Returns:
            SignedMessage: The signed sync confirmation message
        """
        from ..models.sync_models import SyncConfirmationMessage
        
        message = SyncConfirmationMessage(
            original_message_id=original_message_id,
            final_rotation_timestamp=final_rotation_timestamp,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id
        )
        
        return self.sign_message(message, master_sae_id)
    
    def create_rotation_completed(self, original_message_id: str,
                                new_key_id: str,
                                rotation_timestamp: int,
                                master_sae_id: str, slave_sae_id: str) -> SignedMessage:
        """
        Create a signed rotation completed message.
        
        Args:
            original_message_id: ID of the original key notification message
            new_key_id: ID of the newly rotated key
            rotation_timestamp: Timestamp when rotation was completed
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            
        Returns:
            SignedMessage: The signed rotation completed message
        """
        from ..models.sync_models import RotationCompletedMessage
        
        message = RotationCompletedMessage(
            original_message_id=original_message_id,
            new_key_id=new_key_id,
            rotation_timestamp=rotation_timestamp,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id
        )
        
        return self.sign_message(message, slave_sae_id)
    
    def create_cleanup_status_request(self, original_message_id: str,
                                    new_key_id: str,
                                    master_sae_id: str, slave_sae_id: str) -> SignedMessage:
        """
        Create a signed cleanup status request message.
        
        Args:
            original_message_id: ID of the original key notification message
            new_key_id: ID of the newly rotated key
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            
        Returns:
            SignedMessage: The signed cleanup status request message
        """
        from ..models.sync_models import CleanupStatusRequestMessage
        
        message = CleanupStatusRequestMessage(
            original_message_id=original_message_id,
            new_key_id=new_key_id,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id
        )
        
        return self.sign_message(message, master_sae_id)
    
    def create_cleanup_status_response(self, original_message_id: str,
                                     status: str,
                                     master_sae_id: str, slave_sae_id: str,
                                     service_status: Optional[str] = None,
                                     error_message: Optional[str] = None) -> SignedMessage:
        """
        Create a signed cleanup status response message.
        
        Args:
            original_message_id: ID of the original cleanup status request
            status: Status ('success' or 'failed')
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            service_status: Optional detailed service status
            error_message: Optional error message if status is 'failed'
            
        Returns:
            SignedMessage: The signed cleanup status response message
        """
        from ..models.sync_models import CleanupStatusResponseMessage
        
        message = CleanupStatusResponseMessage(
            original_message_id=original_message_id,
            status=status,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id,
            service_status=service_status,
            error_message=error_message
        )
        
        return self.sign_message(message, slave_sae_id)
    
    def create_cleanup_delete_request(self, original_message_id: str,
                                    old_key_ids: List[str],
                                    master_sae_id: str, slave_sae_id: str) -> SignedMessage:
        """
        Create a signed cleanup delete request message.
        
        Args:
            original_message_id: ID of the original key notification message
            old_key_ids: List of old key IDs to delete
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            
        Returns:
            SignedMessage: The signed cleanup delete request message
        """
        from ..models.sync_models import CleanupDeleteRequestMessage
        
        message = CleanupDeleteRequestMessage(
            original_message_id=original_message_id,
            old_key_ids=old_key_ids,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id
        )
        
        return self.sign_message(message, master_sae_id)
    
    def create_cleanup_delete_response(self, original_message_id: str,
                                     status: str,
                                     master_sae_id: str, slave_sae_id: str,
                                     deleted_key_ids: List[str] = None,
                                     failed_key_ids: List[str] = None,
                                     error_message: Optional[str] = None) -> SignedMessage:
        """
        Create a signed cleanup delete response message.
        
        Args:
            original_message_id: ID of the original cleanup delete request
            status: Status ('success' or 'failed')
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            deleted_key_ids: List of successfully deleted key IDs
            failed_key_ids: List of key IDs that failed to delete
            error_message: Optional error message if status is 'failed'
            
        Returns:
            SignedMessage: The signed cleanup delete response message
        """
        from ..models.sync_models import CleanupDeleteResponseMessage
        
        if deleted_key_ids is None:
            deleted_key_ids = []
        if failed_key_ids is None:
            failed_key_ids = []
        
        message = CleanupDeleteResponseMessage(
            original_message_id=original_message_id,
            status=status,
            master_sae_id=master_sae_id,
            slave_sae_id=slave_sae_id,
            deleted_key_ids=deleted_key_ids,
            failed_key_ids=failed_key_ids,
            error_message=error_message
        )
        
        return self.sign_message(message, slave_sae_id)
    
    def create_cleanup_acknowledgment(self, original_message_id: str,
                                    status: str,
                                    master_sae_id: str, slave_sae_id: str) -> SignedMessage:
        """
        Create a signed cleanup acknowledgment message.
        
        Args:
            original_message_id: ID of the original cleanup delete response
            status: Status ('completed' or 'failed')
            master_sae_id: Master SAE ID
            slave_sae_id: Slave SAE ID
            
        Returns:
            SignedMessage: The signed cleanup acknowledgment message
        """
        from ..models.sync_models import CleanupAcknowledgmentMessage
        
        message = CleanupAcknowledgmentMessage(
            original_message_id=original_message_id,
            status=status,
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
