"""
Cryptographic Utilities for SAE Client.
Handles key material operations, certificate utilities, and security validation.
"""

import logging
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List, Union
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidSignature
import cryptography.x509 as x509

from ..config import config_manager, logger


class CryptographicUtils:
    """Comprehensive cryptographic utilities for SAE operations."""
    
    def __init__(self):
        """Initialize cryptographic utilities."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
    
    def generate_random_key(self, key_size: int = 256) -> bytes:
        """
        Generate a cryptographically secure random key.
        
        Args:
            key_size: Key size in bits
            
        Returns:
            bytes: Random key material
        """
        try:
            key_bytes = key_size // 8
            key = secrets.token_bytes(key_bytes)
            self.logger.debug(f"Generated random key of size {key_size} bits")
            return key
        except Exception as e:
            self.logger.error(f"Failed to generate random key: {e}")
            raise
    
    def generate_key_material(self, key_type: str, key_size: int = 256) -> Dict[str, Any]:
        """
        Generate key material for different key types.
        
        Args:
            key_type: Type of key (AES, RSA, etc.)
            key_size: Key size in bits
            
        Returns:
            Dict[str, Any]: Key material with metadata
        """
        try:
            if key_type.upper() == "AES":
                key = self.generate_random_key(key_size)
                return {
                    'key_material': base64.b64encode(key).decode('utf-8'),
                    'key_size': key_size,
                    'key_type': 'AES',
                    'algorithm': 'AES-256-GCM' if key_size == 256 else 'AES-128-GCM',
                    'generated_at': datetime.now().isoformat()
                }
            elif key_type.upper() == "RSA":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                
                # Serialize keys
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                return {
                    'private_key': base64.b64encode(private_pem).decode('utf-8'),
                    'public_key': base64.b64encode(public_pem).decode('utf-8'),
                    'key_size': key_size,
                    'key_type': 'RSA',
                    'algorithm': f'RSA-{key_size}',
                    'generated_at': datetime.now().isoformat()
                }
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
                
        except Exception as e:
            self.logger.error(f"Failed to generate key material: {e}")
            raise
    
    def encrypt_data(self, data: bytes, key: bytes, algorithm: str = "AES-256-GCM") -> Dict[str, Any]:
        """
        Encrypt data using symmetric encryption.
        
        Args:
            data: Data to encrypt
            key: Encryption key
            algorithm: Encryption algorithm
            
        Returns:
            Dict[str, Any]: Encrypted data with metadata
        """
        try:
            if algorithm.upper() == "AES-256-GCM":
                # Generate random IV
                iv = secrets.token_bytes(12)
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                
                # Encrypt data
                ciphertext = encryptor.update(data) + encryptor.finalize()
                
                return {
                    'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                    'iv': base64.b64encode(iv).decode('utf-8'),
                    'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
                    'algorithm': algorithm,
                    'encrypted_at': datetime.now().isoformat()
                }
            else:
                raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
                
        except Exception as e:
            self.logger.error(f"Failed to encrypt data: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: Dict[str, Any], key: bytes) -> bytes:
        """
        Decrypt data using symmetric encryption.
        
        Args:
            encrypted_data: Encrypted data dictionary
            key: Decryption key
            
        Returns:
            bytes: Decrypted data
        """
        try:
            algorithm = encrypted_data.get('algorithm', 'AES-256-GCM')
            
            if algorithm.upper() == "AES-256-GCM":
                # Decode components
                ciphertext = base64.b64decode(encrypted_data['ciphertext'])
                iv = base64.b64decode(encrypted_data['iv'])
                tag = base64.b64decode(encrypted_data['tag'])
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                # Decrypt data
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                return plaintext
            else:
                raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
                
        except Exception as e:
            self.logger.error(f"Failed to decrypt data: {e}")
            raise
    
    def hash_data(self, data: bytes, algorithm: str = "SHA-256") -> str:
        """
        Hash data using specified algorithm.
        
        Args:
            data: Data to hash
            algorithm: Hashing algorithm
            
        Returns:
            str: Hexadecimal hash value
        """
        try:
            if algorithm.upper() == "SHA-256":
                hash_obj = hashlib.sha256(data)
            elif algorithm.upper() == "SHA-512":
                hash_obj = hashlib.sha512(data)
            elif algorithm.upper() == "SHA-1":
                hash_obj = hashlib.sha1(data)
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
            return hash_obj.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Failed to hash data: {e}")
            raise
    
    def derive_key(self, password: str, salt: Optional[bytes] = None, key_size: int = 256) -> Tuple[bytes, bytes]:
        """
        Derive a key from a password using PBKDF2.
        
        Args:
            password: Password to derive key from
            salt: Salt for key derivation (generated if None)
            key_size: Key size in bits
            
        Returns:
            Tuple[bytes, bytes]: Derived key and salt
        """
        try:
            if salt is None:
                salt = secrets.token_bytes(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_size // 8,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            key = kdf.derive(password.encode('utf-8'))
            return key, salt
            
        except Exception as e:
            self.logger.error(f"Failed to derive key: {e}")
            raise
    
    def hmac_sign(self, data: bytes, key: bytes, algorithm: str = "SHA-256") -> str:
        """
        Create HMAC signature of data.
        
        Args:
            data: Data to sign
            key: Signing key
            algorithm: Hash algorithm for HMAC
            
        Returns:
            str: Base64 encoded HMAC signature
        """
        try:
            if algorithm.upper() == "SHA-256":
                h = HMAC(key, hashes.SHA256(), backend=default_backend())
            elif algorithm.upper() == "SHA-512":
                h = HMAC(key, hashes.SHA512(), backend=default_backend())
            else:
                raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
            
            h.update(data)
            signature = h.finalize()
            
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Failed to create HMAC signature: {e}")
            raise
    
    def verify_hmac(self, data: bytes, key: bytes, signature: str, algorithm: str = "SHA-256") -> bool:
        """
        Verify HMAC signature.
        
        Args:
            data: Original data
            key: Signing key
            signature: Base64 encoded signature
            algorithm: Hash algorithm for HMAC
            
        Returns:
            bool: True if signature is valid
        """
        try:
            expected_signature = self.hmac_sign(data, key, algorithm)
            return expected_signature == signature
            
        except Exception as e:
            self.logger.error(f"Failed to verify HMAC signature: {e}")
            return False
    
    def validate_key_material(self, key_material: str) -> bool:
        """
        Validate key material format.
        
        Args:
            key_material: Base64 encoded key material
            
        Returns:
            bool: True if key material is valid
        """
        try:
            # Check if it's valid base64
            decoded = base64.b64decode(key_material)
            
            # Check reasonable key sizes (16-4096 bytes)
            if len(decoded) < 16 or len(decoded) > 4096:
                return False
            
            return True
            
        except Exception:
            return False
    
    def generate_key_id(self, key_material: str, algorithm: str = "SHA-256") -> str:
        """
        Generate a unique key ID from key material.
        
        Args:
            key_material: Base64 encoded key material
            algorithm: Hash algorithm for ID generation
            
        Returns:
            str: Unique key ID
        """
        try:
            decoded = base64.b64decode(key_material)
            key_hash = self.hash_data(decoded, algorithm)
            
            # Use first 16 characters as key ID
            key_id = f"key_{key_hash[:16]}"
            return key_id
            
        except Exception as e:
            self.logger.error(f"Failed to generate key ID: {e}")
            raise
    
    def extract_certificate_info(self, cert_data: bytes) -> Dict[str, Any]:
        """
        Extract information from certificate data.
        
        Args:
            cert_data: Certificate data in PEM or DER format
            
        Returns:
            Dict[str, Any]: Certificate information
        """
        try:
            # Try to load as PEM
            try:
                cert = x509.load_pem_x509_certificate(cert_data)
            except ValueError:
                # Try to load as DER
                cert = x509.load_der_x509_certificate(cert_data)
            
            # Extract information
            subject = cert.subject
            issuer = cert.issuer
            
            # Get common name
            cn = None
            for name in subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
                cn = name.value
                break
            
            return {
                'subject': str(subject),
                'issuer': str(issuer),
                'common_name': cn,
                'serial_number': str(cert.serial_number),
                'valid_from': cert.not_valid_before.isoformat(),
                'valid_until': cert.not_valid_after.isoformat(),
                'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(),
                'fingerprint_sha1': cert.fingerprint(hashes.SHA1()).hex(),
                'is_valid': cert.not_valid_before <= datetime.now() <= cert.not_valid_after
            }
            
        except Exception as e:
            self.logger.error(f"Failed to extract certificate info: {e}")
            raise
    
    def validate_certificate_chain(self, cert_chain: List[bytes]) -> bool:
        """
        Validate a certificate chain.
        
        Args:
            cert_chain: List of certificates in order (leaf to root)
            
        Returns:
            bool: True if chain is valid
        """
        try:
            if len(cert_chain) < 2:
                return False
            
            # Load certificates
            certs = []
            for cert_data in cert_chain:
                try:
                    cert = x509.load_pem_x509_certificate(cert_data)
                    certs.append(cert)
                except ValueError:
                    cert = x509.load_der_x509_certificate(cert_data)
                    certs.append(cert)
            
            # Validate chain
            for i in range(len(certs) - 1):
                issuer_cert = certs[i + 1]
                subject_cert = certs[i]
                
                try:
                    issuer_cert.public_key().verify(
                        subject_cert.signature,
                        subject_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        subject_cert.signature_hash_algorithm
                    )
                except InvalidSignature:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to validate certificate chain: {e}")
            return False
    
    def generate_secure_random(self, length: int = 32) -> str:
        """
        Generate secure random bytes and return as base64.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            str: Base64 encoded random bytes
        """
        try:
            random_bytes = secrets.token_bytes(length)
            return base64.b64encode(random_bytes).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Failed to generate secure random: {e}")
            raise
    
    def create_key_wrapper(self, key: bytes, wrapping_key: bytes) -> Dict[str, Any]:
        """
        Wrap a key with another key for secure storage.
        
        Args:
            key: Key to wrap
            wrapping_key: Key used for wrapping
            
        Returns:
            Dict[str, Any]: Wrapped key data
        """
        try:
            # Generate random IV
            iv = secrets.token_bytes(12)
            
            # Create cipher for wrapping
            cipher = Cipher(
                algorithms.AES(wrapping_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Wrap the key
            wrapped_key = encryptor.update(key) + encryptor.finalize()
            
            return {
                'wrapped_key': base64.b64encode(wrapped_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
                'algorithm': 'AES-256-GCM',
                'wrapped_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to wrap key: {e}")
            raise
    
    def unwrap_key(self, wrapped_data: Dict[str, Any], unwrapping_key: bytes) -> bytes:
        """
        Unwrap a key using the unwrapping key.
        
        Args:
            wrapped_data: Wrapped key data
            unwrapping_key: Key used for unwrapping
            
        Returns:
            bytes: Unwrapped key
        """
        try:
            # Decode components
            wrapped_key = base64.b64decode(wrapped_data['wrapped_key'])
            iv = base64.b64decode(wrapped_data['iv'])
            tag = base64.b64decode(wrapped_data['tag'])
            
            # Create cipher for unwrapping
            cipher = Cipher(
                algorithms.AES(unwrapping_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Unwrap the key
            key = decryptor.update(wrapped_key) + decryptor.finalize()
            
            return key
            
        except Exception as e:
            self.logger.error(f"Failed to unwrap key: {e}")
            raise
    
    def calculate_key_fingerprint(self, key_material: str, algorithm: str = "SHA-256") -> str:
        """
        Calculate fingerprint of key material.
        
        Args:
            key_material: Base64 encoded key material
            algorithm: Hash algorithm
            
        Returns:
            str: Key fingerprint
        """
        try:
            decoded = base64.b64decode(key_material)
            return self.hash_data(decoded, algorithm)
        except Exception as e:
            self.logger.error(f"Failed to calculate key fingerprint: {e}")
            raise
    
    def validate_key_size(self, key_material: str, expected_size: int) -> bool:
        """
        Validate that key material has expected size.
        
        Args:
            key_material: Base64 encoded key material
            expected_size: Expected key size in bits
            
        Returns:
            bool: True if key size matches
        """
        try:
            decoded = base64.b64decode(key_material)
            actual_size = len(decoded) * 8
            return actual_size == expected_size
        except Exception:
            return False


# Global cryptographic utilities instance
crypto_utils = CryptographicUtils()
