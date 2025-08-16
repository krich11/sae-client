"""
Authentication Service for SAE Client.
Handles mTLS certificate management, SAE identity, and security operations.
"""

import logging
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature, InvalidKey
import ipaddress

from ..config import config_manager, logger


class AuthenticationService:
    """Comprehensive authentication service for SAE operations."""
    
    def __init__(self):
        """Initialize authentication service."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
        self._load_certificates()
    
    def _load_certificates(self):
        """Load and validate certificates."""
        try:
            self.sae_cert_path = Path(self.config.sae_cert_path)
            self.sae_key_path = Path(self.config.sae_key_path)
            self.ca_cert_path = Path(self.config.ca_cert_path)
            
            self.logger.info("Loading certificates for authentication")
            
            # Load SAE certificate and key
            if self.sae_cert_path.exists() and self.sae_key_path.exists():
                self.sae_cert = self._load_certificate(self.sae_cert_path)
                self.sae_key = self._load_private_key(self.sae_key_path)
                self.logger.info("SAE certificate and key loaded successfully")
            else:
                self.sae_cert = None
                self.sae_key = None
                self.logger.warning("SAE certificate or key not found")
            
            # Load CA certificate
            if self.ca_cert_path.exists():
                self.ca_cert = self._load_certificate(self.ca_cert_path)
                self.logger.info("CA certificate loaded successfully")
            else:
                self.ca_cert = None
                self.logger.warning("CA certificate not found")
                
        except Exception as e:
            self.logger.error(f"Failed to load certificates: {e}")
            self.sae_cert = None
            self.sae_key = None
            self.ca_cert = None
    
    def _load_certificate(self, cert_path: Path) -> Optional[x509.Certificate]:
        """Load X.509 certificate from file."""
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Try to load as PEM
            try:
                cert = x509.load_pem_x509_certificate(cert_data)
                return cert
            except ValueError:
                # Try to load as DER
                cert = x509.load_der_x509_certificate(cert_data)
                return cert
                
        except Exception as e:
            self.logger.error(f"Failed to load certificate {cert_path}: {e}")
            return None
    
    def _load_private_key(self, key_path: Path) -> Optional[rsa.RSAPrivateKey]:
        """Load private key from file."""
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            # Try to load as PEM
            try:
                key = load_pem_private_key(key_data, password=None)
                return key
            except ValueError:
                self.logger.error(f"Failed to load private key {key_path}: Invalid format")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to load private key {key_path}: {e}")
            return None
    
    def validate_certificate_chain(self) -> bool:
        """
        Validate the certificate chain.
        
        Returns:
            bool: True if certificate chain is valid
        """
        try:
            if not self.sae_cert or not self.ca_cert:
                self.logger.warning("Cannot validate certificate chain: missing certificates")
                return False
            
            # Check if SAE certificate is signed by CA
            try:
                self.ca_cert.public_key().verify(
                    self.sae_cert.signature,
                    self.sae_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    self.sae_cert.signature_hash_algorithm
                )
                self.logger.info("Certificate chain validation successful")
                return True
            except InvalidSignature:
                self.logger.error("Certificate chain validation failed: invalid signature")
                return False
                
        except Exception as e:
            self.logger.error(f"Certificate chain validation error: {e}")
            return False
    
    def get_sae_identity(self) -> Dict[str, Any]:
        """
        Get SAE identity information from certificate.
        
        Returns:
            Dict[str, Any]: SAE identity information
        """
        if not self.sae_cert:
            return {
                'sae_id': self.config.sae_id,
                'certificate': None,
                'subject': None,
                'issuer': None,
                'valid_from': None,
                'valid_until': None
            }
        
        try:
            subject = self.sae_cert.subject
            issuer = self.sae_cert.issuer
            
            # Extract common name from subject
            cn = None
            for name in subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                cn = name.value
                break
            
            return {
                'sae_id': cn or self.config.sae_id,
                'certificate': self.sae_cert,
                'subject': str(subject),
                'issuer': str(issuer),
                'valid_from': self.sae_cert.not_valid_before,
                'valid_until': self.sae_cert.not_valid_after,
                'serial_number': str(self.sae_cert.serial_number),
                'fingerprint': self.sae_cert.fingerprint(hashes.SHA256()).hex()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get SAE identity: {e}")
            return {
                'sae_id': self.config.sae_id,
                'certificate': None,
                'error': str(e)
            }
    
    def is_certificate_valid(self) -> bool:
        """
        Check if SAE certificate is valid and not expired.
        
        Returns:
            bool: True if certificate is valid
        """
        if not self.sae_cert:
            return False
        
        try:
            now = datetime.now()
            return (
                self.sae_cert.not_valid_before <= now <= self.sae_cert.not_valid_after
            )
        except Exception as e:
            self.logger.error(f"Certificate validation error: {e}")
            return False
    
    def get_certificate_info(self) -> Dict[str, Any]:
        """
        Get detailed certificate information.
        
        Returns:
            Dict[str, Any]: Certificate information
        """
        if not self.sae_cert:
            return {'error': 'No certificate loaded'}
        
        try:
            return {
                'subject': str(self.sae_cert.subject),
                'issuer': str(self.sae_cert.issuer),
                'serial_number': str(self.sae_cert.serial_number),
                'version': self.sae_cert.version.name,
                'valid_from': self.sae_cert.not_valid_before.isoformat(),
                'valid_until': self.sae_cert.not_valid_after.isoformat(),
                'is_valid': self.is_certificate_valid(),
                'fingerprint_sha256': self.sae_cert.fingerprint(hashes.SHA256()).hex(),
                'fingerprint_sha1': self.sae_cert.fingerprint(hashes.SHA1()).hex(),
                'public_key_type': type(self.sae_cert.public_key()).__name__,
                'signature_algorithm': self.sae_cert.signature_algorithm_oid._name,
                'extensions': [ext.oid._name for ext in self.sae_cert.extensions]
            }
        except Exception as e:
            self.logger.error(f"Failed to get certificate info: {e}")
            return {'error': str(e)}
    
    def create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """
        Create SSL context for mTLS connections.
        
        Returns:
            ssl.SSLContext: SSL context if certificates are available
        """
        try:
            if not self.sae_cert or not self.sae_key:
                self.logger.warning("Cannot create SSL context: missing SAE certificate or key")
                return None
            
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # Set client certificate and key
            context.load_cert_chain(
                certfile=str(self.sae_cert_path),
                keyfile=str(self.sae_key_path)
            )
            
            # Set CA certificate for server verification
            if self.ca_cert_path.exists():
                context.load_verify_locations(cafile=str(self.ca_cert_path))
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = False  # For lab environment
            else:
                self.logger.warning("CA certificate not found, disabling server verification")
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            # Set cipher suites
            context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
            
            self.logger.info("SSL context created successfully")
            return context
            
        except Exception as e:
            self.logger.error(f"Failed to create SSL context: {e}")
            return None
    
    def test_connection(self, host: str, port: int) -> bool:
        """
        Test mTLS connection to a server.
        
        Args:
            host: Server hostname
            port: Server port
            
        Returns:
            bool: True if connection successful
        """
        try:
            context = self.create_ssl_context()
            if not context:
                self.logger.error("Cannot test connection: no SSL context")
                return False
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    self.logger.info(f"Connection successful to {host}:{port}")
                    self.logger.info(f"Server certificate: {cert.get('subject', 'Unknown')}")
                    return True
                    
        except Exception as e:
            self.logger.error(f"Connection test failed to {host}:{port}: {e}")
            return False
    
    def verify_server_certificate(self, server_cert: x509.Certificate) -> bool:
        """
        Verify server certificate against CA.
        
        Args:
            server_cert: Server certificate to verify
            
        Returns:
            bool: True if certificate is valid
        """
        try:
            if not self.ca_cert:
                self.logger.warning("Cannot verify server certificate: no CA certificate")
                return False
            
            # Check if server certificate is signed by CA
            self.ca_cert.public_key().verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server_cert.signature_hash_algorithm
            )
            
            # Check if certificate is not expired
            now = datetime.now()
            if not (server_cert.not_valid_before <= now <= server_cert.not_valid_after):
                self.logger.error("Server certificate is expired or not yet valid")
                return False
            
            self.logger.info("Server certificate verification successful")
            return True
            
        except InvalidSignature:
            self.logger.error("Server certificate verification failed: invalid signature")
            return False
        except Exception as e:
            self.logger.error(f"Server certificate verification error: {e}")
            return False
    
    def generate_key_pair(self, key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate a new RSA key pair.
        
        Args:
            key_size: Key size in bits
            
        Returns:
            Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]: Generated key pair
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            self.logger.info(f"Generated RSA key pair with size {key_size}")
            return private_key, public_key
            
        except Exception as e:
            self.logger.error(f"Failed to generate key pair: {e}")
            raise
    
    def create_self_signed_certificate(self, common_name: str, days: int = 365) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Create a self-signed certificate.
        
        Args:
            common_name: Common name for the certificate
            days: Validity period in days
            
        Returns:
            Tuple[x509.Certificate, rsa.RSAPrivateKey]: Certificate and private key
        """
        try:
            # Generate key pair
            private_key, public_key = self.generate_key_pair()
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAE Client Lab"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "QKD"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now()
            ).not_valid_after(
                datetime.now() + timedelta(days=days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(common_name),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            self.logger.info(f"Created self-signed certificate for {common_name}")
            return cert, private_key
            
        except Exception as e:
            self.logger.error(f"Failed to create self-signed certificate: {e}")
            raise
    
    def save_certificate(self, cert: x509.Certificate, file_path: Path):
        """Save certificate to file."""
        try:
            with open(file_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            self.logger.info(f"Saved certificate to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save certificate: {e}")
            raise
    
    def save_private_key(self, key: rsa.RSAPrivateKey, file_path: Path, password: Optional[str] = None):
        """Save private key to file."""
        try:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
            
            with open(file_path, 'wb') as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algorithm
                ))
            self.logger.info(f"Saved private key to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save private key: {e}")
            raise
    
    def get_certificate_paths(self) -> Dict[str, str]:
        """
        Get certificate file paths.
        
        Returns:
            Dict[str, str]: Certificate file paths
        """
        return {
            'sae_cert': str(self.sae_cert_path),
            'sae_key': str(self.sae_key_path),
            'ca_cert': str(self.ca_cert_path)
        }
    
    def check_certificate_files(self) -> Dict[str, bool]:
        """
        Check if certificate files exist.
        
        Returns:
            Dict[str, bool]: File existence status
        """
        return {
            'sae_cert': self.sae_cert_path.exists(),
            'sae_key': self.sae_key_path.exists(),
            'ca_cert': self.ca_cert_path.exists()
        }


# Global authentication service instance
auth_service = AuthenticationService()
