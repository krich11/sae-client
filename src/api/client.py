"""
KME API Client for SAE Client.
Handles communication with the KME server using mTLS authentication.
"""

import requests
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

from ..config import config_manager, logger
from ..models.api_models import (
    StatusSpec, KeyRequest, KeyResponse, ErrorResponse,
    CertificateExtension, KeyType, ErrorCode
)


class KMEClient:
    """Client for communicating with KME server."""
    
    def __init__(self):
        """Initialize KME client."""
        self.config = config_manager.config
        self.session = self._create_session()
        self.logger = logging.getLogger(__name__)
    
    def _create_session(self) -> requests.Session:
        """Create requests session with mTLS configuration."""
        session = requests.Session()
        
        # Configure mTLS certificates
        cert_paths = config_manager.get_cert_paths()
        
        if Path(cert_paths['sae_cert']).exists() and Path(cert_paths['sae_key']).exists():
            session.cert = (cert_paths['sae_cert'], cert_paths['sae_key'])
            self.logger.info("mTLS certificates configured")
        else:
            self.logger.warning("SAE certificates not found, using basic authentication")
        
        # Configure CA certificate for server verification
        if Path(cert_paths['ca_cert']).exists():
            session.verify = cert_paths['ca_cert']
            self.logger.info("CA certificate configured for server verification")
        else:
            self.logger.warning("CA certificate not found, disabling SSL verification")
            session.verify = False
        
        # Configure timeouts and retries
        session.timeout = self.config.timeout
        
        return session
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request to KME server."""
        url = config_manager.get_kme_url(endpoint)
        
        try:
            self.logger.debug(f"Making {method} request to {url}")
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise
    
    def _parse_certificate_extension(self, headers: Dict[str, str]) -> Optional[CertificateExtension]:
        """Parse certificate extension from response headers."""
        try:
            return CertificateExtension(
                client_verified=headers.get('X-Client-Verified', ''),
                client_dn=headers.get('X-Client-DN', ''),
                client_issuer=headers.get('X-Client-Issuer', ''),
                ssl_protocol=headers.get('X-SSL-Protocol', ''),
                ssl_cipher=headers.get('X-SSL-Cipher', '')
            )
        except Exception as e:
            self.logger.warning(f"Failed to parse certificate extension: {e}")
            return None
    
    def get_status(self) -> StatusSpec:
        """Get KME server status."""
        try:
            response = self._make_request('GET', '/status')
            data = response.json()
            
            # Parse certificate extension
            cert_ext = self._parse_certificate_extension(response.headers)
            
            return StatusSpec(
                status=data.get('status', 'unknown'),
                version=data.get('version', 'unknown'),
                timestamp=datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat())),
                easy_kms_certificate_extension=cert_ext
            )
        except Exception as e:
            self.logger.error(f"Failed to get KME status: {e}")
            raise
    
    def request_encryption_keys(self, key_size: int = 256, quantity: int = 1) -> KeyResponse:
        """Request encryption keys from KME."""
        return self._request_keys(KeyType.ENCRYPTION, key_size, quantity)
    
    def request_decryption_keys(self, key_size: int = 256, quantity: int = 1) -> KeyResponse:
        """Request decryption keys from KME."""
        return self._request_keys(KeyType.DECRYPTION, key_size, quantity)
    
    def _request_keys(self, key_type: KeyType, key_size: int, quantity: int) -> KeyResponse:
        """Request keys from KME server."""
        try:
            request_data = KeyRequest(
                key_type=key_type,
                key_size=key_size,
                quantity=quantity
            )
            
            endpoint = '/enc_keys' if key_type == KeyType.ENCRYPTION else '/dec_keys'
            response = self._make_request('POST', endpoint, json=request_data.dict())
            data = response.json()
            
            # Parse certificate extension
            cert_ext = self._parse_certificate_extension(response.headers)
            
            return KeyResponse(
                keys=data.get('keys', []),
                total_keys=data.get('total_keys', 0),
                easy_kms_certificate_extension=cert_ext
            )
        except Exception as e:
            self.logger.error(f"Failed to request {key_type} keys: {e}")
            raise
    
    def get_encryption_keys(self, key_id: Optional[str] = None) -> KeyResponse:
        """Get encryption keys from KME."""
        return self._get_keys('/enc_keys', key_id)
    
    def get_decryption_keys(self, key_id: Optional[str] = None) -> KeyResponse:
        """Get decryption keys from KME."""
        return self._get_keys('/dec_keys', key_id)
    
    def _get_keys(self, endpoint: str, key_id: Optional[str] = None) -> KeyResponse:
        """Get keys from KME server."""
        try:
            params = {}
            if key_id:
                params['key_id'] = key_id
            
            response = self._make_request('GET', endpoint, params=params)
            data = response.json()
            
            # Parse certificate extension
            cert_ext = self._parse_certificate_extension(response.headers)
            
            return KeyResponse(
                keys=data.get('keys', []),
                total_keys=data.get('total_keys', 0),
                easy_kms_certificate_extension=cert_ext
            )
        except Exception as e:
            self.logger.error(f"Failed to get keys from {endpoint}: {e}")
            raise
    
    def test_connection(self) -> bool:
        """Test connection to KME server."""
        try:
            status = self.get_status()
            self.logger.info(f"KME connection successful: {status.status}")
            return True
        except Exception as e:
            self.logger.error(f"KME connection failed: {e}")
            return False
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get comprehensive server information."""
        try:
            status = self.get_status()
            return {
                'status': status.status,
                'version': status.version,
                'timestamp': status.timestamp.isoformat(),
                'certificate_info': status.easy_kms_certificate_extension.dict() if status.easy_kms_certificate_extension else None
            }
        except Exception as e:
            self.logger.error(f"Failed to get server info: {e}")
            return {'error': str(e)}


# Global KME client instance
kme_client = KMEClient()
