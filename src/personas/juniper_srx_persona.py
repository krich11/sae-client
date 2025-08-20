"""
Juniper SRX Persona - Junos 24 REST API Integration.
This persona manages cryptographic keys on Juniper SRX devices running Junos 24.
Uses REST API for device management and key operations.
"""

import json
import logging
import requests
import warnings
from datetime import datetime
from typing import Dict, Any, Optional
from urllib3.exceptions import InsecureRequestWarning

from .base_persona import BasePersona, RotationContext, PreConfigureContext

# Suppress SSL certificate warnings for Juniper devices
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class Juniper_SrxPersona(BasePersona):
    """Juniper SRX persona for Junos 24 REST API integration."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Juniper SRX persona."""
        self.persona_name = "juniper_srx"
        super().__init__(config)
        self.version = "1.0.0"
        self.description = "Juniper SRX persona for Junos 24 REST API"
        self.logger = logging.getLogger(__name__)
        
        # Juniper SRX specific configuration
        self.device_ip = config.get('device_ip', '192.168.1.1')
        self.username = config.get('username', 'admin')
        self.password = config.get('password', '')
        self.api_port = config.get('api_port', 443)
        self.api_protocol = config.get('api_protocol', 'https')
        self.verify_ssl = config.get('verify_ssl', False)
        self.timeout = config.get('timeout', 30)
        
        # Session management
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.timeout = self.timeout
        
        # API endpoints
        self.base_url = f"{self.api_protocol}://{self.device_ip}:{self.api_port}"
        self.auth_url = f"{self.base_url}/api/v1/auth/login"
        self.config_url = f"{self.base_url}/api/v1/configuration"
        self.operational_url = f"{self.base_url}/api/v1/operational"
        
        # Authentication token
        self.auth_token = None
        
        self.logger.info("Juniper SRX Persona Initialized")
        self.logger.info(f"Device IP: {self.device_ip}")
        self.logger.info(f"API Protocol: {self.api_protocol}")
        self.logger.info(f"API Port: {self.api_port}")
        self.logger.info(f"SSL Verification: {self.verify_ssl}")
    
    def _validate_config(self):
        """Validate Juniper SRX persona configuration."""
        required_fields = ['device_ip', 'username', 'password']
        missing_fields = [field for field in required_fields if not self.config.get(field)]
        
        if missing_fields:
            raise ValueError(f"Missing required configuration fields: {missing_fields}")
        
        if not self.config.get('password'):
            raise ValueError("Password is required for Juniper SRX authentication")
        
        self.logger.info("Juniper SRX persona: Configuration validation completed")
    
    def _authenticate(self) -> bool:
        """
        Authenticate with Juniper SRX device.
        
        Returns:
            bool: True if authentication successful
        """
        try:
            if self.config.get('debug_mode', False):
                self.logger.info("Authenticating with Juniper SRX device...")
                self.logger.info(f"Auth URL: {self.auth_url}")
            
            # Junos 24 REST API authentication
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            response = self.session.post(
                self.auth_url,
                json=auth_data,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                auth_response = response.json()
                self.auth_token = auth_response.get('token')
                
                if self.auth_token:
                    # Set authorization header for subsequent requests
                    self.session.headers.update({
                        'Authorization': f'Bearer {self.auth_token}',
                        'Content-Type': 'application/json'
                    })
                    
                    if self.config.get('debug_mode', False):
                        self.logger.info("Authentication successful")
                        self.logger.info(f"Token: {self.auth_token[:20]}...")
                    
                    return True
                else:
                    self.logger.error("No authentication token received")
                    return False
            else:
                self.logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    def _execute_api_call(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Optional[Dict]:
        """
        Execute API call to Juniper SRX device.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint
            data: Request data (for POST/PUT)
            
        Returns:
            Dict: Response data or None if failed
        """
        try:
            url = f"{self.base_url}{endpoint}"
            
            if self.config.get('debug_mode', False):
                self.logger.info(f"API Call: {method} {url}")
                if data:
                    self.logger.info(f"Request Data: {json.dumps(data, indent=2)}")
            
            if method.upper() == 'GET':
                response = self.session.get(url)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, json=data)
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return None
            
            if response.status_code in [200, 201, 204]:
                if self.config.get('debug_mode', False):
                    self.logger.info(f"API Response: {response.status_code}")
                    if response.text:
                        self.logger.info(f"Response Data: {response.text[:500]}...")
                
                if response.text:
                    return response.json()
                return {}
            else:
                self.logger.error(f"API call failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"API call error: {e}")
            return None
    
    def test_connection(self) -> bool:
        """
        Test connection to Juniper SRX device.
        
        Returns:
            bool: True if connection successful
        """
        try:
            if self.config.get('debug_mode', False):
                self.logger.info("Testing connection to Juniper SRX device...")
            
            # Authenticate first
            if not self._authenticate():
                return False
            
            # Test by getting device information
            device_info = self._execute_api_call('GET', '/api/v1/operational/system/information')
            
            if device_info:
                if self.config.get('debug_mode', False):
                    self.logger.info("Connection test successful")
                    self.logger.info(f"Device Info: {json.dumps(device_info, indent=2)}")
                return True
            else:
                self.logger.error("Connection test failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Connection test error: {e}")
            return False
    
    def pre_configure_key(self, context: PreConfigureContext) -> bool:
        """
        Pre-configure a key in Juniper SRX device.
        
        Args:
            context: PreConfigureContext containing key and device parameters
            
        Returns:
            bool: True if key was successfully pre-configured
        """
        try:
            if self.config.get('debug_mode', False):
                self.logger.info("Juniper SRX: Pre-configure key requested")
                self.logger.info(f"  Key ID: {context.key_id}")
                self.logger.info(f"  Device Interface: {context.device_interface}")
                self.logger.info(f"  Encryption Algorithm: {context.encryption_algorithm}")
            
            # Authenticate if needed
            if not self.auth_token and not self._authenticate():
                self.logger.error("Failed to authenticate for pre-configure operation")
                return False
            
            # Junos 24 uses different key management depending on the interface
            if context.device_interface and 'ipsec' in context.device_interface.lower():
                # IPsec key configuration
                key_data = {
                    "ipsec": {
                        "security-association": {
                            "pre-shared-key": {
                                "key-id": context.key_id,
                                "key-value": context.key_material
                            }
                        }
                    }
                }
                endpoint = "/api/v1/configuration/security/ipsec"
            else:
                # Default to security key configuration
                key_data = {
                    "security": {
                        "key": {
                            "key-id": context.key_id,
                            "key-value": context.key_material,
                            "algorithm": context.encryption_algorithm
                        }
                    }
                }
                endpoint = "/api/v1/configuration/security"
            
            # Execute the configuration
            result = self._execute_api_call('POST', endpoint, key_data)
            
            if result is not None:
                if self.config.get('debug_mode', False):
                    self.logger.info("Key pre-configured successfully")
                return True
            else:
                self.logger.error("Failed to pre-configure key")
                return False
                
        except Exception as e:
            self.logger.error(f"Pre-configure key error: {e}")
            return False
    
    def rotate_key(self, context: RotationContext) -> bool:
        """
        Rotate/activate a key in Juniper SRX device.
        
        Args:
            context: RotationContext containing rotation parameters
            
        Returns:
            bool: True if key rotation was successful
        """
        try:
            if self.config.get('debug_mode', False):
                self.logger.info("Juniper SRX: Key rotation requested")
                self.logger.info(f"  Key ID: {context.key_id}")
                self.logger.info(f"  Rotation Timestamp: {context.rotation_timestamp}")
                self.logger.info(f"  Session ID: {context.session_id}")
            
            # Authenticate if needed
            if not self.auth_token and not self._authenticate():
                self.logger.error("Failed to authenticate for rotation operation")
                return False
            
            # Activate the key (make it the active key)
            activation_data = {
                "security": {
                    "key-activation": {
                        "key-id": context.key_id,
                        "activate": True
                    }
                }
            }
            
            # Execute the activation
            result = self._execute_api_call('POST', '/api/v1/configuration/security', activation_data)
            
            if result is not None:
                if self.config.get('debug_mode', False):
                    self.logger.info("Key rotation completed successfully")
                return True
            else:
                self.logger.error("Failed to rotate key")
                return False
                
        except Exception as e:
            self.logger.error(f"Key rotation error: {e}")
            return False
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from Juniper SRX device.
        
        Args:
            key_id: Key ID to delete
            
        Returns:
            bool: True if key was successfully deleted
        """
        try:
            if self.config.get('debug_mode', False):
                self.logger.info("Juniper SRX: Delete key requested")
                self.logger.info(f"  Key ID: {key_id}")
            
            # Authenticate if needed
            if not self.auth_token and not self._authenticate():
                self.logger.error("Failed to authenticate for delete operation")
                return False
            
            # Delete the key
            result = self._execute_api_call('DELETE', f"/api/v1/configuration/security/key/{key_id}")
            
            if result is not None:
                if self.config.get('debug_mode', False):
                    self.logger.info("Key deleted successfully")
                return True
            else:
                self.logger.error("Failed to delete key")
                return False
                
        except Exception as e:
            self.logger.error(f"Delete key error: {e}")
            return False
    
    def cleanup_old_keys(self) -> bool:
        """
        Cleanup old/expired keys from Juniper SRX device.
        
        Returns:
            bool: True if cleanup was successful
        """
        try:
            if self.config.get('debug_mode', False):
                self.logger.info("Juniper SRX: Cleanup old keys requested")
            
            # Authenticate if needed
            if not self.auth_token and not self._authenticate():
                self.logger.error("Failed to authenticate for cleanup operation")
                return False
            
            # Get list of keys
            keys = self._execute_api_call('GET', '/api/v1/operational/security/keys')
            
            if keys:
                # Find old/expired keys and delete them
                deleted_count = 0
                for key in keys.get('keys', []):
                    if key.get('status') == 'expired':
                        key_id = key.get('key-id')
                        if key_id:
                            if self.delete_key(key_id):
                                deleted_count += 1
                
                if self.config.get('debug_mode', False):
                    self.logger.info(f"Cleanup completed: {deleted_count} keys deleted")
                
                return True
            else:
                self.logger.error("Failed to get keys for cleanup")
                return False
                
        except Exception as e:
            self.logger.error(f"Cleanup old keys error: {e}")
            return False
    
    def get_device_status(self) -> Dict[str, Any]:
        """
        Get current Juniper SRX device status.
        
        Returns:
            Dict containing device status information
        """
        try:
            if self.config.get('debug_mode', False):
                self.logger.info("Juniper SRX: Get device status requested")
            
            # Authenticate if needed
            if not self.auth_token and not self._authenticate():
                return {
                    "device_ip": self.device_ip,
                    "device_type": "juniper_srx",
                    "persona": "Juniper SRX",
                    "version": self.version,
                    "status": "authentication_failed",
                    "connected": False,
                    "error": "Authentication failed"
                }
            
            # Get system information
            system_info = self._execute_api_call('GET', '/api/v1/operational/system/information')
            
            # Get security status
            security_status = self._execute_api_call('GET', '/api/v1/operational/security/status')
            
            # Build status response
            status_data = {
                "device_ip": self.device_ip,
                "device_type": "juniper_srx",
                "persona": "Juniper SRX",
                "version": self.version,
                "simulation_mode": False,
                "last_operation": datetime.now().strftime("%c"),
                "status": "connected",
                "connected": True
            }
            
            if system_info:
                status_data.update({
                    "hostname": system_info.get('hostname', 'Unknown'),
                    "model": system_info.get('model', 'Unknown'),
                    "serial_number": system_info.get('serial-number', 'Unknown'),
                    "os_version": system_info.get('version', 'Unknown')
                })
            
            if security_status:
                status_data.update({
                    "security_status": security_status.get('status', 'Unknown'),
                    "active_keys": security_status.get('active-keys', 0)
                })
            
            if self.config.get('debug_mode', False):
                self.logger.info("Device status retrieved successfully")
            
            return status_data
            
        except Exception as e:
            self.logger.error(f"Get device status error: {e}")
            return {
                "device_ip": self.device_ip,
                "device_type": "juniper_srx",
                "persona": "Juniper SRX",
                "version": self.version,
                "status": "error",
                "connected": False,
                "error": str(e)
            }
    
    def validate_key_material(self, key_material: str) -> bool:
        """
        Validate key material format for Juniper SRX.
        
        Args:
            key_material: Base64-encoded key material
            
        Returns:
            bool: True if key material is valid
        """
        try:
            import base64
            decoded = base64.b64decode(key_material)
            
            # Juniper SRX supports various key sizes
            # Common sizes: 128, 192, 256 bits (16, 24, 32 bytes)
            if len(decoded) not in [16, 24, 32]:
                self.logger.warning(f"Key material size {len(decoded)} bytes may not be optimal for Juniper SRX")
                # Still allow it, but warn
            
            if self.config.get('debug_mode', False):
                self.logger.info(f"Juniper SRX key validation: PASSED (size: {len(decoded)} bytes)")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Key material validation failed: {e}")
            return False
