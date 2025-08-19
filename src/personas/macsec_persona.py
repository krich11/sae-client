"""
MACsec Persona Implementation.
Example persona for MACsec device key rotation.
"""

import subprocess
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from .base_persona import BasePersona, PreConfigureContext, RotationContext


class MacsecPersona(BasePersona):
    """MACsec device persona implementation."""
    
    version = "1.0.0"
    description = "MACsec device key rotation implementation"
    
    def _validate_config(self):
        """Validate MACsec-specific configuration."""
        required_fields = ['interface', 'key_algorithm']
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"Required config field missing: {field}")
        
        # Validate interface exists
        interface = self.config.get('interface')
        if interface:
            try:
                result = subprocess.run(
                    ['ip', 'link', 'show', interface],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                    self.logger.warning(f"Interface {interface} not found")
            except Exception as e:
                self.logger.warning(f"Could not verify interface {interface}: {e}")
    
    def pre_configure_key(self, context: PreConfigureContext) -> bool:
        """
        Pre-configure a key in the MACsec device.
        
        Args:
            context: PreConfigureContext containing key and device parameters
            
        Returns:
            bool: True if key was successfully pre-configured
        """
        try:
            # Debug logging for MACsec key pre-configuration
            if self.config.get('debug_mode', False):
                self.logger.info(f"MACSEC PRE-CONFIGURE KEY:")
                self.logger.info(f"  Interface: {context.device_interface or self.config.get('interface')}")
                self.logger.info(f"  Key ID: {context.key_id}")
                self.logger.info(f"  Key Material Size: {len(context.key_material)} bytes")
                self.logger.info(f"  Encryption Algorithm: {context.encryption_algorithm}")
                self.logger.info(f"  Key Priority: {context.key_priority}")
                if context.custom_metadata:
                    self.logger.info(f"  Custom Metadata: {context.custom_metadata}")
            
            interface = context.device_interface or self.config.get('interface')
            
            # Example MACsec key pre-configuration command
            cmd = [
                'macsec', 'pre-configure-key',
                '--interface', interface,
                '--key-id', context.key_id,
                '--key-material', context.key_material,
                '--algorithm', context.encryption_algorithm,
                '--priority', context.key_priority
            ]
            
            # Add custom metadata if provided
            if context.custom_metadata:
                for key, value in context.custom_metadata.items():
                    cmd.extend(['--metadata', f"{key}={value}"])
            
            # Debug logging for command
            if self.config.get('debug_mode', False):
                self.logger.info(f"MACSEC PRE-CONFIGURE COMMAND:")
                self.logger.info(f"  Command: {' '.join(cmd)}")
            
            # Execute command (commented out for safety)
            # result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            # if result.returncode != 0:
            #     self.log_operation('pre-configure', context.key_id, 'failed', result.stderr)
            #     return False
            
            # For demo purposes, simulate success
            self.logger.info(f"Pre-configured key {context.key_id} on interface {interface}")
            self.log_operation('pre-configure', context.key_id, 'success', f'Interface: {interface}')
            return True
            
        except Exception as e:
            self.log_operation('pre-configure', context.key_id, 'failed', str(e))
            self.logger.error(f"Failed to pre-configure key {context.key_id}: {e}")
            return False
    
    def rotate_key(self, context: RotationContext) -> bool:
        """
        Rotate to the specified key at the given timestamp.
        
        Args:
            context: RotationContext containing all rotation parameters
            
        Returns:
            bool: True if key rotation was successful
        """
        try:
            # Debug logging for MACsec key rotation
            if self.config.get('debug_mode', False):
                import time
                self.logger.info(f"MACSEC ROTATE KEY:")
                self.logger.info(f"  Interface: {context.device_interface or self.config.get('interface')}")
                self.logger.info(f"  Key ID: {context.key_id}")
                self.logger.info(f"  Rotation Timestamp: {context.rotation_timestamp}")
                self.logger.info(f"  Rotation Time: {time.ctime(context.rotation_timestamp)}")
                self.logger.info(f"  Current Time: {time.ctime()}")
                self.logger.info(f"  Encryption Algorithm: {context.encryption_algorithm}")
                self.logger.info(f"  Key Priority: {context.key_priority}")
                self.logger.info(f"  Rollback on Failure: {context.rollback_on_failure}")
                self.logger.info(f"  Session ID: {context.session_id}")
                if context.custom_metadata:
                    self.logger.info(f"  Custom Metadata: {context.custom_metadata}")
            
            interface = context.device_interface or self.config.get('interface')
            
            # Example MACsec key rotation command
            cmd = [
                'macsec', 'rotate-key',
                '--interface', interface,
                '--key-id', context.key_id,
                '--timestamp', str(context.rotation_timestamp),
                '--algorithm', context.encryption_algorithm,
                '--priority', context.key_priority
            ]
            
            # Add rollback option
            if context.rollback_on_failure:
                cmd.append('--rollback-on-failure')
            
            # Add custom metadata if provided
            if context.custom_metadata:
                for key, value in context.custom_metadata.items():
                    cmd.extend(['--metadata', f"{key}={value}"])
            
            # Add notification URL if provided
            if context.notification_url:
                cmd.extend(['--notification-url', context.notification_url])
                if context.notification_headers:
                    for header, value in context.notification_headers.items():
                        cmd.extend(['--notification-header', f"{header}={value}"])
            
            # Debug logging for command
            if self.config.get('debug_mode', False):
                self.logger.info(f"MACSEC ROTATION COMMAND:")
                self.logger.info(f"  Command: {' '.join(cmd)}")
            
            # Execute command (commented out for safety)
            # result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            # if result.returncode != 0:
            #     self.log_operation('rotate', context.key_id, 'failed', result.stderr)
            #     return False
            
            # For demo purposes, simulate success
            self.logger.info(f"Rotated to key {context.key_id} on interface {interface}")
            self.log_operation('rotate', context.key_id, 'success', f'Interface: {interface}')
            return True
            
        except Exception as e:
            self.log_operation('rotate', context.key_id, 'failed', str(e))
            self.logger.error(f"Failed to rotate to key {context.key_id}: {e}")
            return False
    
    def cleanup_old_keys(self) -> bool:
        """
        Clean up old/expired keys from the MACsec device.
        
        Returns:
            bool: True if cleanup was successful
        """
        try:
            interface = self.config.get('interface')
            cleanup_delay = self.config.get('cleanup_delay', 30)
            
            # Example MACsec key cleanup command
            cmd = [
                'macsec', 'cleanup-keys',
                '--interface', interface,
                '--delay', str(cleanup_delay)
            ]
            
            # Execute command (commented out for safety)
            # result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            # if result.returncode != 0:
            #     self.log_operation('cleanup', 'all', 'failed', result.stderr)
            #     return False
            
            # For demo purposes, simulate success
            self.logger.info(f"Cleaned up old keys on interface {interface}")
            self.log_operation('cleanup', 'all', 'success', f'Interface: {interface}')
            return True
            
        except Exception as e:
            self.log_operation('cleanup', 'all', 'failed', str(e))
            self.logger.error(f"Failed to cleanup old keys: {e}")
            return False
    
    def get_device_status(self) -> Dict[str, Any]:
        """
        Get current MACsec device status.
        
        Returns:
            Dict containing device status information
        """
        try:
            interface = self.config.get('interface')
            
            # Example MACsec status command
            cmd = ['macsec', 'show-status', '--interface', interface]
            
            # Execute command (commented out for safety)
            # result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            # if result.returncode != 0:
            #     return {
            #         'connected': False,
            #         'interface': interface,
            #         'status': 'error',
            #         'error': result.stderr
            #     }
            # 
            # # Parse status output
            # status_data = json.loads(result.stdout)
            
            # For demo purposes, return simulated status
            status_data = {
                'connected': True,
                'interface': interface,
                'status': 'active',
                'current_key_id': 'demo_key_001',
                'key_count': 3,
                'last_rotation': datetime.now().isoformat(),
                'encryption_enabled': True,
                'integrity_enabled': True
            }
            
            self.device_status = status_data.get('status', 'unknown')
            return status_data
            
        except Exception as e:
            self.logger.error(f"Failed to get device status: {e}")
            return {
                'connected': False,
                'interface': self.config.get('interface', 'unknown'),
                'status': 'error',
                'error': str(e)
            }
    
    def get_active_keys(self) -> Dict[str, Any]:
        """
        Get currently active keys on the MACsec device.
        
        Returns:
            Dict containing active key information
        """
        try:
            interface = self.config.get('interface')
            
            # Example MACsec key list command
            cmd = ['macsec', 'list-keys', '--interface', interface]
            
            # Execute command (commented out for safety)
            # result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            # if result.returncode != 0:
            #     return {'error': result.stderr}
            # 
            # keys_data = json.loads(result.stdout)
            
            # For demo purposes, return simulated key data
            keys_data = {
                'active_key': {
                    'key_id': 'demo_key_001',
                    'algorithm': 'aes-gcm-256',
                    'created': '2024-01-01T12:00:00Z',
                    'expires': '2024-01-02T12:00:00Z'
                },
                'configured_keys': [
                    {
                        'key_id': 'demo_key_002',
                        'algorithm': 'aes-gcm-256',
                        'status': 'configured'
                    }
                ]
            }
            
            return keys_data
            
        except Exception as e:
            self.logger.error(f"Failed to get active keys: {e}")
            return {'error': str(e)}
    
    def test_macsec_connectivity(self) -> bool:
        """
        Test MACsec connectivity.
        
        Returns:
            bool: True if connectivity test passes
        """
        try:
            interface = self.config.get('interface')
            
            # Example MACsec connectivity test
            cmd = ['macsec', 'test-connectivity', '--interface', interface]
            
            # Execute command (commented out for safety)
            # result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            # return result.returncode == 0
            
            # For demo purposes, simulate success
            self.logger.info(f"MACsec connectivity test passed for interface {interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"MACsec connectivity test failed: {e}")
            return False
