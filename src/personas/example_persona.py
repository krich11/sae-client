"""
Example Persona Implementation.
Demonstrates how to implement a persona with flexible context parameters.
This persona prints messages for all operations and can be used as a template.
"""

import logging
import time
from typing import Dict, Any, Optional
from pathlib import Path

from .base_persona import BasePersona, PreConfigureContext, RotationContext


class ExamplePersona(BasePersona):
    """Example persona that prints messages for all operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize example persona."""
        # Set persona attributes before calling parent init
        self.persona_name = "Example"
        self.version = "1.0.0"
        self.description = "Example persona for demonstration and testing"
        
        # Example-specific configuration
        self.device_name = config.get('device_name', 'example-device')
        self.simulation_mode = config.get('simulation_mode', True)
        self.operation_delay = config.get('operation_delay', 1.0)  # seconds
        
        super().__init__(config)
        
        print(f"🔧 {self.persona_name} Persona Initialized")
        print(f"   Device: {self.device_name}")
        print(f"   Simulation Mode: {self.simulation_mode}")
        print(f"   Operation Delay: {self.operation_delay}s")
    
    def _validate_config(self):
        """Validate example persona configuration."""
        print(f"🔍 {self.persona_name} Persona: Validating Configuration")
        
        required_fields = ['device_name']
        for field in required_fields:
            if field not in self.config:
                print(f"   ⚠️  Warning: Missing config field '{field}', using default")
        
        print(f"   ✅ Configuration validation completed")
    
    def pre_configure_key(self, context: PreConfigureContext) -> bool:
        """
        Pre-configure a key in the example device.
        
        Args:
            context: PreConfigureContext containing key and device parameters
            
        Returns:
            bool: True if key was successfully pre-configured
        """
        print(f"🔑 {self.persona_name} Persona: Pre-Configure Key")
        print(f"   Key ID: {context.key_id}")
        print(f"   Key Material Size: {len(context.key_material)} bytes")
        print(f"   Device Interface: {context.device_interface or 'default'}")
        print(f"   Encryption Algorithm: {context.encryption_algorithm}")
        print(f"   Key Priority: {context.key_priority}")
        
        if context.custom_metadata:
            print(f"   Custom Metadata:")
            for key, value in context.custom_metadata.items():
                print(f"     {key}: {value}")
        
        # Simulate operation delay
        if self.simulation_mode:
            print(f"   ⏳ Simulating pre-configuration delay ({self.operation_delay}s)...")
            time.sleep(self.operation_delay)
        
        # Example pre-configuration logic
        print(f"   📝 Example pre-configuration steps:")
        print(f"     1. Validate key material format")
        print(f"     2. Check device interface availability")
        print(f"     3. Reserve key slot in device")
        print(f"     4. Store key material securely")
        print(f"     5. Configure encryption parameters")
        
        # Log the operation
        self.log_operation('pre-configure', context.key_id, 'success', 
                          f'Device: {self.device_name}, Interface: {context.device_interface}')
        
        print(f"   ✅ Key pre-configuration completed successfully")
        return True
    
    def rotate_key(self, context: RotationContext) -> bool:
        """
        Rotate to the specified key at the given timestamp.
        
        Args:
            context: RotationContext containing all rotation parameters
            
        Returns:
            bool: True if key rotation was successful
        """
        print(f"🔄 {self.persona_name} Persona: Rotate Key")
        print(f"   Key ID: {context.key_id}")
        print(f"   Rotation Timestamp: {context.rotation_timestamp}")
        print(f"   Rotation Time: {time.ctime(context.rotation_timestamp)}")
        print(f"   Current Time: {time.ctime()}")
        print(f"   Device Interface: {context.device_interface or 'default'}")
        print(f"   Encryption Algorithm: {context.encryption_algorithm}")
        print(f"   Key Priority: {context.key_priority}")
        print(f"   Rollback on Failure: {context.rollback_on_failure}")
        print(f"   Session ID: {context.session_id}")
        print(f"   Master SAE: {context.master_sae_id}")
        print(f"   Slave SAE: {context.slave_sae_id}")
        print(f"   Advance Warning: {context.advance_warning_seconds}s")
        print(f"   Cleanup Delay: {context.cleanup_delay_seconds}s")
        print(f"   Validate Before: {context.validate_key_before_rotation}")
        print(f"   Validate After: {context.validate_device_after_rotation}")
        
        if context.notification_url:
            print(f"   Notification URL: {context.notification_url}")
            if context.notification_headers:
                print(f"   Notification Headers: {context.notification_headers}")
        
        if context.custom_metadata:
            print(f"   Custom Metadata:")
            for key, value in context.custom_metadata.items():
                print(f"     {key}: {value}")
        
        # Simulate operation delay
        if self.simulation_mode:
            print(f"   ⏳ Simulating key rotation delay ({self.operation_delay}s)...")
            time.sleep(self.operation_delay)
        
        # Example rotation logic
        print(f"   📝 Example key rotation steps:")
        print(f"     1. Validate current device state")
        print(f"     2. Check key availability")
        print(f"     3. Prepare new key for activation")
        print(f"     4. Execute key rotation command")
        print(f"     5. Verify rotation success")
        print(f"     6. Update device status")
        
        if context.rollback_on_failure:
            print(f"     7. Configure rollback mechanism")
        
        if context.notification_url:
            print(f"     8. Send notification to {context.notification_url}")
        
        # Log the operation
        self.log_operation('rotate', context.key_id, 'success',
                          f'Device: {self.device_name}, Interface: {context.device_interface}')
        
        print(f"   ✅ Key rotation completed successfully")
        return True
    
    def cleanup_old_keys(self) -> bool:
        """
        Clean up old/expired keys from the example device.
        
        Returns:
            bool: True if cleanup was successful
        """
        print(f"🧹 {self.persona_name} Persona: Cleanup Old Keys")
        print(f"   Device: {self.device_name}")
        
        # Simulate operation delay
        if self.simulation_mode:
            print(f"   ⏳ Simulating cleanup delay ({self.operation_delay}s)...")
            time.sleep(self.operation_delay)
        
        # Example cleanup logic
        print(f"   📝 Example cleanup steps:")
        print(f"     1. Scan for expired keys")
        print(f"     2. Identify unused key slots")
        print(f"     3. Remove expired key material")
        print(f"     4. Free up key slots")
        print(f"     5. Update device inventory")
        
        # Log the operation
        self.log_operation('cleanup', 'all', 'success', f'Device: {self.device_name}')
        
        print(f"   ✅ Key cleanup completed successfully")
        return True
    
    def get_device_status(self) -> Dict[str, Any]:
        """
        Get current example device status.
        
        Returns:
            Dict containing device status information
        """
        print(f"📊 {self.persona_name} Persona: Get Device Status")
        print(f"   Device: {self.device_name}")
        
        # Example device status
        status = {
            "device_name": self.device_name,
            "device_type": "example-device",
            "connected": True,
            "status": "operational",
            "version": self.version,
            "persona": self.persona_name,
            "simulation_mode": self.simulation_mode,
            "operation_delay": self.operation_delay,
            "last_operation": time.ctime(),
            "key_slots": {
                "total": 10,
                "used": 3,
                "available": 7
            },
            "supported_algorithms": ["AES-256", "ChaCha20", "AES-128"],
            "supported_interfaces": ["eth0", "eth1", "bond0"]
        }
        
        print(f"   📝 Device Status:")
        for key, value in status.items():
            if isinstance(value, dict):
                print(f"     {key}:")
                for sub_key, sub_value in value.items():
                    print(f"       {sub_key}: {sub_value}")
            else:
                print(f"     {key}: {value}")
        
        print(f"   ✅ Device status retrieved successfully")
        return status
    
    def test_connection(self) -> bool:
        """
        Test connection to the example device.
        
        Returns:
            bool: True if connection is successful
        """
        print(f"🔌 {self.persona_name} Persona: Test Connection")
        print(f"   Device: {self.device_name}")
        
        # Simulate connection test
        if self.simulation_mode:
            print(f"   ⏳ Simulating connection test ({self.operation_delay}s)...")
            time.sleep(self.operation_delay)
        
        # Example connection test
        print(f"   📝 Connection test steps:")
        print(f"     1. Check device availability")
        print(f"     2. Verify authentication")
        print(f"     3. Test communication protocol")
        print(f"     4. Validate device response")
        
        connection_ok = True  # Simulate successful connection
        
        if connection_ok:
            print(f"   ✅ Connection test successful")
        else:
            print(f"   ❌ Connection test failed")
        
        return connection_ok
    
    def validate_key_material(self, key_material: str) -> bool:
        """
        Validate key material format.
        
        Args:
            key_material: Base64-encoded key material
            
        Returns:
            bool: True if key material is valid
        """
        print(f"🔍 {self.persona_name} Persona: Validate Key Material")
        print(f"   Key Material Size: {len(key_material)} bytes")
        
        try:
            import base64
            decoded = base64.b64decode(key_material)
            print(f"   Decoded Size: {len(decoded)} bytes")
            
            # Example validation logic
            print(f"   📝 Validation steps:")
            print(f"     1. Check base64 encoding")
            print(f"     2. Validate key length")
            print(f"     3. Check key format")
            print(f"     4. Verify key strength")
            
            # Simulate validation
            if self.simulation_mode:
                print(f"   ⏳ Simulating validation ({self.operation_delay}s)...")
                time.sleep(self.operation_delay)
            
            is_valid = len(decoded) >= 8 and len(decoded) <= 64
            
            if is_valid:
                print(f"   ✅ Key material validation successful")
            else:
                print(f"   ❌ Key material validation failed")
            
            return is_valid
            
        except Exception as e:
            print(f"   ❌ Key material validation error: {e}")
            return False
    
    def get_persona_info(self) -> Dict[str, Any]:
        """
        Get persona information.
        
        Returns:
            Dict containing persona information
        """
        print(f"ℹ️  {self.persona_name} Persona: Get Persona Info")
        
        info = {
            "name": self.persona_name,
            "version": self.version,
            "description": self.description,
            "device_name": self.device_name,
            "simulation_mode": self.simulation_mode,
            "operation_delay": self.operation_delay,
            "supported_operations": [
                "pre_configure_key",
                "rotate_key", 
                "cleanup_old_keys",
                "get_device_status",
                "test_connection",
                "validate_key_material"
            ],
            "supported_algorithms": ["AES-256", "ChaCha20", "AES-128"],
            "supported_interfaces": ["eth0", "eth1", "bond0"],
            "last_updated": time.ctime()
        }
        
        print(f"   📝 Persona Information:")
        for key, value in info.items():
            if isinstance(value, list):
                print(f"     {key}: {', '.join(value)}")
            else:
                print(f"     {key}: {value}")
        
        return info
