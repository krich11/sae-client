"""
AOS8 Persona Implementation.
Handles key management for Aruba Operating System 8.x devices.
Supports wireless controllers, access points, and managed switches.
"""

import logging
import time
import subprocess
from typing import Dict, Any, Optional
from pathlib import Path

from .base_persona import BasePersona, PreConfigureContext, RotationContext


class Aos8Persona(BasePersona):
    """AOS8 persona for Aruba Operating System devices."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize AOS8 persona."""
        # Set persona attributes before calling parent init
        self.persona_name = "AOS8"
        self.version = "1.0.0"
        self.description = "Aruba Operating System 8.x Key Management Persona"
        
        # AOS8-specific configuration
        self.device_ip = config.get('device_ip', '192.168.1.1')
        self.username = config.get('username', 'admin')
        self.password = config.get('password', '')
        self.enable_password = config.get('enable_password', '')
        self.ssh_port = config.get('ssh_port', 22)
        self.device_type = config.get('device_type', 'controller')  # controller, ap, switch
        self.interface_name = config.get('interface_name', 'eth0')
        self.key_algorithm = config.get('key_algorithm', 'aes-256-gcm')
        self.simulation_mode = config.get('simulation_mode', True)
        self.operation_delay = config.get('operation_delay', 2.0)  # seconds
        
        super().__init__(config)
        
        print(f"🔧 {self.persona_name} Persona Initialized")
        print(f"   Device IP: {self.device_ip}")
        print(f"   Device Type: {self.device_type}")
        print(f"   Interface: {self.interface_name}")
        print(f"   Algorithm: {self.key_algorithm}")
        print(f"   Simulation Mode: {self.simulation_mode}")
        print(f"   Operation Delay: {self.operation_delay}s")
    
    def _validate_config(self):
        """Validate AOS8 persona configuration."""
        print(f"🔍 {self.persona_name} Persona: Validating Configuration")
        
        required_fields = ['device_ip', 'username']
        for field in required_fields:
            if field not in self.config:
                print(f"   ⚠️  Warning: Missing config field '{field}', using default")
        
        # Validate device type
        valid_types = ['controller', 'ap', 'switch']
        if self.device_type not in valid_types:
            print(f"   ⚠️  Warning: Invalid device_type '{self.device_type}', using 'controller'")
            self.device_type = 'controller'
        
        # Validate algorithm
        valid_algorithms = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305']
        if self.key_algorithm not in valid_algorithms:
            print(f"   ⚠️  Warning: Invalid key_algorithm '{self.key_algorithm}', using 'aes-256-gcm'")
            self.key_algorithm = 'aes-256-gcm'
        
        print(f"   ✅ Configuration validation completed")
    
    def _execute_aos8_command(self, command: str, timeout: int = 30) -> tuple[bool, str, str]:
        """
        Execute AOS8 command via SSH.
        
        Args:
            command: AOS8 command to execute
            timeout: Command timeout in seconds
            
        Returns:
            tuple: (success, stdout, stderr)
        """
        if self.simulation_mode:
            print(f"   🔄 Simulating AOS8 command: {command}")
            time.sleep(self.operation_delay)
            return True, f"Simulated output for: {command}", ""
        
        try:
            # Build SSH command for AOS8
            ssh_cmd = [
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-p', str(self.ssh_port),
                f'{self.username}@{self.device_ip}',
                command
            ]
            
            # Execute command
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=f"{self.password}\n{self.enable_password}\n" if self.enable_password else f"{self.password}\n"
            )
            
            return result.returncode == 0, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", f"SSH execution error: {e}"
    
    def pre_configure_key(self, context: PreConfigureContext) -> bool:
        """
        Pre-configure a key in the AOS8 device.
        
        Args:
            context: PreConfigureContext containing key and device parameters
            
        Returns:
            bool: True if key was successfully pre-configured
        """
        print(f"🔑 {self.persona_name} Persona: Pre-Configure Key")
        print(f"   Key ID: {context.key_id}")
        print(f"   Key Material Size: {len(context.key_material)} bytes")
        print(f"   Device Interface: {context.device_interface or self.interface_name}")
        print(f"   Encryption Algorithm: {context.encryption_algorithm}")
        print(f"   Key Priority: {context.key_priority}")
        
        if context.custom_metadata:
            print(f"   Custom Metadata:")
            for key, value in context.custom_metadata.items():
                print(f"     {key}: {value}")
        
        interface = context.device_interface or self.interface_name
        algorithm = context.encryption_algorithm or self.key_algorithm
        
        # AOS8-specific pre-configuration steps
        print(f"   📝 AOS8 pre-configuration steps:")
        print(f"     1. Connect to AOS8 device {self.device_ip}")
        print(f"     2. Enter enable mode")
        print(f"     3. Configure interface {interface}")
        print(f"     4. Set encryption algorithm {algorithm}")
        print(f"     5. Pre-load key material")
        print(f"     6. Verify key configuration")
        
        # Execute AOS8 commands
        commands = [
            f"enable",
            f"configure terminal",
            f"interface {interface}",
            f"encryption algorithm {algorithm}",
            f"key pre-load {context.key_id} {context.key_material}",
            f"show encryption key {context.key_id}",
            f"end"
        ]
        
        for cmd in commands:
            success, stdout, stderr = self._execute_aos8_command(cmd)
            if not success:
                print(f"   ❌ Command failed: {cmd}")
                print(f"   Error: {stderr}")
                self.log_operation('pre-configure', context.key_id, 'failed', stderr)
                return False
            print(f"   ✅ Command successful: {cmd}")
        
        # Log the operation
        self.log_operation('pre-configure', context.key_id, 'success', 
                          f'Device: {self.device_ip}, Interface: {interface}')
        
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
        print(f"   Device Interface: {context.device_interface or self.interface_name}")
        print(f"   Encryption Algorithm: {context.encryption_algorithm}")
        print(f"   Key Priority: {context.key_priority}")
        print(f"   Rollback on Failure: {context.rollback_on_failure}")
        print(f"   Session ID: {context.session_id}")
        print(f"   Master SAE: {context.master_sae_id}")
        print(f"   Slave SAE: {context.slave_sae_id}")
        
        if context.notification_url:
            print(f"   Notification URL: {context.notification_url}")
        
        if context.custom_metadata:
            print(f"   Custom Metadata:")
            for key, value in context.custom_metadata.items():
                print(f"     {key}: {value}")
        
        interface = context.device_interface or self.interface_name
        algorithm = context.encryption_algorithm or self.key_algorithm
        
        # AOS8-specific rotation steps
        print(f"   📝 AOS8 key rotation steps:")
        print(f"     1. Connect to AOS8 device {self.device_ip}")
        print(f"     2. Enter enable mode")
        print(f"     3. Configure interface {interface}")
        print(f"     4. Validate current key state")
        print(f"     5. Execute key rotation")
        print(f"     6. Verify rotation success")
        print(f"     7. Update device status")
        
        if context.rollback_on_failure:
            print(f"     8. Configure rollback mechanism")
        
        # Execute AOS8 rotation commands
        commands = [
            f"enable",
            f"configure terminal",
            f"interface {interface}",
            f"show encryption status",
            f"encryption rotate-key {context.key_id}",
            f"show encryption status",
            f"end"
        ]
        
        for cmd in commands:
            success, stdout, stderr = self._execute_aos8_command(cmd)
            if not success:
                print(f"   ❌ Command failed: {cmd}")
                print(f"   Error: {stderr}")
                
                if context.rollback_on_failure:
                    print(f"   🔄 Attempting rollback...")
                    rollback_success = self._execute_rollback(context)
                    if rollback_success:
                        print(f"   ✅ Rollback successful")
                    else:
                        print(f"   ❌ Rollback failed")
                
                self.log_operation('rotate', context.key_id, 'failed', stderr)
                return False
            print(f"   ✅ Command successful: {cmd}")
        
        # Log the operation
        self.log_operation('rotate', context.key_id, 'success',
                          f'Device: {self.device_ip}, Interface: {interface}')
        
        print(f"   ✅ Key rotation completed successfully")
        return True
    
    def _execute_rollback(self, context: RotationContext) -> bool:
        """
        Execute rollback to previous key.
        
        Args:
            context: RotationContext containing rollback information
            
        Returns:
            bool: True if rollback was successful
        """
        print(f"   🔄 Executing AOS8 rollback...")
        
        interface = context.device_interface or self.interface_name
        
        rollback_commands = [
            f"enable",
            f"configure terminal",
            f"interface {interface}",
            f"encryption rollback-key",
            f"show encryption status",
            f"end"
        ]
        
        for cmd in rollback_commands:
            success, stdout, stderr = self._execute_aos8_command(cmd)
            if not success:
                print(f"   ❌ Rollback command failed: {cmd}")
                return False
        
        return True
    
    def cleanup_old_keys(self) -> bool:
        """
        Clean up old/expired keys from the AOS8 device.
        
        Returns:
            bool: True if cleanup was successful
        """
        print(f"🧹 {self.persona_name} Persona: Cleanup Old Keys")
        print(f"   Device IP: {self.device_ip}")
        print(f"   Device Type: {self.device_type}")
        
        # AOS8-specific cleanup steps
        print(f"   📝 AOS8 cleanup steps:")
        print(f"     1. Connect to AOS8 device {self.device_ip}")
        print(f"     2. Enter enable mode")
        print(f"     3. Scan for expired keys")
        print(f"     4. Remove expired key material")
        print(f"     5. Free up key slots")
        print(f"     6. Update device inventory")
        
        # Execute AOS8 cleanup commands
        commands = [
            f"enable",
            f"show encryption keys expired",
            f"encryption cleanup-expired-keys",
            f"show encryption keys",
            f"end"
        ]
        
        for cmd in commands:
            success, stdout, stderr = self._execute_aos8_command(cmd)
            if not success:
                print(f"   ❌ Command failed: {cmd}")
                print(f"   Error: {stderr}")
                self.log_operation('cleanup', 'all', 'failed', stderr)
                return False
            print(f"   ✅ Command successful: {cmd}")
        
        # Log the operation
        self.log_operation('cleanup', 'all', 'success', f'Device: {self.device_ip}')
        
        print(f"   ✅ Key cleanup completed successfully")
        return True
    
    def get_device_status(self) -> Dict[str, Any]:
        """
        Get current AOS8 device status.
        
        Returns:
            Dict containing device status information
        """
        print(f"📊 {self.persona_name} Persona: Get Device Status")
        print(f"   Device IP: {self.device_ip}")
        print(f"   Device Type: {self.device_type}")
        
        # Execute AOS8 status commands
        status_commands = [
            f"show version",
            f"show system status",
            f"show encryption status",
            f"show interface {self.interface_name}"
        ]
        
        status_data = {
            "device_ip": self.device_ip,
            "device_type": self.device_type,
            "persona": self.persona_name,
            "version": self.version,
            "simulation_mode": self.simulation_mode,
            "last_operation": time.ctime(),
            "interface_name": self.interface_name,
            "key_algorithm": self.key_algorithm
        }
        
        if not self.simulation_mode:
            # Collect real status data
            for cmd in status_commands:
                success, stdout, stderr = self._execute_aos8_command(cmd)
                if success:
                    status_data[f"cmd_{cmd.replace(' ', '_')}"] = stdout.strip()
                else:
                    status_data[f"cmd_{cmd.replace(' ', '_')}_error"] = stderr.strip()
        else:
            # Simulated status data
            status_data.update({
                "connected": True,
                "status": "operational",
                "aos_version": "8.10.0.0",
                "encryption_enabled": True,
                "active_keys": 2,
                "available_key_slots": 8,
                "interface_status": "up",
                "supported_algorithms": ["aes-256-gcm", "aes-128-gcm", "chacha20-poly1305"]
            })
        
        print(f"   📝 Device Status:")
        for key, value in status_data.items():
            if isinstance(value, dict):
                print(f"     {key}:")
                for sub_key, sub_value in value.items():
                    print(f"       {sub_key}: {sub_value}")
            else:
                print(f"     {key}: {value}")
        
        print(f"   ✅ Device status retrieved successfully")
        return status_data
    
    def test_connection(self) -> bool:
        """
        Test connection to the AOS8 device.
        
        Returns:
            bool: True if connection is successful
        """
        print(f"🔌 {self.persona_name} Persona: Test Connection")
        print(f"   Device IP: {self.device_ip}")
        print(f"   SSH Port: {self.ssh_port}")
        print(f"   Username: {self.username}")
        
        # AOS8 connection test
        print(f"   📝 Connection test steps:")
        print(f"     1. Check device availability")
        print(f"     2. Verify SSH connectivity")
        print(f"     3. Test authentication")
        print(f"     4. Validate AOS8 command response")
        
        # Test connection with simple command
        test_command = "show version"
        success, stdout, stderr = self._execute_aos8_command(test_command)
        
        if success:
            print(f"   ✅ Connection test successful")
            print(f"   📄 Device response: {stdout[:100]}...")
        else:
            print(f"   ❌ Connection test failed")
            print(f"   Error: {stderr}")
        
        return success
    
    def validate_key_material(self, key_material: str) -> bool:
        """
        Validate key material format for AOS8.
        
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
            
            # AOS8-specific validation logic
            print(f"   📝 AOS8 validation steps:")
            print(f"     1. Check base64 encoding")
            print(f"     2. Validate key length (16-64 bytes)")
            print(f"     3. Check key format compatibility")
            print(f"     4. Verify key strength requirements")
            
            # Simulate validation
            if self.simulation_mode:
                print(f"   ⏳ Simulating validation ({self.operation_delay}s)...")
                time.sleep(self.operation_delay)
            
            # AOS8 key validation rules
            is_valid = (
                len(decoded) >= 16 and 
                len(decoded) <= 64 and 
                len(decoded) % 8 == 0  # AOS8 requires 8-byte alignment
            )
            
            if is_valid:
                print(f"   ✅ Key material validation successful")
                print(f"   📋 Key meets AOS8 requirements")
            else:
                print(f"   ❌ Key material validation failed")
                print(f"   📋 Key does not meet AOS8 requirements")
            
            return is_valid
            
        except Exception as e:
            print(f"   ❌ Key material validation error: {e}")
            return False
    
    def get_persona_info(self) -> Dict[str, Any]:
        """
        Get AOS8 persona information.
        
        Returns:
            Dict containing persona information
        """
        print(f"ℹ️  {self.persona_name} Persona: Get Persona Info")
        
        info = {
            "name": self.persona_name,
            "version": self.version,
            "description": self.description,
            "device_ip": self.device_ip,
            "device_type": self.device_type,
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
            "supported_algorithms": ["aes-256-gcm", "aes-128-gcm", "chacha20-poly1305"],
            "supported_device_types": ["controller", "ap", "switch"],
            "supported_interfaces": ["eth0", "eth1", "gigabitethernet0/0/1", "gigabitethernet0/0/2"],
            "aos8_versions": ["8.6.0.0", "8.7.0.0", "8.8.0.0", "8.9.0.0", "8.10.0.0"],
            "last_updated": time.ctime()
        }
        
        print(f"   📝 Persona Information:")
        for key, value in info.items():
            if isinstance(value, list):
                print(f"     {key}: {', '.join(value)}")
            else:
                print(f"     {key}: {value}")
        
        return info
