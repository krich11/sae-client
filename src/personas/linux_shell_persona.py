"""
Linux Shell Persona Implementation.
Handles key management by executing shell commands on the underlying Linux operating system.
Supports file-based key storage, system commands, and shell scripting.
"""

import logging
import time
import subprocess
import os
import shlex
from typing import Dict, Any, Optional, List
from pathlib import Path

from .base_persona import BasePersona, PreConfigureContext, RotationContext


class LinuxShellPersona(BasePersona):
    """Linux Shell persona for executing system commands."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Linux Shell persona."""
        # Set persona attributes before calling parent init
        self.persona_name = "Linux Shell"
        self.version = "1.0.0"
        self.description = "Linux Shell Command Execution Persona"
        
        # Linux Shell-specific configuration
        self.shell_path = config.get('shell_path', '/bin/bash')
        self.key_directory = config.get('key_directory', '/tmp/sae-keys')
        self.simulation_mode = config.get('simulation_mode', False)
        self.operation_delay = config.get('operation_delay', 1.0)  # seconds
        self.command_timeout = config.get('command_timeout', 30)  # seconds
        self.sudo_enabled = config.get('sudo_enabled', False)
        self.sudo_user = config.get('sudo_user', 'root')
        
        super().__init__(config)
        
        # Only show initialization details in debug mode
        if self.config.get('debug_mode', False):
            print(f"🔧 {self.persona_name} Persona Initialized")
            print(f"   Shell Path: {self.shell_path}")
            print(f"   Key Directory: {self.key_directory}")
            print(f"   Simulation Mode: {self.simulation_mode}")
            print(f"   Operation Delay: {self.operation_delay}s")
            print(f"   Command Timeout: {self.command_timeout}s")
            print(f"   Sudo Enabled: {self.sudo_enabled}")
            print(f"   Sudo User: {self.sudo_user}")
    
    def _validate_config(self):
        """Validate Linux Shell persona configuration."""
        if self.config.get('debug_mode', False):
            print(f"🔍 {self.persona_name} Persona: Validating Configuration")
        
        # Validate shell path exists
        if not os.path.exists(self.shell_path):
            if self.config.get('debug_mode', False):
                print(f"   ⚠️  Warning: Shell path '{self.shell_path}' does not exist")
        
        # Create key directory if it doesn't exist
        if not os.path.exists(self.key_directory):
            try:
                os.makedirs(self.key_directory, mode=0o700, exist_ok=True)
                if self.config.get('debug_mode', False):
                    print(f"   ✅ Created key directory: {self.key_directory}")
            except Exception as e:
                if self.config.get('debug_mode', False):
                    print(f"   ❌ Failed to create key directory: {e}")
        
        if self.config.get('debug_mode', False):
            print(f"   ✅ Configuration validation completed")
    
    def _execute_shell_command(self, command: str, timeout: int = None) -> tuple[bool, str, str]:
        """
        Execute a shell command on the Linux system.
        
        Args:
            command: Shell command to execute
            timeout: Command timeout in seconds
            
        Returns:
            tuple: (success, stdout, stderr)
        """
        if self.simulation_mode:
            if self.config.get('debug_mode', False):
                print(f"   🔄 Simulating shell command: {command}")
            time.sleep(self.operation_delay)
            return True, f"Simulated output for: {command}", ""
        
        try:
            if timeout is None:
                timeout = self.command_timeout
            
            # Prepare command with sudo if enabled
            if self.sudo_enabled:
                full_command = f"sudo -u {self.sudo_user} {command}"
            else:
                full_command = command
            
            if self.config.get('debug_mode', False):
                print(f"   🐚 Executing: {full_command}")
            
            # Execute command with timeout
            result = subprocess.run(
                full_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.key_directory
            )
            
            if self.config.get('debug_mode', False):
                print(f"   📊 Return Code: {result.returncode}")
                if result.stdout:
                    print(f"   📄 STDOUT: {result.stdout.strip()}")
                if result.stderr:
                    print(f"   ⚠️  STDERR: {result.stderr.strip()}")
            
            success = result.returncode == 0
            return success, result.stdout.strip(), result.stderr.strip()
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {timeout} seconds"
            if self.config.get('debug_mode', False):
                print(f"   ❌ {error_msg}")
            return False, "", error_msg
        except Exception as e:
            error_msg = f"Command execution error: {e}"
            if self.config.get('debug_mode', False):
                print(f"   ❌ {error_msg}")
            return False, "", error_msg
    
    def pre_configure_key(self, context: PreConfigureContext) -> bool:
        """
        Pre-configure a key by storing it in the Linux filesystem.
        
        Args:
            context: PreConfigureContext containing key information
            
        Returns:
            bool: True if pre-configuration was successful
        """
        print(f"🔧 {self.persona_name} Persona: Pre-configure Key")
        print(f"   Key ID: {context.key_id}")
        print(f"   Key Directory: {self.key_directory}")
        print(f"   Key Material: {len(context.key_material)} bytes")
        
        try:
            # Create key file path
            key_file = os.path.join(self.key_directory, f"{context.key_id}.key")
            
            # Write key material to file
            print(f"   📝 Writing key to file: {key_file}")
            success, stdout, stderr = self._execute_shell_command(f"echo '{context.key_material}' > {key_file}")
            
            if not success:
                print(f"   ❌ Failed to write key file: {stderr}")
                return False
            
            # Set proper permissions (readable only by owner)
            print(f"   🔐 Setting file permissions")
            success, stdout, stderr = self._execute_shell_command(f"chmod 600 {key_file}")
            
            if not success:
                print(f"   ⚠️  Warning: Failed to set permissions: {stderr}")
                # Continue anyway, as the key was written
            
            print(f"   ✅ Key {context.key_id} pre-configured successfully")
            return True
            
        except Exception as e:
            print(f"   ❌ Pre-configuration failed: {e}")
            return False
    
    def rotate_key(self, context: RotationContext) -> bool:
        """
        Rotate keys by executing shell commands.
        
        Args:
            context: RotationContext containing rotation information
            
        Returns:
            bool: True if rotation was successful
        """
        print(f"🔄 {self.persona_name} Persona: Rotate Key")
        print(f"   Key ID: {context.key_id}")
        print(f"   Rotation Timestamp: {context.rotation_timestamp}")
        print(f"   Key Directory: {self.key_directory}")
        
        try:
            # Get the key material from the key service
            from src.services.key_service import key_service
            key = key_service.get_key(context.key_id)
            if not key:
                print(f"   ❌ Key {context.key_id} not found in key service")
                return False
            
            key_material = key.key_material
            
            # Step 1: Create new key file
            new_key_file = os.path.join(self.key_directory, f"{context.key_id}.key")
            print(f"   🔄 Step 1: Creating new key file")
            
            success, stdout, stderr = self._execute_shell_command(f"echo '{key_material}' > {new_key_file}")
            if not success:
                print(f"   ❌ Failed to create new key file: {stderr}")
                return False
            
            # Step 2: Set proper permissions
            print(f"   🔄 Step 2: Setting file permissions")
            success, stdout, stderr = self._execute_shell_command(f"chmod 600 {new_key_file}")
            if not success:
                print(f"   ⚠️  Warning: Failed to set permissions: {stderr}")
            
            # Step 3: Execute any custom rotation commands from config
            rotation_commands = self.config.get('rotation_commands', [])
            if rotation_commands:
                print(f"   🔄 Step 3: Executing rotation commands")
                for i, cmd in enumerate(rotation_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Rotation command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Rotation command {i} completed")
            else:
                print(f"   ℹ️  No custom rotation commands configured")
            
            # Step 4: Verify key file exists
            print(f"   🔄 Step 4: Verifying key file")
            success, stdout, stderr = self._execute_shell_command(f"test -f {new_key_file} && echo 'exists'")
            if not success or 'exists' not in stdout:
                print(f"   ❌ Key file verification failed")
                return False
            
            print(f"   ✅ Key rotation completed successfully")
            return True
            
        except Exception as e:
            print(f"   ❌ Key rotation failed: {e}")
            return False
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from the Linux filesystem.
        
        Args:
            key_id: The key ID to delete
            
        Returns:
            bool: True if deletion was successful
        """
        print(f"🗑️  {self.persona_name} Persona: Delete Key")
        print(f"   Key ID: {key_id}")
        print(f"   Key Directory: {self.key_directory}")
        
        try:
            # Step 1: Check if key file exists
            key_file = os.path.join(self.key_directory, f"{key_id}.key")
            print(f"   🔍 Step 1: Checking if key file exists")
            
            success, stdout, stderr = self._execute_shell_command(f"test -f {key_file} && echo 'exists'")
            if not success or 'exists' not in stdout:
                print(f"   ⚠️  Key file {key_file} not found - skipping deletion")
                return True  # Not an error if file doesn't exist
            
            # Step 2: Delete the key file
            print(f"   🗑️  Step 2: Deleting key file")
            success, stdout, stderr = self._execute_shell_command(f"rm -f {key_file}")
            if not success:
                print(f"   ❌ Failed to delete key file: {stderr}")
                return False
            
            # Step 3: Verify deletion
            print(f"   ✅ Step 3: Verifying deletion")
            success, stdout, stderr = self._execute_shell_command(f"test -f {key_file} && echo 'still_exists'")
            if success and 'still_exists' in stdout:
                print(f"   ❌ Key file still exists after deletion")
                return False
            
            print(f"   ✅ Key {key_id} successfully deleted and verified")
            return True
            
        except Exception as e:
            print(f"   ❌ Key deletion failed: {e}")
            return False
    
    def get_current_keys(self) -> List[str]:
        """
        Get list of current key files in the key directory.
        
        Returns:
            List of key IDs currently stored on the system
        """
        if self.simulation_mode:
            if self.config.get('debug_mode', False):
                print(f"   🔄 Simulating key list retrieval")
            time.sleep(self.operation_delay)
            return []
        
        try:
            success, stdout, stderr = self._execute_shell_command("ls -1 *.key 2>/dev/null | sed 's/\\.key$//'")
            
            if not success:
                print(f"   ❌ Failed to list keys: {stderr}")
                return []
            
            if stdout.strip():
                key_ids = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
                if self.config.get('debug_mode', False):
                    print(f"   📋 Found {len(key_ids)} keys:")
                    for key_id in key_ids:
                        print(f"      - {key_id}")
                return key_ids
            else:
                if self.config.get('debug_mode', False):
                    print(f"   ℹ️  No keys found in directory")
                return []
                
        except Exception as e:
            print(f"   ❌ Error getting current keys: {e}")
            return []
    
    def test_connection(self) -> bool:
        """
        Test connection by executing a simple shell command.
        
        Returns:
            bool: True if connection test was successful
        """
        print(f"🔍 {self.persona_name} Persona: Test Connection")
        
        try:
            # Test basic shell command execution
            success, stdout, stderr = self._execute_shell_command("echo 'Linux Shell Persona Test'")
            
            if success and 'Linux Shell Persona Test' in stdout:
                print(f"   ✅ Connection test successful")
                return True
            else:
                print(f"   ❌ Connection test failed: {stderr}")
                return False
                
        except Exception as e:
            print(f"   ❌ Connection test error: {e}")
            return False
    
    def get_persona_info(self) -> Dict[str, Any]:
        """
        Get information about the Linux Shell persona.
        
        Returns:
            Dict containing persona information
        """
        return {
            "persona_name": self.persona_name,
            "version": self.version,
            "description": self.description,
            "shell_path": self.shell_path,
            "key_directory": self.key_directory,
            "simulation_mode": self.simulation_mode,
            "sudo_enabled": self.sudo_enabled,
            "sudo_user": self.sudo_user,
            "current_keys": self.get_current_keys()
        }
