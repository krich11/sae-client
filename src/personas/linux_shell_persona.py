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
        self.key_directory = config.get('key_directory', '/opt/sae/keys')
        self.simulation_mode = config.get('simulation_mode', False)
        self.operation_delay = config.get('operation_delay', 1.0)  # seconds
        self.command_timeout = config.get('command_timeout', 30)  # seconds
        self.sudo_enabled = config.get('sudo_enabled', False)
        self.sudo_user = config.get('sudo_user', 'root')
        self.sudo_password = config.get('sudo_password', None)
        
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
            if self.sudo_enabled:
                print(f"   Sudo User: {self.sudo_user}")
                print(f"   Sudo Password: {'***' if self.sudo_password else 'None'}")
    
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
                if self.sudo_password:
                    # Use echo to pipe password to sudo
                    full_command = f"echo '{self.sudo_password}' | sudo -S -u {self.sudo_user} {command}"
                else:
                    # No password needed (NOPASSWD in sudoers)
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
        Pre-configure a key by executing arbitrary shell commands.
        
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
            # Execute pre-configure commands
            preconfigure_commands = self.config.get('preconfigure_commands', [])
            if preconfigure_commands:
                print(f"   🔄 Executing pre-configure commands")
                for i, cmd in enumerate(preconfigure_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Pre-configure command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Pre-configure command {i} completed")
            else:
                print(f"   ℹ️  No custom pre-configure commands configured")
            
            # Execute any post-preconfigure commands
            post_preconfigure_commands = self.config.get('post_preconfigure_commands', [])
            if post_preconfigure_commands:
                print(f"   🔄 Executing post-preconfigure commands")
                for i, cmd in enumerate(post_preconfigure_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Post-preconfigure command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Post-preconfigure command {i} completed")
            else:
                print(f"   ℹ️  No custom post-preconfigure commands configured")
            
            print(f"   ✅ Key {context.key_id} pre-configured successfully")
            return True
            
        except Exception as e:
            print(f"   ❌ Pre-configuration failed: {e}")
            return False
    
    def rotate_key(self, context: RotationContext) -> bool:
        """
        Rotate keys by executing arbitrary shell commands.
        
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
            # Execute pre-rotation commands
            pre_rotation_commands = self.config.get('pre_rotation_commands', [])
            if pre_rotation_commands:
                print(f"   🔄 Executing pre-rotation commands")
                for i, cmd in enumerate(pre_rotation_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Pre-rotation command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Pre-rotation command {i} completed")
            else:
                print(f"   ℹ️  No custom pre-rotation commands configured")
            
            # Execute rotation commands
            rotation_commands = self.config.get('rotation_commands', [])
            if rotation_commands:
                print(f"   🔄 Executing rotation commands")
                for i, cmd in enumerate(rotation_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Rotation command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Rotation command {i} completed")
            else:
                print(f"   ℹ️  No custom rotation commands configured")
            
            # Execute post-rotation commands
            post_rotation_commands = self.config.get('post_rotation_commands', [])
            if post_rotation_commands:
                print(f"   🔄 Executing post-rotation commands")
                for i, cmd in enumerate(post_rotation_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Post-rotation command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Post-rotation command {i} completed")
            else:
                print(f"   ℹ️  No custom post-rotation commands configured")
            
            print(f"   ✅ Key rotation completed successfully")
            return True
            
        except Exception as e:
            print(f"   ❌ Key rotation failed: {e}")
            return False
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key by executing arbitrary shell commands.
        
        Args:
            key_id: The key ID to delete
            
        Returns:
            bool: True if deletion was successful
        """
        print(f"🗑️  {self.persona_name} Persona: Delete Key")
        print(f"   Key ID: {key_id}")
        print(f"   Key Directory: {self.key_directory}")
        
        try:
            # Execute pre-deletion commands
            pre_deletion_commands = self.config.get('pre_deletion_commands', [])
            if pre_deletion_commands:
                print(f"   🔄 Executing pre-deletion commands")
                for i, cmd in enumerate(pre_deletion_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Pre-deletion command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Pre-deletion command {i} completed")
            else:
                print(f"   ℹ️  No custom pre-deletion commands configured")
            
            # Execute deletion commands
            deletion_commands = self.config.get('deletion_commands', [])
            if deletion_commands:
                print(f"   🔄 Executing deletion commands")
                for i, cmd in enumerate(deletion_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Deletion command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Deletion command {i} completed")
            else:
                print(f"   ℹ️  No custom deletion commands configured")
            
            # Execute post-deletion commands
            post_deletion_commands = self.config.get('post_deletion_commands', [])
            if post_deletion_commands:
                print(f"   🔄 Executing post-deletion commands")
                for i, cmd in enumerate(post_deletion_commands, 1):
                    print(f"   📝 Command {i}: {cmd}")
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    if not success:
                        print(f"   ❌ Post-deletion command {i} failed: {stderr}")
                        return False
                    print(f"   ✅ Post-deletion command {i} completed")
            else:
                print(f"   ℹ️  No custom post-deletion commands configured")
            
            print(f"   ✅ Key {key_id} deletion completed successfully")
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
