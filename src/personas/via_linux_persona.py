"""
VIA Linux Persona Implementation.
Specialized Linux Shell persona for VIA PPK XML file generation.
Handles key management by creating formatted PPK.xml files for VIA systems.
"""

import os
import time
import uuid
from typing import Dict, Any
from .linux_shell_persona import LinuxShellPersona


class ViaLinuxPersona(LinuxShellPersona):
    """VIA Linux persona for PPK XML file generation."""
    
    def __init__(self, config: dict):
        """Initialize VIA Linux persona."""
        # Set persona attributes before calling parent init
        self.persona_name = "VIA Linux"
        self.version = "1.0.0"
        self.description = "VIA Linux PPK XML File Generation Persona (Master SAE Only)"
        
        super().__init__(config)
        
        # Only show initialization details in debug mode
        if self.config.get('debug_mode', False):
            print(f"🔧 {self.persona_name} Persona Initialized")
            print(f"   Specialized for VIA PPK XML generation")
            print(f"   Master SAE only")
    
    def pre_configure_key(self, context):
        """
        Pre-configure a key by creating VIA PPK.xml file.
        
        Args:
            context: PreConfigureContext containing key information
            
        Returns:
            bool: True if pre-configuration was successful
        """
        print(f"🔧 {self.persona_name} Persona: Pre-configure Key")
        print(f"   Key ID: {context.key_id}")
        print(f"   Key Material Length: {len(context.key_material)} bytes")
        print(f"   Creating VIA PPK.xml file")
        
        try:
            # Log current working directory and environment
            print(f"   📁 Working Directory: {getattr(self, 'script_directory', self.key_directory)}")
            print(f"   ⚙️  Script Directory: {getattr(self, 'script_directory', 'Not set')}")
            print(f"   🔧 Sudo Enabled: {self.sudo_enabled}")
            if self.sudo_enabled:
                print(f"   👤 Sudo User: {self.sudo_user}")
                print(f"   🔐 Sudo Password: {'Set' if self.sudo_password else 'Not set'}")
            
            # Check current PPK.xml status before pre-configure
            print(f"   🔍 Pre-configure PPK.xml status check:")
            ppk_file = "/usr/share/via/PPK.xml"
            success, stdout, stderr = self._execute_shell_command(f"test -f {ppk_file} && echo 'exists'")
            ppk_exists_before = success and 'exists' in stdout
            print(f"      PPK.xml exists before pre-configure: {ppk_exists_before}")
            
            if ppk_exists_before:
                # Get file details
                success, stdout, stderr = self._execute_shell_command(f"ls -la {ppk_file}")
                if success:
                    print(f"      PPK.xml file details: {stdout.strip()}")
                else:
                    print(f"      Could not get PPK.xml file details: {stderr}")
            
            # Get the slave SAE ID from the key service
            print(f"   🔍 Retrieving slave SAE information:")
            from src.services.key_service import key_service
            key = key_service.get_key(context.key_id)
            
            if key and key.allowed_sae_id:
                # Get the slave SAE IP address from known peers
                from src.services.sae_peers import sae_peers
                peer_address = sae_peers.get_peer_address(key.allowed_sae_id)
                
                if peer_address:
                    sae_ip = peer_address[0]  # Get the host/IP address
                    print(f"      📋 Using slave SAE IP: {sae_ip} (from SAE ID: {key.allowed_sae_id})")
                else:
                    # Fallback to master SAE IP if slave not found in peers
                    from src.config import config
                    sae_ip = getattr(config, 'sae_ip', 'unknown')
                    print(f"      ⚠️  Slave SAE {key.allowed_sae_id} not found in known peers, using master SAE IP: {sae_ip}")
            else:
                # Fallback to master SAE IP if no slave SAE ID found
                from src.config import config
                sae_ip = getattr(config, 'sae_ip', 'unknown')
                print(f"      ⚠️  No slave SAE ID found, using master SAE IP: {sae_ip}")
            
            # Generate random temporary file name
            temp_file = f"/tmp/{uuid.uuid4().hex}.tmp"
            print(f"   📝 Generated temporary file: {temp_file}")
            
            # Create the PPK.xml content
            ppk_xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<PPK_PROFILE>
    <controllers>
        <controller>
            <name>{sae_ip}</name>
            <PPK_ID>{context.key_id}</PPK_ID>
            <PPK_VAL>{context.key_material}</PPK_VAL>
        </controller>
    </controllers>
</PPK_PROFILE>'''
            
            print(f"   📄 PPK.xml content preview:")
            print(f"      SAE IP: {sae_ip}")
            print(f"      PPK ID: {context.key_id}")
            print(f"      PPK Value: {context.key_material[:20]}... (truncated)")
            
            # Write to temporary file first
            print(f"   📝 Writing to temporary file: {temp_file}")
            print(f"   🕐 Start time: {time.strftime('%H:%M:%S')}")
            success, stdout, stderr = self._execute_shell_command(f"cat > {temp_file} << 'EOF'\n{ppk_xml_content}\nEOF")
            print(f"   🕐 End time: {time.strftime('%H:%M:%S')}")
            
            if not success:
                print(f"   ❌ Failed to write temporary file: {stderr}")
                return False
            
            # Verify temporary file was created
            print(f"   🔍 Verifying temporary file creation:")
            success, stdout, stderr = self._execute_shell_command(f"test -f {temp_file} && echo 'exists'")
            if success and 'exists' in stdout:
                print(f"      Temporary file created successfully")
                # Get file size
                success, stdout, stderr = self._execute_shell_command(f"wc -c < {temp_file}")
                if success:
                    print(f"      Temporary file size: {stdout.strip()} bytes")
            else:
                print(f"      ❌ Temporary file not found after creation")
                return False
            
            # Move to final location with sudo
            print(f"   🔄 Moving to final location: {ppk_file}")
            print(f"   🕐 Start time: {time.strftime('%H:%M:%S')}")
            success, stdout, stderr = self._execute_shell_command(f"sudo mv {temp_file} {ppk_file}")
            print(f"   🕐 End time: {time.strftime('%H:%M:%S')}")
            
            if not success:
                print(f"   ❌ Failed to move file to final location: {stderr}")
                # Clean up temp file
                self._execute_shell_command(f"rm -f {temp_file}")
                return False
            
            # Set proper permissions
            print(f"   🔐 Setting file permissions")
            print(f"   🕐 Start time: {time.strftime('%H:%M:%S')}")
            success, stdout, stderr = self._execute_shell_command(f"sudo chmod 644 {ppk_file}")
            print(f"   🕐 End time: {time.strftime('%H:%M:%S')}")
            
            if not success:
                print(f"   ⚠️  Warning: Failed to set permissions: {stderr}")
            else:
                print(f"   ✅ File permissions set successfully")
            
            # Set file ownership
            print(f"   🔐 Setting file ownership")
            print(f"   🕐 Start time: {time.strftime('%H:%M:%S')}")
            success, stdout, stderr = self._execute_shell_command(f"sudo chown root:root {ppk_file}")
            print(f"   🕐 End time: {time.strftime('%H:%M:%S')}")
            
            if not success:
                print(f"   ⚠️  Warning: Failed to set ownership: {stderr}")
            else:
                print(f"   ✅ File ownership set successfully")
            
            # Verify final file status
            print(f"   🔍 Final PPK.xml verification:")
            success, stdout, stderr = self._execute_shell_command(f"ls -la {ppk_file}")
            if success:
                print(f"      Final file details: {stdout.strip()}")
            else:
                print(f"      Could not get final file details: {stderr}")
            
            # Show file contents (first few lines)
            success, stdout, stderr = self._execute_shell_command(f"head -5 {ppk_file}")
            if success:
                print(f"      PPK.xml contents (first 5 lines):")
                for line in stdout.strip().split('\n'):
                    print(f"        {line}")
            else:
                print(f"      Could not read PPK.xml contents: {stderr}")
            
            print(f"   ✅ PPK.xml file created successfully at {ppk_file}")
            print(f"   📊 Pre-configure Summary:")
            print(f"      - Key ID: {context.key_id}")
            print(f"      - SAE IP: {sae_ip}")
            print(f"      - PPK.xml before: {'Exists' if ppk_exists_before else 'Missing'}")
            print(f"      - PPK.xml after: 'Exists'")
            print(f"      - File operations: SUCCESS")
            
            return True
            
        except Exception as e:
            print(f"   ❌ PPK.xml creation failed with exception: {e}")
            import traceback
            print(f"   📋 Exception traceback:")
            for line in traceback.format_exc().split('\n'):
                if line.strip():
                    print(f"      {line}")
            return False
    
    def rotate_key(self, context):
        """
        Rotate keys by executing rotation commands from config.
        
        Args:
            context: RotationContext containing rotation information
            
        Returns:
            bool: True if rotation was successful
        """
        print(f"🔄 {self.persona_name} Persona: Rotate Key")
        print(f"   Key ID: {context.key_id}")
        print(f"   Rotation Timestamp: {context.rotation_timestamp}")
        print(f"   Session ID: {context.session_id}")
        print(f"   Device Interface: {context.device_interface}")
        print(f"   Encryption Algorithm: {context.encryption_algorithm}")
        print(f"   Key Priority: {context.key_priority}")
        print(f"   Rollback on Failure: {context.rollback_on_failure}")
        
        try:
            # Log current working directory and environment
            print(f"   📁 Working Directory: {getattr(self, 'script_directory', self.key_directory)}")
            print(f"   ⚙️  Script Directory: {getattr(self, 'script_directory', 'Not set')}")
            print(f"   🔧 Sudo Enabled: {self.sudo_enabled}")
            if self.sudo_enabled:
                print(f"   👤 Sudo User: {self.sudo_user}")
                print(f"   🔐 Sudo Password: {'Set' if self.sudo_password else 'Not set'}")
            
            # Check current PPK.xml status before rotation
            print(f"   🔍 Pre-rotation PPK.xml status check:")
            ppk_file = "/usr/share/via/PPK.xml"
            success, stdout, stderr = self._execute_shell_command(f"test -f {ppk_file} && echo 'exists'")
            ppk_exists_before = success and 'exists' in stdout
            print(f"      PPK.xml exists before rotation: {ppk_exists_before}")
            
            if ppk_exists_before:
                # Get file details
                success, stdout, stderr = self._execute_shell_command(f"ls -la {ppk_file}")
                if success:
                    print(f"      PPK.xml file details: {stdout.strip()}")
                else:
                    print(f"      Could not get PPK.xml file details: {stderr}")
            
            # Execute rotation commands from config
            rotation_commands = self.config.get('rotation_commands', [])
            print(f"   📋 Found {len(rotation_commands)} rotation commands in config")
            
            if rotation_commands:
                print(f"   🔄 Starting rotation command execution")
                for i, cmd in enumerate(rotation_commands, 1):
                    print(f"   ┌─── Command {i}/{len(rotation_commands)} ───")
                    print(f"   📝 Executing: {cmd}")
                    print(f"   🕐 Start time: {time.strftime('%H:%M:%S')}")
                    
                    # Execute the command
                    success, stdout, stderr = self._execute_shell_command(cmd)
                    
                    print(f"   🕐 End time: {time.strftime('%H:%M:%S')}")
                    print(f"   📊 Return Code: {0 if success else 'Non-zero'}")
                    
                    if stdout:
                        print(f"   📄 STDOUT: {stdout}")
                    if stderr:
                        print(f"   ⚠️  STDERR: {stderr}")
                    
                    if not success:
                        print(f"   ❌ Rotation command {i} FAILED")
                        print(f"   └─── Command {i} failed, aborting rotation ───")
                        return False
                    else:
                        print(f"   ✅ Rotation command {i} SUCCESS")
                        print(f"   └─── Command {i} completed ───")
            else:
                print(f"   ℹ️  No rotation commands configured - skipping command execution")
            
            # Check PPK.xml status after rotation
            print(f"   🔍 Post-rotation PPK.xml status check:")
            success, stdout, stderr = self._execute_shell_command(f"test -f {ppk_file} && echo 'exists'")
            ppk_exists_after = success and 'exists' in stdout
            print(f"      PPK.xml exists after rotation: {ppk_exists_after}")
            
            if ppk_exists_after:
                # Get updated file details
                success, stdout, stderr = self._execute_shell_command(f"ls -la {ppk_file}")
                if success:
                    print(f"      PPK.xml file details: {stdout.strip()}")
                else:
                    print(f"      Could not get PPK.xml file details: {stderr}")
                
                # Show file contents (first few lines)
                success, stdout, stderr = self._execute_shell_command(f"head -5 {ppk_file}")
                if success:
                    print(f"      PPK.xml contents (first 5 lines):")
                    for line in stdout.strip().split('\n'):
                        print(f"        {line}")
                else:
                    print(f"      Could not read PPK.xml contents: {stderr}")
            
            # Check VIA service status after rotation
            print(f"   🔍 Post-rotation VIA service status:")
            via_services = ["via-vpn", "via-service", "via"]
            for service in via_services:
                success, stdout, stderr = self._execute_shell_command(f"systemctl is-active {service}.service")
                if success:
                    print(f"      {service}.service: {stdout.strip()}")
                else:
                    print(f"      {service}.service: {stderr.strip()}")
            
            print(f"   ✅ Key rotation completed successfully")
            print(f"   📊 Rotation Summary:")
            print(f"      - Commands executed: {len(rotation_commands)}")
            print(f"      - PPK.xml before: {'Exists' if ppk_exists_before else 'Missing'}")
            print(f"      - PPK.xml after: {'Exists' if ppk_exists_after else 'Missing'}")
            print(f"      - All commands: {'SUCCESS' if rotation_commands else 'SKIPPED'}")
            
            return True
            
        except Exception as e:
            print(f"   ❌ Key rotation failed with exception: {e}")
            import traceback
            print(f"   📋 Exception traceback:")
            for line in traceback.format_exc().split('\n'):
                if line.strip():
                    print(f"      {line}")
            return False
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key by removing VIA PPK.xml file.
        
        Args:
            key_id: The key ID to delete
            
        Returns:
            bool: True if deletion was successful
        """
        print(f"🗑️  {self.persona_name} Persona: Delete Key")
        print(f"   Key ID: {key_id}")
        print(f"   Removing VIA PPK.xml file")
        
        try:
            ppk_file = "/usr/share/via/PPK.xml"
            
            # Check if PPK.xml exists
            print(f"   🔍 Checking if PPK.xml exists")
            success, stdout, stderr = self._execute_shell_command(f"test -f {ppk_file} && echo 'exists'")
            if not success or 'exists' not in stdout:
                print(f"   ⚠️  PPK.xml file not found - skipping deletion")
                return True  # Not an error if file doesn't exist
            
            # Delete the PPK.xml file
            print(f"   🗑️  Deleting PPK.xml file")
            success, stdout, stderr = self._execute_shell_command(f"sudo rm -f {ppk_file}")
            if not success:
                print(f"   ❌ Failed to delete PPK.xml file: {stderr}")
                return False
            
            # Verify deletion
            print(f"   ✅ Verifying deletion")
            success, stdout, stderr = self._execute_shell_command(f"test -f {ppk_file} && echo 'still_exists'")
            if success and 'still_exists' in stdout:
                print(f"   ❌ PPK.xml file still exists after deletion")
                return False
            
            print(f"   ✅ PPK.xml file successfully deleted")
            return True
            
        except Exception as e:
            print(f"   ❌ PPK.xml deletion failed: {e}")
            return False
    
    def cleanup_old_keys(self) -> bool:
        """
        Clean up old/expired keys from the VIA system.
        
        Returns:
            bool: True if cleanup was successful
        """
        print(f"🧹 {self.persona_name} Persona: Cleanup Old Keys")
        
        try:
            # For VIA, we just need to remove the PPK.xml file
            ppk_file = "/usr/share/via/PPK.xml"
            
            # Check if PPK.xml exists
            success, stdout, stderr = self._execute_shell_command(f"test -f {ppk_file} && echo 'exists'")
            if success and 'exists' in stdout:
                # Remove the file
                success, stdout, stderr = self._execute_shell_command(f"sudo rm -f {ppk_file}")
                if success:
                    print(f"   ✅ Cleaned up old PPK.xml file")
                else:
                    print(f"   ❌ Failed to remove PPK.xml file: {stderr}")
                    return False
            else:
                print(f"   ℹ️  No PPK.xml file found to clean up")
            
            print(f"   ✅ Key cleanup completed successfully")
            return True
            
        except Exception as e:
            print(f"   ❌ Key cleanup failed: {e}")
            return False
    
    def get_device_status(self) -> Dict[str, Any]:
        """
        Get current VIA device status.
        
        Returns:
            Dict containing device status information
        """
        print(f"📊 {self.persona_name} Persona: Get Device Status")
        
        try:
            status = {
                "device_type": "VIA Linux",
                "persona_name": self.persona_name,
                "version": self.version,
                "description": self.description
            }
            
            # Check if VIA directory exists
            success, stdout, stderr = self._execute_shell_command("test -d /usr/share/via && echo 'exists'")
            via_dir_exists = success and 'exists' in stdout
            via_dir_path = "/usr/share/via"
            status["via_directory_exists"] = f"{via_dir_exists} ({via_dir_path})"
            
            # Check if PPK.xml exists
            success, stdout, stderr = self._execute_shell_command("test -f /usr/share/via/PPK.xml && echo 'exists'")
            ppk_exists = success and 'exists' in stdout
            ppk_path = "/usr/share/via/PPK.xml"
            status["ppk_file_exists"] = f"{ppk_exists} ({ppk_path})" if ppk_exists else ppk_exists
                            
            # Comprehensive VIA service status check
            via_services = ["via-vpn", "via-service", "via"]
            service_status = {}
            
            for service in via_services:
                # Check if service exists
                success, stdout, stderr = self._execute_shell_command(f"systemctl list-unit-files {service}.service | grep {service}")
                if success and service in stdout:
                    # Get detailed service status
                    success, stdout, stderr = self._execute_shell_command(f"systemctl status {service}.service --no-pager")
                    if success:
                        # Parse status for key information
                        lines = stdout.split('\n')
                        active_status = "unknown"
                        
                        for line in lines:
                            if 'Active:' in line:
                                active_status = line.strip()
                                break
                        
                        service_status[service] = {
                            "exists": True,
                            "active_status": active_status
                        }
                else:
                    service_status[service] = {"exists": False}
            
            status["via_services"] = service_status
            
            print(f"   ✅ Device status retrieved successfully")
            
            return status
            
        except Exception as e:
            print(f"   ❌ Failed to get device status: {e}")
            return {
                "connected": False,
                "error": str(e),
                "device_type": "VIA Linux",
                "persona_name": self.persona_name
            }
