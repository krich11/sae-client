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
        print(f"   Creating VIA PPK.xml file")
        
        try:
            # Get SAE configuration (master SAE)
            from src.config import config_manager
            sae_ip = config_manager.config.sae_ip  # Master SAE IP
            
            # Generate random temporary file name
            temp_file = f"/tmp/{uuid.uuid4().hex}.tmp"
            
            # Create the PPK.xml content
            ppk_xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<PPK>
    <name>{sae_ip}</name>
    <PPK_ID>{context.key_id}</PPK_ID>
    <PPK_VAL>{context.key_material}</PPK_VAL>
</PPK>'''
            
            # Write to temporary file first
            print(f"   📝 Writing to temporary file: {temp_file}")
            success, stdout, stderr = self._execute_shell_command(f"cat > {temp_file} << 'EOF'\n{ppk_xml_content}\nEOF")
            
            if not success:
                print(f"   ❌ Failed to write temporary file: {stderr}")
                return False
            
            # Move to final location with sudo
            ppk_file = "/usr/share/via/PPK.xml"
            print(f"   🔄 Moving to final location: {ppk_file}")
            success, stdout, stderr = self._execute_shell_command(f"sudo mv {temp_file} {ppk_file}")
            
            if not success:
                print(f"   ❌ Failed to move file to final location: {stderr}")
                # Clean up temp file
                self._execute_shell_command(f"rm -f {temp_file}")
                return False
            
            # Set proper permissions
            print(f"   🔐 Setting file permissions")
            success, stdout, stderr = self._execute_shell_command(f"sudo chmod 644 {ppk_file}")
            
            if not success:
                print(f"   ⚠️  Warning: Failed to set permissions: {stderr}")
            
            print(f"   ✅ PPK.xml file created successfully at {ppk_file}")
            return True
            
        except Exception as e:
            print(f"   ❌ PPK.xml creation failed: {e}")
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
        
        try:
            # Execute rotation commands from config
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
                print(f"   ℹ️  No rotation commands configured")
            
            print(f"   ✅ Key rotation completed successfully")
            return True
            
        except Exception as e:
            print(f"   ❌ Key rotation failed: {e}")
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
