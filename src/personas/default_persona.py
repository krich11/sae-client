"""
Default Persona - Message Exchange Only.
This persona handles message exchange but doesn't perform actual device operations.
Useful for testing or when no specific device integration is needed.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional

from .base_persona import BasePersona, RotationContext, PreConfigureContext


class DefaultPersona(BasePersona):
    """Default persona that only handles message exchange without device operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize default persona."""
        self.persona_name = "default"
        super().__init__(config)
        self.version = "1.0.0"
        self.description = "Default persona - message exchange only"
        self.logger = logging.getLogger(__name__)
        
        self.logger.info("Default Persona Initialized")
        self.logger.info("This persona only handles message exchange - no device operations will be performed")
    
    def _validate_config(self):
        """Validate default persona configuration."""
        # Default persona doesn't require any specific configuration validation
        # since it doesn't perform actual device operations
        self.logger.info("Default persona: Configuration validation completed (no validation required)")
    
    def test_connection(self) -> bool:
        """
        Test connection (always succeeds for default persona).
        
        Returns:
            bool: Always True
        """
        self.logger.info("Default persona: Connection test requested (always succeeds)")
        return True
    
    def pre_configure_key(self, context: PreConfigureContext) -> bool:
        """
        Pre-configure key (logs operation but doesn't perform it).
        
        Args:
            context: Pre-configure context
            
        Returns:
            bool: Always True (simulated success)
        """
        self.logger.info("Default persona: Pre-configure key requested")
        self.logger.info(f"  Key ID: {context.key_id}")
        self.logger.info(f"  Device Interface: {context.device_interface}")
        self.logger.info(f"  Encryption Algorithm: {context.encryption_algorithm}")
        self.logger.info("  Operation: SIMULATED (no actual device operation)")
        return True
    
    def rotate_key(self, context: RotationContext) -> bool:
        """
        Rotate key (logs operation but doesn't perform it).
        
        Args:
            context: Rotation context
            
        Returns:
            bool: Always True (simulated success)
        """
        self.logger.info("Default persona: Key rotation requested")
        self.logger.info(f"  Key ID: {context.key_id}")
        self.logger.info(f"  Rotation Timestamp: {context.rotation_timestamp}")
        self.logger.info(f"  Session ID: {context.session_id}")
        self.logger.info(f"  Master SAE: {context.master_sae_id}")
        self.logger.info(f"  Slave SAE: {context.slave_sae_id}")
        self.logger.info("  Operation: SIMULATED (no actual device operation)")
        return True
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete key (logs operation but doesn't perform it).
        
        Args:
            key_id: Key ID to delete
            
        Returns:
            bool: Always True (simulated success)
        """
        self.logger.info("Default persona: Delete key requested")
        self.logger.info(f"  Key ID: {key_id}")
        self.logger.info("  Operation: SIMULATED (no actual device operation)")
        return True
    
    def cleanup_old_keys(self) -> bool:
        """
        Cleanup old keys (logs operation but doesn't perform it).
        
        Returns:
            bool: Always True (simulated success)
        """
        self.logger.info("Default persona: Cleanup old keys requested")
        self.logger.info("  Operation: SIMULATED (no actual device operation)")
        return True
    
    def get_device_status(self) -> Dict[str, Any]:
        """
        Get device status (returns simulated status).
        
        Returns:
            Dict containing simulated device status
        """
        self.logger.info("Default persona: Get device status requested")
        
        return {
            "device_ip": "127.0.0.1",
            "device_type": "default",
            "persona": "Default",
            "version": self.version,
            "simulation_mode": True,
            "last_operation": datetime.now().strftime("%c"),
            "status": "simulated",
            "connected": True,
            "message": "Default persona - no actual device operations performed"
        }
    
    def validate_key_material(self, key_material: str) -> bool:
        """
        Validate key material (basic validation only).
        
        Args:
            key_material: Base64-encoded key material
            
        Returns:
            bool: True if key material format is valid
        """
        self.logger.info("Default persona: Key material validation requested")
        
        try:
            import base64
            decoded = base64.b64decode(key_material)
            if len(decoded) < 8 or len(decoded) > 64:
                self.logger.warning(f"Key material size {len(decoded)} bytes is outside expected range")
                return False
            
            self.logger.info(f"Key material validation: PASSED (size: {len(decoded)} bytes)")
            return True
        except Exception as e:
            self.logger.error(f"Key material validation failed: {e}")
            return False
