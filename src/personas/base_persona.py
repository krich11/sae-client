"""
Base Persona Interface.
Defines the interface for device-specific key rotation implementations.
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class RotationContext:
    """Context for key rotation operations with flexible parameters."""
    key_id: str
    rotation_timestamp: int
    # Device-specific parameters
    device_interface: Optional[str] = None
    encryption_algorithm: str = "AES-256"
    key_priority: str = "normal"
    rollback_on_failure: bool = True
    # Notification parameters
    notification_url: Optional[str] = None
    notification_headers: Dict[str, str] = field(default_factory=dict)
    # Session information
    session_id: Optional[str] = None
    master_sae_id: Optional[str] = None
    slave_sae_id: Optional[str] = None
    # Custom metadata
    custom_metadata: Dict[str, Any] = field(default_factory=dict)
    # Timing parameters
    advance_warning_seconds: int = 30
    cleanup_delay_seconds: int = 60
    # Validation parameters
    validate_key_before_rotation: bool = True
    validate_device_after_rotation: bool = True


@dataclass
class PreConfigureContext:
    """Context for key pre-configuration operations."""
    key_id: str
    key_material: str
    device_interface: Optional[str] = None
    encryption_algorithm: str = "AES-256"
    key_priority: str = "normal"
    custom_metadata: Dict[str, Any] = field(default_factory=dict)


class BasePersona(ABC):
    """Base class for device persona implementations."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize persona with configuration.
        
        Args:
            config: Device-specific configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.device_status = "unknown"
        self._validate_config()
    
    @abstractmethod
    def _validate_config(self):
        """Validate persona-specific configuration."""
        pass
    
    @abstractmethod
    def pre_configure_key(self, context: PreConfigureContext) -> bool:
        """
        Pre-configure a key in the device.
        
        Args:
            context: PreConfigureContext containing key and device parameters
            
        Returns:
            bool: True if key was successfully pre-configured
        """
        # Debug logging for key pre-configuration
        if hasattr(self, 'config') and self.config.get('debug_mode', False):
            self.logger.info(f"PERSONA PRE-CONFIGURE KEY:")
            self.logger.info(f"  Persona: {self.__class__.__name__}")
            self.logger.info(f"  Key ID: {context.key_id}")
            self.logger.info(f"  Key Material Size: {len(context.key_material)} bytes")
            self.logger.info(f"  Key Material (first 32 chars): {context.key_material[:32]}...")
            self.logger.info(f"  Device Interface: {context.device_interface}")
            self.logger.info(f"  Encryption Algorithm: {context.encryption_algorithm}")
            self.logger.info(f"  Key Priority: {context.key_priority}")
            if context.custom_metadata:
                self.logger.info(f"  Custom Metadata: {context.custom_metadata}")
        
        pass
    
    @abstractmethod
    def rotate_key(self, context: RotationContext) -> bool:
        """
        Rotate to the specified key at the given timestamp.
        
        Args:
            context: RotationContext containing all rotation parameters
            
        Returns:
            bool: True if key rotation was successful
        """
        # Debug logging for key rotation
        if hasattr(self, 'config') and self.config.get('debug_mode', False):
            import time
            self.logger.info(f"PERSONA ROTATE KEY:")
            self.logger.info(f"  Persona: {self.__class__.__name__}")
            self.logger.info(f"  Key ID: {context.key_id}")
            self.logger.info(f"  Rotation Timestamp: {context.rotation_timestamp}")
            self.logger.info(f"  Rotation Time: {time.ctime(context.rotation_timestamp)}")
            self.logger.info(f"  Current Time: {time.ctime()}")
            self.logger.info(f"  Device Interface: {context.device_interface}")
            self.logger.info(f"  Encryption Algorithm: {context.encryption_algorithm}")
            self.logger.info(f"  Key Priority: {context.key_priority}")
            self.logger.info(f"  Rollback on Failure: {context.rollback_on_failure}")
            self.logger.info(f"  Session ID: {context.session_id}")
            self.logger.info(f"  Master SAE: {context.master_sae_id}")
            self.logger.info(f"  Slave SAE: {context.slave_sae_id}")
            if context.custom_metadata:
                self.logger.info(f"  Custom Metadata: {context.custom_metadata}")
        
        pass
    
    @abstractmethod
    def cleanup_old_keys(self) -> bool:
        """
        Clean up old/expired keys from the device.
        
        Returns:
            bool: True if cleanup was successful
        """
        pass
    
    @abstractmethod
    def get_device_status(self) -> Dict[str, Any]:
        """
        Get current device status.
        
        Returns:
            Dict containing device status information
        """
        pass
    
    def get_persona_info(self) -> Dict[str, Any]:
        """
        Get persona information.
        
        Returns:
            Dict containing persona information
        """
        return {
            "name": self.__class__.__name__,
            "version": getattr(self, 'version', '1.0.0'),
            "description": getattr(self, 'description', 'Base persona implementation'),
            "device_status": self.device_status,
            "config": self.config
        }
    
    def test_connection(self) -> bool:
        """
        Test connection to the device.
        
        Returns:
            bool: True if connection is successful
        """
        try:
            status = self.get_device_status()
            return status.get('connected', False)
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def validate_key_material(self, key_material: str) -> bool:
        """
        Validate key material format.
        
        Args:
            key_material: Base64-encoded key material
            
        Returns:
            bool: True if key material is valid
        """
        try:
            import base64
            # Try to decode the key material
            decoded = base64.b64decode(key_material)
            # Check if it's a reasonable size (8-64 bytes)
            if len(decoded) < 8 or len(decoded) > 64:
                self.logger.warning(f"Key material size {len(decoded)} bytes is outside expected range")
                return False
            
            # Debug logging for key validation
            if hasattr(self, 'config') and self.config.get('debug_mode', False):
                self.logger.info(f"PERSONA KEY VALIDATION:")
                self.logger.info(f"  Persona: {self.__class__.__name__}")
                self.logger.info(f"  Key Material Size: {len(key_material)} bytes")
                self.logger.info(f"  Decoded Size: {len(decoded)} bytes")
                self.logger.info(f"  Validation: PASSED")
            
            return True
        except Exception as e:
            self.logger.error(f"Key material validation failed: {e}")
            return False
    
    def log_operation(self, operation: str, key_id: str, status: str, details: Optional[str] = None):
        """
        Log a persona operation.
        
        Args:
            operation: Operation name (e.g., 'pre_configure', 'rotate', 'cleanup')
            key_id: Key ID involved in the operation
            status: Operation status ('success', 'failed', 'pending')
            details: Additional details about the operation
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "key_id": key_id,
            "status": status,
            "persona": self.__class__.__name__
        }
        
        if details:
            log_entry["details"] = details
        
        if status == "success":
            self.logger.info(f"Operation {operation} for key {key_id} completed successfully")
        elif status == "failed":
            self.logger.error(f"Operation {operation} for key {key_id} failed: {details}")
        else:
            self.logger.info(f"Operation {operation} for key {key_id}: {status}")
        
        # Store operation log if configured
        if hasattr(self, 'operation_log') and self.operation_log:
            self.operation_log.append(log_entry)


class PersonaManager:
    """Manages persona plugin loading and instantiation."""
    
    def __init__(self):
        """Initialize persona manager."""
        self.logger = logging.getLogger(__name__)
        self.personas: Dict[str, BasePersona] = {}
        self.persona_configs: Dict[str, Dict[str, Any]] = {}
        self._load_persona_configs()
    
    def _load_persona_configs(self):
        """Load persona configurations from config files."""
        try:
            config_dir = Path("personas/config")
            if config_dir.exists():
                for config_file in config_dir.glob("*.json"):
                    persona_name = config_file.stem
                    try:
                        import json
                        with open(config_file, 'r') as f:
                            config = json.load(f)
                        self.persona_configs[persona_name] = config
                        self.logger.info(f"Loaded config for persona: {persona_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to load config for persona {persona_name}: {e}")
            else:
                self.logger.info("No persona config directory found, using defaults")
        except Exception as e:
            self.logger.error(f"Error loading persona configs: {e}")
    
    def load_persona(self, persona_name: str) -> Optional[BasePersona]:
        """
        Load a persona plugin.
        
        Args:
            persona_name: Name of the persona to load
            
        Returns:
            BasePersona: Loaded persona instance, or None if loading failed
        """
        try:
            # Check if persona is already loaded
            if persona_name in self.personas:
                return self.personas[persona_name]
            
            # Get persona configuration
            config = self.persona_configs.get(persona_name, {})
            
            # Import persona module
            module_name = f"src.personas.{persona_name}_persona"
            try:
                module = __import__(module_name, fromlist=[f"{persona_name.title()}Persona"])
                persona_class = getattr(module, f"{persona_name.title()}Persona")
                
                # Create persona instance
                persona = persona_class(config)
                self.personas[persona_name] = persona
                
                self.logger.info(f"Successfully loaded persona: {persona_name}")
                return persona
                
            except ImportError:
                self.logger.warning(f"Persona module not found: {module_name}")
                return None
            except AttributeError:
                self.logger.warning(f"Persona class not found in module: {module_name}")
                return None
            except Exception as e:
                self.logger.error(f"Failed to instantiate persona {persona_name}: {e}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error loading persona {persona_name}: {e}")
            return None
    
    def get_persona(self, persona_name: str) -> Optional[BasePersona]:
        """
        Get a persona instance.
        
        Args:
            persona_name: Name of the persona
            
        Returns:
            BasePersona: Persona instance, or None if not found
        """
        return self.personas.get(persona_name)
    
    def list_personas(self) -> Dict[str, Dict[str, Any]]:
        """
        List all loaded personas.
        
        Returns:
            Dict containing information about loaded personas
        """
        persona_info = {}
        for name, persona in self.personas.items():
            persona_info[name] = persona.get_persona_info()
        return persona_info
    
    def unload_persona(self, persona_name: str) -> bool:
        """
        Unload a persona plugin.
        
        Args:
            persona_name: Name of the persona to unload
            
        Returns:
            bool: True if persona was unloaded successfully
        """
        try:
            if persona_name in self.personas:
                del self.personas[persona_name]
                self.logger.info(f"Unloaded persona: {persona_name}")
                return True
            else:
                self.logger.warning(f"Persona not found: {persona_name}")
                return False
        except Exception as e:
            self.logger.error(f"Error unloading persona {persona_name}: {e}")
            return False


# Global persona manager instance
persona_manager = PersonaManager()
