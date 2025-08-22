"""
VIA Linux Persona Implementation.
Specialized Linux Shell persona for VIA PPK XML file generation.
Handles key management by creating formatted PPK.xml files for VIA systems.
"""

from .linux_shell_persona import LinuxShellPersona


class ViaLinuxPersona(LinuxShellPersona):
    """VIA Linux persona for PPK XML file generation."""
    
    def __init__(self, config: dict):
        """Initialize VIA Linux persona."""
        # Set persona attributes before calling parent init
        self.persona_name = "VIA Linux"
        self.version = "1.0.0"
        self.description = "VIA Linux PPK XML File Generation Persona (Master SAE Only)"
        
        # Force PPK format for VIA
        config['ppk_format'] = True
        
        super().__init__(config)
        
        # Only show initialization details in debug mode
        if self.config.get('debug_mode', False):
            print(f"🔧 {self.persona_name} Persona Initialized")
            print(f"   Specialized for VIA PPK XML generation")
            print(f"   Master SAE only")
            print(f"   PPK Format: Enabled")
