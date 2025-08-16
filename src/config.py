"""
Configuration management for SAE Client.
Handles environment variables, certificate paths, and application settings.
"""

import os
import logging
from pathlib import Path
from typing import Optional
from pydantic import BaseSettings, Field


class SAEConfig(BaseSettings):
    """Configuration settings for SAE Client."""
    
    # SAE Identity
    sae_id: str = Field(default="SAE_001", description="SAE identifier")
    sae_mode: str = Field(default="master", description="SAE mode: master or slave")
    
    # KME Server Configuration
    kme_host: str = Field(default="localhost", description="KME server host")
    kme_port: int = Field(default=443, description="KME server port")
    kme_base_url: str = Field(default="https://localhost:443", description="KME server base URL")
    
    # Certificate Configuration
    sae_cert_path: str = Field(default="./certs/sae/sae.crt", description="SAE certificate path")
    sae_key_path: str = Field(default="./certs/sae/sae.key", description="SAE private key path")
    ca_cert_path: str = Field(default="./certs/ca/ca.crt", description="CA certificate path")
    
    # Local Storage
    data_dir: str = Field(default="./data", description="Data directory")
    logs_dir: str = Field(default="./logs", description="Logs directory")
    keys_file: str = Field(default="./data/keys.json", description="Keys storage file")
    
    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="./logs/sae_client.log", description="Log file path")
    
    # Network Settings
    timeout: int = Field(default=30, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    
    # Master/Slave Settings
    master_slave_port: int = Field(default=8080, description="Master/Slave communication port")
    notification_timeout: int = Field(default=10, description="Notification timeout in seconds")
    
    class Config:
        env_file = ".env"
        env_prefix = "SAE_"
        case_sensitive = False


class ConfigManager:
    """Manages SAE client configuration."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration manager."""
        self.config = SAEConfig()
        self.config_file = config_file or ".env"
        self._setup_logging()
        self._validate_paths()
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        
        # Create logs directory if it doesn't exist
        log_dir = Path(self.config.logs_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("SAE Client configuration initialized")
    
    def _validate_paths(self):
        """Validate and create necessary directories."""
        paths_to_create = [
            self.config.data_dir,
            self.config.logs_dir,
            Path(self.config.sae_cert_path).parent,
            Path(self.config.sae_key_path).parent,
            Path(self.config.ca_cert_path).parent,
        ]
        
        for path in paths_to_create:
            Path(path).mkdir(parents=True, exist_ok=True)
        
        self.logger.info("Directory structure validated")
    
    def get_kme_url(self, endpoint: str = "") -> str:
        """Get full KME URL for given endpoint."""
        base = self.config.kme_base_url.rstrip('/')
        endpoint = endpoint.lstrip('/')
        return f"{base}/{endpoint}" if endpoint else base
    
    def get_cert_paths(self) -> dict:
        """Get certificate paths as dictionary."""
        return {
            'sae_cert': self.config.sae_cert_path,
            'sae_key': self.config.sae_key_path,
            'ca_cert': self.config.ca_cert_path,
        }
    
    def is_master_mode(self) -> bool:
        """Check if SAE is in master mode."""
        return self.config.sae_mode.lower() == "master"
    
    def is_slave_mode(self) -> bool:
        """Check if SAE is in slave mode."""
        return self.config.sae_mode.lower() == "slave"
    
    def update_config(self, **kwargs):
        """Update configuration values."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                self.logger.info(f"Updated config: {key} = {value}")
    
    def save_to_env(self):
        """Save current configuration to .env file."""
        env_content = []
        for field_name, field in self.config.__fields__.items():
            value = getattr(self.config, field_name)
            env_content.append(f"SAE_{field_name.upper()}={value}")
        
        with open(self.config_file, 'w') as f:
            f.write('\n'.join(env_content))
        
        self.logger.info(f"Configuration saved to {self.config_file}")


# Global configuration instance
config_manager = ConfigManager()
config = config_manager.config
logger = config_manager.logger
