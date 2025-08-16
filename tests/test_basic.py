"""
Basic tests for SAE Client.
Tests core functionality and imports.
"""

import sys
import os
import pytest
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_imports():
    """Test that all modules can be imported."""
    try:
        from config import config_manager, config
        from models.api_models import KeyType, KeyStatus, LocalKey
        from api.client import kme_client
        from services.notification_service import master_notification_service, slave_notification_service
        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")


def test_config_loading():
    """Test configuration loading."""
    from config import config_manager
    
    # Test basic config properties
    assert config_manager.config.sae_id == "SAE_001"
    assert config_manager.config.sae_mode == "master"
    assert config_manager.config.kme_host == "localhost"
    assert config_manager.config.kme_port == 443


def test_api_models():
    """Test API model creation."""
    from models.api_models import KeyType, KeyStatus, LocalKey
    from datetime import datetime
    
    # Test key creation
    key = LocalKey(
        key_id="test_key_001",
        key_type=KeyType.ENCRYPTION,
        key_material="dGVzdF9rZXlfZGF0YQ==",  # base64 encoded
        key_size=256,
        source="test",
        creation_time=datetime.now(),
        status=KeyStatus.AVAILABLE
    )
    
    assert key.key_id == "test_key_001"
    assert key.key_type == KeyType.ENCRYPTION
    assert key.key_size == 256
    assert key.status == KeyStatus.AVAILABLE


def test_notification_services():
    """Test notification service initialization."""
    from services.notification_service import master_notification_service, slave_notification_service
    
    # Test service initialization
    assert master_notification_service is not None
    assert slave_notification_service is not None
    
    # Test callback registration
    assert 'key_available' in master_notification_service.notification_callbacks
    assert 'key_request' in master_notification_service.notification_callbacks


def test_master_mode_detection():
    """Test master mode detection."""
    from config import config_manager
    
    # Test mode detection
    assert config_manager.is_master_mode() == True
    assert config_manager.is_slave_mode() == False


def test_kme_client_initialization():
    """Test KME client initialization."""
    from api.client import kme_client
    
    # Test client initialization
    assert kme_client is not None
    assert hasattr(kme_client, 'get_status')
    assert hasattr(kme_client, 'request_encryption_keys')
    assert hasattr(kme_client, 'request_decryption_keys')


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
