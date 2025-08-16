#!/usr/bin/env python3
"""
Comprehensive test script for SAE Client core services.
Tests all implemented functionality to ensure everything works together.
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_imports():
    """Test that all core services can be imported."""
    print("Testing imports...")
    
    try:
        from src.config import config_manager, config
        print("✓ Config imported successfully")
    except Exception as e:
        print(f"✗ Config import failed: {e}")
        return False
    
    try:
        from src.services.key_service import key_service
        print("✓ Key service imported successfully")
    except Exception as e:
        print(f"✗ Key service import failed: {e}")
        return False
    
    try:
        from src.services.storage_service import storage_service
        print("✓ Storage service imported successfully")
    except Exception as e:
        print(f"✗ Storage service import failed: {e}")
        return False
    
    try:
        from src.api.auth import auth_service
        print("✓ Auth service imported successfully")
    except Exception as e:
        print(f"✗ Auth service import failed: {e}")
        return False
    
    try:
        from src.utils.crypto import crypto_utils
        print("✓ Crypto utils imported successfully")
    except Exception as e:
        print(f"✗ Crypto utils import failed: {e}")
        return False
    
    return True

def test_crypto_utils():
    """Test cryptographic utilities."""
    print("\nTesting cryptographic utilities...")
    
    from src.utils.crypto import crypto_utils
    
    try:
        # Test random key generation
        key = crypto_utils.generate_random_key(256)
        assert len(key) == 32, f"Expected 32 bytes, got {len(key)}"
        print("✓ Random key generation works")
        
        # Test key material generation
        aes_key = crypto_utils.generate_key_material("AES", 256)
        assert 'key_material' in aes_key
        assert aes_key['key_size'] == 256
        print("✓ AES key material generation works")
        
        # Test data encryption/decryption
        test_data = b"Hello, SAE Client!"
        encrypted = crypto_utils.encrypt_data(test_data, key)
        decrypted = crypto_utils.decrypt_data(encrypted, key)
        assert decrypted == test_data
        print("✓ Data encryption/decryption works")
        
        # Test hashing
        hash_value = crypto_utils.hash_data(test_data, "SHA-256")
        assert len(hash_value) == 64  # SHA-256 hex length
        print("✓ Data hashing works")
        
        # Test key validation
        key_material = aes_key['key_material']
        assert crypto_utils.validate_key_material(key_material)
        print("✓ Key validation works")
        
        return True
        
    except Exception as e:
        print(f"✗ Crypto utils test failed: {e}")
        return False

def test_storage_service():
    """Test storage service functionality."""
    print("\nTesting storage service...")
    
    from src.services.storage_service import storage_service
    from src.models.api_models import LocalKey, KeyType, KeyStatus
    from datetime import datetime, timedelta
    
    try:
        # Test configuration storage
        test_config = {"test_key": "test_value", "number": 42}
        assert storage_service.save_configuration("test_config", test_config)
        loaded_config = storage_service.load_configuration("test_config")
        assert loaded_config == test_config
        print("✓ Configuration storage works")
        
        # Test key storage
        test_key = LocalKey(
            key_id="test_key_001",
            key_type=KeyType.ENCRYPTION,
            key_material="dGVzdF9rZXlfbWF0ZXJpYWw=",  # base64 encoded
            key_size=256,
            source="test",
            creation_time=datetime.now(),
            expiry_time=datetime.now() + timedelta(hours=1),
            status=KeyStatus.AVAILABLE,
            metadata={"test": True}
        )
        
        assert storage_service.save_key(test_key)
        loaded_key = storage_service.load_key("test_key_001")
        assert loaded_key is not None
        assert loaded_key.key_id == test_key.key_id
        print("✓ Key storage works")
        
        # Test key deletion
        assert storage_service.delete_key("test_key_001")
        assert storage_service.load_key("test_key_001") is None
        print("✓ Key deletion works")
        
        # Test statistics
        stats = storage_service.get_storage_statistics()
        assert 'total_keys' in stats
        print("✓ Storage statistics work")
        
        return True
        
    except Exception as e:
        print(f"✗ Storage service test failed: {e}")
        return False

def test_key_service():
    """Test key management service."""
    print("\nTesting key management service...")
    
    from src.services.key_service import key_service
    from src.models.api_models import KeyType, KeyStatus
    from datetime import datetime, timedelta
    
    try:
        # Test key statistics
        stats = key_service.get_key_statistics()
        assert isinstance(stats, dict)
        assert 'total_keys' in stats
        print("✓ Key statistics work")
        
        # Test key storage from master (simulated)
        key_data = {
            'key_type': 'encryption',
            'key_material': 'bWFzdGVyX2tleV9tYXRlcmlhbA==',  # base64 encoded
            'key_size': 256,
            'creation_time': datetime.now().isoformat(),
            'expiry_time': (datetime.now() + timedelta(hours=1)).isoformat()
        }
        
        stored_key = key_service.store_key_from_master("master_key_001", key_data, "MASTER_001")
        assert stored_key.key_id == "master_key_001"
        assert stored_key.source == "master:MASTER_001"
        print("✓ Key storage from master works")
        
        # Test key retrieval
        retrieved_key = key_service.get_key("master_key_001")
        assert retrieved_key is not None
        assert retrieved_key.key_id == "master_key_001"
        print("✓ Key retrieval works")
        
        # Test available keys
        available_keys = key_service.get_available_keys(KeyType.ENCRYPTION)
        assert len(available_keys) >= 1
        print("✓ Available keys filtering works")
        
        # Test key usage
        used_key = key_service.use_key("master_key_001")
        assert used_key.status == KeyStatus.USED
        print("✓ Key usage tracking works")
        
        # Test key export
        exported_data = key_service.export_key_data("master_key_001")
        assert 'key_id' in exported_data
        assert exported_data['key_id'] == "master_key_001"
        print("✓ Key export works")
        
        # Test key deletion
        assert key_service.delete_key("master_key_001")
        assert key_service.get_key("master_key_001") is None
        print("✓ Key deletion works")
        
        return True
        
    except Exception as e:
        print(f"✗ Key service test failed: {e}")
        return False

def test_auth_service():
    """Test authentication service."""
    print("\nTesting authentication service...")
    
    from src.api.auth import auth_service
    
    try:
        # Test certificate file checking
        cert_status = auth_service.check_certificate_files()
        assert isinstance(cert_status, dict)
        assert 'sae_cert' in cert_status
        print("✓ Certificate file checking works")
        
        # Test certificate paths
        cert_paths = auth_service.get_certificate_paths()
        assert isinstance(cert_paths, dict)
        assert 'sae_cert' in cert_paths
        print("✓ Certificate paths work")
        
        # Test SAE identity (without certificates)
        identity = auth_service.get_sae_identity()
        assert 'sae_id' in identity
        print("✓ SAE identity works")
        
        # Test key pair generation
        private_key, public_key = auth_service.generate_key_pair(2048)
        assert private_key is not None
        assert public_key is not None
        print("✓ Key pair generation works")
        
        # Test self-signed certificate creation
        cert, key = auth_service.create_self_signed_certificate("test.sae.local", 30)
        assert cert is not None
        assert key is not None
        print("✓ Self-signed certificate creation works")
        
        return True
        
    except Exception as e:
        print(f"✗ Auth service test failed: {e}")
        return False

def test_integration():
    """Test integration between services."""
    print("\nTesting service integration...")
    
    from src.services.key_service import key_service
    from src.services.storage_service import storage_service
    from src.utils.crypto import crypto_utils
    from src.models.api_models import KeyType, KeyStatus
    from datetime import datetime, timedelta
    
    try:
        # Generate a key using crypto utils
        key_material = crypto_utils.generate_key_material("AES", 256)
        
        # Store it using key service
        key_data = {
            'key_type': 'encryption',
            'key_material': key_material['key_material'],
            'key_size': key_material['key_size'],
            'creation_time': datetime.now().isoformat(),
            'expiry_time': (datetime.now() + timedelta(hours=1)).isoformat()
        }
        
        stored_key = key_service.store_key_from_master("integration_test_key", key_data, "TEST_MASTER")
        
        # Verify it's stored in storage service
        storage_key = storage_service.load_key("integration_test_key")
        assert storage_key is not None
        assert storage_key.key_id == "integration_test_key"
        
        # Test key validation
        assert crypto_utils.validate_key_material(stored_key.key_material)
        
        # Clean up
        key_service.delete_key("integration_test_key")
        
        print("✓ Service integration works")
        return True
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("SAE Client Core Services Test Suite")
    print("=" * 50)
    
    tests = [
        ("Import Tests", test_imports),
        ("Cryptographic Utilities", test_crypto_utils),
        ("Storage Service", test_storage_service),
        ("Key Management Service", test_key_service),
        ("Authentication Service", test_auth_service),
        ("Service Integration", test_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"✓ {test_name} PASSED")
            else:
                print(f"✗ {test_name} FAILED")
        except Exception as e:
            print(f"✗ {test_name} FAILED with exception: {e}")
    
    print(f"\n{'='*50}")
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! SAE Client core services are working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
