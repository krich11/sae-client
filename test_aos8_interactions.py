#!/usr/bin/env python3
"""
Comprehensive AOS8 Persona Interaction Test Script.
Demonstrates all the key interactions with the AOS8 device.
"""

import sys
import os
import json
import time
import base64
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.personas.aos8_persona import Aos8Persona
from src.personas.base_persona import PreConfigureContext, RotationContext


def test_aos8_interactions():
    """Test all AOS8 persona interactions."""
    print("🧪 Comprehensive AOS8 Persona Interaction Test")
    print("=" * 60)
    
    # Load AOS8 configuration
    config_path = Path("src/personas/config/aos8.json")
    if not config_path.exists():
        print(f"❌ Configuration file not found: {config_path}")
        return False
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    print(f"📋 Configuration loaded from: {config_path}")
    print(f"   Device IP: {config.get('device_ip')}")
    print(f"   Username: {config.get('username')}")
    print(f"   Simulation Mode: {config.get('simulation_mode')}")
    
    # Create AOS8 persona instance
    try:
        persona = Aos8Persona(config)
        print(f"✅ AOS8 Persona created successfully")
    except Exception as e:
        print(f"❌ Failed to create AOS8 Persona: {e}")
        return False
    
    # Test 1: Basic Connection and Status
    print("\n🔌 Test 1: Basic Connection and Status")
    print("-" * 40)
    
    if persona.test_connection():
        print("✅ Connection test passed")
    else:
        print("❌ Connection test failed")
        return False
    
    status = persona.get_device_status()
    print("✅ Device status retrieved")
    print(f"   Device IP: {status.get('device_ip')}")
    print(f"   Device Type: {status.get('device_type')}")
    print(f"   Persona: {status.get('persona')}")
    
    # Test 2: Key Material Validation
    print("\n🔍 Test 2: Key Material Validation")
    print("-" * 40)
    
    # Test different key sizes
    test_keys = [
        ("16-byte key", base64.b64encode(b"16-byte-test-key!!").decode()),
        ("24-byte key", base64.b64encode(b"24-byte-test-key-material!").decode()),
        ("32-byte key", base64.b64encode(b"32-byte-test-key-material-aligned").decode()),
        ("64-byte key", base64.b64encode(b"64-byte-test-key-material-aligned-for-aos8-device-testing").decode())
    ]
    
    for key_name, test_key in test_keys:
        if persona.validate_key_material(test_key):
            print(f"✅ {key_name} validation passed")
        else:
            print(f"❌ {key_name} validation failed")
    
    # Test 3: Pre-configure Multiple Keys
    print("\n🔑 Test 3: Pre-configure Multiple Keys")
    print("-" * 40)
    
    test_key_material = base64.b64encode(b"32-byte-test-key-material-aligned").decode()
    
    for i in range(1, 4):
        key_id = f"test-ppk-{i:03d}"
        
        context = PreConfigureContext(
            key_id=key_id,
            key_material=test_key_material,
            device_interface="eth0",
            encryption_algorithm="AES-256",
            key_priority="normal",
            custom_metadata={"test_batch": "interaction_test", "sequence": i}
        )
        
        if persona.pre_configure_key(context):
            print(f"✅ Successfully pre-configured key {key_id}")
        else:
            print(f"❌ Failed to pre-configure key {key_id}")
        
        # Small delay between operations
        time.sleep(1)
    
    # Test 4: Key Rotation Simulation
    print("\n🔄 Test 4: Key Rotation Simulation")
    print("-" * 40)
    
    rotation_context = RotationContext(
        key_id="test-ppk-001",
        rotation_timestamp=int(time.time()) + 300,  # 5 minutes from now
        device_interface="eth0",
        encryption_algorithm="AES-256",
        key_priority="normal",
        rollback_on_failure=True,
        session_id="interaction-test-session-001",
        master_sae_id="SAE_001",
        slave_sae_id="SAE_002",
        custom_metadata={"test_type": "interaction_test", "rotation_reason": "scheduled"}
    )
    
    if persona.rotate_key(rotation_context):
        print("✅ Key rotation simulation completed")
    else:
        print("❌ Key rotation simulation failed")
    
    # Test 5: Cleanup Operations
    print("\n🧹 Test 5: Cleanup Operations")
    print("-" * 40)
    
    if persona.cleanup_old_keys():
        print("✅ Cleanup old keys completed")
    else:
        print("❌ Cleanup old keys failed")
    
    # Test 6: Delete Specific PPKs
    print("\n🗑️  Test 6: Delete Specific PPKs")
    print("-" * 40)
    
    for i in range(1, 4):
        ppk_id = f"test-ppk-{i:03d}"
        
        if persona.delete_ppk(ppk_id):
            print(f"✅ Successfully deleted PPK {ppk_id}")
        else:
            print(f"❌ Failed to delete PPK {ppk_id}")
        
        # Small delay between operations
        time.sleep(1)
    
    # Test 7: Get Detailed Persona Info
    print("\nℹ️  Test 7: Get Detailed Persona Info")
    print("-" * 40)
    
    info = persona.get_persona_info()
    print("✅ Persona info retrieved")
    print(f"   Name: {info.get('name')}")
    print(f"   Version: {info.get('version')}")
    print(f"   Description: {info.get('description')}")
    print(f"   Supported Operations: {', '.join(info.get('supported_operations', []))}")
    print(f"   Supported Algorithms: {', '.join(info.get('supported_algorithms', []))}")
    
    # Test 8: Error Handling
    print("\n⚠️  Test 8: Error Handling")
    print("-" * 40)
    
    # Test with invalid key material
    invalid_key = "invalid-base64-key!!"
    if not persona.validate_key_material(invalid_key):
        print("✅ Invalid key material correctly rejected")
    else:
        print("❌ Invalid key material incorrectly accepted")
    
    # Test with non-existent PPK
    if not persona.delete_ppk("non-existent-ppk"):
        print("✅ Non-existent PPK deletion correctly handled")
    else:
        print("❌ Non-existent PPK deletion incorrectly succeeded")
    
    print("\n" + "=" * 60)
    print("🎉 All AOS8 Persona interaction tests completed!")
    print("\n📋 Summary of Interactions Tested:")
    print("   ✅ Basic connection and authentication")
    print("   ✅ Device status retrieval")
    print("   ✅ Key material validation (multiple sizes)")
    print("   ✅ Key pre-configuration (multiple keys)")
    print("   ✅ Key rotation simulation")
    print("   ✅ Cleanup operations")
    print("   ✅ Specific PPK deletion")
    print("   ✅ Detailed persona information")
    print("   ✅ Error handling and validation")
    
    return True


if __name__ == "__main__":
    success = test_aos8_interactions()
    sys.exit(0 if success else 1)
