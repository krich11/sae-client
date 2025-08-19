# Persona System

The persona system provides a flexible, pluggable architecture for device-specific key management implementations.

## Overview

Personas are device-specific implementations that handle:
- Key pre-configuration
- Key rotation
- Key cleanup
- Device status monitoring
- Connection testing
- Key validation

## Example Persona

The `example_persona.py` demonstrates how to implement a persona with:
- **Flexible parameter passing** using context objects
- **Comprehensive logging** and status reporting
- **Simulation mode** for testing
- **Configuration management**
- **Error handling**

## Quick Start

### 1. Test the Example Persona

```bash
# Start interactive mode
python sae_client.py interactive

# List available personas
show personas

# Test the example persona
persona test example
```

### 2. Configure the Example Persona

Edit `src/personas/config/example.json`:
```json
{
    "device_name": "your-device-name",
    "simulation_mode": true,
    "operation_delay": 1.0,
    "default_interface": "eth0"
}
```

### 3. Use the Example Persona

Set in your `.env` file:
```bash
SAE_DEVICE_PERSONA=example
```

## Creating Your Own Persona

### 1. Create Persona File

Create `src/personas/yourdevice_persona.py`:

```python
from .base_persona import BasePersona, PreConfigureContext, RotationContext

class YourdevicePersona(BasePersona):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Your initialization code
    
    def _validate_config(self):
        # Validate your configuration
        pass
    
    def pre_configure_key(self, context: PreConfigureContext) -> bool:
        # Implement key pre-configuration
        print(f"Pre-configuring key {context.key_id}")
        return True
    
    def rotate_key(self, context: RotationContext) -> bool:
        # Implement key rotation
        print(f"Rotating to key {context.key_id}")
        return True
    
    def cleanup_old_keys(self) -> bool:
        # Implement key cleanup
        print("Cleaning up old keys")
        return True
    
    def get_device_status(self) -> Dict[str, Any]:
        # Return device status
        return {"status": "operational"}
```

### 2. Create Configuration File

Create `src/personas/config/yourdevice.json`:

```json
{
    "device_name": "your-device",
    "interface": "eth0",
    "algorithm": "AES-256",
    "custom_setting": "value"
}
```

### 3. Test Your Persona

```bash
# Test your persona
persona test yourdevice

# Use your persona
SAE_DEVICE_PERSONA=yourdevice
```

## Flexible Parameter Passing

The persona system uses context objects for flexible parameter passing:

### PreConfigureContext
```python
context = PreConfigureContext(
    key_id="abc123",
    key_material="base64-encoded-key",
    device_interface="eth0",
    encryption_algorithm="AES-256",
    key_priority="high",
    custom_metadata={"tunnel_id": "tunnel1"}
)
```

### RotationContext
```python
context = RotationContext(
    key_id="abc123",
    rotation_timestamp=1640995200,
    device_interface="eth0",
    encryption_algorithm="AES-256",
    key_priority="high",
    rollback_on_failure=True,
    notification_url="https://webhook.example.com/status",
    session_id="session123",
    master_sae_id="SAE_001",
    slave_sae_id="SAE_002",
    custom_metadata={"tunnel_id": "tunnel1", "vrf": "vrf1"}
)
```

## Available Parameters

### Device-Specific
- `device_interface`: Network interface name
- `encryption_algorithm`: Encryption algorithm (AES-256, ChaCha20, etc.)
- `key_priority`: Key priority (high, normal, low)
- `rollback_on_failure`: Enable rollback on failure

### Notification
- `notification_url`: Webhook URL for status updates
- `notification_headers`: HTTP headers for notifications

### Session
- `session_id`: Session identifier
- `master_sae_id`: Master SAE ID
- `slave_sae_id`: Slave SAE ID

### Custom
- `custom_metadata`: Dictionary for any additional data

### Timing
- `advance_warning_seconds`: Warning time before rotation
- `cleanup_delay_seconds`: Delay before cleanup

### Validation
- `validate_key_before_rotation`: Validate key before rotation
- `validate_device_after_rotation`: Validate device after rotation

## Best Practices

1. **Use the example persona as a template**
2. **Implement all required methods**
3. **Add comprehensive logging**
4. **Handle errors gracefully**
5. **Use configuration files for device-specific settings**
6. **Test thoroughly before deployment**
7. **Document your persona's requirements**

## Integration with SAE

The persona system integrates with the SAE client through:

1. **UDP Service**: Calls persona methods during key rotation
2. **CLI Commands**: `show personas`, `persona test`
3. **Configuration**: `SAE_DEVICE_PERSONA` environment variable
4. **State Machine**: Manages rotation timing and coordination

## Example Output

When using the example persona, you'll see detailed output like:

```
🔧 Example Persona Initialized
   Device: example-device-001
   Simulation Mode: True
   Operation Delay: 1.0s

🔄 Example Persona: Rotate Key
   Key ID: abc123
   Rotation Timestamp: 1640995200
   Rotation Time: Tue Jan 01 12:00:00 2022
   Device Interface: eth0
   Encryption Algorithm: AES-256
   Key Priority: high
   Rollback on Failure: True
   Session ID: session123
   Master SAE: SAE_001
   Slave SAE: SAE_002

   📝 Example key rotation steps:
     1. Validate current device state
     2. Check key availability
     3. Prepare new key for activation
     4. Execute key rotation command
     5. Verify rotation success
     6. Update device status
     7. Configure rollback mechanism

   ✅ Key rotation completed successfully
```
