# SAE-to-SAE Key Synchronization Plan

## Overview

This document outlines the implementation plan for SAE-to-SAE key synchronization using UDP with signed messages. This system allows SAE A (master) to notify SAE B (slave) of available key IDs and coordinate key rotation timing to minimize downtime.

## Architecture

### Communication Protocol
- **Protocol**: UDP with signed messages
- **Authentication**: Digital signatures using SAE private keys
- **Message Format**: JSON payloads with cryptographic signatures
- **State Management**: Simple state machine with minimal state

### Key Components
1. **UDP Message Handler**: Listens for incoming notifications
2. **Message Signer/Verifier**: Handles cryptographic signatures
3. **State Machine**: Manages synchronization states
4. **Timer Manager**: Coordinates key rotation timing
5. **Persona Plugin System**: Device-specific implementations

## Message Flow

### Phase 1: Key Notification
```
SAE A (Master) → SAE B (Slave)
Payload: {
  "message_type": "key_notification",
  "key_ids": ["key1", "key2", "key3"],
  "rotation_timestamp": 1640995200,  // 5 minutes in future
  "master_sae_id": "SAE_A",
  "slave_sae_id": "SAE_B",
  "message_id": "uuid-1234",
  "timestamp": 1640994900
}
Signature: RSA-SHA256(sa_a_private_key, payload)
```

### Phase 2: Key Request & Selection
```
SAE B (Slave) → KME
Request: ETSI "Get key with key IDs" for received key_ids
Response: Key material for selected keys
```

### Phase 3: Acknowledgment
```
SAE B (Slave) → SAE A (Master)
Payload: {
  "message_type": "key_acknowledgment",
  "original_message_id": "uuid-1234",
  "selected_key_id": "key2",  // Optional
  "status": "ready",
  "slave_sae_id": "SAE_B",
  "master_sae_id": "SAE_A",
  "timestamp": 1640994950
}
Signature: RSA-SHA256(sa_b_private_key, payload)
```

### Phase 4: Final Confirmation
```
SAE A (Master) → SAE B (Slave)
Payload: {
  "message_type": "rotation_confirmation",
  "original_message_id": "uuid-1234",
  "rotation_timestamp": 1640995200,
  "master_sae_id": "SAE_A",
  "slave_sae_id": "SAE_B",
  "timestamp": 1640994960
}
Signature: RSA-SHA256(sa_a_private_key, payload)
```

### Phase 5: Key Rotation (Synchronized)
```
Both SAEs execute key rotation at rotation_timestamp
- Pre-configure new keys in devices
- Rotate keys at exact timestamp
- Clean up old keys
```

## Implementation Plan

### 1. Core Infrastructure

#### 1.1 UDP Message Handler
- **File**: `src/services/udp_service.py`
- **Features**:
  - UDP socket listener
  - Message parsing and validation
  - Signature verification
  - State machine integration

#### 1.2 Message Signing/Verification
- **File**: `src/utils/message_signer.py`
- **Features**:
  - RSA-SHA256 signing
  - Signature verification
  - Message integrity checks

#### 1.3 State Machine
- **File**: `src/services/sync_state_machine.py`
- **States**:
  - `IDLE`: Waiting for notifications
  - `NOTIFIED`: Received key notification
  - `KEYS_REQUESTED`: Requested keys from KME
  - `ACKNOWLEDGED`: Sent acknowledgment
  - `CONFIRMED`: Received final confirmation
  - `ROTATING`: Executing key rotation

### 2. Persona Plugin System

#### 2.1 Plugin Interface
- **File**: `src/personas/base_persona.py`
- **Interface Methods**:
  - `pre_configure_key(key_id, key_material)`
  - `rotate_key(key_id, rotation_timestamp)`
  - `cleanup_old_keys()`
  - `get_device_status()`

#### 2.2 Example Personas
- **File**: `src/personas/macsec_persona.py`
- **File**: `src/personas/ipsec_persona.py`
- **File**: `src/personas/custom_persona.py`

### 3. Configuration

#### 3.1 SAE Configuration
```python
# .env additions
SAE_UDP_PORT=5000
SAE_SYNC_TIMEOUT=30
SAE_ROTATION_ADVANCE_TIME=300  # 5 minutes
SAE_DEVICE_PERSONA=macsec
```

#### 3.2 Device Configuration
```python
# personas/config/macsec_config.json
{
  "interface": "eth0",
  "key_algorithm": "aes-gcm-256",
  "pre_config_time": 60,
  "cleanup_delay": 30
}
```

### 4. CLI Commands

#### 4.1 Master Commands
```bash
# Notify slave of available keys
python sae_client.py notify-slave-sync --slave-id SAE_B --key-ids "key1,key2,key3"

# Check synchronization status
python sae_client.py sync-status
```

#### 4.2 Slave Commands
```bash
# Start UDP listener
python sae_client.py start-sync-listener

# Check received notifications
python sae_client.py list-notifications
```

### 5. Message Security

#### 5.1 Signature Verification
- Verify sender SAE ID matches certificate
- Check message timestamp (reject old messages)
- Validate message format and required fields
- Verify cryptographic signature

#### 5.2 Replay Protection
- Include message_id in all messages
- Track processed message_ids
- Reject duplicate message_ids
- Use timestamps for message freshness

## Implementation Phases

### Phase 1: Core Infrastructure
1. UDP message handler
2. Message signing/verification
3. Basic state machine
4. Configuration system

### Phase 2: Persona System
1. Base persona interface
2. Example persona implementations
3. Plugin loading system
4. Device configuration

### Phase 3: Integration
1. CLI commands
2. Integration with existing SAE client
3. Testing and validation
4. Documentation

### Phase 4: Advanced Features
1. Multiple slave support
2. Key rotation scheduling
3. Monitoring and logging
4. Error recovery

## Security Considerations

### 1. Message Authentication
- All messages must be signed with SAE private keys
- Verify signatures using SAE public keys
- Reject unsigned or invalidly signed messages

### 2. Message Integrity
- Include message_id to prevent replay attacks
- Use timestamps to ensure message freshness
- Validate message format and required fields

### 3. Network Security
- Consider using VPN or secure network
- Implement rate limiting on UDP messages
- Log all message activities for audit

### 4. Key Management
- Secure storage of SAE private keys
- Regular key rotation for SAE certificates
- Proper cleanup of old keys

## Testing Strategy

### 1. Unit Tests
- Message signing/verification
- State machine transitions
- Persona plugin interface

### 2. Integration Tests
- End-to-end message flow
- KME integration
- Device persona integration

### 3. Security Tests
- Signature verification
- Replay attack prevention
- Message tampering detection

### 4. Performance Tests
- UDP message throughput
- Key rotation timing accuracy
- Memory usage under load

## Monitoring and Logging

### 1. Message Logging
- Log all incoming/outgoing messages
- Record signature verification results
- Track state machine transitions

### 2. Performance Monitoring
- UDP message latency
- Key rotation timing accuracy
- Device configuration success rates

### 3. Error Tracking
- Failed signature verifications
- State machine errors
- Device persona errors

## Future Enhancements

### 1. Multiple Slave Support
- Broadcast notifications to multiple slaves
- Coordinated key rotation across multiple devices
- Load balancing across multiple paths

### 2. Advanced Scheduling
- Recurring key rotation schedules
- Dynamic rotation timing based on usage
- Predictive key rotation

### 3. Monitoring Integration
- SNMP integration for device monitoring
- Prometheus metrics for key rotation
- Grafana dashboards for visualization
