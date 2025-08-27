# UDP Service Communications - Ping Pong Diagram

## Overview
This diagram shows the complete UDP communication flow between Master and Slave SAEs during key synchronization, rotation, and cleanup operations.

## Key Synchronization Flow

```
┌─────────────┐                                    ┌─────────────┐
│ Master SAE  │                                    │ Slave SAE   │
│             │                                    │             │
└──────┬──────┘                                    └──────┬──────┘
       │                                                   │
       │ 1. KEY_NOTIFICATION                              │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • key_ids: [key1, key2, ...]               │   │
       │ │ • rotation_timestamp: future_time           │   │
       │ │ • master_sae_id: "sae1"                    │   │
       │ │ • slave_sae_id: "sae2"                     │   │
       │ └─────────────────────────────────────────────┘   │
       │───────────────────────────────────────────────────>│
       │                                                   │
       │                                                   │ 2. Request keys from KME
       │                                                   │ (ETSI 'Get key with key IDs')
       │                                                   │
       │                                                   │ 3. Store keys locally
       │                                                   │
       │                                                   │ 4. Mark keys as ASSIGNED
       │                                                   │
       │ 5. KEY_ACKNOWLEDGMENT                             │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • original_message_id: (from step 1)       │   │
       │ │ • selected_key_id: "key1"                  │   │
       │ │ • status: "ready"                          │   │
       │ │ • master_sae_id: "sae2"                    │   │
       │ │ • slave_sae_id: "sae1"                     │   │
       │ └─────────────────────────────────────────────┘   │
       │<──────────────────────────────────────────────────│
       │                                                   │
       │ 6. SYNC_CONFIRMATION                              │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • original_message_id: (from step 1)       │   │
       │ │ • final_rotation_timestamp: confirmed_time │   │
       │ │ • master_sae_id: "sae1"                    │   │
       │ │ • slave_sae_id: "sae2"                     │   │
       │ └─────────────────────────────────────────────┘   │
       │───────────────────────────────────────────────────>│
       │                                                   │
       │                                                   │ 7. Schedule rotation timer
       │                                                   │
       │                                                   │ 8. Execute key rotation
       │                                                   │ (at scheduled time)
       │                                                   │
       │                                                   │ 9. Mark new key IN_PRODUCTION
       │                                                   │
       │                                                   │ 10. Mark old key ROLLED
       │                                                   │
       │ 11. ROTATION_COMPLETED                             │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • original_message_id: (from step 1)       │   │
       │ │ • new_key_id: "new_key"                    │   │
       │ │ • rotation_timestamp: actual_time           │   │
       │ │ • master_sae_id: "sae2"                    │   │
       │ │ • slave_sae_id: "sae1"                     │   │
       │ └─────────────────────────────────────────────┘   │
       │<──────────────────────────────────────────────────│
       │                                                   │
       │ 12. Execute master rotation                      │
       │                                                   │
       │ 13. Initiate cleanup protocol                    │
       │                                                   │
```

## Cleanup Protocol Flow

```
┌─────────────┐                                    ┌─────────────┐
│ Master SAE  │                                    │ Slave SAE   │
│             │                                    │             │
└──────┬──────┘                                    └──────┬──────┘
       │                                                   │
       │ 1. CLEANUP_STATUS_REQUEST                         │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • original_message_id: (from sync)          │   │
       │ │ • new_key_id: "new_key"                     │   │
       │ │ • master_sae_id: "sae1"                     │   │
       │ │ • slave_sae_id: "sae2"                      │   │
       │ └─────────────────────────────────────────────┘   │
       │───────────────────────────────────────────────────>│
       │                                                   │
       │                                                   │ 2. Check local key status
       │                                                   │
       │                                                   │ 3. Get rolled keys count
       │                                                   │
       │ 4. CLEANUP_STATUS_RESPONSE                        │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • original_message_id: (from step 1)       │   │
       │ │ • rolled_keys_count: 1                      │   │
       │ │ • service_status: "operational"             │   │
       │ │ • master_sae_id: "sae2"                     │   │
       │ │ • slave_sae_id: "sae1"                      │   │
       │ └─────────────────────────────────────────────┘   │
       │<──────────────────────────────────────────────────│
       │                                                   │
       │ 5. CLEANUP_DELETE_REQUEST                         │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • original_message_id: (from sync)          │   │
       │ │ • new_key_id: "new_key"                     │   │
       │ │ • master_sae_id: "sae1"                     │   │
       │ │ • slave_sae_id: "sae2"                      │   │
       │ └─────────────────────────────────────────────┘   │
       │───────────────────────────────────────────────────>│
       │                                                   │
       │                                                   │ 6. Delete rolled keys from device
       │                                                   │ (using persona delete_key)
       │                                                   │
       │                                                   │ 7. Delete rolled keys from storage
       │                                                   │
       │                                                   │ 8. Clean up sessions
       │                                                   │
       │ 9. CLEANUP_DELETE_RESPONSE                        │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • original_message_id: (from step 5)       │   │
       │ │ • deleted_key_ids: ["old_key"]              │   │
       │ │ • failed_key_ids: []                        │   │
       │ │ • master_sae_id: "sae2"                     │   │
       │ │ │ • slave_sae_id: "sae1"                    │   │
       │ └─────────────────────────────────────────────┘   │
       │<──────────────────────────────────────────────────│
       │                                                   │
       │ 10. Perform local cleanup                        │
       │                                                   │
       │ 11. CLEANUP_ACKNOWLEDGMENT                       │
       │ ┌─────────────────────────────────────────────┐   │
       │ │ • message_id: uuid                          │   │
       │ │ • original_message_id: (from sync)          │   │
       │ │ • status: "completed"                       │   │
       │ │ • master_sae_id: "sae1"                     │   │
       │ │ • slave_sae_id: "sae2"                      │   │
       │ └─────────────────────────────────────────────┘   │
       │───────────────────────────────────────────────────>│
       │                                                   │
       │                                                   │ 12. Cleanup protocol complete
       │                                                   │
```

## State Machine Transitions

```
┌─────────────┐    KEY_NOTIFICATION    ┌─────────────┐
│    IDLE     │───────────────────────>│  NOTIFIED   │
└─────────────┘                       └─────────────┘
                                              │
                                              │ KEY_ACKNOWLEDGMENT
                                              ▼
┌─────────────┐    SYNC_CONFIRMATION   ┌─────────────┐
│ CONFIRMED   │<───────────────────────│ACKNOWLEDGED │
└─────────────┘                       └─────────────┘
       │                                      │
       │ Schedule rotation                    │ Schedule rotation
       ▼                                      ▼
┌─────────────┐                       ┌─────────────┐
│  ROTATING   │                       │  ROTATING   │
└─────────────┘                       └─────────────┘
       │                                      │
       │ Execute rotation                     │ Execute rotation
       ▼                                      ▼
┌─────────────┐    ROTATION_COMPLETED  ┌─────────────┐
│PENDING_DONE │<───────────────────────│PENDING_DONE │
└─────────────┘                       └─────────────┘
       │                                      │
       │ Initiate cleanup                     │
       ▼                                      │
┌─────────────┐    CLEANUP_STATUS_REQUEST    │
│CLEANUP_STATUS│─────────────────────────────>│
│  CHECKING   │                              │
└─────────────┘                              │
       │                                     │
       │ CLEANUP_STATUS_RESPONSE             │
       │<────────────────────────────────────│
       │                                     │
       │ CLEANUP_DELETE_REQUEST              │
       │────────────────────────────────────>│
       │                                     │
       │ CLEANUP_DELETE_RESPONSE             │
       │<────────────────────────────────────│
       │                                     │
       │ CLEANUP_ACKNOWLEDGMENT              │
       │────────────────────────────────────>│
       │                                     │
       ▼                                     ▼
┌─────────────┐                       ┌─────────────┐
│    IDLE     │                       │    IDLE     │
└─────────────┘                       └─────────────┘
```

## Message Types Summary

| Message Type | Direction | Purpose | Key Fields |
|--------------|-----------|---------|------------|
| `KEY_NOTIFICATION` | Master → Slave | Notify slave of available keys | `key_ids`, `rotation_timestamp` |
| `KEY_ACKNOWLEDGMENT` | Slave → Master | Acknowledge key notification | `original_message_id`, `selected_key_id` |
| `SYNC_CONFIRMATION` | Master → Slave | Confirm synchronization | `original_message_id`, `final_rotation_timestamp` |
| `ROTATION_COMPLETED` | Slave → Master | Notify master of rotation completion | `original_message_id`, `new_key_id` |
| `CLEANUP_STATUS_REQUEST` | Master → Slave | Check slave cleanup readiness | `original_message_id`, `new_key_id` |
| `CLEANUP_STATUS_RESPONSE` | Slave → Master | Report cleanup status | `rolled_keys_count`, `service_status` |
| `CLEANUP_DELETE_REQUEST` | Master → Slave | Request cleanup execution | `original_message_id`, `new_key_id` |
| `CLEANUP_DELETE_RESPONSE` | Slave → Master | Report cleanup results | `deleted_key_ids`, `failed_key_ids` |
| `CLEANUP_ACKNOWLEDGMENT` | Master → Slave | Acknowledge cleanup completion | `original_message_id`, `status` |
| `ERROR` | Either → Either | Report errors | `error_code`, `error_message` |

## Key Features

1. **Message Signing**: All messages are cryptographically signed for authenticity
2. **Session Tracking**: Each synchronization creates a session with state machine
3. **Timeout Handling**: Messages have timestamps and validation
4. **Error Recovery**: Error messages and state transitions handle failures
5. **Device Integration**: Cleanup protocol integrates with device personas
6. **Thread Safety**: Sessions use locks for concurrent access
7. **Debug Logging**: Comprehensive logging for troubleshooting

## Error Handling

- **Invalid messages**: Rejected with ERROR response
- **State violations**: Handled by state machine validation
- **Network failures**: Timeout-based retry mechanisms
- **Device failures**: Reported in cleanup responses
- **Session timeouts**: Automatic cleanup of expired sessions
