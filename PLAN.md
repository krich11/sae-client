# SAE Client Implementation Plan

## Overview
This document outlines the plan for creating a standalone ETSI GS QKD 014 compliant SAE (Secure Application Entity) client capable of both master and slave operations. The client will be completely independent of the KME project and designed for laboratory use.

## Architecture

### Directory Structure
```
sae-client/
├── docs/                    # Documentation (ETSI spec, user guides)
├── src/                     # Source code
│   ├── __init__.py
│   ├── main.py             # Main entry point
│   ├── config.py           # Configuration management
│   ├── models/             # Data models
│   │   ├── __init__.py
│   │   ├── api_models.py   # ETSI API models
│   │   └── data_models.py  # Internal data models
│   ├── api/                # API client
│   │   ├── __init__.py
│   │   ├── client.py       # KME API client
│   │   └── auth.py         # mTLS authentication
│   ├── services/           # Business logic
│   │   ├── __init__.py
│   │   ├── key_service.py  # Key management
│   │   ├── storage_service.py # Local storage
│   │   └── notification_service.py # Master/Slave notifications
│   └── utils/              # Utilities
│       ├── __init__.py
│       ├── crypto.py       # Cryptographic utilities
│       └── validation.py   # Input validation
├── certs/                  # Certificate storage
│   ├── sae/               # SAE certificates
│   └── ca/                # CA certificates
├── tests/                 # Test files
├── data/                  # Local data storage
├── logs/                  # Log files
├── requirements.txt       # Python dependencies
├── setup_sae.sh          # Setup script
├── sae_client.py         # Command-line interface
├── README.md             # Project documentation
└── PLAN.md               # This document
```

## Core Components

### 1. Configuration Management (`src/config.py`)
- Environment-based configuration
- Certificate path management
- KME server connection settings
- Logging configuration
- Master/Slave mode settings

### 2. ETSI API Models (`src/models/api_models.py`)
- Complete ETSI GS QKD 014 data models
- Request/Response structures
- Error handling models
- Validation schemas

### 3. KME API Client (`src/api/client.py`)
- HTTP client for KME communication
- mTLS certificate handling
- Request/response processing
- Error handling and retries

### 4. Key Management Service (`src/services/key_service.py`)
- Key request/response handling
- Key storage and retrieval
- Key lifecycle management
- Encryption/decryption operations

### 5. Notification Service (`src/services/notification_service.py`)
- **Master Operations:**
  - `notify_slave_available_key(slave_id, key_id, key_data)`
  - Key availability notifications
  - Slave status tracking
  
- **Slave Operations:**
  - `on_key_available_notification(master_id, key_id, key_data)`
  - Key availability callbacks
  - Master notification handling

### 6. Storage Service (`src/services/storage_service.py`)
- Local key storage (unencrypted for lab use)
- Configuration persistence
- Log management
- Certificate storage

## Implementation Phases

### Phase 1: Foundation (Week 1)
1. **Project Setup**
   - Create directory structure
   - Set up Python virtual environment
   - Install dependencies
   - Basic configuration management

2. **ETSI Models**
   - Implement all ETSI GS QKD 014 data models
   - Create validation schemas
   - Add serialization/deserialization

3. **Basic API Client**
   - HTTP client with mTLS support
   - Basic KME communication
   - Error handling

### Phase 2: Core Functionality (Week 2)
1. **Key Management**
   - Key request/response handling
   - Local key storage
   - Key lifecycle management

2. **Authentication**
   - mTLS certificate handling
   - SAE identity management
   - Certificate validation

3. **Storage Service**
   - Local data persistence
   - Configuration management
   - Log management

### Phase 3: Master/Slave Operations (Week 3)
1. **Master Mode**
   - Key request from KME
   - Slave notification system
   - Key distribution logic

2. **Slave Mode**
   - Key availability monitoring
   - Master notification handling
   - Key reception and storage

3. **Notification System**
   - Inter-process communication
   - Event-driven architecture
   - Callback mechanisms

### Phase 4: User Interface (Week 4)
1. **Command Line Interface**
   - Interactive menu system
   - Configuration management
   - Operation modes (Master/Slave)

2. **Setup Script**
   - Automated installation
   - Certificate management
   - Environment setup

3. **Testing and Validation**
   - Unit tests
   - Integration tests
   - ETSI compliance validation

## Key Features

### Master Mode Capabilities
- Request keys from KME server
- Store received keys locally
- Notify slave SAEs of available keys
- Manage key distribution
- Monitor key availability

### Slave Mode Capabilities
- Receive notifications from master SAEs
- Request keys from master SAEs
- Store received keys locally
- Provide key availability status
- Handle key lifecycle events

### Common Features
- mTLS authentication with KME
- ETSI GS QKD 014 compliance
- Local key storage
- Configuration management
- Logging and monitoring
- Certificate management

## Security Considerations (Lab Environment)
- **Key Storage**: Unencrypted local storage for simplicity
- **Authentication**: mTLS certificates for KME communication
- **Network**: Local network communication
- **Access Control**: File system permissions
- **Audit**: Comprehensive logging

## Dependencies
- Python 3.8+
- cryptography
- requests
- pydantic
- click (for CLI)
- rich (for UI)
- pytest (for testing)

## Testing Strategy
1. **Unit Tests**: Individual component testing
2. **Integration Tests**: KME server integration
3. **Compliance Tests**: ETSI specification validation
4. **End-to-End Tests**: Complete workflow testing

## Migration to Separate Repository
After completion, the `sae-client` directory will be:
1. Extracted as a standalone repository
2. Updated with proper documentation
3. Configured with CI/CD pipeline
4. Published as a separate package

## Success Criteria
- [ ] 100% ETSI GS QKD 014 compliance
- [ ] Complete master/slave functionality
- [ ] Standalone operation (no KME dependencies)
- [ ] Comprehensive testing suite
- [ ] User-friendly setup and operation
- [ ] Complete documentation
- [ ] Ready for separate repository migration
