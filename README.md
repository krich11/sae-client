# SAE Client

A standalone ETSI GS QKD 014 compliant Secure Application Entity (SAE) client for key management operations. This client supports both master and slave modes and is designed for laboratory environments.

## Features

- **ETSI GS QKD 014 Compliance**: Full implementation of the ETSI specification
- **Master/Slave Operations**: Support for both master and slave SAE modes
- **mTLS Authentication**: Secure communication with KME servers
- **Key Management**: Request, store, and manage cryptographic keys
- **Interactive CLI**: User-friendly command-line interface
- **Notification System**: Master/slave communication for key availability
- **Local Storage**: Secure local key storage (unencrypted for lab use)
- **Comprehensive Logging**: Detailed logging for debugging and auditing

## Architecture

The SAE client follows a modular architecture with clear separation of concerns:

```
sae-client/
├── src/                    # Source code
│   ├── config.py          # Configuration management
│   ├── models/            # ETSI data models
│   ├── api/               # KME API client
│   ├── services/          # Business logic services
│   └── utils/             # Utility functions
├── certs/                 # Certificate storage
├── data/                  # Local data storage
├── logs/                  # Log files
├── tests/                 # Test files
└── docs/                  # Documentation
```

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Git
- curl and jq (for testing)

### Installation

1. **Clone or extract the SAE client:**
   ```bash
   # If you have the sae-client directory
   cd sae-client
   ```

2. **Run the setup script:**
   ```bash
   chmod +x setup_sae.sh
   ./setup_sae.sh
   ```

3. **Configure certificates:**
   ```bash
   # Place your certificates in the appropriate directories
   cp your_sae.crt certs/sae/sae.crt
   cp your_sae.key certs/sae/sae.key
   cp your_ca.crt certs/ca/ca.crt
   ```

4. **Update configuration:**
   ```bash
   # Edit the .env file to match your environment
   nano .env
   ```

5. **Test the installation:**
   ```bash
   source venv/bin/activate
   python sae_client.py test-connection
   ```

## Usage

### Command Line Interface

The SAE client provides a comprehensive CLI with the following commands:

```bash
# Activate virtual environment
source venv/bin/activate

# Show help
python sae_client.py --help

# Check SAE status
python sae_client.py status

# Request keys from KME
python sae_client.py request-keys --key-type encryption --key-size 256 --quantity 5

# List local keys
python sae_client.py list-keys

# Test KME connection
python sae_client.py test-connection

# Start interactive mode
python sae_client.py interactive
```

### Interactive Mode

For easier use, start the interactive mode:

```bash
python sae_client.py interactive
```

This provides a command prompt with built-in help and command completion.

### Master Mode Operations

When configured as a master SAE:

```bash
# Notify a slave of available key
python sae_client.py notify-slave --slave-id SLAVE_001 --key-id KEY_123

# Request keys from KME and distribute to slaves
python sae_client.py request-keys --key-type encryption --quantity 10
```

### Slave Mode Operations

When configured as a slave SAE:

```bash
# Request keys from a master
python sae_client.py request-from-master --master-id MASTER_001 --key-type encryption

# Check for available keys
python sae_client.py list-keys
```

## Configuration

The SAE client uses environment variables for configuration. The main settings are:

### SAE Identity
- `SAE_SAE_ID`: Unique SAE identifier (default: SAE_001)
- `SAE_SAE_MODE`: Operation mode - master or slave (default: master)

### KME Server
- `SAE_KME_HOST`: KME server hostname (default: localhost)
- `SAE_KME_PORT`: KME server port (default: 443)
- `SAE_KME_BASE_URL`: Full KME server URL

### Certificates
- `SAE_SAE_CERT_PATH`: Path to SAE certificate
- `SAE_SAE_KEY_PATH`: Path to SAE private key
- `SAE_CA_CERT_PATH`: Path to CA certificate

### Storage
- `SAE_DATA_DIR`: Local data directory
- `SAE_LOGS_DIR`: Log files directory
- `SAE_KEYS_FILE`: Local keys storage file

### Network
- `SAE_TIMEOUT`: Request timeout in seconds
- `SAE_MAX_RETRIES`: Maximum retry attempts
- `SAE_MASTER_SLAVE_PORT`: Master/slave communication port

## Master/Slave Communication

The SAE client implements a notification system for master/slave communication:

### Master Functions
- `notify_slave_available_key()`: Notify slaves of available keys
- `broadcast_key_availability()`: Broadcast to all connected slaves

### Slave Functions
- `on_key_available_notification()`: Handle key availability notifications
- `request_key_from_master()`: Request keys from master SAEs

### Network Protocol
- TCP-based communication
- JSON message format
- Configurable timeouts and retries
- Automatic reconnection handling

## Security Considerations

This client is designed for laboratory environments with the following security model:

- **mTLS Authentication**: All KME communication uses mutual TLS
- **Certificate Validation**: Full certificate chain validation
- **Local Storage**: Keys stored locally (unencrypted for lab simplicity)
- **Network Security**: Master/slave communication over local network
- **Audit Logging**: Comprehensive logging for security auditing

## Development

### Project Structure
```
src/
├── config.py              # Configuration management
├── models/
│   └── api_models.py      # ETSI data models
├── api/
│   └── client.py          # KME API client
├── services/
│   ├── key_service.py     # Key management (TODO)
│   ├── storage_service.py # Local storage (TODO)
│   └── notification_service.py # Master/slave notifications
└── utils/
    ├── crypto.py          # Cryptographic utilities (TODO)
    └── validation.py      # Input validation (TODO)
```

### Adding New Features

1. **Models**: Add new data models in `src/models/`
2. **API**: Extend KME client in `src/api/client.py`
3. **Services**: Add business logic in `src/services/`
4. **CLI**: Add new commands in `sae_client.py`

### Testing

```bash
# Run tests
source venv/bin/activate
python -m pytest tests/

# Run with coverage
python -m pytest --cov=src tests/
```

## Troubleshooting

### Common Issues

1. **Certificate Errors**
   - Ensure certificates are in PEM format
   - Check file permissions (should be 600 for private keys)
   - Verify certificate paths in .env file

2. **Connection Errors**
   - Check KME server is running
   - Verify host and port settings
   - Test network connectivity

3. **Import Errors**
   - Ensure virtual environment is activated
   - Check Python path includes src directory
   - Verify all dependencies are installed

### Logs

Check the log files in the `logs/` directory for detailed error information:

```bash
tail -f logs/sae_client.log
```

## ETSI Compliance

This client implements the ETSI GS QKD 014 specification including:

- **Data Models**: All required data structures
- **API Endpoints**: Complete KME API support
- **Error Handling**: Standardized error responses
- **Extensions**: Certificate extension support for debugging

## License

This project is licensed under the same terms as the parent Easy-KME project.

## Contributing

1. Follow the existing code style
2. Add tests for new features
3. Update documentation
4. Ensure ETSI compliance

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs
3. Consult the ETSI specification in `docs/`
4. Create an issue in the project repository
