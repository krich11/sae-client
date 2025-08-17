#!/bin/bash

# SAE Client Setup Script
# Sets up the SAE client environment and dependencies
# Uses existing virtual environment if available, creates new one if needed

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        python_version=$(python3 --version 2>&1 | awk '{print $2}')
        print_status "Found Python $python_version"
        
        # Check if version is 3.8 or higher
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
            return 0
        else
            print_error "Python 3.8 or higher is required. Found: $python_version"
            return 1
        fi
    else
        print_error "Python 3 is not installed"
        return 1
    fi
}

# Function to install system dependencies
install_system_dependencies() {
    print_header "Installing System Dependencies"
    
    if command_exists apt-get; then
        print_status "Using apt package manager"
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv git curl jq
    elif command_exists yum; then
        print_status "Using yum package manager"
        sudo yum install -y python3 python3-pip python3-venv git curl jq
    elif command_exists dnf; then
        print_status "Using dnf package manager"
        sudo dnf install -y python3 python3-pip python3-venv git curl jq
    else
        print_error "Unsupported package manager. Please install Python 3, pip, git, curl, and jq manually."
        exit 1
    fi
    
    print_status "System dependencies installed successfully"
}

# Function to create or use existing virtual environment
create_virtual_environment() {
    print_header "Setting Up Virtual Environment"
    
    if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
        print_status "Existing virtual environment found. Using existing venv..."
        source venv/bin/activate
        
        # Check if the virtual environment is working
        if python3 -c "import sys; print('Python version:', sys.version)" > /dev/null 2>&1; then
            print_status "Existing virtual environment is valid and activated"
            
            # Upgrade pip in existing environment
            print_status "Upgrading pip in existing environment..."
            pip install --upgrade pip --quiet
            
            return 0
        else
            print_warning "Existing virtual environment appears corrupted. Removing and creating new one..."
            rm -rf venv
        fi
    fi
    
    # Create new virtual environment if none exists or if existing one is corrupted
    print_status "Creating new virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip --quiet
    
    print_status "Virtual environment created successfully"
}

# Function to install Python dependencies
install_python_dependencies() {
    print_header "Installing Python Dependencies"
    
    source venv/bin/activate
    
    # Check if requirements are already installed
    print_status "Checking existing dependencies..."
    if pip show pydantic-settings > /dev/null 2>&1; then
        print_status "Dependencies appear to be already installed. Checking for updates..."
        
        # Install/upgrade dependencies with optimized flags
        print_status "Installing/upgrading dependencies (this may take a few minutes)..."
        pip install --no-cache-dir --prefer-binary --use-pep517 --quiet --upgrade -r requirements.txt
        
        if [ $? -eq 0 ]; then
            print_status "Python dependencies updated successfully"
        else
            print_warning "Some dependencies failed to install with optimized flags, trying standard installation..."
            pip install --upgrade -r requirements.txt
        fi
    else
        # Fresh installation
        print_status "Installing dependencies (this may take a few minutes)..."
        pip install --no-cache-dir --prefer-binary --use-pep517 --quiet -r requirements.txt
        
        if [ $? -eq 0 ]; then
            print_status "Python dependencies installed successfully"
        else
            print_warning "Some dependencies failed to install with optimized flags, trying standard installation..."
            pip install -r requirements.txt
        fi
    fi
}

# Function to create directory structure
create_directory_structure() {
    print_header "Creating Directory Structure"
    
    # Create directories
    mkdir -p certs/sae certs/ca data logs tests
    
    # Set proper permissions
    chmod 700 certs/sae certs/ca data logs
    
    print_status "Directory structure created successfully"
}

# Function to create default configuration
create_default_config() {
    print_header "Creating Default Configuration"
    
    # Create .env file with default values
    cat > .env << EOF
# SAE Client Configuration
SAE_SAE_ID=SAE_001
SAE_SAE_MODE=master
SAE_KME_HOST=localhost
SAE_KME_PORT=443
SAE_KME_BASE_URL=https://localhost:443
SAE_SAE_CERT_PATH=./certs/sae/sae.crt
SAE_SAE_KEY_PATH=./certs/sae/sae.key
SAE_CA_CERT_PATH=./certs/ca/ca.crt
SAE_DATA_DIR=./data
SAE_LOGS_DIR=./logs
SAE_KEYS_FILE=./data/keys.json
SAE_LOG_LEVEL=INFO
SAE_LOG_FILE=./logs/sae_client.log
SAE_TIMEOUT=30
SAE_MAX_RETRIES=3
SAE_MASTER_SLAVE_PORT=8080
SAE_NOTIFICATION_TIMEOUT=10
EOF
    
    print_status "Default configuration created (.env file)"
}

# Function to make scripts executable
make_executable() {
    print_header "Setting Permissions"
    
    chmod +x sae_client.py
    
    print_status "Scripts made executable"
}

# Function to validate installation
validate_installation() {
    print_header "Validating Installation"
    
    source venv/bin/activate
    
    # Test Python imports
    print_status "Testing Python imports..."
    python3 -c "
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.getcwd())
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

try:
    # Test basic config import
    from src.config import config_manager
    print('✓ Config import successful')
    
    # Test models import
    from src.models.api_models import KeyType, KeyStatus
    print('✓ Models import successful')
    
    # Test API client import (this may fail if certificates don't exist, which is OK)
    try:
        from src.api.client import kme_client
        print('✓ API client import successful')
    except Exception as e:
        print(f'⚠ API client import warning: {e}')
    
    # Test notification service import
    try:
        from src.services.notification_service import master_notification_service, slave_notification_service
        print('✓ Notification service import successful')
    except Exception as e:
        print(f'⚠ Notification service import warning: {e}')
    
    print('✓ All core imports successful')
except ImportError as e:
    print(f'✗ Import error: {e}')
    sys.exit(1)
except Exception as e:
    print(f'⚠ Import warning: {e}')
"
    
    # Test CLI
    print_status "Testing CLI..."
    python3 sae_client.py --help > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_status "✓ CLI test successful"
    else
        print_error "✗ CLI test failed"
        return 1
    fi
    
    print_status "Installation validation completed successfully"
}

# Function to get user input for certificate attributes
get_certificate_attributes() {
    print_status "Certificate Attributes Configuration"
    echo ""
    print_status "Please provide the following certificate attributes:"
    echo ""
    
    # Get country
    read -e -p "Country (2-letter code, e.g., US): " COUNTRY
    COUNTRY=${COUNTRY:-US}
    
    # Get state/province
    read -e -p "State/Province (e.g., California): " STATE
    STATE=${STATE:-California}
    
    # Get city/locality
    read -e -p "City/Locality (e.g., San Francisco): " CITY
    CITY=${CITY:-San Francisco}
    
    # Get organization
    read -e -p "Organization (e.g., SAE Client Lab): " ORGANIZATION
    ORGANIZATION=${ORGANIZATION:-SAE Client Lab}
    
    # Get organizational unit
    read -e -p "Organizational Unit (e.g., QKD): " ORG_UNIT
    ORG_UNIT=${ORG_UNIT:-QKD}
    
    # Get common name
    read -e -p "Common Name (e.g., SAE_CLIENT_001): " COMMON_NAME
    COMMON_NAME=${COMMON_NAME:-SAE_CLIENT_001}
    
    # Get key size
    read -e -p "Key size in bits (2048, 4096): " KEY_SIZE
    KEY_SIZE=${KEY_SIZE:-2048}
    
    # Get validity days
    read -e -p "Validity in days (365, 730): " VALIDITY_DAYS
    VALIDITY_DAYS=${VALIDITY_DAYS:-365}
    
    # Get subject alternative names
    echo ""
    print_status "Subject Alternative Names (SANs):"
    read -e -p "DNS names (comma-separated, e.g., localhost,sae-client.local): " DNS_NAMES
    DNS_NAMES=${DNS_NAMES:-localhost,sae-client.local}
    
    read -e -p "IP addresses (comma-separated, e.g., 127.0.0.1): " IP_ADDRESSES
    IP_ADDRESSES=${IP_ADDRESSES:-127.0.0.1}
    
    echo ""
    print_status "Certificate attributes configured:"
    echo "  Country: $COUNTRY"
    echo "  State: $STATE"
    echo "  City: $CITY"
    echo "  Organization: $ORGANIZATION"
    echo "  Organizational Unit: $ORG_UNIT"
    echo "  Common Name: $COMMON_NAME"
    echo "  Key Size: $KEY_SIZE bits"
    echo "  Validity: $VALIDITY_DAYS days"
    echo "  DNS Names: $DNS_NAMES"
    echo "  IP Addresses: $IP_ADDRESSES"
    echo ""
}

# Function to create OpenSSL config with user attributes
create_openssl_config() {
    local config_file="$1"
    
    # Parse DNS names and IP addresses
    local dns_section=""
    local ip_section=""
    local dns_count=1
    local ip_count=1
    
    # Process DNS names
    IFS=',' read -ra DNS_ARRAY <<< "$DNS_NAMES"
    for dns in "${DNS_ARRAY[@]}"; do
        dns=$(echo "$dns" | xargs)  # trim whitespace
        if [[ -n "$dns" ]]; then
            dns_section="${dns_section}DNS.$dns_count = $dns"$'\n'
            ((dns_count++))
        fi
    done
    
    # Process IP addresses
    IFS=',' read -ra IP_ARRAY <<< "$IP_ADDRESSES"
    for ip in "${IP_ARRAY[@]}"; do
        ip=$(echo "$ip" | xargs)  # trim whitespace
        if [[ -n "$ip" ]]; then
            ip_section="${ip_section}IP.$ip_count = $ip"$'\n'
            ((ip_count++))
        fi
    done
    
    # Create the OpenSSL configuration file
    cat > "$config_file" << EOF
[req]
default_bits = $KEY_SIZE
default_keyfile = sae.key
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
encrypt_key = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORGANIZATION
OU = $ORG_UNIT
CN = $COMMON_NAME

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
$dns_section$ip_section
EOF
}

# Function to create CSR for SAE
create_sae_csr() {
    print_header "Creating SAE Certificate Signing Request"
    
    # Create certs/sae directory if it doesn't exist
    mkdir -p certs/sae
    
    # Get user input for certificate attributes
    get_certificate_attributes
    
    # Create OpenSSL config with user attributes
    create_openssl_config "certs/sae/sae_cert.conf"
    
    print_status "Creating SAE private key and CSR..."
    print_status "Using key size: $KEY_SIZE bits"
    print_status "Validity period: $VALIDITY_DAYS days"
    
    # Generate private key and CSR
    cd certs/sae
    openssl req -new -newkey rsa:$KEY_SIZE -keyout sae.key -out sae.csr -config sae_cert.conf -nodes
    
    if [ $? -eq 0 ]; then
        print_status "✓ SAE private key and CSR created successfully"
        print_status "Files created:"
        echo "  - certs/sae/sae.key (private key, $KEY_SIZE bits)"
        echo "  - certs/sae/sae.csr (certificate signing request)"
        echo "  - certs/sae/sae_cert.conf (OpenSSL configuration)"
        echo ""
        print_status "Certificate includes required SAE extensions:"
        echo "  ✓ clientAuth extended key usage"
        echo "  ✓ digitalSignature, keyEncipherment, keyAgreement key usage"
        echo "  ✓ Subject Alternative Names (SANs)"
        echo ""
        print_status "Next steps for certificate:"
        echo "1. Submit the CSR (sae.csr) to your Certificate Authority"
        echo "2. Once you receive the signed certificate, save it as 'sae.crt' in certs/sae/"
        echo "3. Ensure the certificate has 'clientAuth' extended key usage"
        echo "4. Update your .env file with the correct certificate paths"
        echo ""
    else
        print_error "✗ Failed to create SAE private key and CSR"
        return 1
    fi
    
    cd ../..
}

# Function to show next steps
show_next_steps() {
    print_header "Installation Complete!"
    
    echo ""
    print_status "SAE Client has been installed successfully."
    echo ""
    print_status "Next steps:"
    echo "1. Configure your certificates:"
    echo "   - Place your SAE certificate in: certs/sae/sae.crt"
    echo "   - Place your SAE private key in: certs/sae/sae.key"
    echo "   - Place your CA certificate in: certs/ca/ca.crt"
    echo ""
    echo "2. Update configuration:"
    echo "   - Edit .env file to match your environment"
    echo "   - Update KME server settings"
    echo "   - Set your SAE ID and mode (master/slave)"
    echo ""
    echo "3. Test the installation:"
    echo "   source venv/bin/activate"
    echo "   python sae_client.py test-connection"
    echo ""
    echo "4. Start using the client:"
    echo "   source venv/bin/activate"
    echo "   python sae_client.py interactive"
    echo ""
    print_status "For more information, see the documentation in docs/"
}

# Main installation function
main() {
    print_header "SAE Client Setup"
    echo ""
    print_status "This script will set up the SAE client environment."
    echo ""
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_error "Please do not run this script as root"
        exit 1
    fi
    
    # Check Python version
    if ! check_python_version; then
        print_error "Python 3.8 or higher is required"
        exit 1
    fi
    
    # Install system dependencies
    install_system_dependencies
    
    # Create or use existing virtual environment
    create_virtual_environment
    
    # Install or update Python dependencies
    install_python_dependencies
    
    # Create directory structure
    create_directory_structure
    
    # Create default configuration
    create_default_config
    
    # Make scripts executable
    make_executable
    
    # Validate installation
    if validate_installation; then
        show_next_steps
        
        # Ask about creating CSR
        echo ""
        print_status "Certificate Setup"
        echo ""
        read -p "Would you like to create a Certificate Signing Request (CSR) for your SAE client? (y/n): " -n 1 -r
        echo ""
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if create_sae_csr; then
                echo ""
                print_status "CSR creation completed successfully!"
                echo ""
                print_status "Summary of what was created:"
                echo "  ✓ SAE private key: certs/sae/sae.key"
                echo "  ✓ Certificate signing request: certs/sae/sae.csr"
                echo "  ✓ OpenSSL configuration: certs/sae/sae_cert.conf"
                echo ""
                print_status "To complete certificate setup:"
                echo "1. Submit sae.csr to your Certificate Authority"
                echo "2. Save the signed certificate as certs/sae/sae.crt"
                echo "3. Update your .env file with certificate paths"
                echo "4. Test with: python sae_client.py test-connection"
                echo ""
            else
                print_error "CSR creation failed. You can create certificates manually later."
            fi
        else
            echo ""
            print_status "Skipping CSR creation. You can create certificates manually when needed."
        fi
    else
        print_error "Installation validation failed"
        exit 1
    fi
}

# Run main function
main "$@"
