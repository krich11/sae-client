#!/bin/bash

# SAE Client Setup Script
# Sets up the SAE client environment and dependencies

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

# Function to create virtual environment
create_virtual_environment() {
    print_header "Creating Virtual Environment"
    
    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists. Removing old one..."
        rm -rf venv
    fi
    
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    print_status "Virtual environment created successfully"
}

# Function to install Python dependencies
install_python_dependencies() {
    print_header "Installing Python Dependencies"
    
    source venv/bin/activate
    
    # Install dependencies with optimized flags
    print_status "Installing dependencies (this may take a few minutes)..."
    pip install --no-cache-dir --prefer-binary --use-pep517 --quiet -r requirements.txt
    
    if [ $? -eq 0 ]; then
        print_status "Python dependencies installed successfully"
    else
        print_warning "Some dependencies failed to install with optimized flags, trying standard installation..."
        pip install -r requirements.txt
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
sys.path.insert(0, 'src')
try:
    from config import config_manager
    from api.client import kme_client
    from services.notification_service import master_notification_service, slave_notification_service
    from models.api_models import KeyType, KeyStatus
    print('✓ All imports successful')
except ImportError as e:
    print(f'✗ Import error: {e}')
    sys.exit(1)
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
    
    # Create virtual environment
    create_virtual_environment
    
    # Install Python dependencies
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
    else
        print_error "Installation validation failed"
        exit 1
    fi
}

# Run main function
main "$@"
