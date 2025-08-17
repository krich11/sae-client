#!/usr/bin/env python3
"""
SAE Client Command Line Interface.
Main entry point for the SAE client application.
"""

import sys
import os
import click
import logging
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config import config_manager, config, logger
from src.api.client import kme_client
from src.services.notification_service import master_notification_service, slave_notification_service
from src.models.api_models import KeyType, KeyStatus, SAEStatus

console = Console()


def print_banner():
    """Print application banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    SAE Client v1.0.0                        ║
    ║              ETSI GS QKD 014 Compliant Client               ║
    ║                                                              ║
    ║  Secure Application Entity (SAE) Client for Key Management  ║
    ║  Supports both Master and Slave operations                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))


def print_status(status: SAEStatus):
    """Print SAE status information."""
    table = Table(title="SAE Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("SAE ID", status.sae_id)
    table.add_row("Mode", status.mode)
    table.add_row("Status", status.status)
    table.add_row("Available Keys", str(status.available_keys))
    table.add_row("Total Keys", str(status.total_keys))
    table.add_row("Last Activity", status.last_activity.strftime("%Y-%m-%d %H:%M:%S"))
    
    if status.connected_slaves:
        table.add_row("Connected Slaves", ", ".join(status.connected_slaves))
    if status.connected_master:
        table.add_row("Connected Master", status.connected_master)
    
    console.print(table)


def print_keys(keys, title="Available Keys"):
    """Print key information in a table."""
    if not keys:
        console.print(f"[yellow]No {title.lower()} found[/yellow]")
        return
    
    table = Table(title=title)
    table.add_column("Key ID", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Size", style="yellow")
    table.add_column("Status", style="magenta")
    table.add_column("Source", style="blue")
    table.add_column("Created", style="white")
    
    for key in keys:
        table.add_row(
            key.key_id,
            key.key_type.value,
            str(key.key_size),
            key.status.value,
            key.source,
            key.creation_time.strftime("%Y-%m-%d %H:%M:%S")
        )
    
    console.print(table)


@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def cli(config, verbose):
    """SAE Client - ETSI GS QKD 014 Compliant Key Management Client."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if config:
        config_manager.config_file = config
    
    print_banner()


@cli.command()
def status():
    """Show SAE client status."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Checking SAE status...", total=None)
        
        try:
            # Get KME server status
            kme_status = kme_client.get_status()
            
            # Create SAE status
            sae_status = SAEStatus(
                sae_id=config.sae_id,
                mode=config.sae_mode,
                status="active" if kme_status.status == "running" else "inactive",
                available_keys=0,  # TODO: Get from local storage
                total_keys=0,      # TODO: Get from local storage
                last_activity=datetime.now(),
                connected_slaves=[] if config_manager.is_master_mode() else None,
                connected_master=None if config_manager.is_master_mode() else "MASTER_001"
            )
            
            progress.update(task, completed=True)
            print_status(sae_status)
            
            # Show KME connection status
            console.print(f"\n[green]✓[/green] KME Server: {kme_status.status}")
            console.print(f"[green]✓[/green] KME Version: {kme_status.version}")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error checking status: {e}")


@cli.command()
@click.option('--key-type', type=click.Choice(['encryption', 'decryption']), default='encryption')
@click.option('--key-size', default=256, help='Key size in bits')
@click.option('--quantity', default=1, help='Number of keys to request')
def request_keys(key_type, key_size, quantity):
    """Request keys from KME server."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Requesting {quantity} {key_type} keys...", total=None)
        
        try:
            if key_type == 'encryption':
                response = kme_client.request_encryption_keys(key_size, quantity)
            else:
                response = kme_client.request_decryption_keys(key_size, quantity)
            
            progress.update(task, completed=True)
            
            console.print(f"\n[green]✓[/green] Successfully received {response.total_keys} keys")
            
            # Display key information
            keys = []
            for spec_key in response.keys:
                key = spec_key.key_container
                keys.append(key)
            
            print_keys(keys, f"Received {key_type.title()} Keys")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error requesting keys: {e}")


@cli.command()
def list_keys():
    """List locally stored keys."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Loading local keys...", total=None)
        
        try:
            # TODO: Load keys from local storage
            # For now, show empty list
            keys = []
            
            progress.update(task, completed=True)
            print_keys(keys, "Local Keys")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error loading keys: {e}")


@cli.command()
@click.option('--slave-id', required=True, help='Slave SAE ID to notify')
@click.option('--key-id', required=True, help='Key ID to notify about')
def notify_slave(slave_id, key_id):
    """Notify a slave SAE of available key (Master mode only)."""
    if not config_manager.is_master_mode():
        console.print("[red]Error: This command is only available in master mode[/red]")
        return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Notifying slave {slave_id}...", total=None)
        
        try:
            # TODO: Get actual key data from local storage
            key_data = {
                'key_type': KeyType.ENCRYPTION,
                'key_size': 256,
                'key_material': 'dummy_key_material',
                'expiry_time': None
            }
            
            success = master_notification_service.notify_slave_available_key(
                slave_id, key_id, key_data
            )
            
            progress.update(task, completed=True)
            
            if success:
                console.print(f"[green]✓[/green] Successfully notified slave {slave_id}")
            else:
                console.print(f"[red]✗[/red] Failed to notify slave {slave_id}")
                
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error notifying slave: {e}")


@cli.command()
@click.option('--master-id', required=True, help='Master SAE ID to request from')
@click.option('--key-type', type=click.Choice(['encryption', 'decryption']), default='encryption')
@click.option('--key-size', default=256, help='Key size in bits')
@click.option('--quantity', default=1, help='Number of keys to request')
def request_from_master(master_id, key_type, key_size, quantity):
    """Request keys from a master SAE (Slave mode only)."""
    if not config_manager.is_slave_mode():
        console.print("[red]Error: This command is only available in slave mode[/red]")
        return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Requesting keys from master {master_id}...", total=None)
        
        try:
            success = slave_notification_service.request_key_from_master(
                master_id, KeyType(key_type), key_size, quantity
            )
            
            progress.update(task, completed=True)
            
            if success:
                console.print(f"[green]✓[/green] Successfully requested keys from master {master_id}")
            else:
                console.print(f"[red]✗[/red] Failed to request keys from master {master_id}")
                
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error requesting from master: {e}")


@cli.command()
def test_connection():
    """Test connection to KME server."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Testing KME connection...", total=None)
        
        try:
            success = kme_client.test_connection()
            
            progress.update(task, completed=True)
            
            if success:
                console.print("[green]✓[/green] KME connection successful")
                
                # Show server info
                server_info = kme_client.get_server_info()
                if 'error' not in server_info:
                    console.print(f"[green]✓[/green] Server Status: {server_info['status']}")
                    console.print(f"[green]✓[/green] Server Version: {server_info['version']}")
            else:
                console.print("[red]✗[/red] KME connection failed")
                
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Connection test error: {e}")


@cli.command()
def interactive():
    """Start interactive mode."""
    console.print("[bold blue]SAE Client Interactive Mode[/bold blue]")
    console.print("Type 'help' for available commands, 'quit' to exit\n")
    
    while True:
        try:
            command = input("SAE> ")
            
            if command.lower() in ['quit', 'exit', 'q']:
                console.print("Goodbye!")
                break
            elif command.lower() == 'help':
                console.print("""
Available commands:
  status              - Show SAE status
  request-keys        - Request keys from KME
  list-keys           - List local keys
  notify-slave        - Notify slave of available key (Master mode)
  request-from-master - Request keys from master (Slave mode)
  test-connection     - Test KME connection
  test-menu           - Test Easy-KME server routes
  help                - Show this help
  quit                - Exit interactive mode
                """)
            elif command.lower() == 'status':
                # Call status function directly
                try:
                    # Get KME server status
                    kme_status = kme_client.get_status()
                    
                    # Get key statistics
                    from src.services.key_service import key_service
                    key_stats = key_service.get_key_statistics()
                    
                    # Create SAE status
                    sae_status = SAEStatus(
                        sae_id=config.sae_id,
                        mode=config.sae_mode,
                        status="active" if kme_status.status == "running" else "inactive",
                        available_keys=key_stats['available_keys'],
                        total_keys=key_stats['total_keys'],
                        last_activity=datetime.now(),
                        connected_slaves=[] if config_manager.is_master_mode() else None,
                        connected_master=None if config_manager.is_master_mode() else "MASTER_001"
                    )
                    
                    print_status(sae_status)
                    
                    # Show KME connection status
                    console.print(f"\n[green]✓[/green] KME Server: {kme_status.status}")
                    console.print(f"[green]✓[/green] KME Version: {kme_status.version}")
                    
                except Exception as e:
                    console.print(f"[red]✗[/red] Error checking status: {e}")
                    
            elif command.lower() == 'request-keys':
                # Call request-keys function directly with defaults
                try:
                    response = kme_client.request_encryption_keys(256, 1)
                    console.print(f"\n[green]✓[/green] Successfully received {response.total_keys} keys")
                    
                    # Display key information
                    keys = []
                    for spec_key in response.keys:
                        key = spec_key.key_container
                        keys.append(key)
                    
                    print_keys(keys, "Received Encryption Keys")
                    
                except Exception as e:
                    console.print(f"[red]✗[/red] Error requesting keys: {e}")
                    
            elif command.lower() == 'list-keys':
                # Call list-keys function directly
                try:
                    from src.services.key_service import key_service
                    available_keys = key_service.get_available_keys()
                    print_keys(available_keys, "Local Keys")
                    
                except Exception as e:
                    console.print(f"[red]✗[/red] Error listing keys: {e}")
                    
            elif command.lower() == 'test-connection':
                # Call test-connection function directly
                try:
                    success = kme_client.test_connection()
                    
                    if success:
                        console.print("[green]✓[/green] KME connection successful")
                        
                        # Show server info
                        server_info = kme_client.get_server_info()
                        if 'error' not in server_info:
                            console.print(f"[green]✓[/green] Server Status: {server_info['status']}")
                            console.print(f"[green]✓[/green] Server Version: {server_info['version']}")
                    else:
                        console.print("[red]✗[/red] KME connection failed")
                        
                except Exception as e:
                    console.print(f"[red]✗[/red] Connection test error: {e}")
            elif command.lower() == 'test-menu':
                test_menu()
            else:
                console.print(f"[yellow]Unknown command: {command}[/yellow]")
                console.print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            console.print("\nGoodbye!")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


def test_menu():
    """Test menu for Easy-KME server routes."""
    while True:
        console.print("\n[bold blue]Easy-KME Server Test Menu[/bold blue]")
        console.print("""
Available test options:
  1. Test Root endpoint (/)
  2. Test Health check (/health)
  3. Test KME Status (/api/v1/keys/{slave_sae_id}/status)
  4. Test Master SAE Key Request POST (/api/v1/keys/{slave_sae_id}/enc_keys)
  5. Test Master SAE Key Request GET (/api/v1/keys/{slave_sae_id}/enc_keys)
  6. Test Slave SAE Key Request POST (/api/v1/keys/{master_sae_id}/dec_keys)
  7. Test Slave SAE Key Request GET (/api/v1/keys/{master_sae_id}/dec_keys)
  8. Test API Documentation (/docs)
  9. Test ReDoc Documentation (/redoc)
  10. Test All Routes
  0. Back to main menu
        """)
        
        choice = input("Enter your choice (0-10): ").strip()
        
        if choice == '0':
            break
        elif choice == '1':
            test_root_endpoint()
        elif choice == '2':
            test_health_endpoint()
        elif choice == '3':
            test_kme_status()
        elif choice == '4':
            test_master_key_request_post()
        elif choice == '5':
            test_master_key_request_get()
        elif choice == '6':
            test_slave_key_request_post()
        elif choice == '7':
            test_slave_key_request_get()
        elif choice == '8':
            test_docs_endpoint()
        elif choice == '9':
            test_redoc_endpoint()
        elif choice == '10':
            test_all_routes()
        else:
            console.print("[yellow]Invalid choice. Please enter 0-10.[/yellow]")


def test_root_endpoint():
    """Test the root endpoint."""
    console.print("\n[bold]Testing Root Endpoint (/) - GET[/bold]")
    console.print("[dim]Purpose: Root endpoint (No ETSI Compliance)[/dim]")
    
    try:
        response = kme_client.session.get(f"{config.kme_base_url}/")
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response: {response.text[:200]}...")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_health_endpoint():
    """Test the health endpoint."""
    console.print("\n[bold]Testing Health Endpoint (/health) - GET[/bold]")
    console.print("[dim]Purpose: Health check (No ETSI Compliance)[/dim]")
    
    try:
        response = kme_client.session.get(f"{config.kme_base_url}/health")
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response: {response.text[:200]}...")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_kme_status():
    """Test the KME status endpoint."""
    console.print("\n[bold]Testing KME Status (/api/v1/keys/{slave_sae_id}/status) - GET[/bold]")
    console.print("[dim]Purpose: Get KME status (✅ ETSI Compliant)[/dim]")
    
    slave_sae_id = input("Enter slave SAE ID (or press Enter for default 'SLAVE_001'): ").strip()
    slave_sae_id = slave_sae_id or "SLAVE_001"
    
    try:
        response = kme_client.session.get(f"{config.kme_base_url}/api/v1/keys/{slave_sae_id}/status")
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response: {response.text[:200]}...")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_master_key_request_post():
    """Test the master SAE key request POST endpoint."""
    console.print("\n[bold]Testing Master SAE Key Request POST (/api/v1/keys/{slave_sae_id}/enc_keys) - POST[/bold]")
    console.print("[dim]Purpose: Master SAE key request (✅ ETSI Compliant)[/dim]")
    
    slave_sae_id = input("Enter slave SAE ID (or press Enter for default 'SLAVE_001'): ").strip()
    slave_sae_id = slave_sae_id or "SLAVE_001"
    
    key_size = input("Enter key size in bits (or press Enter for default 256): ").strip()
    key_size = int(key_size) if key_size else 256
    
    quantity = input("Enter quantity (or press Enter for default 1): ").strip()
    quantity = int(quantity) if quantity else 1
    
    request_data = {
        "key_type": "encryption",
        "key_size": key_size,
        "quantity": quantity
    }
    
    try:
        response = kme_client.session.post(
            f"{config.kme_base_url}/api/v1/keys/{slave_sae_id}/enc_keys",
            json=request_data
        )
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response: {response.text[:200]}...")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_master_key_request_get():
    """Test the master SAE key request GET endpoint."""
    console.print("\n[bold]Testing Master SAE Key Request GET (/api/v1/keys/{slave_sae_id}/enc_keys) - GET[/bold]")
    console.print("[dim]Purpose: Master SAE key request simple (✅ ETSI Compliant)[/dim]")
    
    slave_sae_id = input("Enter slave SAE ID (or press Enter for default 'SLAVE_001'): ").strip()
    slave_sae_id = slave_sae_id or "SLAVE_001"
    
    try:
        response = kme_client.session.get(f"{config.kme_base_url}/api/v1/keys/{slave_sae_id}/enc_keys")
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response: {response.text[:200]}...")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_slave_key_request_post():
    """Test the slave SAE key request POST endpoint."""
    console.print("\n[bold]Testing Slave SAE Key Request POST (/api/v1/keys/{master_sae_id}/dec_keys) - POST[/bold]")
    console.print("[dim]Purpose: Slave SAE key request (✅ ETSI Compliant)[/dim]")
    
    master_sae_id = input("Enter master SAE ID (or press Enter for default 'MASTER_001'): ").strip()
    master_sae_id = master_sae_id or "MASTER_001"
    
    key_size = input("Enter key size in bits (or press Enter for default 256): ").strip()
    key_size = int(key_size) if key_size else 256
    
    quantity = input("Enter quantity (or press Enter for default 1): ").strip()
    quantity = int(quantity) if quantity else 1
    
    request_data = {
        "key_type": "decryption",
        "key_size": key_size,
        "quantity": quantity
    }
    
    try:
        response = kme_client.session.post(
            f"{config.kme_base_url}/api/v1/keys/{master_sae_id}/dec_keys",
            json=request_data
        )
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response: {response.text[:200]}...")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_slave_key_request_get():
    """Test the slave SAE key request GET endpoint."""
    console.print("\n[bold]Testing Slave SAE Key Request GET (/api/v1/keys/{master_sae_id}/dec_keys) - GET[/bold]")
    console.print("[dim]Purpose: Slave SAE key request simple (✅ ETSI Compliant)[/dim]")
    
    master_sae_id = input("Enter master SAE ID (or press Enter for default 'MASTER_001'): ").strip()
    master_sae_id = master_sae_id or "MASTER_001"
    
    try:
        response = kme_client.session.get(f"{config.kme_base_url}/api/v1/keys/{master_sae_id}/dec_keys")
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response: {response.text[:200]}...")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_docs_endpoint():
    """Test the API documentation endpoint."""
    console.print("\n[bold]Testing API Documentation (/docs) - GET[/bold]")
    console.print("[dim]Purpose: API documentation (No ETSI Compliance)[/dim]")
    
    try:
        response = kme_client.session.get(f"{config.kme_base_url}/docs")
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response length: {len(response.text)} characters")
        if response.status_code == 200:
            console.print("[green]✓[/green] Documentation page accessible")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_redoc_endpoint():
    """Test the ReDoc documentation endpoint."""
    console.print("\n[bold]Testing ReDoc Documentation (/redoc) - GET[/bold]")
    console.print("[dim]Purpose: API documentation (No ETSI Compliance)[/dim]")
    
    try:
        response = kme_client.session.get(f"{config.kme_base_url}/redoc")
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        console.print(f"[green]✓[/green] Response length: {len(response.text)} characters")
        if response.status_code == 200:
            console.print("[green]✓[/green] ReDoc page accessible")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_all_routes():
    """Test all Easy-KME server routes."""
    console.print("\n[bold blue]Testing All Easy-KME Server Routes[/bold blue]")
    console.print("=" * 50)
    
    tests = [
        ("Root Endpoint", test_root_endpoint),
        ("Health Check", test_health_endpoint),
        ("KME Status", test_kme_status),
        ("Master Key Request POST", test_master_key_request_post),
        ("Master Key Request GET", test_master_key_request_get),
        ("Slave Key Request POST", test_slave_key_request_post),
        ("Slave Key Request GET", test_slave_key_request_get),
        ("API Documentation", test_docs_endpoint),
        ("ReDoc Documentation", test_redoc_endpoint)
    ]
    
    for test_name, test_func in tests:
        console.print(f"\n[bold]Testing: {test_name}[/bold]")
        try:
            test_func()
        except Exception as e:
            console.print(f"[red]✗[/red] Test failed: {e}")
    
    console.print("\n[bold green]All route tests completed![/bold green]")


if __name__ == '__main__':
    cli()
