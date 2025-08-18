#!/usr/bin/env python3
"""
SAE Client Command Line Interface.
Main entry point for the SAE client application.
"""

import sys
import os
import json
import click
import logging
import readline
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

# Available commands for autocomplete
AVAILABLE_COMMANDS = [
    'health',
    'status',
    'request-keys', 
    'list-keys',
    'reset-keys',
    'notify-slave',
    'request-from-master',
    'test-connection',
    'test-menu',
    'help',
    '?',
    'quit',
    'exit',
    'q'
]

def command_completer(text, state):
    """Command completer function for readline."""
    if not text:
        options = AVAILABLE_COMMANDS
    else:
        options = [cmd for cmd in AVAILABLE_COMMANDS if cmd.lower().startswith(text.lower())]
    
    if state < len(options):
        return options[state]
    return None


def print_banner():
    """Print application banner."""
    console.print("[bold blue]┌──────────────────────────────────────────────────────────────┐[/bold blue]")
    console.print("[bold blue]│                    SAE Client v1.0.0                         │[/bold blue]")
    console.print("[bold blue]│              ETSI GS QKD 014 Compliant Client                │[/bold blue]")
    console.print("[bold blue]│                                                              │[/bold blue]")
    console.print("[bold blue]│  Secure Application Entity (SAE) Client for Key Management   │[/bold blue]")
    console.print("[bold blue]│  Supports both Master and Slave operations                   │[/bold blue]")
    console.print("[bold blue]└──────────────────────────────────────────────────────────────┘[/bold blue]")


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
    
    # Check if we're dealing with ETSI keys or Local keys
    if keys and hasattr(keys[0], 'key_ID'):
        # ETSI key format
        table = Table(title=title)
        table.add_column("Key ID", style="cyan")
        table.add_column("Key Material (Base64)", style="green")
        table.add_column("Key ID Extension", style="yellow")
        table.add_column("Key Extension", style="magenta")
        
        for key in keys:
            key_id_ext = str(key.key_ID_extension) if key.key_ID_extension else "None"
            key_ext = str(key.key_extension) if key.key_extension else "None"
            
            # Truncate key material for display
            key_material = key.key[:32] + "..." if len(key.key) > 32 else key.key
            
            table.add_row(
                key.key_ID,
                key_material,
                key_id_ext,
                key_ext
            )
    else:
        # Local key format
        table = Table(title=title)
        table.add_column("Key ID", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Status", style="magenta")
        table.add_column("Source", style="blue")
        table.add_column("Allowed SAE", style="magenta")
        table.add_column("Created", style="white")
        
        for key in keys:
            # Truncate key material for display
            key_material = key.key_material[:32] + "..." if len(key.key_material) > 32 else key.key_material
            
            # Get allowed SAE from metadata
            allowed_sae = key.metadata.get('allowed_sae_id', 'N/A') if key.metadata else 'N/A'
            
            table.add_row(
                key.key_id,
                key.key_type.value if hasattr(key.key_type, 'value') else str(key.key_type),
                str(key.key_size),
                key.status.value if hasattr(key.status, 'value') else str(key.status),
                key.source,
                allowed_sae,
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
def health():
    """Show SAE client health and configuration."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Checking SAE health...", total=None)
        
        try:
            # Get KME server health and root info
            kme_health = kme_client.get_health()
            kme_root_info = kme_client.get_root_info()
            
            # Get key statistics
            from src.services.key_service import key_service
            key_stats = key_service.get_key_statistics()
            
            # Create SAE status
            sae_status = SAEStatus(
                sae_id=config.sae_id,
                mode=config.sae_mode,
                status="active" if kme_health.status == "healthy" else "inactive",
                available_keys=key_stats['available_keys'],
                total_keys=key_stats['total_keys'],
                last_activity=datetime.now(),
                connected_slaves=[] if config_manager.is_master_mode() else None,
                connected_master=None if config_manager.is_master_mode() else "MASTER_001"
            )
            
            progress.update(task, completed=True)
            
            # Print SAE Configuration
            console.print("\n[bold blue]SAE Configuration[/bold blue]")
            config_table = Table(title="SAE Node Configuration")
            config_table.add_column("Property", style="cyan")
            config_table.add_column("Value", style="green")
            
            config_table.add_row("SAE ID", config.sae_id)
            config_table.add_row("Mode", config.sae_mode)
            config_table.add_row("KME Host", config.kme_host)
            config_table.add_row("KME Port", str(config.kme_port))
            config_table.add_row("KME Base URL", config.kme_base_url)
            config_table.add_row("SSL Verification", "Enabled" if config.verify_ssl else "Disabled")
            config_table.add_row("Timeout", f"{config.timeout}s")
            config_table.add_row("Max Retries", str(config.max_retries))
            config_table.add_row("Data Directory", config.data_dir)
            config_table.add_row("Logs Directory", config.logs_dir)
            config_table.add_row("Certificate Path", config.sae_cert_path)
            config_table.add_row("Private Key Path", config.sae_key_path)
            config_table.add_row("CA Certificate Path", config.ca_cert_path)
            
            console.print(config_table)
            
            # Print SAE Status
            print_status(sae_status)
            
            # Show KME server information
            console.print(f"\n[bold blue]KME Server Information[/bold blue]")
            console.print(f"[green]✓[/green] Status: {kme_health.status}")
            console.print(f"[green]✓[/green] Version: {kme_root_info.get('version', 'unknown')}")
            console.print(f"[green]✓[/green] Specification: {kme_root_info.get('specification', 'unknown')}")
            console.print(f"[green]✓[/green] Message: {kme_root_info.get('message', 'unknown')}")
            console.print(f"[green]✓[/green] Documentation: {kme_root_info.get('docs', 'unknown')}")
            console.print(f"[green]✓[/green] Health Timestamp: {kme_health.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error checking health: {e}")


@cli.command()
@click.option('--slave-id', help='Slave SAE ID to check status for')
def status(slave_id):
    """Check KME status for key availability and capabilities."""
    if not slave_id:
        slave_id = input("Enter slave SAE ID to check status for: ").strip()
        if not slave_id:
            console.print("[red]✗[/red] Slave SAE ID is required")
            return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Checking KME status for slave {slave_id}...", total=None)
        
        try:
            # Call the KME status endpoint
            response = kme_client.session.get(f"{config.kme_base_url}/api/v1/keys/{slave_id}/status")
            
            if response.status_code == 200:
                data = response.json()
                
                progress.update(task, completed=True)
                
                # Display status information
                console.print(f"\n[bold blue]KME Status for Slave SAE: {slave_id}[/bold blue]")
                
                status_table = Table(title="Key Availability and Capabilities")
                status_table.add_column("Property", style="cyan")
                status_table.add_column("Value", style="green")
                status_table.add_column("Description", style="yellow")
                
                status_table.add_row("Source KME ID", data.get('source_KME_ID', 'N/A'), "KME providing the status")
                status_table.add_row("Target KME ID", data.get('target_KME_ID', 'N/A'), "Target KME (if different)")
                status_table.add_row("Master SAE ID", data.get('master_SAE_ID', 'N/A'), "Calling master SAE")
                status_table.add_row("Slave SAE ID", data.get('slave_SAE_ID', 'N/A'), "Specified slave SAE")
                status_table.add_row("Default Key Size", str(data.get('key_size', 'N/A')), "Default key size in bits")
                status_table.add_row("Stored Key Count", str(data.get('stored_key_count', 'N/A')), "Available keys for this SAE")
                status_table.add_row("Max Key Count", str(data.get('max_key_count', 'N/A')), "Maximum keys KME can store")
                status_table.add_row("Max Per Request", str(data.get('max_key_per_request', 'N/A')), "Max keys per single request")
                status_table.add_row("Max Key Size", str(data.get('max_key_size', 'N/A')), "Maximum supported key size")
                status_table.add_row("Min Key Size", str(data.get('min_key_size', 'N/A')), "Minimum supported key size")
                status_table.add_row("Max SAE Count", str(data.get('max_SAE_ID_count', 'N/A')), "Max additional SAEs for multicast")
                
                console.print(status_table)
                
                # Show recommendations
                console.print(f"\n[bold blue]Recommendations:[/bold blue]")
                stored_count = data.get('stored_key_count', 0)
                max_per_request = data.get('max_key_per_request', 1)
                
                if stored_count > 0:
                    console.print(f"[green]✓[/green] {stored_count} keys available for requests")
                    console.print(f"[green]✓[/green] Optimal request size: {min(max_per_request, stored_count)} keys")
                else:
                    console.print(f"[yellow]⚠[/yellow] No keys currently available")
                
                if data.get('max_SAE_ID_count', 0) > 0:
                    console.print(f"[green]✓[/green] Multicast supported (up to {data.get('max_SAE_ID_count')} additional SAEs)")
                else:
                    console.print(f"[yellow]⚠[/yellow] Multicast not supported")
                    
            else:
                progress.update(task, completed=True)
                console.print(f"[red]✗[/red] KME status request failed: {response.status_code}")
                try:
                    error_data = response.json()
                    console.print(f"[red]✗[/red] Error: {error_data.get('message', 'Unknown error')}")
                except:
                    console.print(f"[red]✗[/red] Response: {response.text}")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error checking KME status: {e}")


@cli.command()
@click.option('--key-type', type=click.Choice(['encryption', 'decryption']), default='encryption')
@click.option('--key-size', default=256, help='Key size in bits')
@click.option('--quantity', default=1, help='Number of keys to request')
@click.option('--slave-sae-id', help='Slave SAE ID (required for encryption keys)')
@click.option('--master-sae-id', help='Master SAE ID (required for decryption keys)')
def request_keys(key_type, key_size, quantity, slave_sae_id, master_sae_id):
    """Request keys from KME server."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Requesting {quantity} {key_type} keys...", total=None)
        
        try:
            if key_type == 'encryption':
                # For encryption keys, we need slave SAE ID
                if not slave_sae_id:
                    slave_sae_id = input("Enter slave SAE ID: ").strip()
                    if not slave_sae_id:
                        console.print("[red]✗[/red] Slave SAE ID is required for encryption keys")
                        return
                
                response = kme_client.request_encryption_keys_for_slave(slave_sae_id, key_size, quantity)
            else:
                # For decryption keys, we need master SAE ID
                if not master_sae_id:
                    master_sae_id = input("Enter master SAE ID: ").strip()
                    if not master_sae_id:
                        console.print("[red]✗[/red] Master SAE ID is required for decryption keys")
                        return
                
                response = kme_client.request_decryption_keys_for_master(master_sae_id, key_size, quantity)
            
            progress.update(task, completed=True)
            
            console.print(f"\n[green]✓[/green] Successfully received {len(response.keys)} keys")
            
            # Display key information
            print_keys(response.keys, f"Received {key_type.title()} Keys")
            
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
            from src.services.key_service import key_service
            available_keys = key_service.get_available_keys()
            
            progress.update(task, completed=True)
            print_keys(available_keys, "Local Keys")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error loading keys: {e}")


@cli.command()
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def reset_keys(confirm):
    """Reset the key database (clear all stored keys)."""
    if not confirm:
        console.print("[yellow]Warning: This will permanently delete all stored keys![/yellow]")
        if not click.confirm("Are you sure you want to reset the key database?"):
            console.print("Operation cancelled.")
            return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Resetting key database...", total=None)
        
        try:
            from src.services.key_service import key_service
            from src.services.storage_service import storage_service
            
            # Get count of keys before deletion
            key_count = len(key_service.get_available_keys())
            
            # Reset the database
            storage_service.reset_database()
            
            # Reload keys in memory
            key_service._load_keys()
            
            progress.update(task, completed=True)
            console.print(f"[green]✓[/green] Successfully reset key database")
            console.print(f"[green]✓[/green] Deleted {key_count} keys")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error resetting key database: {e}")


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
@click.option('--key-ids', help='Comma-separated list of key IDs to request')
def request_from_master(master_id, key_ids):
    """Request keys from a master SAE using ETSI 'Get key with key IDs' method (Slave role only)."""
    if not config_manager.is_slave():
        console.print("[red]Error: This command is only available for SAEs with slave role[/red]")
        return
    
    # Parse key IDs
    if key_ids:
        key_id_list = [kid.strip() for kid in key_ids.split(',') if kid.strip()]
    else:
        # Prompt for key IDs if not provided
        key_ids_input = input("Enter key IDs to request (comma-separated): ").strip()
        if not key_ids_input:
            console.print("[red]✗[/red] Key IDs are required for ETSI 'Get key with key IDs' method")
            return
        key_id_list = [kid.strip() for kid in key_ids_input.split(',') if kid.strip()]
    
    if not key_id_list:
        console.print("[red]✗[/red] At least one key ID is required")
        return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Requesting {len(key_id_list)} keys from master {master_id}...", total=None)
        
        try:
            success = slave_notification_service.request_key_from_master(
                master_id, key_ids=key_id_list
            )
            
            progress.update(task, completed=True)
            
            if success:
                console.print(f"[green]✓[/green] Successfully requested {len(key_id_list)} keys from master {master_id}")
                console.print(f"[green]✓[/green] Keys requested: {', '.join(key_id_list)}")
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


def check_certificate_files():
    """Check if required certificate files exist and warn if missing."""
    missing_files = []
    
    # Check SAE certificate
    if not Path(config.sae_cert_path).exists():
        missing_files.append(f"SAE Certificate: {config.sae_cert_path}")
    
    # Check SAE private key
    if not Path(config.sae_key_path).exists():
        missing_files.append(f"SAE Private Key: {config.sae_key_path}")
    
    # Check CA certificate
    if not Path(config.ca_cert_path).exists():
        missing_files.append(f"CA Certificate: {config.ca_cert_path}")
    
    if missing_files:
        console.print("\n[bold red]⚠ CERTIFICATE WARNING ⚠[/bold red]")
        console.print("[red]The following certificate files are missing:[/red]")
        for file in missing_files:
            console.print(f"  [red]• {file}[/red]")
        console.print("\n[yellow]This may cause authentication failures when connecting to the KME.[/yellow]")
        console.print("[yellow]Please ensure all certificates are properly configured before proceeding.[/yellow]")
        console.print("[dim]You can run './setup_sae.sh' to create certificates if needed.[/dim]")
        console.print()
    
    return len(missing_files) == 0

@cli.command()
def interactive():
    """Start interactive mode."""
    # Setup readline for command autocomplete
    try:
        readline.set_completer(command_completer)
        readline.parse_and_bind('tab: complete')
        autocomplete_available = True
    except Exception as e:
        console.print(f"[yellow]Warning: Autocomplete not available: {e}[/yellow]")
        autocomplete_available = False
    
    console.print("[bold blue]SAE Client Interactive Mode[/bold blue]")
    console.print("Type 'help' for available commands, 'quit' to exit")
    if autocomplete_available:
        console.print("[dim]Tip: Press TAB for command autocomplete[/dim]")
    console.print()
    
    # Check certificate files and warn if missing
    check_certificate_files()
    
    while True:
        try:
            command = input(f"{config.sae_id}> ")
            
            # Skip empty commands (just carriage return)
            if not command.strip():
                continue
            
            if command.lower() in ['quit', 'exit', 'q']:
                console.print("Goodbye!")
                break
            elif command.lower() in ['help', '?']:
                console.print("""
Available commands:
  health              - Show SAE health and configuration
  request-keys        - Request keys from KME
  list-keys           - List local keys
  notify-slave        - Notify slave of available key (Master role)
  request-from-master - Request keys from master (Slave role)
  test-connection     - Test KME connection
  test-menu           - Test Easy-KME server routes
  help, ?             - Show this help
  quit                - Exit interactive mode
                """)
            elif command.lower() == 'health':
                # Call health function directly
                try:
                    # Get KME server health and root info
                    kme_health = kme_client.get_health()
                    kme_root_info = kme_client.get_root_info()
                    
                    # Get key statistics
                    from src.services.key_service import key_service
                    key_stats = key_service.get_key_statistics()
                    
                    # Create SAE status
                    sae_status = SAEStatus(
                        sae_id=config.sae_id,
                        mode=config_manager.get_roles_display(),
                        status="active" if kme_health.status == "healthy" else "inactive",
                        available_keys=key_stats['available_keys'],
                        total_keys=key_stats['total_keys'],
                        last_activity=datetime.now(),
                        connected_slaves=[] if config_manager.is_master() else None,
                        connected_master=None if config_manager.is_master() else "MASTER_001"
                    )
                    
                    # Print SAE Configuration
                    console.print("\n[bold blue]SAE Configuration[/bold blue]")
                    config_table = Table(title="SAE Node Configuration")
                    config_table.add_column("Property", style="cyan")
                    config_table.add_column("Value", style="green")
                    
                    config_table.add_row("SAE ID", config.sae_id)
                    config_table.add_row("Roles", config_manager.get_roles_display())
                    config_table.add_row("Mode (Legacy)", config.sae_mode)
                    config_table.add_row("KME Host", config.kme_host)
                    config_table.add_row("KME Port", str(config.kme_port))
                    config_table.add_row("KME Base URL", config.kme_base_url)
                    config_table.add_row("SSL Verification", "Enabled" if config.verify_ssl else "Disabled")
                    config_table.add_row("Timeout", f"{config.timeout}s")
                    config_table.add_row("Max Retries", str(config.max_retries))
                    config_table.add_row("Data Directory", config.data_dir)
                    config_table.add_row("Logs Directory", config.logs_dir)
                    config_table.add_row("Certificate Path", config.sae_cert_path)
                    config_table.add_row("Private Key Path", config.sae_key_path)
                    config_table.add_row("CA Certificate Path", config.ca_cert_path)
                    
                    console.print(config_table)
                    
                    # Print SAE Status
                    print_status(sae_status)
                    
                    # Show KME server information
                    console.print(f"\n[bold blue]KME Server Information[/bold blue]")
                    console.print(f"[green]✓[/green] Status: {kme_health.status}")
                    console.print(f"[green]✓[/green] Version: {kme_root_info.get('version', 'unknown')}")
                    console.print(f"[green]✓[/green] Specification: {kme_root_info.get('specification', 'unknown')}")
                    console.print(f"[green]✓[/green] Message: {kme_root_info.get('message', 'unknown')}")
                    console.print(f"[green]✓[/green] Documentation: {kme_root_info.get('docs', 'unknown')}")
                    console.print(f"[green]✓[/green] Health Timestamp: {kme_health.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                except Exception as e:
                    console.print(f"[red]✗[/red] Error checking health: {e}")
                    
            elif command.lower() == 'status':
                # Call status function directly
                try:
                    slave_id = input("Enter slave SAE ID to check status for: ").strip()
                    if not slave_id:
                        console.print("[red]✗[/red] Slave SAE ID is required")
                        continue
                    
                    # Call the KME status endpoint
                    response = kme_client.session.get(f"{config.kme_base_url}/api/v1/keys/{slave_id}/status")
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Display status information
                        console.print(f"\n[bold blue]KME Status for Slave SAE: {slave_id}[/bold blue]")
                        
                        status_table = Table(title="Key Availability and Capabilities")
                        status_table.add_column("Property", style="cyan")
                        status_table.add_column("Value", style="green")
                        status_table.add_column("Description", style="yellow")
                        
                        status_table.add_row("Source KME ID", data.get('source_KME_ID', 'N/A'), "KME providing the status")
                        status_table.add_row("Target KME ID", data.get('target_KME_ID', 'N/A'), "Target KME (if different)")
                        status_table.add_row("Master SAE ID", data.get('master_SAE_ID', 'N/A'), "Calling master SAE")
                        status_table.add_row("Slave SAE ID", data.get('slave_SAE_ID', 'N/A'), "Specified slave SAE")
                        status_table.add_row("Default Key Size", str(data.get('key_size', 'N/A')), "Default key size in bits")
                        status_table.add_row("Stored Key Count", str(data.get('stored_key_count', 'N/A')), "Available keys for this SAE")
                        status_table.add_row("Max Key Count", str(data.get('max_key_count', 'N/A')), "Maximum keys KME can store")
                        status_table.add_row("Max Per Request", str(data.get('max_key_per_request', 'N/A')), "Max keys per single request")
                        status_table.add_row("Max Key Size", str(data.get('max_key_size', 'N/A')), "Maximum supported key size")
                        status_table.add_row("Min Key Size", str(data.get('min_key_size', 'N/A')), "Minimum supported key size")
                        status_table.add_row("Max SAE Count", str(data.get('max_SAE_ID_count', 'N/A')), "Max additional SAEs for multicast")
                        
                        console.print(status_table)
                        
                        # Show recommendations
                        console.print(f"\n[bold blue]Recommendations:[/bold blue]")
                        stored_count = data.get('stored_key_count', 0)
                        max_per_request = data.get('max_key_per_request', 1)
                        
                        if stored_count > 0:
                            console.print(f"[green]✓[/green] {stored_count} keys available for requests")
                            console.print(f"[green]✓[/green] Optimal request size: {min(max_per_request, stored_count)} keys")
                        else:
                            console.print(f"[yellow]⚠[/yellow] No keys currently available")
                        
                        if data.get('max_SAE_ID_count', 0) > 0:
                            console.print(f"[green]✓[/green] Multicast supported (up to {data.get('max_SAE_ID_count')} additional SAEs)")
                        else:
                            console.print(f"[yellow]⚠[/yellow] Multicast not supported")
                            
                    else:
                        console.print(f"[red]✗[/red] KME status request failed: {response.status_code}")
                        try:
                            error_data = response.json()
                            console.print(f"[red]✗[/red] Error: {error_data.get('message', 'Unknown error')}")
                        except:
                            console.print(f"[red]✗[/red] Response: {response.text}")
                    
                except Exception as e:
                    console.print(f"[red]✗[/red] Error checking KME status: {e}")
                    
            elif command.lower() == 'request-keys':
                # Call request-keys function directly with ETSI compliance
                try:
                    # Prompt for slave SAE ID for encryption keys
                    slave_sae_id = input("Enter slave SAE ID: ").strip()
                    if not slave_sae_id:
                        console.print("[red]✗[/red] Slave SAE ID is required for encryption keys")
                        continue
                    
                    from src.services.key_service import key_service
                    response = key_service.request_keys_from_kme(KeyType.ENCRYPTION, 256, 1, slave_sae_id=slave_sae_id)
                    console.print(f"\n[green]✓[/green] Successfully received and stored {len(response.keys)} keys")
                    
                    # Display key information
                    print_keys(response.keys, "Received Encryption Keys")
                    
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
                    
            elif command.lower() == 'reset-keys':
                # Call reset-keys function directly
                try:
                    console.print("[yellow]Warning: This will permanently delete all stored keys![/yellow]")
                    confirm = input("Are you sure you want to reset the key database? (yes/no): ").strip().lower()
                    
                    if confirm in ['yes', 'y']:
                        from src.services.key_service import key_service
                        from src.services.storage_service import storage_service
                        
                        # Get count of keys before deletion
                        key_count = len(key_service.get_available_keys())
                        
                        # Reset the database
                        if storage_service.reset_database():
                            # Reload keys in memory
                            key_service._load_keys()
                            console.print(f"[green]✓[/green] Successfully reset key database")
                            console.print(f"[green]✓[/green] Deleted {key_count} keys")
                        else:
                            console.print(f"[red]✗[/red] Failed to reset key database")
                    else:
                        console.print("Operation cancelled.")
                        
                except Exception as e:
                    console.print(f"[red]✗[/red] Error resetting key database: {e}")
                    
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
                    
            elif command.lower() == 'request-from-master':
                # Call request-from-master function directly with ETSI compliance
                try:
                    if not config_manager.is_slave():
                        console.print("[red]✗[/red] This command is only available for SAEs with slave role")
                        continue
                    
                    # Prompt for master SAE ID
                    master_sae_id = input("Enter master SAE ID: ").strip()
                    if not master_sae_id:
                        console.print("[red]✗[/red] Master SAE ID is required")
                        continue
                    
                    # Prompt for key IDs
                    key_ids_input = input("Enter key IDs to request (comma-separated): ").strip()
                    if not key_ids_input:
                        console.print("[red]✗[/red] Key IDs are required for ETSI 'Get key with key IDs' method")
                        continue
                    
                    key_id_list = [kid.strip() for kid in key_ids_input.split(',') if kid.strip()]
                    if not key_id_list:
                        console.print("[red]✗[/red] At least one key ID is required")
                        continue
                    
                    # Make the request
                    success = slave_notification_service.request_key_from_master(
                        master_sae_id, key_ids=key_id_list
                    )
                    
                    if success:
                        console.print(f"[green]✓[/green] Successfully requested {len(key_id_list)} keys from master {master_sae_id}")
                        console.print(f"[green]✓[/green] Keys requested: {', '.join(key_id_list)}")
                    else:
                        console.print(f"[red]✗[/red] Failed to request keys from master {master_sae_id}")
                        
                except Exception as e:
                    console.print(f"[red]✗[/red] Error requesting from master: {e}")
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
  b. Back to main menu
        """)
        
        choice = input("Enter your choice (1-10, b): ").strip()
        
        if choice.lower() == 'b':
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
        
        # Pretty print JSON response
        try:
            json_data = response.json()
            json_str = json.dumps(json_data, indent=2)
            if len(json_str) > 2048:
                console.print(f"[green]✓[/green] Response (truncated):\n{json_str[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response:\n{json_str}")
        except json.JSONDecodeError:
            # Not JSON, show as text
            if len(response.text) > 2048:
                console.print(f"[green]✓[/green] Response (truncated): {response.text[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response: {response.text}")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


def test_health_endpoint():
    """Test the health endpoint."""
    console.print("\n[bold]Testing Health Endpoint (/health) - GET[/bold]")
    console.print("[dim]Purpose: Health check (No ETSI Compliance)[/dim]")
    
    try:
        response = kme_client.session.get(f"{config.kme_base_url}/health")
        console.print(f"[green]✓[/green] Status Code: {response.status_code}")
        
        # Pretty print JSON response
        try:
            json_data = response.json()
            json_str = json.dumps(json_data, indent=2)
            if len(json_str) > 2048:
                console.print(f"[green]✓[/green] Response (truncated):\n{json_str[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response:\n{json_str}")
        except json.JSONDecodeError:
            # Not JSON, show as text
            if len(response.text) > 2048:
                console.print(f"[green]✓[/green] Response (truncated): {response.text[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response: {response.text}")
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
        
        # Pretty print JSON response
        try:
            json_data = response.json()
            json_str = json.dumps(json_data, indent=2)
            if len(json_str) > 2048:
                console.print(f"[green]✓[/green] Response (truncated):\n{json_str[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response:\n{json_str}")
        except json.JSONDecodeError:
            # Not JSON, show as text
            if len(response.text) > 2048:
                console.print(f"[green]✓[/green] Response (truncated): {response.text[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response: {response.text}")
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
            
        # Pretty print JSON response
        try:
            json_data = response.json()
            json_str = json.dumps(json_data, indent=2)
            if len(json_str) > 2048:
                console.print(f"[green]✓[/green] Response (truncated):\n{json_str[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response:\n{json_str}")
        except json.JSONDecodeError:
            # Not JSON, show as text
            if len(response.text) > 2048:
                console.print(f"[green]✓[/green] Response (truncated): {response.text[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response: {response.text}")
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
        
        # Pretty print JSON response
        try:
            json_data = response.json()
            json_str = json.dumps(json_data, indent=2)
            if len(json_str) > 2048:
                console.print(f"[green]✓[/green] Response (truncated):\n{json_str[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response:\n{json_str}")
        except json.JSONDecodeError:
            # Not JSON, show as text
            if len(response.text) > 2048:
                console.print(f"[green]✓[/green] Response (truncated): {response.text[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response: {response.text}")
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
        
        # Pretty print JSON response
        try:
            json_data = response.json()
            json_str = json.dumps(json_data, indent=2)
            if len(json_str) > 2048:
                console.print(f"[green]✓[/green] Response (truncated):\n{json_str[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response:\n{json_str}")
        except json.JSONDecodeError:
            # Not JSON, show as text
            if len(response.text) > 2048:
                console.print(f"[green]✓[/green] Response (truncated): {response.text[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response: {response.text}")
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
        
        # Pretty print JSON response
        try:
            json_data = response.json()
            json_str = json.dumps(json_data, indent=2)
            if len(json_str) > 2048:
                console.print(f"[green]✓[/green] Response (truncated):\n{json_str[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response:\n{json_str}")
        except json.JSONDecodeError:
            # Not JSON, show as text
            if len(response.text) > 2048:
                console.print(f"[green]✓[/green] Response (truncated): {response.text[:2048]}...")
            else:
                console.print(f"[green]✓[/green] Response: {response.text}")
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
