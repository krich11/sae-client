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
        table = Table(title=title, show_header=True, header_style="bold magenta")
        table.add_column("Key ID", style="cyan", no_wrap=True, overflow="fold")
        table.add_column("Key Material (Base64)", style="green", no_wrap=True, overflow="fold")
        table.add_column("Key ID Extension", style="yellow")
        table.add_column("Key Extension", style="magenta")
        
        for key in keys:
            key_id_ext = str(key.key_ID_extension) if key.key_ID_extension else "None"
            key_ext = str(key.key_extension) if key.key_extension else "None"
            
            table.add_row(
                key.key_ID,  # Full key ID - no truncation
                key.key,     # Full key material - no truncation
                key_id_ext,
                key_ext
            )
            
            # Add debug row with full key material if debug mode is enabled
            if config_manager.config.debug_mode:
                import hashlib
                key_id_and_material = f"{key.key_ID}{key.key}"
                md5_hash = hashlib.md5(key_id_and_material.encode()).hexdigest()
                
                # Add a row with full key material and MD5 hash
                table.add_row(
                    f"[dim]Full Key Material:[/dim]",
                    f"[dim]{key.key}[/dim]",  # Full key material - no truncation
                    f"[dim]MD5: {md5_hash}[/dim]",
                    ""  # Empty for key extension column
                )
        
        console.print(table)
        
        # Debug mode: Print full key details separately to ensure no truncation
        if config_manager.config.debug_mode:
            console.print("\n[bold yellow]DEBUG MODE - Full ETSI Key Details:[/bold yellow]")
            for key in keys:
                import hashlib
                key_id_and_material = f"{key.key_ID}{key.key}"
                md5_hash = hashlib.md5(key_id_and_material.encode()).hexdigest()
                
                console.print(f"\n[cyan]Key ID:[/cyan] {key.key_ID}")
                console.print(f"[green]Key Material:[/green] {key.key}")
                console.print(f"[yellow]MD5 Hash (ID+Material):[/yellow] {md5_hash}")
                console.print("─" * 80)
    else:
        # Local key format
        table = Table(title=title, show_header=True, header_style="bold magenta")
        table.add_column("Key ID", style="cyan", no_wrap=True, overflow="fold")
        table.add_column("Type", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Status", style="magenta")
        table.add_column("Source", style="blue")
        table.add_column("Allowed SAE", style="magenta")
        table.add_column("Created", style="white")
        
        for key in keys:
            # Get allowed SAE from the dedicated field or metadata
            allowed_sae = key.allowed_sae_id if hasattr(key, 'allowed_sae_id') and key.allowed_sae_id else (key.metadata.get('allowed_sae_id', 'N/A') if key.metadata else 'N/A')
            
            table.add_row(
                key.key_id,  # Full key ID - no truncation
                key.key_type.value if hasattr(key.key_type, 'value') else str(key.key_type),
                str(key.key_size),
                key.status.value if hasattr(key.status, 'value') else str(key.status),
                key.source,
                allowed_sae,
                key.creation_time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
            # Add debug row with full key material if debug mode is enabled
            if config_manager.config.debug_mode:
                import hashlib
                key_id_and_material = f"{key.key_id}{key.key_material}"
                md5_hash = hashlib.md5(key_id_and_material.encode()).hexdigest()
                
                # Add a row with full key material and MD5 hash
                table.add_row(
                    f"[dim]Full Key Material:[/dim]",
                    f"[dim]{key.key_material}[/dim]",  # Full key material - no truncation
                    f"[dim]MD5: {md5_hash}[/dim]",
                    "",  # Empty for status column
                    "",  # Empty for source column
                    "",  # Empty for allowed SAE column
                    ""   # Empty for created column
        )
    
        console.print(table)
        
        # Debug mode: Print full key details separately to ensure no truncation
        if config_manager.config.debug_mode:
            console.print("\n[bold yellow]DEBUG MODE - Full Key Details:[/bold yellow]")
            for key in keys:
                import hashlib
                key_id_and_material = f"{key.key_id}{key.key_material}"
                md5_hash = hashlib.md5(key_id_and_material.encode()).hexdigest()
                
                console.print(f"\n[cyan]Key ID:[/cyan] {key.key_id}")
                console.print(f"[green]Key Material:[/green] {key.key_material}")
                console.print(f"[yellow]MD5 Hash (ID+Material):[/yellow] {md5_hash}")
                console.print(f"[blue]Size:[/blue] {key.key_size} bits")
                console.print(f"[magenta]Allowed SAE:[/magenta] {key.allowed_sae_id if hasattr(key, 'allowed_sae_id') and key.allowed_sae_id else 'N/A'}")
                console.print("─" * 80)


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
def debug():
    """Toggle debug mode on/off."""
    current_debug = config_manager.config.debug_mode
    new_debug = not current_debug
    config_manager.update_config(debug_mode=new_debug)
    
    if new_debug:
        console.print("[green]✓[/green] Debug mode enabled")
        console.print("[yellow]Debug mode will show:")
        console.print("  • Full key IDs and key material")
        console.print("  • MD5 hashes of key ID + material")
        console.print("  • All KME request URLs and JSON data")
        console.print("  • All KME response JSON data")
        console.print("  • All UDP synchronization messages")
        console.print("  • Message signing and verification details")
        console.print("  • Session state transitions")
        console.print("  • Key rotation scheduling and execution")
        console.print("  • Device persona operations")
    else:
        console.print("[green]✓[/green] Debug mode disabled")


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
            
            # Show combined KME information
            if 'status' in kme_root_info:
                console.print(f"[green]✓[/green] Server Status: {kme_root_info['status']}")
            if 'version' in kme_root_info:
                console.print(f"[green]✓[/green] Server Version: {kme_root_info['version']}")
            if 'timestamp' in kme_root_info:
                console.print(f"[green]✓[/green] Server Timestamp: {kme_root_info['timestamp']}")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Health check error: {e}")


@cli.command()
@click.option('--slave-id', required=True, help='Slave SAE ID to get status for')
def status(slave_id):
    """Get ETSI GS QKD 014 status for a specific slave SAE."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Getting status for slave {slave_id}...", total=None)
        
        try:
            # Get ETSI status for the specified slave SAE
            status_data = kme_client.get_etsi_status(slave_id)
            
            progress.update(task, completed=True)
            
            # Display status information
            console.print(f"\n[bold blue]ETSI Status for Slave SAE: {slave_id}[/bold blue]")
            
            # Create status table
            status_table = Table(title="KME Status Information")
            status_table.add_column("Property", style="cyan")
            status_table.add_column("Value", style="green")
            
            # Add status fields based on ETSI GS QKD 014 Section 6.1
            if 'source_KME_ID' in status_data:
                status_table.add_row("Source KME ID", status_data['source_KME_ID'])
            if 'target_KME_ID' in status_data:
                status_table.add_row("Target KME ID", status_data['target_KME_ID'])
            if 'master_SAE_ID' in status_data:
                status_table.add_row("Master SAE ID", status_data['master_SAE_ID'])
            if 'slave_SAE_ID' in status_data:
                status_table.add_row("Slave SAE ID", status_data['slave_SAE_ID'])
            if 'key_size' in status_data:
                status_table.add_row("Default Key Size", f"{status_data['key_size']} bits")
            if 'stored_key_count' in status_data:
                status_table.add_row("Stored Key Count", str(status_data['stored_key_count']))
            if 'max_key_count' in status_data:
                status_table.add_row("Max Key Count", str(status_data['max_key_count']))
            if 'max_key_per_request' in status_data:
                status_table.add_row("Max Keys Per Request", str(status_data['max_key_per_request']))
            if 'max_key_size' in status_data:
                status_table.add_row("Max Key Size", f"{status_data['max_key_size']} bits")
            if 'min_key_size' in status_data:
                status_table.add_row("Min Key Size", f"{status_data['min_key_size']} bits")
            if 'max_SAE_ID_count' in status_data:
                status_table.add_row("Max SAE ID Count", str(status_data['max_SAE_ID_count']))
            if 'status_extension' in status_data:
                status_table.add_row("Status Extension", str(status_data['status_extension']))
            
            console.print(status_table)
            
            # Show summary
            console.print(f"\n[green]✓[/green] Successfully retrieved status for slave {slave_id}")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Status check error: {e}")
            console.print(f"[green]✓[/green] Version: {kme_root_info.get('version', 'unknown')}")
            console.print(f"[green]✓[/green] Specification: {kme_root_info.get('specification', 'unknown')}")
            console.print(f"[green]✓[/green] Message: {kme_root_info.get('message', 'unknown')}")
            console.print(f"[green]✓[/green] Documentation: {kme_root_info.get('docs', 'unknown')}")
            console.print(f"[green]✓[/green] Health Timestamp: {kme_health.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Error checking health: {e}")



@cli.command()
@click.option('--key-type', type=click.Choice(['encryption', 'decryption']), default='encryption')
@click.option('--key-size', default=256, help='Key size in bits')
@click.option('--quantity', default=1, help='Number of keys to request')
@click.option('--slave-sae-id', help='Slave SAE ID(s) - comma-separated list (first ID used for API call, rest as additional_slave_SAE_IDs)')
@click.option('--master-sae-id', help='Master SAE ID (required for decryption keys)')
def request_keys(key_type, key_size, quantity, slave_sae_id, master_sae_id):
    """Request keys from KME server."""
    
    # Prompt for number of keys if not provided
    if quantity == 1:
        quantity_input = input("Enter number of keys to request (default: 1): ").strip()
        if quantity_input:
            try:
                quantity = int(quantity_input)
                if quantity <= 0:
                    console.print("[red]✗[/red] Number of keys must be positive")
                    return
            except ValueError:
                console.print("[red]✗[/red] Invalid number of keys")
                return
    
    # Prompt for key size if not provided
    if key_size == 256:
        key_size_input = input("Enter key size in bits (default: 256): ").strip()
        if key_size_input:
            try:
                key_size = int(key_size_input)
                if key_size <= 0:
                    console.print("[red]✗[/red] Key size must be positive")
                    return
            except ValueError:
                console.print("[red]✗[/red] Invalid key size")
                return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Requesting {quantity} {key_type} keys of size {key_size} bits...", total=None)
        
        try:
            from src.services.key_service import key_service
            
            if key_type == 'encryption':
                # For encryption keys, we need slave SAE ID
                if not slave_sae_id:
                    slave_sae_id = input("Enter slave SAE ID(s) - comma-separated list: ").strip()
                    if not slave_sae_id:
                        console.print("[red]✗[/red] Slave SAE ID is required for encryption keys")
                        return
                
                # Parse comma-separated SAE IDs
                sae_ids = [sae_id.strip() for sae_id in slave_sae_id.split(',') if sae_id.strip()]
                if not sae_ids:
                    console.print("[red]✗[/red] At least one slave SAE ID is required")
                    return
                
                # Use first SAE ID for API call, rest as additional_slave_SAE_IDs
                primary_slave_id = sae_ids[0]
                additional_slave_ids = sae_ids[1:] if len(sae_ids) > 1 else None
                
                console.print(f"[blue]Primary slave SAE ID: {primary_slave_id}[/blue]")
                if additional_slave_ids:
                    console.print(f"[blue]Additional slave SAE IDs: {', '.join(additional_slave_ids)}[/blue]")
                
                response = key_service.request_keys_from_kme(
                    KeyType.ENCRYPTION, 
                    key_size, 
                    quantity, 
                    slave_sae_id=primary_slave_id,
                    additional_slave_sae_ids=additional_slave_ids
                )
            else:
                # For decryption keys, we need master SAE ID
                if not master_sae_id:
                    master_sae_id = input("Enter master SAE ID: ").strip()
                    if not master_sae_id:
                        console.print("[red]✗[/red] Master SAE ID is required for decryption keys")
                        return
                
                response = key_service.request_keys_from_kme(KeyType.DECRYPTION, key_size, quantity, master_sae_id=master_sae_id)
            
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
    """Notify a slave SAE of available key."""
    
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
@click.option('--key-ids', help='Comma-separated list of key IDs to request (e.g., "key1,key2,key3")')
def request_from_master(master_id, key_ids):
    """Request keys from a master SAE using ETSI 'Get key with key IDs' method.
    
    This command allows requesting multiple keys by providing a comma-separated list of key IDs.
    The keys must have been previously shared by the master SAE for this slave SAE to access them.
    
    Examples:
        python sae_client.py request-from-master --master-id SAE_001 --key-ids "key1,key2,key3"
        python sae_client.py request-from-master --master-id SAE_001  # Prompts for key IDs
    """
    
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
                if len(key_id_list) == 1:
                    console.print(f"[green]✓[/green] Key requested: {key_id_list[0]}")
                else:
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
  status              - Get ETSI status for a slave SAE
  request-keys        - Request keys from KME
  list-keys           - List local keys
  notify-slave        - Notify slave of available key
  request-from-master - Request keys from master
  test-connection     - Test KME connection
  test-menu           - Test Easy-KME server routes
  debug               - Toggle debug mode on/off
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
                    
                    # Get ETSI status for the specified slave SAE
                    status_data = kme_client.get_etsi_status(slave_id)
                    
                    # Display status information
                    console.print(f"\n[bold blue]ETSI Status for Slave SAE: {slave_id}[/bold blue]")
                    
                    # Create status table
                    status_table = Table(title="KME Status Information")
                    status_table.add_column("Property", style="cyan")
                    status_table.add_column("Value", style="green")
                    
                    # Add status fields based on ETSI GS QKD 014 Section 6.1
                    if 'source_KME_ID' in status_data:
                        status_table.add_row("Source KME ID", status_data['source_KME_ID'])
                    if 'target_KME_ID' in status_data:
                        status_table.add_row("Target KME ID", status_data['target_KME_ID'])
                    if 'master_SAE_ID' in status_data:
                        status_table.add_row("Master SAE ID", status_data['master_SAE_ID'])
                    if 'slave_SAE_ID' in status_data:
                        status_table.add_row("Slave SAE ID", status_data['slave_SAE_ID'])
                    if 'key_size' in status_data:
                        status_table.add_row("Default Key Size", f"{status_data['key_size']} bits")
                    if 'stored_key_count' in status_data:
                        status_table.add_row("Stored Key Count", str(status_data['stored_key_count']))
                    if 'max_key_count' in status_data:
                        status_table.add_row("Max Key Count", str(status_data['max_key_count']))
                    if 'max_key_per_request' in status_data:
                        status_table.add_row("Max Keys Per Request", str(status_data['max_key_per_request']))
                    if 'max_key_size' in status_data:
                        status_table.add_row("Max Key Size", f"{status_data['max_key_size']} bits")
                    if 'min_key_size' in status_data:
                        status_table.add_row("Min Key Size", f"{status_data['min_key_size']} bits")
                    if 'max_SAE_ID_count' in status_data:
                        status_table.add_row("Max SAE ID Count", str(status_data['max_SAE_ID_count']))
                    if 'status_extension' in status_data:
                        status_table.add_row("Status Extension", str(status_data['status_extension']))
                    
                    console.print(status_table)
                    
                    # Show summary
                    console.print(f"\n[green]✓[/green] Successfully retrieved status for slave {slave_id}")
                    
                except Exception as e:
                    console.print(f"[red]✗[/red] Status check error: {e}")
                    
            elif command.lower() == 'request-keys':
                # Call request-keys function directly with ETSI compliance
                try:
                    # Prompt for number of keys
                    quantity_input = input("Enter number of keys to request (default: 1): ").strip()
                    quantity = 1
                    if quantity_input:
                        try:
                            quantity = int(quantity_input)
                            if quantity <= 0:
                                console.print("[red]✗[/red] Number of keys must be positive")
                                continue
                        except ValueError:
                            console.print("[red]✗[/red] Invalid number of keys")
                            continue
                    
                    # Prompt for key size
                    key_size_input = input("Enter key size in bits (default: 256): ").strip()
                    key_size = 256
                    if key_size_input:
                        try:
                            key_size = int(key_size_input)
                            if key_size <= 0:
                                console.print("[red]✗[/red] Key size must be positive")
                                continue
                        except ValueError:
                            console.print("[red]✗[/red] Invalid key size")
                            continue
                    
                    # Prompt for slave SAE ID(s) for encryption keys
                    slave_sae_id = input("Enter slave SAE ID(s) - comma-separated list: ").strip()
                    if not slave_sae_id:
                        console.print("[red]✗[/red] Slave SAE ID is required for encryption keys")
                        continue
                    
                    # Parse comma-separated SAE IDs
                    sae_ids = [sae_id.strip() for sae_id in slave_sae_id.split(',') if sae_id.strip()]
                    if not sae_ids:
                        console.print("[red]✗[/red] At least one slave SAE ID is required")
                        continue
                    
                    # Use first SAE ID for API call, rest as additional_slave_SAE_IDs
                    primary_slave_id = sae_ids[0]
                    additional_slave_ids = sae_ids[1:] if len(sae_ids) > 1 else None
                    
                    console.print(f"[blue]Primary slave SAE ID: {primary_slave_id}[/blue]")
                    if additional_slave_ids:
                        console.print(f"[blue]Additional slave SAE IDs: {', '.join(additional_slave_ids)}[/blue]")
                    
                    from src.services.key_service import key_service
                    response = key_service.request_keys_from_kme(
                        KeyType.ENCRYPTION, 
                        key_size, 
                        quantity, 
                        slave_sae_id=primary_slave_id,
                        additional_slave_sae_ids=additional_slave_ids
                    )
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
                    
                    # Prompt for master SAE ID
                    master_sae_id = input("Enter master SAE ID: ").strip()
                    if not master_sae_id:
                        console.print("[red]✗[/red] Master SAE ID is required")
                        continue
                    
                    # Prompt for key IDs
                    key_ids_input = input("Enter key IDs to request (comma-separated, e.g., key1,key2,key3): ").strip()
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
                        if len(key_id_list) == 1:
                            console.print(f"[green]✓[/green] Key requested: {key_id_list[0]}")
                        else:
                            console.print(f"[green]✓[/green] Keys requested: {', '.join(key_id_list)}")
                    else:
                        console.print(f"[red]✗[/red] Failed to request keys from master {master_sae_id}")
                        
                except Exception as e:
                    console.print(f"[red]✗[/red] Error requesting from master: {e}")
                    
            elif command.lower() == 'notify-slave':
                # Call notify-slave function directly
                try:
                    # Prompt for slave SAE ID
                    slave_sae_id = input("Enter slave SAE ID: ").strip()
                    if not slave_sae_id:
                        console.print("[red]✗[/red] Slave SAE ID is required")
                        continue
                    
                    # Prompt for key ID
                    key_id = input("Enter key ID to notify about: ").strip()
                    if not key_id:
                        console.print("[red]✗[/red] Key ID is required")
                        continue
                    
                    # Get actual key data from local storage
                    from src.services.key_service import key_service
                    available_keys = key_service.get_available_keys()
                    
                    # Find the key in local storage
                    key_data = None
                    for key in available_keys:
                        if key.key_id == key_id:
                            key_data = {
                                'key_type': key.key_type,
                                'key_size': key.key_size,
                                'key_material': key.key_material,
                                'expiry_time': key.expiry_time.isoformat() if key.expiry_time else None
                            }
                            break
                    
                    if not key_data:
                        console.print(f"[yellow]⚠[/yellow] Key {key_id} not found in local storage, using dummy data")
                        key_data = {
                            'key_type': KeyType.ENCRYPTION,
                            'key_size': 256,
                            'key_material': 'dummy_key_material',
                            'expiry_time': None
                        }
                    
                    # Make the notification
                    success = master_notification_service.notify_slave_available_key(
                        slave_sae_id, key_id, key_data
                    )
                    
                    if success:
                        console.print(f"[green]✓[/green] Successfully notified slave {slave_sae_id} about key {key_id}")
                    else:
                        console.print(f"[red]✗[/red] Failed to notify slave {slave_sae_id}")
                        
                except Exception as e:
                    console.print(f"[red]✗[/red] Error notifying slave: {e}")
                    
            elif command.lower() == 'debug':
                # Toggle debug mode
                current_debug = config_manager.config.debug_mode
                new_debug = not current_debug
                config_manager.update_config(debug_mode=new_debug)
                
                if new_debug:
                    console.print("[green]✓[/green] Debug mode enabled")
                    console.print("[yellow]Debug mode will show:")
                    console.print("  • Full key IDs and key material")
                    console.print("  • MD5 hashes of key ID + material")
                    console.print("  • All KME request URLs and JSON data")
                    console.print("  • All KME response JSON data")
                else:
                    console.print("[green]✓[/green] Debug mode disabled")
                    
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


@cli.command()
@click.option('--slave-id', required=True, help='Slave SAE ID to notify')
@click.option('--key-ids', required=True, help='Comma-separated list of key IDs to notify about')
@click.option('--slave-host', required=True, help='Slave SAE host/IP address')
@click.option('--slave-port', default=5000, help='Slave SAE UDP port (default: 5000)')
@click.option('--rotation-delay', default=300, help='Rotation delay in seconds (default: 300)')
def notify_slave_sync(slave_id, key_ids, slave_host, slave_port, rotation_delay):
    """Notify a slave SAE of available keys for synchronized rotation."""
    try:
        from src.services.udp_service import udp_service
        from src.utils.message_signer import message_signer
        import time
        
        # Debug logging for sync notification
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Notifying slave {slave_id} at {slave_host}:{slave_port}")
            console.print(f"[blue]DEBUG:[/blue] Key IDs: {key_ids}")
            console.print(f"[blue]DEBUG:[/blue] Rotation delay: {rotation_delay} seconds")
        
        # Parse key IDs
        key_id_list = [kid.strip() for kid in key_ids.split(',') if kid.strip()]
        if not key_id_list:
            console.print("[red]✗[/red] At least one key ID is required")
            return
        
        # Calculate rotation timestamp
        rotation_timestamp = int(time.time()) + rotation_delay
        
        # Debug logging for timestamp calculation
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Current time: {time.ctime()}")
            console.print(f"[blue]DEBUG:[/blue] Rotation timestamp: {rotation_timestamp}")
            console.print(f"[blue]DEBUG:[/blue] Rotation time: {time.ctime(rotation_timestamp)}")
        
        # Create key notification message
        signed_message = message_signer.create_key_notification(
            key_ids=key_id_list,
            rotation_timestamp=rotation_timestamp,
            master_sae_id=config.sae_id,
            slave_sae_id=slave_id
        )
        
        # Debug logging for message creation
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Created signed message")
            console.print(f"[blue]DEBUG:[/blue] Message ID: {signed_message.payload[:50]}...")
            console.print(f"[blue]DEBUG:[/blue] Signature size: {len(signed_message.signature)} bytes")
        
        # Send message
        success = udp_service.send_message(signed_message, slave_host, slave_port)
        
        if success:
            console.print(f"[green]✓[/green] Successfully notified slave {slave_id}")
            console.print(f"[green]✓[/green] Key IDs: {', '.join(key_id_list)}")
            console.print(f"[green]✓[/green] Rotation timestamp: {rotation_timestamp}")
            console.print(f"[green]✓[/green] Rotation time: {time.ctime(rotation_timestamp)}")
        else:
            console.print(f"[red]✗[/red] Failed to notify slave {slave_id}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error notifying slave: {e}")


@cli.command()
@click.option('--port', default=5000, help='UDP port to listen on (default: 5000)')
def start_sync_listener(port):
    """Start UDP listener for synchronization messages."""
    try:
        from src.services.udp_service import udp_service
        
        # Debug logging for listener startup
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Starting UDP listener on port {port}")
            console.print(f"[blue]DEBUG:[/blue] Debug mode enabled - will show detailed message logs")
            console.print(f"[blue]DEBUG:[/blue] SAE ID: {config_manager.config.sae_id}")
        
        console.print(f"[blue]Starting UDP listener on port {port}...[/blue]")
        
        success = udp_service.start_listener(port)
        
        if success:
            console.print(f"[green]✓[/green] UDP listener started on port {port}")
            console.print("[yellow]Press Ctrl+C to stop the listener[/yellow]")
            
            # Debug logging for listener status
            if config_manager.config.debug_mode:
                console.print(f"[blue]DEBUG:[/blue] Listener status: {'Running' if udp_service.is_running else 'Stopped'}")
                console.print(f"[blue]DEBUG:[/blue] Socket: {udp_service.socket}")
                console.print(f"[blue]DEBUG:[/blue] Thread: {udp_service.listener_thread}")
            
            try:
                # Keep the listener running
                while udp_service.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopping UDP listener...[/yellow]")
                udp_service.stop_listener()
                console.print("[green]✓[/green] UDP listener stopped")
        else:
            console.print(f"[red]✗[/red] Failed to start UDP listener on port {port}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error starting listener: {e}")


@cli.command()
def sync_status():
    """Show synchronization status and sessions."""
    try:
        from src.services.udp_service import udp_service
        from rich.table import Table
        
        # Debug logging for sync status
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Getting synchronization status")
            console.print(f"[blue]DEBUG:[/blue] SAE ID: {config_manager.config.sae_id}")
            console.print(f"[blue]DEBUG:[/blue] Debug mode: {config_manager.config.debug_mode}")
        
        sessions = udp_service.get_sessions()
        
        # Debug logging for sessions
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Found {len(sessions)} active sessions")
            for session_id, session in sessions.items():
                console.print(f"[blue]DEBUG:[/blue] Session {session_id[:8]}...: {session.state}")
        
        if not sessions:
            console.print("[yellow]No active synchronization sessions[/yellow]")
            return
        
        # Create sessions table
        table = Table(title="Synchronization Sessions")
        table.add_column("Session ID", style="cyan")
        table.add_column("Master SAE", style="green")
        table.add_column("Slave SAE", style="blue")
        table.add_column("State", style="yellow")
        table.add_column("Key Count", style="magenta")
        table.add_column("Rotation Time", style="white")
        table.add_column("Updated", style="dim")
        
        for session_id, session in sessions.items():
            rotation_time = time.ctime(session.rotation_timestamp) if session.rotation_timestamp else "N/A"
            updated_time = session.updated_at.strftime("%H:%M:%S")
            
            table.add_row(
                session_id[:8] + "...",
                session.master_sae_id,
                session.slave_sae_id,
                session.state.value,
                str(len(session.key_ids)),
                rotation_time,
                updated_time
            )
        
        console.print(table)
        
        # Show listener status
        listener_status = "Running" if udp_service.is_running else "Stopped"
        console.print(f"\n[blue]UDP Listener Status:[/blue] {listener_status}")
        
        # Debug logging for listener details
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Listener running: {udp_service.is_running}")
            console.print(f"[blue]DEBUG:[/blue] Socket bound: {udp_service.socket is not None}")
            console.print(f"[blue]DEBUG:[/blue] Thread alive: {udp_service.listener_thread.is_alive() if udp_service.listener_thread else False}")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error getting sync status: {e}")


@cli.command()
def list_personas():
    """List available device personas."""
    try:
        from src.personas.base_persona import persona_manager
        
        personas = persona_manager.list_personas()
        
        if not personas:
            console.print("[yellow]No personas loaded[/yellow]")
            return
        
        from rich.table import Table
        table = Table(title="Available Device Personas")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Description", style="blue")
        table.add_column("Status", style="yellow")
        
        for name, info in personas.items():
            table.add_row(
                name,
                info.get('version', 'N/A'),
                info.get('description', 'N/A'),
                info.get('device_status', 'unknown')
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error listing personas: {e}")


@cli.command()
@click.option('--persona', required=True, help='Persona name to test')
def test_persona(persona):
    """Test a device persona."""
    try:
        from src.personas.base_persona import persona_manager
        
        # Load persona
        persona_instance = persona_manager.load_persona(persona)
        
        if not persona_instance:
            console.print(f"[red]✗[/red] Failed to load persona: {persona}")
            return
        
        console.print(f"[blue]Testing persona: {persona}[/blue]")
        
        # Test connection
        connection_ok = persona_instance.test_connection()
        console.print(f"[{'green' if connection_ok else 'red'}]✓[/{'green' if connection_ok else 'red'}] Connection: {'OK' if connection_ok else 'FAILED'}")
        
        # Get device status
        status = persona_instance.get_device_status()
        console.print(f"[blue]Device Status:[/blue] {status}")
        
        # Test key validation
        test_key = "dGVzdC1rZXktbWF0ZXJpYWw="  # "test-key-material" in base64
        key_valid = persona_instance.validate_key_material(test_key)
        console.print(f"[{'green' if key_valid else 'red'}]✓[/{'green' if key_valid else 'red'}] Key Validation: {'OK' if key_valid else 'FAILED'}")
        
        console.print(f"[green]✓[/green] Persona test completed")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error testing persona: {e}")


if __name__ == '__main__':
    cli()
