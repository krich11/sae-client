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
            command = Prompt.ask("[bold green]SAE>[/bold green]")
            
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
  help                - Show this help
  quit                - Exit interactive mode
                """)
            elif command.lower() == 'status':
                # Invoke status command
                ctx = click.Context(cli)
                status.callback(ctx)
            elif command.lower() == 'request-keys':
                # Invoke request-keys command
                ctx = click.Context(cli)
                request_keys.callback(ctx)
            elif command.lower() == 'list-keys':
                # Invoke list-keys command
                ctx = click.Context(cli)
                list_keys.callback(ctx)
            elif command.lower() == 'test-connection':
                # Invoke test-connection command
                ctx = click.Context(cli)
                test_connection.callback(ctx)
            else:
                console.print(f"[yellow]Unknown command: {command}[/yellow]")
                console.print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            console.print("\nGoodbye!")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


if __name__ == '__main__':
    cli()
