#!/usr/bin/env python3
"""
SAE Client Command Line Interface.
Main entry point for the SAE client application.
"""

import json
import logging
import readline
import sys
import time
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.api.client import kme_client
from src.config import config, config_manager
from src.models.api_models import KeyType, SAEStatus
from src.services.notification_service import master_notification_service, slave_notification_service

console = Console()

# Hierarchical command structure for autocomplete
COMMAND_HIERARCHY = {
    'show': {
        'health': {},
        'status': {'<sae_id>': {}},
        'keys': {'[keyid <key_id>]': {}},
        'sync': {'status': {}},
        'scheduled': {},
        'personas': {},
        'peer': {'[peer_id]': {}},
        'env': {}
    },
    'key': {
        'request': {
            'encryption': {
                'slave': {'<slave_id>': {
                    '[keysize <size>]': {},
                    '[quantity <quantity>]': {}
                }}
            },
            'decryption': {
                'master': {'<master_id>': {
                    'keyid': {'<key_id>': {}}
                }}
            }
        },
        'reset': {
            '[all]': {},
            'keyid': {'<key_id>': {}}
        },
        'notify': {'<sae_id>': {}}
    },
    'persona': {
        'test': {'[persona_name]': {}},
        'preconfigure-key': {'<key_id>': {}},
        'delete-key': {'<key_id>': {}},
        'roll-key': {'<key_id>': {}},
        'status': {'[persona_name]': {}}
    },
    'peer': {
        'add': {'<sae_id>': {'<host>': {'<port>': {'[roles <roles>]': {'[description <desc>]': {}}}}}},
        'remove': {'<sae_id>': {}}
    },
    'debug': {},
    'test-menu': {},
    'help': {},
    '?': {},
    'quit': {},
    'exit': {},
    'q': {}
}

# Flattened command list for simple autocomplete
AVAILABLE_COMMANDS = [
    'show', 'key', 'persona', 'peer', 'debug', 'test-menu', 'help', '?', 'quit', 'exit', 'q'
]


def command_completer(text, state):
    """Hierarchical command completer function for readline."""
    if not text:
        options = list(COMMAND_HIERARCHY.keys())
    else:
        words = text.split()
        if len(words) == 1:
            # First word - suggest top-level commands
            options = [cmd for cmd in COMMAND_HIERARCHY.keys() if cmd.lower().startswith(words[0].lower())]
        else:
            # Subsequent words - traverse the hierarchy
            current_level = COMMAND_HIERARCHY
            options = []
            
            # Navigate to the current level in the hierarchy
            for i, word in enumerate(words[:-1]):
                if word.lower() in current_level:
                    current_level = current_level[word.lower()]
                else:
                    # If we can't find the word, suggest all possible next words
                    break
            
            # Suggest next possible words
            if isinstance(current_level, dict):
                for key in current_level.keys():
                    if key.lower().startswith(words[-1].lower()):
                        options.append(key)
            
            # If no suggestions found, return empty
            if not options:
                return None
    
    if state < len(options):
        # Add space after all completions for easier continuation
        return options[state] + " "
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


def parse_command(command_line):
    """Parse hierarchical command line into command and arguments."""
    words = command_line.strip().split()
    if not words:
        return None, []
    
    command = words[0].lower()
    args = words[1:]
    
    return command, args


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
                    "[dim]Full Key Material:[/dim]",
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
                    "[dim]Full Key Material:[/dim]",
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


@click.group(invoke_without_command=True)
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config, verbose):
    """SAE Client - ETSI GS QKD 014 Compliant Key Management Client."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if config:
        config_manager.config_file = config
    
    print_banner()
    
    # Check for environment file migration
    try:
        from src.utils.env_migrator import migrate_env_file
        console.print("[blue]Checking environment configuration...[/blue]")
        
        # Run migration check (dry run first)
        from src.utils.env_migrator import EnvMigrator
        migrator = EnvMigrator()
        needs_migration, missing_vars = migrator.needs_migration()
        
        if needs_migration:
            console.print("[yellow]⚠️  Environment migration needed![/yellow]")
            console.print("[yellow]Your .env file is missing some configuration variables from env.template.[/yellow]")
            
            if Confirm.ask("Would you like to migrate your .env file now?", default=True):
                console.print("[blue]Migrating environment configuration...[/blue]")
                success = migrate_env_file(backup=True)
                if success:
                    console.print("[green]✅ Environment migration completed successfully![/green]")
                    console.print("[blue]A backup of your original .env file has been created.[/blue]")
                    console.print("[yellow]Please restart the application for changes to take effect.[/yellow]")
                    sys.exit(0)
                else:
                    console.print("[red]❌ Environment migration failed![/red]")
                    console.print("[yellow]You can continue, but some features may not work correctly.[/yellow]")
            else:
                console.print("[yellow]Migration skipped. Some features may not work correctly.[/yellow]")
        else:
            console.print("[green]✅ Environment configuration is up to date[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠️  Could not check environment migration: {e}[/yellow]")
        console.print("[yellow]Continuing with current configuration...[/yellow]")
    
    # If no command is specified, run interactive mode
    if ctx.invoked_subcommand is None:
        interactive()


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
            
            # Print all environment variables
            console.print("\n[bold blue]Environment Variables[/bold blue]")
            env_table = Table(title="All Environment Variables")
            env_table.add_column("Variable", style="cyan")
            env_table.add_column("Value", style="green")
            env_table.add_column("Source", style="yellow")
            
            # Parse .env file to see which variables are actually set
            env_file_vars = set()
            env_file_path = Path(".env")
            if env_file_path.exists():
                with open(env_file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            var_name = line.split('=', 1)[0].strip()
                            env_file_vars.add(var_name)
            
            # Get all environment variables from config
            env_vars = []
            for field_name, field_info in config.__class__.model_fields.items():
                if hasattr(config, field_name):
                    value = getattr(config, field_name)
                    # Format the value for display
                    if isinstance(value, list):
                        display_value = str(value)
                    elif isinstance(value, bool):
                        display_value = str(value)
                    elif isinstance(value, (int, float)):
                        display_value = str(value)
                    else:
                        display_value = str(value)
                    
                    # Determine source (env file or default)
                    env_var_name = f"SAE_{field_name.upper()}"
                    if env_var_name in env_file_vars:
                        source = "Environment"
                    else:
                        source = "Default"
                    
                    env_vars.append((env_var_name, display_value, source))
            
            # Sort by variable name
            env_vars.sort(key=lambda x: x[0])
            
            # Count sources
            env_count = sum(1 for _, _, source in env_vars if source == "Environment")
            default_count = sum(1 for _, _, source in env_vars if source == "Default")
            
            for var_name, value, source in env_vars:
                env_table.add_row(var_name, value, source)
            
            console.print(env_table)
            
            # Print summary
            console.print(f"\n[blue]Environment Summary:[/blue] {env_count} variables from environment, {default_count} using defaults")
            
            # Print SAE Status
            print_status(sae_status)
            
            # Show KME server information
            console.print("\n[bold blue]KME Server Information[/bold blue]")
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
            console.print("[green]✓[/green] Successfully reset key database")
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


def check_key_file():
    """Check if the key file exists and throw an error if missing."""
    from src.config import config_manager
    
    config = config_manager.config
    key_file_path = Path(config.storage_path)
    
    if not key_file_path.exists():
        console.print("[red]✗ ERROR: Key file not found![/red]")
        console.print(f"[red]  Expected file: {key_file_path.absolute()}[/red]")
        console.print(f"[red]  Storage backend: {config.storage_backend}[/red]")
        
        if config.storage_backend.lower() == "json":
            console.print("[red]  Expected format: JSON file with 'keys' object[/red]")
            console.print("[red]  Example format: {\"keys\": {}}[/red]")
        elif config.storage_backend.lower() == "sqlite":
            console.print("[red]  Expected format: SQLite database file[/red]")
            console.print("[red]  Database will be created automatically if it doesn't exist[/red]")
        
        console.print(f"[red]  Configuration source: {config_manager.config_file}[/red]")
        console.print(f"[red]  Storage path setting: SAE_STORAGE_PATH={config.storage_path}[/red]")
        
        raise FileNotFoundError(f"Key file not found: {key_file_path.absolute()}")
    
    # Check if file is readable
    try:
        if config.storage_backend.lower() == "json":
            with open(key_file_path, 'r') as f:
                json.load(f)  # Test if it's valid JSON
        console.print(f"[green]✓[/green] Key file found and accessible: {key_file_path.absolute()}")
    except (json.JSONDecodeError, PermissionError) as e:
        console.print("[red]✗ ERROR: Key file is corrupted or not accessible![/red]")
        console.print(f"[red]  File: {key_file_path.absolute()}[/red]")
        console.print(f"[red]  Error: {e}[/red]")
        raise


@cli.command()
def interactive():
    """Start interactive mode with hierarchical commands."""
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
        console.print("[dim]Tip: Press TAB for hierarchical command autocomplete[/dim]")
    console.print()
    
    # Check certificate files and warn if missing
    check_certificate_files()
    
    # Check key file exists
    check_key_file()
    
    # Start UDP listener in background for synchronization
    try:
        from src.services.udp_service import udp_service
        if not udp_service.is_running:
            udp_service.start_listener(config.udp_port)
            console.print(f"[blue]✓[/blue] UDP listener started on port {config.udp_port}")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not start UDP listener: {e}[/yellow]")
    
    while True:
        try:
            # Add debug indicator to prompt if debug mode is enabled
            debug_indicator = " (debug)" if config.debug_mode else ""
            command_line = input(f"{config.sae_id}{debug_indicator}> ")
            
            # Skip empty commands (just carriage return)
            if not command_line.strip():
                continue
            
            # Parse the command
            command, args = parse_command(command_line)
            
            if command in ['quit', 'exit', 'q']:
                console.print("Goodbye!")
                break
            elif command in ['help', '?']:
                show_help()
            elif command == 'debug':
                handle_debug()
            elif command == 'show':
                handle_show(args)
            elif command == 'key':
                handle_key(args)
            elif command == 'persona':
                handle_persona(args)
            elif command == 'peer':
                handle_peer(args)
            elif command == 'test-menu':
                test_menu()
            else:
                console.print(f"[yellow]Unknown command: {command}[/yellow]")
                console.print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            console.print("\nGoodbye!")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


def show_help():
    """Show hierarchical command help."""
    console.print("""
[bold blue]SAE Client Hierarchical Commands[/bold blue]

[bold cyan]Show Commands:[/bold cyan]
  show health                    - Show SAE health and configuration
  show status <sae_id>          - Get ETSI status for a slave SAE
  show keys [keyid <key_id>]    - List local keys (optionally filter by key ID)
  show sync status              - Show synchronization status and sessions
  show scheduled                - Show scheduled key rotations with timestamps
  show personas                 - List available device personas
  show peer [peer_id]           - List known SAE peers (optionally show specific peer)

[bold cyan]Key Commands:[/bold cyan]
  key request encryption slave <slave_id> [keysize <size>] [quantity <quantity>]
                                - Request encryption keys for a slave SAE
  key request decryption master <master_id> keyid <key_id>
                                - Request decryption keys from a master SAE
  key reset [all | keyid <key_id>]
                                - Reset key database (all keys or specific key)
  key notify <sae_id>           - Notify a slave SAE of available key

[bold cyan]Persona Commands:[/bold cyan]
    persona test [persona_name]              - Test a device persona (uses configured if not specified)
    persona preconfigure-key <key_id>        - Pre-configure a key using configured persona
    persona delete-key <key_id>              - Delete a key using configured persona
    persona roll-key <key_id>                - Roll/rotate a key using configured persona
    persona status [persona_name]            - Get detailed device status (uses configured if not specified)      

[bold cyan]Peer Commands:[/bold cyan]
  peer add <sae_id> <host> <port> [roles <roles>] [description <desc>]
                                - Add a known SAE peer
  peer remove <sae_id>          - Remove a known SAE peer

[bold cyan]System Commands:[/bold cyan]
  debug                         - Toggle debug mode on/off
  test-menu                     - Test Easy-KME server routes
  help, ?                       - Show this help
  quit, exit, q                 - Exit interactive mode

[dim]Note: Press TAB for command autocomplete at any level[/dim]
                """)


def handle_debug():
    """Handle debug command."""
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


def handle_show(args):
    """Handle show commands."""
    if not args:
        console.print("[yellow]Usage: show <subcommand>[/yellow]")
        console.print("Available subcommands: health, status, keys, sync, scheduled, personas, peer, env")
        return
    
    subcommand = args[0].lower()
    
    if subcommand == 'health':
        handle_show_health()
    elif subcommand == 'status':
        handle_show_status(args[1:] if len(args) > 1 else [])
    elif subcommand == 'keys':
        handle_show_keys(args[1:] if len(args) > 1 else [])
    elif subcommand == 'sync':
        handle_show_sync(args[1:] if len(args) > 1 else [])
    elif subcommand == 'personas':
        handle_show_personas()
    elif subcommand == 'peer':
        handle_show_peer(args[1:] if len(args) > 1 else [])
    elif subcommand == 'scheduled':
        handle_show_scheduled(args[1:] if len(args) > 1 else [])
    elif subcommand == 'env':
        handle_show_env(args[1:] if len(args) > 1 else [])
    else:
        console.print(f"[yellow]Unknown show subcommand: {subcommand}[/yellow]")


def handle_show_health():
    """Handle show health command."""
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
        console.print("\n[bold blue]KME Server Information[/bold blue]")
        console.print(f"[green]✓[/green] Status: {kme_health.status}")
        console.print(f"[green]✓[/green] Version: {kme_root_info.get('version', 'unknown')}")
        console.print(f"[green]✓[/green] Specification: {kme_root_info.get('specification', 'unknown')}")
        console.print(f"[green]✓[/green] Message: {kme_root_info.get('message', 'unknown')}")
        console.print(f"[green]✓[/green] Documentation: {kme_root_info.get('docs', 'unknown')}")
        console.print(f"[green]✓[/green] Health Timestamp: {kme_health.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error checking health: {e}")


def handle_show_status(args):
    """Handle show status command."""
    if not args:
        slave_id = input("Enter slave SAE ID to check status for: ").strip()
        if not slave_id:
            console.print("[red]✗[/red] Slave SAE ID is required")
            return
    else:
        slave_id = args[0]
    
    try:
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


def handle_show_keys(args):
    """Handle show keys command."""
    try:
        from src.services.key_service import key_service
        available_keys = key_service.get_available_keys()
        
        # Filter by key ID if specified
        if args and len(args) >= 2 and args[0].lower() == 'keyid':
            key_id = args[1]
            filtered_keys = [key for key in available_keys if key.key_id == key_id]
            if filtered_keys:
                print_keys(filtered_keys, f"Key {key_id}")
            else:
                console.print(f"[yellow]No key found with ID: {key_id}[/yellow]")
        else:
            print_keys(available_keys, "Local Keys")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error listing keys: {e}")


def handle_show_sync(args):
    """Handle show sync command."""
    if not args or args[0].lower() != 'status':
        console.print("[yellow]Usage: show sync status[/yellow]")
        return
    
    try:
        from src.services.udp_service import udp_service
        from rich.table import Table
        
        sessions = udp_service.get_sessions()
        
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
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error getting sync status: {e}")


def handle_show_personas():
    """Handle show personas command."""
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


def handle_show_peer(args):
    """Handle show peer command."""
    try:
        from src.services.sae_peers import sae_peers
        from rich.table import Table
        
        if args:
            # Show specific peer
            peer_id = args[0]
            peer_info = sae_peers.get_peer(peer_id)
            
            if peer_info:
                console.print(f"[green]✓[/green] Found SAE peer {peer_id}")
                console.print(f"[blue]Host:[/blue] {peer_info['host']}")
                console.print(f"[blue]Port:[/blue] {peer_info['port']}")
                console.print(f"[blue]Roles:[/blue] {', '.join(peer_info.get('roles', []))}")
                if peer_info.get('description'):
                    console.print(f"[blue]Description:[/blue] {peer_info['description']}")
                console.print(f"[blue]Added:[/blue] {peer_info.get('added_at', '')}")
            else:
                console.print(f"[yellow]SAE peer {peer_id} not found[/yellow]")
        else:
            # List all peers
            peers = sae_peers.list_peers()
            
            if not peers:
                console.print("[yellow]No known SAE peers[/yellow]")
                return
            
            # Create peers table
            table = Table(title="Known SAE Peers")
            table.add_column("SAE ID", style="cyan")
            table.add_column("Host", style="green")
            table.add_column("Port", style="blue")
            table.add_column("Roles", style="yellow")
            table.add_column("Description", style="magenta")
            table.add_column("Added", style="dim")
            
            for peer in peers:
                roles_text = ', '.join(peer.get('roles', []))
                description = peer.get('description', '')
                added_at = peer.get('added_at', '')
                
                table.add_row(
                    peer['sae_id'],
                    peer['host'],
                    str(peer['port']),
                    roles_text,
                    description,
                    added_at
                )
            
            console.print(table)
            console.print(f"[green]✓[/green] Found {len(peers)} known SAE peer(s)")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error with peer operations: {e}")


def handle_show_env(args):
    """Handle show env command."""
    try:
        from src.config import config_manager
        
        # Get all configuration values
        config = config_manager.config
        
        # Create environment table
        table = Table(title="Environment Configuration")
        table.add_column("Variable", style="cyan", width=30)
        table.add_column("Value", style="green", width=50)
        table.add_column("Source", style="yellow", width=15)
        
        # Get all fields from the config
        for field_name, field in config.model_fields.items():
            value = getattr(config, field_name)
            
            # Format the value for display
            if isinstance(value, list):
                display_value = str(value)
            elif isinstance(value, bool):
                display_value = "True" if value else "False"
            elif value is None:
                display_value = "None"
            else:
                display_value = str(value)
            
            # Truncate long values
            if len(display_value) > 45:
                display_value = display_value[:42] + "..."
            
            # Determine source (env file or default)
            source = "ENV" if hasattr(config, '_env_file') else "DEFAULT"
            
            table.add_row(field_name, display_value, source)
        
        console.print(table)
        
        # Show additional info
        console.print(f"\n[dim]Configuration loaded from: {config_manager.config_file}[/dim]")
        console.print(f"[dim]Total configuration variables: {len(config.model_fields)}[/dim]")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error showing environment: {e}")


def handle_show_scheduled(args):
    """Handle show scheduled command."""
    try:
        from src.services.sync_state_machine import sync_state_machine
        from rich.table import Table
        import time
        
        # Get all active sessions with rotation timestamps
        sessions = sync_state_machine.list_sessions()
        scheduled_sessions = []
        
        current_time = time.time()
        
        for session in sessions.values():
            if session.rotation_timestamp and session.rotation_timestamp > current_time:
                scheduled_sessions.append(session)
        
        if not scheduled_sessions:
            console.print("[yellow]No scheduled key rotations found[/yellow]")
            return
        
        # Sort by rotation timestamp (earliest first)
        scheduled_sessions.sort(key=lambda x: x.rotation_timestamp)
        
        # Create scheduled table
        table = Table(title="Scheduled Key Rotations")
        table.add_column("Session ID", style="cyan", width=20)
        table.add_column("Master SAE", style="green", width=10)
        table.add_column("Slave SAE", style="blue", width=10)
        table.add_column("Key IDs", style="magenta", width=30)
        table.add_column("Rotation Time", style="white", width=25)
        table.add_column("Time Until", style="yellow", width=20)
        
        for session in scheduled_sessions:
            # Calculate time until rotation
            time_until = session.rotation_timestamp - current_time
            
            # Format time until (hours, minutes, seconds)
            hours = int(time_until // 3600)
            minutes = int((time_until % 3600) // 60)
            seconds = int(time_until % 60)
            
            # Build time string, truncating zero values
            time_parts = []
            if hours > 0:
                time_parts.append(f"{hours}h")
            if minutes > 0:
                time_parts.append(f"{minutes}m")
            if seconds > 0 or not time_parts:  # Always show seconds if no other parts
                time_parts.append(f"{seconds}s")
            
            time_until_str = " ".join(time_parts)
            
            # Format rotation time
            rotation_time = time.ctime(session.rotation_timestamp)
            
            # Truncate session ID for display
            session_id_display = session.session_id[:17] + "..." if len(session.session_id) > 20 else session.session_id
            
            # Truncate key IDs for display
            key_ids_display = ", ".join(session.key_ids[:2])  # Show first 2 key IDs
            if len(session.key_ids) > 2:
                key_ids_display += f" (+{len(session.key_ids) - 2} more)"
            
            table.add_row(
                session_id_display,
                session.master_sae_id,
                session.slave_sae_id,
                key_ids_display,
                rotation_time,
                f"({time_until_str})"
            )
        
        console.print(table)
        console.print(f"[green]✓[/green] Found {len(scheduled_sessions)} scheduled key rotation(s)")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error displaying scheduled rotations: {e}")


def handle_key(args):
    """Handle key commands."""
    if not args:
        console.print("[yellow]Usage: key <subcommand>[/yellow]")
        console.print("Available subcommands: request, reset, notify")
        return
    
    subcommand = args[0].lower()
    
    if subcommand == 'request':
        handle_key_request(args[1:])
    elif subcommand == 'reset':
        handle_key_reset(args[1:])
    elif subcommand == 'notify':
        handle_key_notify(args[1:])
    else:
        console.print(f"[yellow]Unknown key subcommand: {subcommand}[/yellow]")


def handle_key_request(args):
    """Handle key request command."""
    if not args:
        console.print("[yellow]Usage: key request <type> <role> <id> [options][/yellow]")
        return
    
    if len(args) < 3:
        console.print("[yellow]Usage: key request <encryption|decryption> <slave|master> <id> [options][/yellow]")
        return
    
    key_type = args[0].lower()
    role = args[1].lower()
    target_id = args[2]
    
    if key_type == 'encryption' and role == 'slave':
        # key request encryption slave <slave_id> [keysize <size>] [quantity <quantity>]
        handle_key_request_encryption_slave(args[2:])
    elif key_type == 'decryption' and role == 'master':
        # key request decryption master <master_id> keyid <key_id>
        handle_key_request_decryption_master(args[2:])
    else:
        console.print(f"[yellow]Invalid key request: {key_type} {role}[/yellow]")


def handle_key_request_encryption_slave(args):
    """Handle key request encryption slave command."""
    if not args:
        console.print("[yellow]Usage: key request encryption slave <slave_id> [keysize <size>] [quantity <quantity>][/yellow]")
        return
    
    slave_id = args[0]
    key_size = 256
    quantity = 1
    
    # Parse optional arguments
    i = 1
    while i < len(args):
        if args[i].lower() == 'keysize' and i + 1 < len(args):
            try:
                key_size = int(args[i + 1])
                i += 2
            except ValueError:
                console.print("[red]✗[/red] Invalid key size")
                return
        elif args[i].lower() == 'quantity' and i + 1 < len(args):
            try:
                quantity = int(args[i + 1])
                i += 2
            except ValueError:
                console.print("[red]✗[/red] Invalid quantity")
                return
        else:
            i += 1
    
    try:
        from src.services.key_service import key_service
        response = key_service.request_keys_from_kme(
            KeyType.ENCRYPTION, 
            key_size, 
            quantity, 
            slave_sae_id=slave_id
        )
        console.print(f"\n[green]✓[/green] Successfully received and stored {len(response.keys)} keys")
        print_keys(response.keys, "Received Encryption Keys")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error requesting keys: {e}")


def handle_key_request_decryption_master(args):
    """Handle key request decryption master command."""
    if len(args) < 3 or args[1].lower() != 'keyid':
        console.print("[yellow]Usage: key request decryption master <master_id> keyid <key_id>[/yellow]")
        return
    
    master_id = args[0]
    key_id = args[2]
    
    try:
        success = slave_notification_service.request_key_from_master(
            master_id, key_ids=[key_id]
        )
        
        if success:
            console.print(f"[green]✓[/green] Successfully requested key {key_id} from master {master_id}")
        else:
            console.print(f"[red]✗[/red] Failed to request key from master {master_id}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error requesting from master: {e}")


def handle_key_reset(args):
    """Handle key reset command."""
    if not args:
        console.print("[yellow]Usage: key reset [all | keyid <key_id>][/yellow]")
        return
    
    if args[0].lower() == 'all':
        # Reset all keys
        console.print("[yellow]Warning: This will permanently delete all stored keys![/yellow]")
        confirm = input("Are you sure you want to reset the key database? (yes/no): ").strip().lower()
        
        if confirm in ['yes', 'y']:
            try:
                from src.services.key_service import key_service
                from src.services.storage_service import storage_service
                
                # Get count of keys before deletion
                key_count = len(key_service.get_available_keys())
                
                # Reset the database
                if storage_service.reset_database():
                    # Reload keys in memory
                    key_service._load_keys()
                    console.print("[green]✓[/green] Successfully reset key database")
                    console.print(f"[green]✓[/green] Deleted {key_count} keys")
                else:
                    console.print("[red]✗[/red] Failed to reset key database")
            except Exception as e:
                console.print(f"[red]✗[/red] Error resetting key database: {e}")
        else:
            console.print("Operation cancelled.")
    elif len(args) >= 2 and args[0].lower() == 'keyid':
        # Reset specific key
        key_id = args[1]
        console.print(f"[yellow]Warning: This will permanently delete key {key_id}![/yellow]")
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        
        if confirm in ['yes', 'y']:
            try:
                from src.services.key_service import key_service
                # TODO: Implement single key deletion
                console.print("[yellow]Single key deletion not yet implemented[/yellow]")
            except Exception as e:
                console.print(f"[red]✗[/red] Error deleting key: {e}")
        else:
            console.print("Operation cancelled.")
    else:
        console.print("[yellow]Usage: key reset [all | keyid <key_id>][/yellow]")


def handle_key_notify(args):
    """Handle key notify command."""
    if not args:
        console.print("[yellow]Usage: key notify <sae_id>[/yellow]")
        return
    
    slave_id = args[0]
    
    try:
        # Get actual key data from local storage - filter by the specific slave
        from src.services.key_service import key_service
        available_keys = key_service.get_available_keys(allowed_sae_id=slave_id)
        
        if not available_keys:
            console.print(f"[yellow]No keys available for slave {slave_id}[/yellow]")
            console.print(f"[yellow]Use 'key request encryption slave {slave_id}' to request keys for this slave first[/yellow]")
            return
        
        # Use the first available key for this slave
        key = available_keys[0]
        
        # Debug logging for key notification
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Found {len(available_keys)} keys available for slave {slave_id}")
            console.print(f"[blue]DEBUG:[/blue] Selected key {key.key_id} for notification")
            console.print(f"[blue]DEBUG:[/blue] Key type: {key.key_type}")
            console.print(f"[blue]DEBUG:[/blue] Key size: {key.key_size} bits")
            console.print(f"[blue]DEBUG:[/blue] Key material: {key.key_material[:50]}..." if len(key.key_material) > 50 else f"[blue]DEBUG:[/blue] Key material: {key.key_material}")
            console.print(f"[blue]DEBUG:[/blue] Key allowed for SAE: {key.allowed_sae_id}")
        
        # Use UDP synchronization system for actual network communication
        from src.services.udp_service import udp_service
        from src.utils.message_signer import message_signer
        from src.services.sae_peers import sae_peers
        import time
        
        # Try to get slave address from known peers
        peer_address = sae_peers.get_peer_address(slave_id)
        if not peer_address:
            console.print(f"[red]✗[/red] Slave {slave_id} not found in known peers")
            console.print(f"[yellow]Use 'peer add' command to add {slave_id} to known peers first[/yellow]")
            return
        
        slave_host, slave_port = peer_address
        
        # Debug logging for peer lookup
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Found slave {slave_id} in known peers: {slave_host}:{slave_port}")
        
        # Get persona timing configuration
        try:
            from src.personas.base_persona import persona_manager
            persona_name = config.device_persona if config.device_persona != "default" else "aos8"
            persona_instance = persona_manager.load_persona(persona_name)
            
            if persona_instance:
                # Use persona's initial roll delay
                rotation_timestamp = persona_instance.calculate_rotation_timestamp()
                initial_delay = persona_instance.get_initial_roll_delay()
                grace_period = persona_instance.get_grace_period()
                
                if config_manager.config.debug_mode:
                    console.print("[blue]DEBUG:[/blue] Using persona timing configuration")
                    console.print(f"[blue]DEBUG:[/blue] Persona: {persona_name}")
                    console.print(f"[blue]DEBUG:[/blue] Initial roll delay: {initial_delay} seconds")
                    console.print(f"[blue]DEBUG:[/blue] Grace period: {grace_period} seconds")
            else:
                # Fallback to default timing
                rotation_timestamp = int(time.time()) + 300  # 5 minutes
                if config_manager.config.debug_mode:
                    console.print("[blue]DEBUG:[/blue] Persona not found, using default timing")
        except Exception as e:
            # Fallback to default timing
            rotation_timestamp = int(time.time()) + 300  # 5 minutes
            if config_manager.config.debug_mode:
                console.print(f"[blue]DEBUG:[/blue] Error loading persona, using default timing: {e}")
        
        # Debug logging for timestamp calculation
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Current time: {time.ctime()}")
            console.print(f"[blue]DEBUG:[/blue] Rotation timestamp: {rotation_timestamp}")
            console.print(f"[blue]DEBUG:[/blue] Rotation time: {time.ctime(rotation_timestamp)}")
        
        # Create key notification message
        signed_message = message_signer.create_key_notification(
            key_ids=[key.key_id],
            rotation_timestamp=rotation_timestamp,
            master_sae_id=config.sae_id,
            slave_sae_id=slave_id
        )
        
        # Debug logging for message creation
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Created signed message")
            console.print(f"[blue]DEBUG:[/blue] Message ID: {signed_message.payload[:50]}...")
            console.print(f"[blue]DEBUG:[/blue] Signature size: {len(signed_message.signature)} bytes")
            console.print(f"[blue]DEBUG:[/blue] Full message payload: {signed_message.payload}")
            console.print(f"[blue]DEBUG:[/blue] Full signature: {signed_message.signature}")
        
        # Send message via UDP
        success = udp_service.send_message(signed_message, slave_host, slave_port)
        
        if success:
            # Create session in state machine for tracking acknowledgment
            from src.services.sync_state_machine import sync_state_machine
            
            # Extract message ID from the signed message
            import base64
            import json
            payload_data = json.loads(base64.b64decode(signed_message.payload))
            message_id = payload_data['message_id']
            
            # Create session ID
            session_id = f"{config.sae_id}_{slave_id}_{message_id}"
            
            # Debug logging for session creation
            if config_manager.config.debug_mode:
                console.print("[blue]DEBUG:[/blue] Creating master session for tracking")
                console.print(f"[blue]DEBUG:[/blue] Session ID: {session_id}")
                console.print(f"[blue]DEBUG:[/blue] Message ID: {message_id}")
                console.print(f"[blue]DEBUG:[/blue] Session ID Length: {len(session_id)}")
                console.print(f"[blue]DEBUG:[/blue] Session ID Characters: {[ord(c) for c in session_id[:20]]}...")
            
            # Create session in state machine
            sync_state_machine.create_session(
                session_id=session_id,
                master_sae_id=config.sae_id,
                slave_sae_id=slave_id,
                key_ids=[key.key_id],
                rotation_timestamp=rotation_timestamp
            )
            
            console.print(f"[green]✓[/green] Successfully notified slave {slave_id}")
            console.print(f"[green]✓[/green] Key ID: {key.key_id}")
            console.print(f"[green]✓[/green] Rotation timestamp: {rotation_timestamp}")
            console.print(f"[green]✓[/green] Rotation time: {time.ctime(rotation_timestamp)}")
            console.print(f"[green]✓[/green] Sent to: {slave_host}:{slave_port}")
            
            # Debug logging for successful send
            if config_manager.config.debug_mode:
                console.print("[blue]DEBUG:[/blue] UDP message sent successfully")
                console.print("[blue]DEBUG:[/blue] Key notification sent - slave will respond with acknowledgment")
                console.print("[blue]DEBUG:[/blue] Master session created - waiting for acknowledgment")
        else:
            console.print(f"[red]✗[/red] Failed to notify slave {slave_id}")
            console.print(f"[red]✗[/red] UDP send failed to {slave_host}:{slave_port}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error notifying slave: {e}")
        if config_manager.config.debug_mode:
            import traceback
            console.print("[blue]DEBUG:[/blue] Full error traceback:")
            console.print(traceback.format_exc())


def handle_persona(args):
    """Handle persona commands."""
    if not args:
        console.print("[yellow]Usage: persona <subcommand>[/yellow]")
        console.print("Available subcommands: test, preconfigure-key, delete-key, roll-key, status")
        return
    
    subcommand = args[0].lower()
    
    if subcommand == 'test':
        handle_persona_test(args[1:])
    elif subcommand == 'preconfigure-key':
        handle_persona_preconfigure_key(args[1:])
    elif subcommand == 'delete-key':
        handle_persona_delete_key(args[1:])
    elif subcommand == 'roll-key':
        handle_persona_roll_key(args[1:])
    elif subcommand == 'status':
        handle_persona_status(args[1:])
    else:
        console.print(f"[yellow]Unknown persona subcommand: {subcommand}[/yellow]")
        console.print("[yellow]Available subcommands: test, preconfigure-key, delete-key, roll-key, status[/yellow]")


def handle_persona_test(args):
    """Handle persona test command."""
    if not args:
        # Try to get configured persona from config
        try:
            from src.config import config
            persona_name = config.device_persona if config.device_persona != "default" else "aos8"
            console.print(f"[blue]Using configured persona: {persona_name}[/blue]")
        except:
            persona_name = input("Enter persona name to test: ").strip()
            if not persona_name:
                console.print("[red]✗[/red] Persona name is required")
                return
    else:
        persona_name = args[0]
    
    try:
        from src.personas.base_persona import persona_manager
        
        # Load persona
        persona_instance = persona_manager.load_persona(persona_name)
        
        if not persona_instance:
            console.print(f"[red]✗[/red] Failed to load persona: {persona_name}")
            return
        
        console.print(f"[blue]Testing persona: {persona_name}[/blue]")
        
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


def handle_persona_preconfigure_key(args):
    """Handle persona preconfigure-key command."""
    if len(args) < 1:
        console.print("[yellow]Usage: persona preconfigure-key <key_id>[/yellow]")
        return
    
    key_id = args[0]
    
    # Get configured persona from config
    try:
        from src.config import config
        persona_name = config.device_persona if config.device_persona != "default" else "aos8"
        console.print(f"[blue]Using configured persona: {persona_name}[/blue]")
    except:
        console.print("[red]✗[/red] No persona configured. Please set device_persona in config.")
        return
    
    try:
        from src.personas.base_persona import persona_manager, PreConfigureContext
        
        # Load persona
        persona_instance = persona_manager.load_persona(persona_name)
        
        if not persona_instance:
            console.print(f"[red]✗[/red] Failed to load persona: {persona_name}")
            return
        
        console.print(f"[blue]Pre-configuring key with persona: {persona_name}[/blue]")
        
        # Create test key material (32 bytes, base64 encoded)
        import base64
        test_key_material = base64.b64encode(b"test-key-material-for-aos8-aligned").decode()
        
        # Create pre-configure context
        context = PreConfigureContext(
            key_id=key_id,
            key_material=test_key_material,
            device_interface="eth0",
            encryption_algorithm="AES-256",
            key_priority="normal"
        )
        
        # Execute pre-configure
        success = persona_instance.pre_configure_key(context)
        
        if success:
            console.print(f"[green]✓[/green] Successfully pre-configured key {key_id}")
        else:
            console.print(f"[red]✗[/red] Failed to pre-configure key {key_id}")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error pre-configuring key: {e}")


def handle_persona_delete_key(args):
    """Handle persona delete-key command."""
    if len(args) < 1:
        console.print("[yellow]Usage: persona delete-key <key_id>[/yellow]")
        return
    
    key_id = args[0]
    
    # Get configured persona from config
    try:
        from src.config import config
        persona_name = config.device_persona if config.device_persona != "default" else "aos8"
        console.print(f"[blue]Using configured persona: {persona_name}[/blue]")
    except:
        console.print("[red]✗[/red] No persona configured. Please set device_persona in config.")
        return
    
    try:
        from src.personas.base_persona import persona_manager
        
        # Load persona
        persona_instance = persona_manager.load_persona(persona_name)
        
        if not persona_instance:
            console.print(f"[red]✗[/red] Failed to load persona: {persona_name}")
            return
        
        console.print(f"[blue]Deleting key with persona: {persona_name}[/blue]")
        
        # Check if persona has delete_ppk method
        if hasattr(persona_instance, 'delete_ppk'):
            success = persona_instance.delete_ppk(key_id)
            
            if success:
                console.print(f"[green]✓[/green] Successfully deleted key {key_id}")
            else:
                console.print(f"[red]✗[/red] Failed to delete key {key_id}")
        else:
            console.print(f"[yellow]Persona {persona_name} does not support key deletion[/yellow]")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error deleting key: {e}")


def handle_persona_roll_key(args):
    """Handle persona roll-key command."""
    if len(args) < 1:
        console.print("[yellow]Usage: persona roll-key <key_id>[/yellow]")
        return
    
    key_id = args[0]
    
    # Get configured persona from config
    try:
        from src.config import config
        persona_name = config.device_persona if config.device_persona != "default" else "aos8"
        console.print(f"[blue]Using configured persona: {persona_name}[/blue]")
    except:
        console.print("[red]✗[/red] No persona configured. Please set device_persona in config.")
        return
    
    try:
        from src.personas.base_persona import persona_manager, RotationContext
        import time
        
        # Load persona
        persona_instance = persona_manager.load_persona(persona_name)
        
        if not persona_instance:
            console.print(f"[red]✗[/red] Failed to load persona: {persona_name}")
            return
        
        console.print(f"[blue]Rolling key with persona: {persona_name}[/blue]")
        
        # Create rotation context using persona timing
        rotation_timestamp = persona_instance.calculate_rotation_timestamp()
        
        # Create rotation context
        rotation_context = RotationContext(
            key_id=key_id,
            rotation_timestamp=rotation_timestamp,
            device_interface="eth0",
            encryption_algorithm="AES-256",
            key_priority="normal",
            rollback_on_failure=True,
            session_id=f"roll-key-{int(time.time())}",
            master_sae_id="SAE_001",
            slave_sae_id="SAE_002"
        )
        
        # Execute key rotation
        success = persona_instance.rotate_key(rotation_context)
        
        if success:
            console.print(f"[green]✓[/green] Successfully initiated key roll for {key_id}")
        else:
            console.print(f"[red]✗[/red] Failed to roll key {key_id}")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error rolling key: {e}")


def handle_persona_status(args):
    """Handle persona status command."""
    if not args:
        # Try to get configured persona from config
        try:
            from src.config import config
            persona_name = config.device_persona if config.device_persona != "default" else "aos8"
            console.print(f"[blue]Using configured persona: {persona_name}[/blue]")
        except:
            console.print("[red]✗[/red] No persona configured. Please set device_persona in config.")
            return
    else:
        persona_name = args[0]
    
    try:
        from src.personas.base_persona import persona_manager
        
        # Load persona
        persona_instance = persona_manager.load_persona(persona_name)
        
        if not persona_instance:
            console.print(f"[red]✗[/red] Failed to load persona: {persona_name}")
            return
        
        console.print(f"[blue]Getting status for persona: {persona_name}[/blue]")
        
        # Get detailed status
        status = persona_instance.get_device_status()
        
        from rich.table import Table
        table = Table(title=f"Device Status - {persona_name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in status.items():
            if isinstance(value, dict):
                table.add_row(key, str(value)[:100] + "..." if len(str(value)) > 100 else str(value))
            else:
                table.add_row(key, str(value))
        
        console.print(table)
        
        # Display timing configuration
        console.print(f"\n[bold blue]Timing Configuration - {persona_name}[/bold blue]")
        timing_table = Table(title="Key Roll Timing Settings")
        timing_table.add_column("Setting", style="cyan")
        timing_table.add_column("Value", style="green")
        timing_table.add_column("Description", style="yellow")
        
        initial_delay = persona_instance.get_initial_roll_delay()
        grace_period = persona_instance.get_grace_period()
        
        timing_table.add_row(
            "Initial Roll Delay", 
            f"{initial_delay} seconds ({initial_delay/60:.1f} minutes)", 
            "Delay proposed in first message"
        )
        timing_table.add_row(
            "Grace Period", 
            f"{grace_period} seconds ({grace_period/60:.1f} minutes)", 
            "Minimum time required for key roll"
        )
        
        # Show next rotation timestamp
        next_rotation = persona_instance.calculate_rotation_timestamp()
        timing_table.add_row(
            "Next Rotation Time", 
            f"{time.ctime(next_rotation)}", 
            "If rotation was scheduled now"
        )
        
        console.print(timing_table)
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error getting persona status: {e}")


def handle_peer(args):
    """Handle peer commands."""
    if not args:
        console.print("[yellow]Usage: peer <subcommand>[/yellow]")
        console.print("Available subcommands: add, remove")
        return
    
    subcommand = args[0].lower()
    
    if subcommand == 'add':
        handle_peer_add(args[1:])
    elif subcommand == 'remove':
        handle_peer_remove(args[1:])
    else:
        console.print(f"[yellow]Unknown peer subcommand: {subcommand}[/yellow]")


def handle_peer_add(args):
    """Handle peer add command."""
    if len(args) < 3:
        console.print("[yellow]Usage: peer add <sae_id> <host> <port> [roles <roles>] [description <desc>][/yellow]")
        return
    
    sae_id = args[0]
    host = args[1]
    port = int(args[2])
    
    roles = None
    description = None
    
    # Parse optional arguments
    i = 3
    while i < len(args):
        if args[i].lower() == 'roles' and i + 1 < len(args):
            roles = [role.strip() for role in args[i + 1].split(',') if role.strip()]
            i += 2
        elif args[i].lower() == 'description' and i + 1 < len(args):
            description = args[i + 1]
            i += 2
        else:
            i += 1
    
    try:
        from src.services.sae_peers import sae_peers
        
        success = sae_peers.add_peer(sae_id, host, port, roles, description)
        
        if success:
            console.print(f"[green]✓[/green] Successfully added SAE peer {sae_id}")
            console.print(f"[green]✓[/green] Address: {host}:{port}")
            if roles:
                console.print(f"[green]✓[/green] Roles: {', '.join(roles)}")
        else:
            console.print(f"[red]✗[/red] Failed to add SAE peer {sae_id}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error adding SAE peer: {e}")


def handle_peer_remove(args):
    """Handle peer remove command."""
    if not args:
        console.print("[yellow]Usage: peer remove <sae_id>[/yellow]")
        return
    
    sae_id = args[0]
    
    try:
        from src.services.sae_peers import sae_peers
        
        success = sae_peers.remove_peer(sae_id)
        
        if success:
            console.print(f"[green]✓[/green] Successfully removed SAE peer {sae_id}")
        else:
            console.print(f"[red]✗[/red] Failed to remove SAE peer {sae_id}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error removing SAE peer: {e}")


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
@click.option('--slave-host', help='Slave SAE host/IP address (optional if SAE is in known peers)')
@click.option('--slave-port', help='Slave SAE UDP port (optional if SAE is in known peers)')
@click.option('--rotation-delay', default=300, help='Rotation delay in seconds (default: 300)')
def notify_slave_sync(slave_id, key_ids, slave_host, slave_port, rotation_delay):
    """Notify a slave SAE of available keys for synchronized rotation."""
    try:
        from src.services.udp_service import udp_service
        from src.utils.message_signer import message_signer
        from src.services.sae_peers import sae_peers
        import time
        
        # Try to get slave address from known peers if not provided
        if not slave_host or not slave_port:
            peer_address = sae_peers.get_peer_address(slave_id)
            if peer_address:
                slave_host, slave_port = peer_address
                console.print(f"[blue]Found slave {slave_id} in known peers: {slave_host}:{slave_port}[/blue]")
            else:
                console.print(f"[red]✗[/red] Slave {slave_id} not found in known peers")
                console.print(f"[yellow]Use 'add-peer' command to add {slave_id} to known peers, or provide --slave-host and --slave-port[/yellow]")
                return
        
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


@cli.command()
@click.option('--sae-id', required=True, help='SAE ID to add')
@click.option('--host', required=True, help='SAE host/IP address')
@click.option('--port', default=5000, help='SAE UDP port (default: 5000)')
@click.option('--roles', help='Comma-separated list of roles (master,slave)')
@click.option('--description', help='Optional description')
def add_peer(sae_id, host, port, roles, description):
    """Add a known SAE peer."""
    try:
        from src.services.sae_peers import sae_peers
        
        # Parse roles
        role_list = None
        if roles:
            role_list = [role.strip() for role in roles.split(',') if role.strip()]
        
        # Debug logging
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Adding SAE peer {sae_id}")
            console.print(f"[blue]DEBUG:[/blue] Host: {host}")
            console.print(f"[blue]DEBUG:[/blue] Port: {port}")
            console.print(f"[blue]DEBUG:[/blue] Roles: {role_list}")
            console.print(f"[blue]DEBUG:[/blue] Description: {description}")
        
        success = sae_peers.add_peer(sae_id, host, port, role_list, description)
        
        if success:
            console.print(f"[green]✓[/green] Successfully added SAE peer {sae_id}")
            console.print(f"[green]✓[/green] Address: {host}:{port}")
            if role_list:
                console.print(f"[green]✓[/green] Roles: {', '.join(role_list)}")
        else:
            console.print(f"[red]✗[/red] Failed to add SAE peer {sae_id}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error adding SAE peer: {e}")


@cli.command()
@click.option('--sae-id', required=True, help='SAE ID to remove')
def remove_peer(sae_id):
    """Remove a known SAE peer."""
    try:
        from src.services.sae_peers import sae_peers
        
        # Debug logging
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Removing SAE peer {sae_id}")
        
        success = sae_peers.remove_peer(sae_id)
        
        if success:
            console.print(f"[green]✓[/green] Successfully removed SAE peer {sae_id}")
        else:
            console.print(f"[red]✗[/red] Failed to remove SAE peer {sae_id}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error removing SAE peer: {e}")


@cli.command()
@click.option('--role', help='Filter by role (master, slave)')
def list_peers(role):
    """List known SAE peers."""
    try:
        from src.services.sae_peers import sae_peers
        from rich.table import Table
        
        # Debug logging
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Listing SAE peers")
            console.print(f"[blue]DEBUG:[/blue] Role filter: {role}")
        
        peers = sae_peers.list_peers(role)
        
        if not peers:
            role_text = f" with role '{role}'" if role else ""
            console.print(f"[yellow]No known SAE peers{role_text}[/yellow]")
            return
        
        # Create peers table
        table = Table(title="Known SAE Peers")
        table.add_column("SAE ID", style="cyan")
        table.add_column("Host", style="green")
        table.add_column("Port", style="blue")
        table.add_column("Roles", style="yellow")
        table.add_column("Description", style="magenta")
        table.add_column("Added", style="dim")
        
        for peer in peers:
            roles_text = ', '.join(peer.get('roles', []))
            description = peer.get('description', '')
            added_at = peer.get('added_at', '')
            
            table.add_row(
                peer['sae_id'],
                peer['host'],
                str(peer['port']),
                roles_text,
                description,
                added_at
            )
        
        console.print(table)
        console.print(f"[green]✓[/green] Found {len(peers)} known SAE peer(s)")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error listing SAE peers: {e}")


@cli.command()
@click.option('--sae-id', required=True, help='SAE ID to look up')
def get_peer(sae_id):
    """Get information about a specific SAE peer."""
    try:
        from src.services.sae_peers import sae_peers
        
        # Debug logging
        if config_manager.config.debug_mode:
            console.print(f"[blue]DEBUG:[/blue] Looking up SAE peer {sae_id}")
        
        peer_info = sae_peers.get_peer(sae_id)
        
        if peer_info:
            console.print(f"[green]✓[/green] Found SAE peer {sae_id}")
            console.print(f"[blue]Host:[/blue] {peer_info['host']}")
            console.print(f"[blue]Port:[/blue] {peer_info['port']}")
            console.print(f"[blue]Roles:[/blue] {', '.join(peer_info.get('roles', []))}")
            if peer_info.get('description'):
                console.print(f"[blue]Description:[/blue] {peer_info['description']}")
            console.print(f"[blue]Added:[/blue] {peer_info.get('added_at', '')}")
        else:
            console.print(f"[yellow]SAE peer {sae_id} not found[/yellow]")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error looking up SAE peer: {e}")


@cli.command()
@click.option('--dry-run', is_flag=True, help='Show what would be migrated without making changes')
@click.option('--no-backup', is_flag=True, help='Skip creating backup of current .env file')
def migrate_env(dry_run, no_backup):
    """Migrate .env file to match env.template structure."""
    try:
        from src.utils.env_migrator import migrate_env_file
        
        console.print("[blue]Environment Migration Utility[/blue]")
        console.print("This will update your .env file to include any missing variables from env.template")
        
        if dry_run:
            console.print("[yellow]Running in dry-run mode - no changes will be made[/yellow]")
            success = migrate_env_file(dry_run=True)
            if success:
                console.print("[green]✅ Dry run completed successfully[/green]")
            else:
                console.print("[red]❌ Dry run failed[/red]")
        else:
            backup = not no_backup
            if backup:
                console.print("[blue]A backup of your current .env file will be created[/blue]")
            
            if Confirm.ask("Proceed with migration?", default=True):
                success = migrate_env_file(backup=backup)
                if success:
                    console.print("[green]✅ Migration completed successfully![/green]")
                    if backup:
                        console.print("[blue]A backup of your original .env file has been created.[/blue]")
                    console.print("[yellow]Please restart the application for changes to take effect.[/yellow]")
                else:
                    console.print("[red]❌ Migration failed![/red]")
            else:
                console.print("[yellow]Migration cancelled[/yellow]")
                
    except Exception as e:
        console.print(f"[red]✗[/red] Error during migration: {e}")


if __name__ == '__main__':
    cli()
