#!/usr/bin/env python3
"""
Certificate Exchange Utility for SAE Signature Verification

This script helps SAEs exchange their certificates so they can verify
each other's signatures in the UDP synchronization system.

Usage:
    python exchange_certificates.py --export <sae_id> --output <path>
    python exchange_certificates.py --import <cert_path> --sae-id <sae_id>
"""

import argparse
import shutil
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()


def export_certificate(sae_id: str, output_path: str):
    """Export the current SAE's certificate for sharing."""
    try:
        # Source certificate path (from current SAE)
        source_cert = Path("certs/sae/sae.crt")
        
        if not source_cert.exists():
            console.print(f"[red]✗[/red] Certificate not found: {source_cert}")
            console.print("[yellow]Run setup_sae.sh first to generate your certificate[/yellow]")
            return False
        
        # Create output directory
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy certificate with SAE ID naming
        dest_cert = Path(output_path)
        shutil.copy2(source_cert, dest_cert)
        
        console.print(f"[green]✓[/green] Certificate exported successfully")
        console.print(f"[blue]Source:[/blue] {source_cert}")
        console.print(f"[blue]Destination:[/blue] {dest_cert}")
        console.print(f"[blue]SAE ID:[/blue] {sae_id}")
        
        # Show instructions for sharing
        console.print()
        console.print(Panel(
            f"Share this certificate file with {sae_id}:\n"
            f"  {dest_cert}\n\n"
            f"They should import it using:\n"
            f"  python exchange_certificates.py --import {dest_cert} --sae-id {sae_id}",
            title="📤 Certificate Export Complete",
            border_style="green"
        ))
        
        return True
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to export certificate: {e}")
        return False


def import_certificate(cert_path: str, sae_id: str):
    """Import another SAE's certificate for signature verification."""
    try:
        source_cert = Path(cert_path)
        
        if not source_cert.exists():
            console.print(f"[red]✗[/red] Certificate file not found: {source_cert}")
            return False
        
        # Create certs directory structure
        certs_dir = Path("certs")
        sae_certs_dir = certs_dir / sae_id.lower()
        sae_certs_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy certificate to SAE-specific directory
        dest_cert = sae_certs_dir / f"{sae_id.lower()}.crt"
        shutil.copy2(source_cert, dest_cert)
        
        console.print(f"[green]✓[/green] Certificate imported successfully")
        console.print(f"[blue]Source:[/blue] {source_cert}")
        console.print(f"[blue]Destination:[/blue] {dest_cert}")
        console.print(f"[blue]SAE ID:[/blue] {sae_id}")
        
        # Verify the certificate can be loaded
        try:
            with open(dest_cert, 'rb') as f:
                cert_data = f.read()
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                public_key = cert.public_key()
                
                # Extract CN from certificate
                cn = None
                for name in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
                    cn = name.value
                    break
                
                console.print(f"[green]✓[/green] Certificate verified successfully")
                console.print(f"[blue]Common Name:[/blue] {cn}")
                console.print(f"[blue]Public Key Type:[/blue] {type(public_key).__name__}")
                
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Certificate loaded but verification failed: {e}")
        
        console.print()
        console.print(Panel(
            f"Certificate for {sae_id} is now available for signature verification.\n"
            f"Location: {dest_cert}\n\n"
            f"You can now verify messages signed by {sae_id}.",
            title="📥 Certificate Import Complete",
            border_style="green"
        ))
        
        return True
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to import certificate: {e}")
        return False


def list_imported_certificates():
    """List all imported certificates."""
    try:
        certs_dir = Path("certs")
        
        if not certs_dir.exists():
            console.print("[yellow]No certificates directory found[/yellow]")
            return
        
        console.print("[bold blue]Imported Certificates:[/bold blue]")
        console.print()
        
        found_certs = False
        
        # Look for SAE-specific certificate directories
        for item in certs_dir.iterdir():
            if item.is_dir() and item.name != "sae":  # Skip the main sae directory
                cert_file = item / f"{item.name}.crt"
                if cert_file.exists():
                    found_certs = True
                    console.print(f"[green]✓[/green] {item.name.upper()}: {cert_file}")
                    
                    # Try to get certificate details
                    try:
                        with open(cert_file, 'rb') as f:
                            cert_data = f.read()
                            from cryptography import x509
                            from cryptography.hazmat.backends import default_backend
                            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                            
                            # Extract CN
                            cn = None
                            for name in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
                                cn = name.value
                                break
                            
                            console.print(f"    [dim]Common Name: {cn}[/dim]")
                            console.print(f"    [dim]Valid: {cert.not_valid_before} to {cert.not_valid_after}[/dim]")
                    except Exception as e:
                        console.print(f"    [dim]Error reading certificate: {e}[/dim]")
        
        if not found_certs:
            console.print("[yellow]No imported certificates found[/yellow]")
            console.print("[dim]Use --import to add certificates from other SAEs[/dim]")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to list certificates: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Certificate Exchange Utility for SAE Signature Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export your certificate for sharing
  python exchange_certificates.py --export SAE_001 --output ./shared/sae_001.crt
  
  # Import another SAE's certificate
  python exchange_certificates.py --import ./shared/sae_002.crt --sae-id SAE_002
  
  # List all imported certificates
  python exchange_certificates.py --list
        """
    )
    
    parser.add_argument("--export", help="Export certificate for specified SAE ID")
    parser.add_argument("--output", help="Output path for exported certificate")
    parser.add_argument("--import", dest="import_cert", help="Import certificate from file")
    parser.add_argument("--sae-id", help="SAE ID for imported certificate")
    parser.add_argument("--list", action="store_true", help="List all imported certificates")
    
    args = parser.parse_args()
    
    console.print("[bold blue]🔐 SAE Certificate Exchange Utility[/bold blue]")
    console.print()
    
    if args.export and args.output:
        export_certificate(args.export, args.output)
    elif args.import_cert and args.sae_id:
        import_certificate(args.import_cert, args.sae_id)
    elif args.list:
        list_imported_certificates()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
