"""
SAE Peers Service.
Manages known SAE peer information from configuration file.
"""

import json
import logging
from typing import Dict, Optional, List
from pathlib import Path

from ..config import config_manager


class SAEPeersService:
    """Service for managing known SAE peer information."""
    
    def __init__(self):
        """Initialize SAE peers service."""
        self.config = config_manager.config
        self.logger = logging.getLogger(__name__)
        self.peers_file = Path(self.config.known_saes_file)
        self.peers: Dict[str, Dict] = {}
        
        # Ensure data directory exists
        self.peers_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing peers
        self._load_peers()
    
    def _load_peers(self):
        """Load known SAEs from file."""
        try:
            if self.peers_file.exists():
                with open(self.peers_file, 'r') as f:
                    self.peers = json.load(f)
                self.logger.info(f"Loaded {len(self.peers)} known SAEs from {self.peers_file}")
            else:
                self.peers = {}
                self.logger.info(f"No known SAEs file found at {self.peers_file}")
        except Exception as e:
            self.logger.error(f"Failed to load known SAEs: {e}")
            self.peers = {}
    
    def _save_peers(self):
        """Save known SAEs to file."""
        try:
            with open(self.peers_file, 'w') as f:
                json.dump(self.peers, f, indent=2, default=str)
            self.logger.debug(f"Saved {len(self.peers)} known SAEs to {self.peers_file}")
        except Exception as e:
            self.logger.error(f"Failed to save known SAEs: {e}")
    
    def add_peer(self, sae_id: str, host: str, port: int = 5000, 
                roles: List[str] = None, description: str = None) -> bool:
        """
        Add a known SAE peer.
        
        Args:
            sae_id: SAE identifier
            host: SAE host/IP address
            port: SAE UDP port (default: 5000)
            roles: List of SAE roles (master, slave)
            description: Optional description
            
        Returns:
            bool: True if peer was added successfully
        """
        try:
            from datetime import datetime
            self.peers[sae_id] = {
                'host': host,
                'port': port,
                'roles': roles or ['slave'],
                'description': description or '',
                'added_at': datetime.now().isoformat()
            }
            
            self._save_peers()
            
            # Debug logging
            if self.config.debug_mode:
                self.logger.info(f"SAE PEER ADDED:")
                self.logger.info(f"  SAE ID: {sae_id}")
                self.logger.info(f"  Host: {host}")
                self.logger.info(f"  Port: {port}")
                self.logger.info(f"  Roles: {roles}")
                self.logger.info(f"  Description: {description}")
            
            self.logger.info(f"Added known SAE peer {sae_id} at {host}:{port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add SAE peer {sae_id}: {e}")
            return False
    
    def remove_peer(self, sae_id: str) -> bool:
        """
        Remove a known SAE peer.
        
        Args:
            sae_id: SAE identifier
            
        Returns:
            bool: True if peer was removed successfully
        """
        try:
            if sae_id in self.peers:
                del self.peers[sae_id]
                self._save_peers()
                
                # Debug logging
                if self.config.debug_mode:
                    self.logger.info(f"SAE PEER REMOVED:")
                    self.logger.info(f"  SAE ID: {sae_id}")
                
                self.logger.info(f"Removed known SAE peer {sae_id}")
                return True
            else:
                self.logger.warning(f"SAE peer {sae_id} not found")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to remove SAE peer {sae_id}: {e}")
            return False
    
    def get_peer(self, sae_id: str) -> Optional[Dict]:
        """
        Get information about a known SAE peer.
        
        Args:
            sae_id: SAE identifier
            
        Returns:
            Dict: Peer information or None if not found
        """
        try:
            peer_info = self.peers.get(sae_id)
            
            if peer_info:
                # Debug logging
                if self.config.debug_mode:
                    self.logger.info(f"SAE PEER LOOKUP:")
                    self.logger.info(f"  SAE ID: {sae_id}")
                    self.logger.info(f"  Host: {peer_info['host']}")
                    self.logger.info(f"  Port: {peer_info['port']}")
                    self.logger.info(f"  Roles: {peer_info['roles']}")
            
            return peer_info
            
        except Exception as e:
            self.logger.error(f"Failed to get SAE peer {sae_id}: {e}")
            return None
    
    def list_peers(self, role: str = None) -> List[Dict]:
        """
        List all known SAE peers, optionally filtered by role.
        
        Args:
            role: Optional role filter (master, slave)
            
        Returns:
            List[Dict]: List of peer information
        """
        try:
            if role:
                peers = [
                    {'sae_id': sae_id, **info}
                    for sae_id, info in self.peers.items()
                    if role in info.get('roles', [])
                ]
            else:
                peers = [
                    {'sae_id': sae_id, **info}
                    for sae_id, info in self.peers.items()
                ]
            
            # Debug logging
            if self.config.debug_mode:
                self.logger.info(f"SAE PEERS LIST:")
                self.logger.info(f"  Role Filter: {role}")
                self.logger.info(f"  Found {len(peers)} peers")
                for peer in peers:
                    self.logger.info(f"  - {peer['sae_id']}: {peer['host']}:{peer['port']}")
            
            return peers
            
        except Exception as e:
            self.logger.error(f"Failed to list SAE peers: {e}")
            return []
    
    def get_peer_address(self, sae_id: str) -> Optional[tuple]:
        """
        Get the address tuple (host, port) for a known SAE peer.
        
        Args:
            sae_id: SAE identifier
            
        Returns:
            tuple: (host, port) or None if not found
        """
        try:
            peer_info = self.get_peer(sae_id)
            if peer_info:
                return (peer_info['host'], peer_info['port'])
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get SAE peer address for {sae_id}: {e}")
            return None


# Global SAE peers service instance
sae_peers = SAEPeersService()
