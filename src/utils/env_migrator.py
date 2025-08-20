"""
Environment file migration utility.

This module handles migration of .env files when env.template is updated
with new configuration variables during development.
"""

import os
import shutil
import logging
from pathlib import Path
from typing import Dict, Set, Tuple
from datetime import datetime


class EnvMigrator:
    """Handles migration of .env files when env.template is updated."""
    
    def __init__(self, project_root: str = "."):
        """Initialize the migrator with project root path."""
        self.project_root = Path(project_root)
        self.env_file = self.project_root / ".env"
        self.env_template = self.project_root / "env.template"
        self.logger = logging.getLogger(__name__)
    
    def _parse_env_file(self, file_path: Path) -> Dict[str, str]:
        """Parse an environment file and return key-value pairs."""
        env_vars = {}
        
        if not file_path.exists():
            return env_vars
        
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse key=value pairs
                if '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
                else:
                    self.logger.warning(f"Invalid line {line_num} in {file_path}: {line}")
        
        return env_vars
    
    def _extract_template_variables(self, template_path: Path) -> Set[str]:
        """Extract variable names from env.template file."""
        variables = set()
        
        if not template_path.exists():
            self.logger.error(f"Template file not found: {template_path}")
            return variables
        
        with open(template_path, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Extract variable names from lines like SAE_VAR=value
                if '=' in line:
                    key = line.split('=', 1)[0].strip()
                    variables.add(key)
        
        return variables
    
    def _create_migrated_env_content(self, current_env: Dict[str, str], template_path: Path) -> str:
        """Create new .env content by merging current values with template structure."""
        if not template_path.exists():
            raise FileNotFoundError(f"Template file not found: {template_path}")
        
        # Read template content
        with open(template_path, 'r') as f:
            template_content = f.read()
        
        # Replace template values with current values where they exist
        migrated_content = template_content
        
        for key, value in current_env.items():
            # Find the line in template that starts with this key
            lines = migrated_content.split('\n')
            for i, line in enumerate(lines):
                if line.strip().startswith(f"{key}="):
                    lines[i] = f"{key}={value}"
                    break
            migrated_content = '\n'.join(lines)
        
        return migrated_content
    
    def needs_migration(self) -> Tuple[bool, Set[str]]:
        """
        Check if migration is needed by comparing current .env with env.template.
        
        Returns:
            Tuple of (needs_migration, missing_variables)
        """
        if not self.env_file.exists():
            self.logger.info("No .env file found - migration needed")
            return True, set()
        
        if not self.env_template.exists():
            self.logger.error("env.template not found")
            return False, set()
        
        # Get current environment variables
        current_env = self._parse_env_file(self.env_file)
        current_vars = set(current_env.keys())
        
        # Get template variables
        template_vars = self._extract_template_variables(self.env_template)
        
        # Find missing variables
        missing_vars = template_vars - current_vars
        
        if missing_vars:
            self.logger.info(f"Migration needed - missing variables: {missing_vars}")
            return True, missing_vars
        else:
            self.logger.info("No migration needed - all template variables present")
            return False, set()
    
    def migrate(self, backup: bool = True) -> bool:
        """
        Perform the migration of .env file.
        
        Args:
            backup: Whether to create a backup of the current .env file
            
        Returns:
            True if migration was successful, False otherwise
        """
        try:
            # Check if migration is needed
            needs_mig, missing_vars = self.needs_migration()
            
            if not needs_mig:
                self.logger.info("No migration needed")
                return True
            
            # Create backup if requested and .env exists
            if backup and self.env_file.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = self.project_root / f".env.backup_{timestamp}"
                shutil.copy2(self.env_file, backup_path)
                self.logger.info(f"Created backup: {backup_path}")
            
            # Get current environment variables
            current_env = self._parse_env_file(self.env_file)
            
            # Create migrated content
            migrated_content = self._create_migrated_env_content(current_env, self.env_template)
            
            # Write new .env file
            with open(self.env_file, 'w') as f:
                f.write(migrated_content)
            
            self.logger.info(f"Successfully migrated .env file with {len(missing_vars)} new variables")
            self.logger.info(f"Added variables: {missing_vars}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Migration failed: {e}")
            return False
    
    def dry_run(self) -> Dict[str, any]:
        """
        Perform a dry run of the migration to see what would change.
        
        Returns:
            Dictionary with migration details
        """
        try:
            needs_mig, missing_vars = self.needs_migration()
            
            if not needs_mig:
                return {
                    "needs_migration": False,
                    "missing_variables": set(),
                    "current_variables": set(),
                    "template_variables": set()
                }
            
            current_env = self._parse_env_file(self.env_file)
            template_vars = self._extract_template_variables(self.env_template)
            
            return {
                "needs_migration": True,
                "missing_variables": missing_vars,
                "current_variables": set(current_env.keys()),
                "template_variables": template_vars,
                "current_values": current_env
            }
            
        except Exception as e:
            self.logger.error(f"Dry run failed: {e}")
            return {"error": str(e)}


def migrate_env_file(project_root: str = ".", backup: bool = True, dry_run: bool = False) -> bool:
    """
    Convenience function to migrate environment file.
    
    Args:
        project_root: Path to project root directory
        backup: Whether to create backup of current .env
        dry_run: If True, only show what would be migrated without making changes
        
    Returns:
        True if successful, False otherwise
    """
    migrator = EnvMigrator(project_root)
    
    if dry_run:
        result = migrator.dry_run()
        if "error" in result:
            print(f"❌ Dry run failed: {result['error']}")
            return False
        
        if not result["needs_migration"]:
            print("✅ No migration needed - all template variables are present")
            return True
        
        print("🔍 Migration Analysis:")
        print(f"   Missing variables: {len(result['missing_variables'])}")
        for var in sorted(result['missing_variables']):
            print(f"   - {var}")
        print(f"   Current variables: {len(result['current_variables'])}")
        print(f"   Template variables: {len(result['template_variables'])}")
        return True
    
    return migrator.migrate(backup=backup)


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run migration
    success = migrate_env_file(dry_run=True)
    if success:
        print("\n🚀 Running actual migration...")
        success = migrate_env_file(backup=True)
        if success:
            print("✅ Migration completed successfully!")
        else:
            print("❌ Migration failed!")
    else:
        print("❌ Migration analysis failed!")
