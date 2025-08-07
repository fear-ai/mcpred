"""
Configuration file loading and management.
"""

import json
import logging
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union, List

from .validation import MCPRedConfig, ConfigValidator


logger = logging.getLogger(__name__)


class ConfigLoader:
    """Load and manage mcpred configuration files."""
    
    DEFAULT_CONFIG_NAMES = [".mcpred", ".mcpred.yaml", ".mcpred.yml", ".mcpred.json", "mcpred.yaml", "mcpred.yml", "mcpred.json"]
    
    def __init__(self):
        self.config_validator = ConfigValidator()
    
    def load_config(self, config_path: Optional[str] = None) -> MCPRedConfig:
        """Load configuration from file or discover default config."""
        try:
            if config_path:
                # Load specific config file
                config_dict = self._load_config_file(config_path)
            else:
                # Discover and load default config
                discovered_path = self._discover_config_file()
                if discovered_path:
                    logger.info(f"Found configuration file: {discovered_path}")
                    config_dict = self._load_config_file(discovered_path)
                else:
                    logger.info("No configuration file found, using defaults")
                    config_dict = {}
            
            # Validate and return configuration
            return self.config_validator.validate_config_dict(config_dict)
            
        except Exception as e:
            logger.error(f"Configuration loading failed: {e}")
            logger.info("Using default configuration")
            return self.config_validator.get_default_config()
    
    def save_config(self, config: MCPRedConfig, output_path: str) -> None:
        """Save configuration to file."""
        try:
            config_dict = config.dict()
            
            # Determine format from file extension
            path_obj = Path(output_path)
            extension = path_obj.suffix.lower()
            
            if extension in ['.yaml', '.yml']:
                self._save_yaml_config(config_dict, output_path)
            elif extension == '.json':
                self._save_json_config(config_dict, output_path)
            else:
                # Default to YAML
                if not extension:
                    output_path += '.yaml'
                self._save_yaml_config(config_dict, output_path)
            
            logger.info(f"Configuration saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Configuration save failed: {e}")
            raise
    
    def create_sample_config(self, output_path: str = ".mcpred.yaml") -> None:
        """Create a sample configuration file."""
        sample_config = {
            "targets": [
                {
                    "url": "http://localhost:8080",
                    "transport_type": "http",
                    "name": "local-server",
                    "description": "Local development server"
                }
            ],
            "transport": {
                "connection_limit": 100,
                "total_timeout": 30.0,
                "connect_timeout": 10.0,
                "disable_ssl_verify": False
            },
            "security": {
                "max_fuzz_requests": 100,
                "malformed_rate": 0.3,
                "max_concurrent_connections": 50,
                "stress_test_duration": 60,
                "enable_dangerous_tests": False
            },
            "reporting": {
                "output_directory": "./reports",
                "default_format": "json",
                "include_raw_data": True,
                "auto_open_html": False
            },
            "log_level": "INFO",
            "verbose": False,
            "parallel_tests": True,
            "fail_fast": False,
            "timeout": 300.0
        }
        
        try:
            self._save_yaml_config(sample_config, output_path)
            logger.info(f"Sample configuration created at {output_path}")
        except Exception as e:
            logger.error(f"Failed to create sample configuration: {e}")
            raise
    
    def merge_cli_overrides(
        self, 
        base_config: MCPRedConfig, 
        cli_overrides: Dict[str, Any]
    ) -> MCPRedConfig:
        """Merge CLI argument overrides into configuration."""
        try:
            return self.config_validator.merge_configs(base_config, cli_overrides)
        except Exception as e:
            logger.error(f"CLI override merge failed: {e}")
            raise
    
    def _discover_config_file(self) -> Optional[str]:
        """Discover configuration file in current directory and parents."""
        current_dir = Path.cwd()
        
        # Check current directory and parent directories
        for directory in [current_dir] + list(current_dir.parents):
            for config_name in self.DEFAULT_CONFIG_NAMES:
                config_path = directory / config_name
                if config_path.exists() and config_path.is_file():
                    return str(config_path)
        
        return None
    
    def _load_config_file(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from specific file."""
        path_obj = Path(config_path)
        
        if not path_obj.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        if not path_obj.is_file():
            raise ValueError(f"Configuration path is not a file: {config_path}")
        
        extension = path_obj.suffix.lower()
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                if extension in ['.yaml', '.yml']:
                    return yaml.safe_load(f) or {}
                elif extension == '.json':
                    return json.load(f) or {}
                else:
                    # Try to detect format by content
                    content = f.read()
                    f.seek(0)
                    
                    # Try JSON first
                    try:
                        return json.loads(content) or {}
                    except json.JSONDecodeError:
                        # Try YAML
                        try:
                            return yaml.safe_load(content) or {}
                        except yaml.YAMLError:
                            raise ValueError(f"Unable to parse configuration file: {config_path}")
                            
        except Exception as e:
            logger.error(f"Failed to load configuration file {config_path}: {e}")
            raise
    
    def _save_yaml_config(self, config_dict: Dict[str, Any], output_path: str) -> None:
        """Save configuration as YAML."""
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(
                config_dict, 
                f, 
                default_flow_style=False, 
                indent=2,
                sort_keys=False
            )
    
    def _save_json_config(self, config_dict: Dict[str, Any], output_path: str) -> None:
        """Save configuration as JSON."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(config_dict, f, indent=2)
    
    def validate_config_file(self, config_path: str) -> bool:
        """Validate configuration file without loading it into application."""
        try:
            config_dict = self._load_config_file(config_path)
            self.config_validator.validate_config_dict(config_dict)
            logger.info(f"Configuration file {config_path} is valid")
            return True
        except Exception as e:
            logger.error(f"Configuration file {config_path} validation failed: {e}")
            return False
    
    def get_effective_config(
        self, 
        config_path: Optional[str] = None,
        cli_overrides: Optional[Dict[str, Any]] = None
    ) -> MCPRedConfig:
        """Get effective configuration with all overrides applied."""
        # Load base configuration
        base_config = self.load_config(config_path)
        
        # Apply CLI overrides if provided
        if cli_overrides:
            return self.merge_cli_overrides(base_config, cli_overrides)
        
        return base_config
    
    def list_available_configs(self, directory: str = ".") -> List[str]:
        """List available configuration files in directory."""
        dir_path = Path(directory)
        available_configs = []
        
        if dir_path.exists() and dir_path.is_dir():
            for config_name in self.DEFAULT_CONFIG_NAMES:
                config_path = dir_path / config_name
                if config_path.exists() and config_path.is_file():
                    available_configs.append(str(config_path))
        
        return available_configs
    
    @staticmethod
    def get_config_search_paths() -> List[str]:
        """Get list of paths where configuration files are searched."""
        current_dir = Path.cwd()
        search_paths = []
        
        # Add current directory and parents
        for directory in [current_dir] + list(current_dir.parents):
            search_paths.append(str(directory))
        
        # Add common config directories
        home_dir = Path.home()
        if home_dir.exists():
            search_paths.append(str(home_dir / '.config' / 'mcpred'))
            search_paths.append(str(home_dir))
        
        return search_paths