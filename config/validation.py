"""
Configuration validation with Pydantic.
"""

import logging
from typing import Dict, List, Any, Optional, Union
from pydantic import BaseModel, Field, validator, root_validator


logger = logging.getLogger(__name__)


class TransportConfig(BaseModel):
    """Transport-specific configuration."""
    
    connection_limit: int = Field(100, ge=1, le=1000, description="Maximum concurrent connections")
    per_host_limit: int = Field(30, ge=1, le=100, description="Maximum connections per host")
    total_timeout: float = Field(30.0, ge=1.0, le=300.0, description="Total request timeout in seconds")
    connect_timeout: float = Field(10.0, ge=1.0, le=60.0, description="Connection timeout in seconds")
    response_timeout: float = Field(5.0, ge=1.0, le=30.0, description="Response timeout in seconds")
    disable_ssl_verify: bool = Field(False, description="Disable SSL certificate verification")
    
    class Config:
        extra = "allow"  # Allow additional transport-specific settings


class SecurityTestConfig(BaseModel):
    """Security testing configuration."""
    
    max_fuzz_requests: int = Field(100, ge=1, le=10000, description="Maximum fuzzing requests")
    malformed_rate: float = Field(0.3, ge=0.0, le=1.0, description="Rate of malformed requests in fuzzing")
    max_concurrent_connections: int = Field(50, ge=1, le=500, description="Maximum concurrent test connections")
    stress_test_duration: int = Field(60, ge=10, le=600, description="Stress test duration in seconds")
    request_rate: int = Field(10, ge=1, le=1000, description="Requests per second for stress testing")
    max_payload_size: int = Field(1024 * 1024, ge=1024, le=100 * 1024 * 1024, description="Maximum payload size for testing")
    enable_dangerous_tests: bool = Field(False, description="Enable potentially dangerous security tests")
    
    @validator('malformed_rate')
    def validate_malformed_rate(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('malformed_rate must be between 0.0 and 1.0')
        return v


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    
    output_directory: str = Field("./reports", description="Directory for report output")
    default_format: str = Field("json", description="Default report format")
    include_raw_data: bool = Field(True, description="Include raw data in reports")
    auto_open_html: bool = Field(False, description="Automatically open HTML reports")
    report_filename_template: str = Field("mcpred-report-{timestamp}", description="Report filename template")
    
    @validator('default_format')
    def validate_format(cls, v):
        allowed_formats = {'json', 'html', 'text', 'txt'}
        if v.lower() not in allowed_formats:
            raise ValueError(f'default_format must be one of {allowed_formats}')
        return v.lower()


class TargetConfig(BaseModel):
    """Target server configuration."""
    
    url: str = Field(..., description="Target server URL")
    transport_type: str = Field("http", description="Transport type")
    name: Optional[str] = Field(None, description="Target name for identification")
    description: Optional[str] = Field(None, description="Target description")
    authentication: Optional[Dict[str, Any]] = Field(None, description="Authentication configuration")
    custom_headers: Optional[Dict[str, str]] = Field(None, description="Custom headers")
    
    @validator('transport_type')
    def validate_transport_type(cls, v):
        allowed_transports = {'http', 'https', 'stdio', 'websocket', 'ws', 'wss', 'sse'}
        if v.lower() not in allowed_transports:
            raise ValueError(f'transport_type must be one of {allowed_transports}')
        return v.lower()
    
    @validator('url')
    def validate_url(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError('url must be a non-empty string')
        # Basic URL validation - more thorough validation happens at runtime
        if not any(v.startswith(proto) for proto in ['http://', 'https://', 'ws://', 'wss://', 'stdio:']):
            if '://' not in v:
                # Assume it's a simple host:port format
                pass
            else:
                raise ValueError('url must be a valid URL or host:port format')
        return v


class MCPRedConfig(BaseModel):
    """Main mcpred configuration."""
    
    # Target configuration
    targets: List[TargetConfig] = Field(default_factory=list, description="List of target configurations")
    default_target: Optional[TargetConfig] = Field(None, description="Default target configuration")
    
    # Test configuration
    transport: TransportConfig = Field(default_factory=TransportConfig, description="Transport configuration")
    security: SecurityTestConfig = Field(default_factory=SecurityTestConfig, description="Security testing configuration")
    reporting: ReportingConfig = Field(default_factory=ReportingConfig, description="Reporting configuration")
    
    # Logging configuration
    log_level: str = Field("INFO", description="Logging level")
    log_file: Optional[str] = Field(None, description="Log file path")
    verbose: bool = Field(False, description="Enable verbose output")
    
    # Runtime options
    parallel_tests: bool = Field(True, description="Run tests in parallel when possible")
    fail_fast: bool = Field(False, description="Stop testing on first critical vulnerability")
    timeout: float = Field(300.0, ge=10.0, le=3600.0, description="Overall operation timeout in seconds")
    
    @validator('log_level')
    def validate_log_level(cls, v):
        allowed_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        if v.upper() not in allowed_levels:
            raise ValueError(f'log_level must be one of {allowed_levels}')
        return v.upper()
    
    @root_validator(skip_on_failure=True)
    def validate_targets(cls, values):
        targets = values.get('targets', [])
        default_target = values.get('default_target')
        
        if not targets and not default_target:
            logger.warning("No targets configured - will need to be provided via command line")
        
        return values
    
    class Config:
        extra = "allow"  # Allow additional configuration options
        validate_assignment = True  # Validate on assignment
        use_enum_values = True


class ConfigValidator:
    """Configuration validation utilities."""
    
    @staticmethod
    def validate_config_dict(config_dict: Dict[str, Any]) -> MCPRedConfig:
        """Validate configuration dictionary."""
        try:
            return MCPRedConfig(**config_dict)
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise
    
    @staticmethod
    def validate_target_config(target_dict: Dict[str, Any]) -> TargetConfig:
        """Validate target configuration dictionary."""
        try:
            return TargetConfig(**target_dict)
        except Exception as e:
            logger.error(f"Target configuration validation failed: {e}")
            raise
    
    @staticmethod
    def get_default_config() -> MCPRedConfig:
        """Get default configuration."""
        return MCPRedConfig()
    
    @staticmethod
    def merge_configs(base_config: MCPRedConfig, override_config: Dict[str, Any]) -> MCPRedConfig:
        """Merge configuration with overrides."""
        try:
            # Convert base config to dict
            base_dict = base_config.dict()
            
            # Deep merge override values
            merged_dict = ConfigValidator._deep_merge(base_dict, override_config)
            
            # Validate merged configuration
            return MCPRedConfig(**merged_dict)
            
        except Exception as e:
            logger.error(f"Configuration merge failed: {e}")
            raise
    
    @staticmethod
    def _deep_merge(base_dict: Dict[str, Any], override_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base_dict.copy()
        
        for key, value in override_dict.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigValidator._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    @staticmethod
    def validate_and_normalize_targets(targets: Union[str, List[str], List[Dict[str, Any]]]) -> List[TargetConfig]:
        """Validate and normalize target configurations."""
        if isinstance(targets, str):
            # Single target URL
            return [TargetConfig(url=targets)]
        
        elif isinstance(targets, list):
            normalized_targets = []
            
            for target in targets:
                if isinstance(target, str):
                    # Target URL string
                    normalized_targets.append(TargetConfig(url=target))
                elif isinstance(target, dict):
                    # Target configuration dict
                    normalized_targets.append(TargetConfig(**target))
                else:
                    raise ValueError(f"Invalid target configuration: {target}")
            
            return normalized_targets
        
        else:
            raise ValueError(f"Invalid targets format: {type(targets)}")


# Configuration schema for external validation
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "targets": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "transport_type": {"type": "string"},
                    "name": {"type": "string"},
                    "description": {"type": "string"}
                },
                "required": ["url"]
            }
        },
        "transport": {
            "type": "object",
            "properties": {
                "connection_limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                "total_timeout": {"type": "number", "minimum": 1.0, "maximum": 300.0},
                "disable_ssl_verify": {"type": "boolean"}
            }
        },
        "security": {
            "type": "object", 
            "properties": {
                "max_fuzz_requests": {"type": "integer", "minimum": 1, "maximum": 10000},
                "malformed_rate": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "enable_dangerous_tests": {"type": "boolean"}
            }
        },
        "reporting": {
            "type": "object",
            "properties": {
                "output_directory": {"type": "string"},
                "default_format": {"type": "string", "enum": ["json", "html", "text", "txt"]},
                "include_raw_data": {"type": "boolean"}
            }
        }
    }
}