"""
Main CLI entry point for mcpred.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from config import ConfigLoader, MCPRedConfig
from core.client import MCPTeamClient
from reporting import ReportGenerator, ReportExporter


# Set up logging
def setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """Set up logging configuration."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        logging.getLogger().addHandler(file_handler)


@click.group(invoke_without_command=True)
@click.option('--config', '--conf', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '--verb', is_flag=True, help='Enable verbose output')
@click.option('--log-level', '--loglev', '-ll', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']), 
              default='INFO', help='Set logging level')
@click.option('--log-file', '--logfile', '-lf', type=click.Path(), help='Log file path')
@click.option('--version', '-v', is_flag=True, help='Show version information')
@click.pass_context
def cli(ctx, config, verbose, log_level, log_file, version):
    """mcpred - MCP Red Team Client for security testing MCP servers.
    
    Quick usage:
      mcpred sc https://api.example.com/mcp        # Full scan
      mcpred dis https://api.example.com/mcp       # Discovery only  
      mcpred conf                                  # Create sample config
      mcpred bigtest.red                           # Run test definition
      mcpred --version                             # Show version
      
    All commands have short aliases (sc, dis).
    Most options have short forms (--tran, --fmt, --conf, etc).
    """
    
    # Handle version flag
    if version:
        try:
            from __init__ import __version__
            click.echo(f"mcpred version {__version__}")
        except ImportError:
            click.echo("mcpred version unknown")
        sys.exit(0)
    
    # Show help if no command provided
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)
    
    # Set up logging - --loglevel overrides --verbose
    if verbose and log_level == 'INFO':  # Only use verbose if loglevel wasn't explicitly set
        log_level = 'DEBUG'
    setup_logging(log_level, log_file)
    
    # Load configuration
    config_loader = ConfigLoader()
    try:
        mcpred_config = config_loader.load_config(config)
        
        # Override with CLI options
        cli_overrides = {}
        if verbose:
            cli_overrides['verbose'] = True
        if log_level != 'INFO':
            cli_overrides['log_level'] = log_level
        if log_file:
            cli_overrides['log_file'] = log_file
        
        if cli_overrides:
            mcpred_config = config_loader.merge_cli_overrides(mcpred_config, cli_overrides)
        
        # Store in context
        ctx.ensure_object(dict)
        ctx.obj['config'] = mcpred_config
        ctx.obj['config_loader'] = config_loader
        
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)


@cli.command('discover')
@click.argument('target', required=False)
@click.option('--transport', '--tran', '-t', type=click.Choice(['http', 'https', 'stdio', 'websocket', 'ws', 'wss']), 
              default='https', help='Transport type')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '--fmt', 'output_format', type=click.Choice(['json', 'html', 'text']), 
              default='text', help='Output format')
@click.option('--timeout', '--time', type=float, help='Operation timeout in seconds')
@click.pass_context
def discover(ctx, target, transport, output, output_format, timeout):
    """Discover server capabilities and potential attack surface.
    
    Smart defaults:
    - https:// URLs default to https transport
    - .html/.htm output files default to html format
    
    Short alias: dis
    
    Example: mcpred dis https://api.example.com/mcp --tran https --fmt html
    """
    
    config: MCPRedConfig = ctx.obj['config']
    
    # Determine target
    if not target:
        if config.default_target:
            target = config.default_target.url
            transport = config.default_target.transport_type
        elif config.targets:
            target = config.targets[0].url
            transport = config.targets[0].transport_type
        else:
            click.echo("No target specified. Use --target or configure default target.", err=True)
            sys.exit(1)
    
    # Smart transport default: https URLs default to https transport 
    if target and target.startswith('https://') and transport == 'https':
        transport = 'https'
    elif target and target.startswith('http://') and transport == 'https':
        transport = 'http'
    elif target and target.startswith('ws://') and transport == 'https':
        transport = 'websocket'
    elif target and target.startswith('wss://') and transport == 'https':
        transport = 'websocket'
    
    # Smart format default: .html/.htm output files default to html format
    if output and output_format == 'text':
        if output.lower().endswith('.html') or output.lower().endswith('.htm'):
            output_format = 'html'
        elif output.lower().endswith('.json'):
            output_format = 'json'
    
    click.echo(f"Discovering capabilities for {target} using {transport} transport...")
    
    async def run_discovery():
        try:
            # Create client
            client = MCPTeamClient(
                target_url=target,
                transport_type=transport,
                security_config=config.security.model_dump() if hasattr(config.security, 'model_dump') else None
            )
            
            # Set timeout if specified
            if timeout:
                client.security_config.total_timeout = timeout
            
            # Run discovery
            capabilities = await client.discover_server()
            
            # Generate report
            report_generator = ReportGenerator()
            client_summary = client.get_summary()
            
            report_data = report_generator.generate_comprehensive_report(
                client_summary=client_summary,
                security_issues=capabilities.security_issues if capabilities.security_issues else None
            )
            
            # Output results
            if output:
                # Export to file
                exporter = ReportExporter()
                exported_path = exporter.export_report(report_data, output, output_format)
                click.echo(f"Discovery report saved to {exported_path}")
            else:
                # Output to console
                if output_format == 'json':
                    import json
                    click.echo(json.dumps(report_data, indent=2))
                else:
                    # Simple text output for console
                    click.echo(f"\nServer Capabilities:")
                    click.echo(f"  Tools: {len(capabilities.tools)}")
                    click.echo(f"  Resources: {len(capabilities.resources)}")
                    click.echo(f"  Prompts: {len(capabilities.prompts)}")
                    if capabilities.security_issues:
                        click.echo(f"  Security Issues: {len(capabilities.security_issues)}")
            
        except Exception as e:
            click.echo(f"Discovery failed: {e}", err=True)
            sys.exit(1)
    
    # Run async operation
    asyncio.run(run_discovery())


@cli.command('scan')
@click.argument('target', required=False)
@click.option('--transport', '--tran', '-t', type=click.Choice(['http', 'https', 'stdio', 'websocket', 'ws', 'wss']), 
              default='https', help='Transport type')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '--fmt', 'output_format', type=click.Choice(['json', 'html', 'text']), 
              default='text', help='Output format')
@click.option('--auth/--noauth', default=True, help='Enable/disable authentication tests')
@click.option('--discovery/--nodiscovery', '--dis/--nodis', default=True, help='Enable/disable server discovery')
@click.option('--fuzz/--nofuzz', default=True, help='Enable/disable protocol fuzzing')
@click.option('--stress/--nostress', default=True, help='Enable/disable stress testing')
@click.pass_context
def scan(ctx, target, transport, output, output_format, auth, discovery, fuzz, stress):
    """Run comprehensive security assessment.
    
    Smart defaults:
    - https:// URLs default to https transport
    - .html/.htm output files default to html format
    
    Short alias: sc
    
    All tests enabled by default. Use --noauth, --nodis, --nofuzz, --nostress to disable.
    
    Examples:
      mcpred sc https://api.example.com/mcp
      mcpred sc https://api.example.com/mcp --tran https --fmt html --nofuzz --nostress
    """
    
    config: MCPRedConfig = ctx.obj['config']
    
    # Determine target
    if not target:
        if config.default_target:
            target = config.default_target.url
            transport = config.default_target.transport_type
        elif config.targets:
            target = config.targets[0].url
            transport = config.targets[0].transport_type
        else:
            click.echo("No target specified. Use --target or configure default target.", err=True)
            sys.exit(1)
    
    # Smart transport default: https URLs default to https transport
    if target and target.startswith('https://') and transport == 'https':
        transport = 'https'
    elif target and target.startswith('http://') and transport == 'https':
        transport = 'http'
    elif target and target.startswith('ws://') and transport == 'https':
        transport = 'websocket'
    elif target and target.startswith('wss://') and transport == 'https':
        transport = 'websocket'
    
    # Smart format default: .html/.htm output files default to html format
    if output and output_format == 'text':
        if output.lower().endswith('.html') or output.lower().endswith('.htm'):
            output_format = 'html'
        elif output.lower().endswith('.json'):
            output_format = 'json'
    
    click.echo(f"Running security assessment for {target}...")
    
    async def run_scan():
        try:
            # Create client
            client = MCPTeamClient(
                target_url=target,
                transport_type=transport,
                security_config=config.security.model_dump() if hasattr(config.security, 'model_dump') else None
            )
            
            # Run tests based on options
            capabilities = None
            security_issues = []
            protocol_violations = []
            stress_results = []
            
            if discovery:
                click.echo("Running server discovery...")
                capabilities = await client.discover_server()
                click.echo(f"   Found {len(capabilities.tools)} tools, {len(capabilities.resources)} resources")
            
            if auth:
                click.echo("Running authentication tests...")
                auth_issues = await client.test_authentication()
                security_issues.extend(auth_issues)
                click.echo(f"   Found {len(auth_issues)} authentication issues")
            
            if fuzz:
                click.echo("Running protocol fuzzing...")
                violations = await client.fuzz_protocol(
                    request_count=config.security.max_fuzz_requests,
                    malformed_rate=config.security.malformed_rate
                )
                protocol_violations.extend(violations)
                click.echo(f"   Found {len(violations)} protocol violations")
            
            if stress:
                click.echo("Running stress tests...")
                stress_metrics = await client.stress_test()
                stress_results.append(stress_metrics)
                click.echo("   Stress testing completed")
            
            # Generate comprehensive report
            report_generator = ReportGenerator()
            client_summary = client.get_summary()
            
            report_data = report_generator.generate_comprehensive_report(
                client_summary=client_summary,
                security_issues=security_issues if security_issues else None,
                protocol_violations=protocol_violations if protocol_violations else None,
                stress_results=stress_results if stress_results else None
            )
            
            # Show summary
            exec_summary = report_data.get('executive_summary', {})
            click.echo(f"\nAssessment Summary:")
            click.echo(f"   Overall Risk: {exec_summary.get('overall_risk_level', 'Unknown').upper()}")
            click.echo(f"   Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
            
            # Output results
            if output:
                # Export to file
                exporter = ReportExporter()
                exported_path = exporter.export_report(report_data, output, output_format)
                click.echo(f"\nFull report saved to {exported_path}")
                
                # Also export HTML for easy viewing
                if output_format != 'html':
                    html_path = str(Path(output).with_suffix('.html'))
                    exporter.export_report(report_data, html_path, 'html')
                    click.echo(f"HTML report saved to {html_path}")
            else:
                # Brief console output
                if exec_summary.get('top_concerns'):
                    click.echo(f"\nTop Concerns:")
                    for concern in exec_summary['top_concerns'][:3]:
                        click.echo(f"   - {concern}")
            
        except Exception as e:
            click.echo(f"Security assessment failed: {e}", err=True)
            sys.exit(1)
    
    # Run async operation
    asyncio.run(run_scan())


@cli.command('conf')
@click.argument('filename', required=False)
@click.option('--type', '-t', type=click.Choice(['test', 'global']), default='test',
              help='Generate test definition (example.red) or global config (.mcpred)')
@click.pass_context
def conf(ctx, filename, type):
    """Configuration management - create sample or validate existing.
    
    Without filename: Creates example.red test definition by default
    With --type global: Creates .mcpred global configuration  
    With filename: Validates the specified configuration file
    
    Examples:
      mcpred conf                        # Create example.red
      mcpred conf --type global          # Create .mcpred
      mcpred conf mytest.red             # Validate mytest.red
    """
    
    config_loader: ConfigLoader = ctx.obj['config_loader']
    
    if not filename:
        # Create sample configuration file
        if type == 'global':
            output = '.mcpred'
            try:
                config_loader.create_sample_config(output)
                click.echo(f"Global configuration created at {output}")
                click.echo("Edit to customize global settings applied to all tests.")
            except Exception as e:
                click.echo(f"Failed to create global configuration: {e}", err=True)
                sys.exit(1)
        else:  # type == 'test'
            output = 'example.red'
            try:
                config_loader.create_sample_red(output)
                click.echo(f"Test definition created at {output}")
                click.echo("Edit to customize test parameters, then run: mcpred example.red")
            except Exception as e:
                click.echo(f"Failed to create test definition: {e}", err=True)
                sys.exit(1)
    else:
        # Validate specified configuration file
        try:
            is_valid = config_loader.validate_config_file(filename)
            if is_valid:
                click.echo(f"Configuration file {filename} is valid")
            else:
                click.echo(f"Configuration file {filename} is invalid")
                sys.exit(1)
        except Exception as e:
            click.echo(f"Validation failed: {e}", err=True)
            sys.exit(1)




@cli.command('run')
@click.argument('red_file', type=click.Path(exists=True))
@click.pass_context
def run_red(ctx, red_file):
    """Run test definition from .red file.
    
    Examples:
      mcpred bigtest.red
      mcpred run quicktest.red
    """
    
    if not red_file.endswith('.red'):
        click.echo("Test definition file must have .red extension", err=True)
        sys.exit(1)
    
    try:
        import yaml
        with open(red_file, 'r') as f:
            red_config = yaml.safe_load(f)
        
        # Extract test parameters
        target = red_config.get('target')
        transport = red_config.get('transport', 'https')
        output = red_config.get('output')
        output_format = red_config.get('format', 'text')
        
        # Test selection
        auth = red_config.get('auth', True)
        discovery = red_config.get('discovery', True)
        fuzz = red_config.get('fuzz', True)
        stress = red_config.get('stress', True)
        
        # Optional security config overrides
        security_overrides = red_config.get('security', {})
        transport_overrides = red_config.get('transport_config', {})
        
        if not target:
            click.echo("Test definition file must specify 'target'", err=True)
            sys.exit(1)
        
        click.echo(f"Running test definition: {red_file}")
        
        # Apply configuration overrides from .red file
        config: MCPRedConfig = ctx.obj['config']
        
        # Apply security config overrides
        if security_overrides:
            for key, value in security_overrides.items():
                if hasattr(config.security, key):
                    setattr(config.security, key, value)
        
        # Apply transport config overrides  
        if transport_overrides:
            for key, value in transport_overrides.items():
                if hasattr(config.transport, key):
                    setattr(config.transport, key, value)
        
        # Run the scan with the parsed arguments
        ctx.invoke(scan, 
                  target=target,
                  transport=transport,
                  output=output,
                  output_format=output_format,
                  auth=auth,
                  discovery=discovery,
                  fuzz=fuzz,
                  stress=stress)
        
    except Exception as e:
        click.echo(f"Failed to run test definition: {e}", err=True)
        sys.exit(1)


# Add command aliases
cli.add_command(discover, name='dis')
cli.add_command(scan, name='sc')


def main():
    """Main entry point for the CLI."""
    # Check if first argument is a .red file
    if len(sys.argv) > 1 and sys.argv[1].endswith('.red'):
        # Insert 'run' command
        sys.argv.insert(1, 'run')
    
    cli()


if __name__ == '__main__':
    main()