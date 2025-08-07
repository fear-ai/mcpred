"""
Main CLI entry point for mcpred.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import click

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']), 
              default='INFO', help='Set logging level')
@click.option('--log-file', type=click.Path(), help='Log file path')
@click.pass_context
def cli(ctx, config, verbose, log_level, log_file):
    """mcpred - MCP Red Team Client for security testing MCP servers."""
    
    # Set up logging
    if verbose:
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


@cli.command()
@click.argument('target', required=False)
@click.option('--transport', '-t', type=click.Choice(['http', 'https', 'stdio', 'websocket', 'ws', 'wss']), 
              default='http', help='Transport type')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'html', 'text']), 
              default='json', help='Output format')
@click.option('--timeout', type=float, help='Operation timeout in seconds')
@click.pass_context
def discover(ctx, target, transport, output, output_format, timeout):
    """Discover server capabilities and potential attack surface."""
    
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
    
    click.echo(f"Discovering capabilities for {target} using {transport} transport...")
    
    async def run_discovery():
        try:
            # Create client
            client = MCPTeamClient(
                target_url=target,
                transport_type=transport,
                security_config=config.security.dict() if hasattr(config.security, 'dict') else None
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


@cli.command()
@click.argument('target', required=False)
@click.option('--transport', '-t', type=click.Choice(['http', 'https', 'stdio', 'websocket', 'ws', 'wss']), 
              default='http', help='Transport type')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'html', 'text']), 
              default='json', help='Output format')
@click.option('--all-tests', is_flag=True, help='Run all security tests')
@click.option('--skip-discovery', is_flag=True, help='Skip server discovery')
@click.option('--skip-auth', is_flag=True, help='Skip authentication tests')
@click.option('--skip-fuzz', is_flag=True, help='Skip protocol fuzzing')
@click.option('--skip-stress', is_flag=True, help='Skip stress testing')
@click.pass_context
def scan(ctx, target, transport, output, output_format, all_tests, skip_discovery, skip_auth, skip_fuzz, skip_stress):
    """Run comprehensive security assessment."""
    
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
    
    click.echo(f"Running security assessment for {target}...")
    
    async def run_scan():
        try:
            # Create client
            client = MCPTeamClient(
                target_url=target,
                transport_type=transport,
                security_config=config.security.dict() if hasattr(config.security, 'dict') else None
            )
            
            # Run tests based on options
            capabilities = None
            security_issues = []
            protocol_violations = []
            stress_results = []
            
            if not skip_discovery or all_tests:
                click.echo("🔍 Running server discovery...")
                capabilities = await client.discover_server()
                click.echo(f"   Found {len(capabilities.tools)} tools, {len(capabilities.resources)} resources")
            
            if not skip_auth or all_tests:
                click.echo("🔐 Running authentication tests...")
                auth_issues = await client.test_authentication()
                security_issues.extend(auth_issues)
                click.echo(f"   Found {len(auth_issues)} authentication issues")
            
            if not skip_fuzz or all_tests:
                click.echo("🔨 Running protocol fuzzing...")
                violations = await client.fuzz_protocol(
                    request_count=config.security.max_fuzz_requests,
                    malformed_rate=config.security.malformed_rate
                )
                protocol_violations.extend(violations)
                click.echo(f"   Found {len(violations)} protocol violations")
            
            if not skip_stress or all_tests:
                click.echo("⚡ Running stress tests...")
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
            click.echo(f"\n📊 Assessment Summary:")
            click.echo(f"   Overall Risk: {exec_summary.get('overall_risk_level', 'Unknown').upper()}")
            click.echo(f"   Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
            
            # Output results
            if output:
                # Export to file
                exporter = ReportExporter()
                exported_path = exporter.export_report(report_data, output, output_format)
                click.echo(f"\n📋 Full report saved to {exported_path}")
                
                # Also export HTML for easy viewing
                if output_format != 'html':
                    html_path = str(Path(output).with_suffix('.html'))
                    exporter.export_report(report_data, html_path, 'html')
                    click.echo(f"📋 HTML report saved to {html_path}")
            else:
                # Brief console output
                if exec_summary.get('top_concerns'):
                    click.echo(f"\n⚠️  Top Concerns:")
                    for concern in exec_summary['top_concerns'][:3]:
                        click.echo(f"   • {concern}")
            
        except Exception as e:
            click.echo(f"Security assessment failed: {e}", err=True)
            sys.exit(1)
    
    # Run async operation
    asyncio.run(run_scan())


@cli.command()
@click.option('--output', '-o', type=click.Path(), default='.mcpred.yaml',
              help='Output path for sample configuration')
@click.pass_context
def init(ctx, output):
    """Initialize sample configuration file."""
    
    config_loader: ConfigLoader = ctx.obj['config_loader']
    
    try:
        config_loader.create_sample_config(output)
        click.echo(f"Sample configuration created at {output}")
        click.echo("Edit the configuration file to customize your testing parameters.")
    except Exception as e:
        click.echo(f"Failed to create configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--config-file', type=click.Path(exists=True), help='Configuration file to validate')
@click.pass_context
def validate(ctx, config_file):
    """Validate configuration file."""
    
    config_loader: ConfigLoader = ctx.obj['config_loader']
    
    if not config_file:
        # Find and validate discovered config
        discovered = config_loader._discover_config_file()
        if discovered:
            config_file = discovered
        else:
            click.echo("No configuration file found to validate.", err=True)
            sys.exit(1)
    
    try:
        is_valid = config_loader.validate_config_file(config_file)
        if is_valid:
            click.echo(f"✅ Configuration file {config_file} is valid")
        else:
            click.echo(f"❌ Configuration file {config_file} is invalid")
            sys.exit(1)
    except Exception as e:
        click.echo(f"Validation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def version(ctx):
    """Show version information."""
    from __init__ import __version__
    click.echo(f"mcpred version {__version__}")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()