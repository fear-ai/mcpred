"""
Discovery command implementation.
"""

import asyncio
import json
import sys
from pathlib import Path

import click

from ...core.client import MCPTeamClient
from ...reporting import ReportGenerator, ReportExporter


@click.command()
@click.argument('target')
@click.option('--transport', '-t', type=click.Choice(['http', 'https', 'stdio', 'websocket', 'ws', 'wss']), 
              default='http', help='Transport type')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'html', 'text']), 
              default='json', help='Output format')
@click.option('--timeout', type=float, help='Discovery timeout in seconds')
@click.option('--fingerprint', is_flag=True, help='Include server fingerprinting')
@click.option('--show-tools', is_flag=True, help='Show detailed tool information')
@click.option('--show-resources', is_flag=True, help='Show detailed resource information')
@click.pass_context
def discover(ctx, target, transport, output, output_format, timeout, fingerprint, show_tools, show_resources):
    """Discover server capabilities and potential attack surface.
    
    TARGET: The MCP server URL or command to connect to
    
    Examples:
        mcpred discover http://localhost:8080
        mcpred discover ws://example.com:9000 -t websocket
        mcpred discover "python server.py" -t stdio
    """
    
    config = ctx.obj.get('config')
    
    click.echo(f"🔍 Discovering capabilities for {target} using {transport} transport...")
    
    async def run_discovery():
        try:
            # Create security config from global config or defaults
            security_config = None
            if config and hasattr(config, 'security'):
                security_config = config.security.dict()
            
            # Apply timeout override
            if timeout and security_config:
                security_config['discovery_timeout'] = timeout
            
            # Create client
            client = MCPTeamClient(
                target_url=target,
                transport_type=transport,
                security_config=security_config
            )
            
            # Run discovery
            capabilities = await client.discover_server()
            
            # Additional fingerprinting if requested
            if fingerprint:
                click.echo("🔬 Running server fingerprinting...")
                # Fingerprinting would be done during discovery
                # This is just for user feedback
            
            # Display console output
            click.echo(f"\n📋 Discovery Results:")
            click.echo(f"   Transport Methods: {', '.join(capabilities.transport_methods)}")
            click.echo(f"   Tools Found: {len(capabilities.tools)}")
            click.echo(f"   Resources Found: {len(capabilities.resources)}")
            click.echo(f"   Prompts Found: {len(capabilities.prompts)}")
            
            if capabilities.security_issues:
                click.echo(f"   Security Issues: {len(capabilities.security_issues)}")
                
                # Show high/critical issues immediately
                high_issues = [
                    issue for issue in capabilities.security_issues
                    if issue.get('severity') in ['high', 'critical']
                ]
                if high_issues:
                    click.echo(f"   ⚠️  High/Critical Issues: {len(high_issues)}")
            
            # Show detailed information if requested
            if show_tools and capabilities.tools:
                click.echo(f"\n🔧 Tools:")
                for tool in capabilities.tools[:5]:  # Show first 5
                    click.echo(f"   • {tool.name}: {tool.description}")
                if len(capabilities.tools) > 5:
                    click.echo(f"   ... and {len(capabilities.tools) - 5} more")
            
            if show_resources and capabilities.resources:
                click.echo(f"\n📁 Resources:")
                for resource in capabilities.resources[:5]:  # Show first 5
                    click.echo(f"   • {resource.name}: {resource.uri}")
                if len(capabilities.resources) > 5:
                    click.echo(f"   ... and {len(capabilities.resources) - 5} more")
            
            # Generate and save report if output specified
            if output:
                report_generator = ReportGenerator()
                client_summary = client.get_summary()
                
                report_data = report_generator.generate_comprehensive_report(
                    client_summary=client_summary,
                    security_issues=capabilities.security_issues if capabilities.security_issues else None
                )
                
                # Export report
                exporter = ReportExporter()
                exported_path = exporter.export_report(report_data, output, output_format)
                click.echo(f"\n📄 Discovery report saved to {exported_path}")
            
            # Return success
            return 0
            
        except KeyboardInterrupt:
            click.echo("\n⏸️  Discovery interrupted by user", err=True)
            return 130
        except Exception as e:
            click.echo(f"\n❌ Discovery failed: {e}", err=True)
            return 1
    
    # Run async operation and exit with return code
    result = asyncio.run(run_discovery())
    sys.exit(result)