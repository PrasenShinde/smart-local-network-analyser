#!/usr/bin/env python3
"""
run.py
────────────────────────────────────────────────────────────────
Main entry point for the Smart Security Analyzer.

Usage:
  python run.py                        # Start API server (default)
  python run.py --cli scan 192.168.1.1 # CLI mode: run a scan
  python run.py --cli osint example.com
  python run.py --cli shadow example.com
  python run.py --help
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

sys.path.insert(0, str(Path(__file__).parent))

from utils.config import settings
from utils.helpers import get_logger

logger = get_logger(__name__)
console = Console()


# ── Server ────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    pass


@cli.command("server")
@click.option("--host", default=settings.api_host, help="Bind host")
@click.option("--port", default=settings.api_port, type=int, help="Bind port")
@click.option("--reload", is_flag=True, default=False, help="Auto-reload on code changes")
def serve(host: str, port: int, reload: bool):
    """Start the REST API server."""
    console.print(Panel.fit(
        f"[bold green]Smart Security Analyzer[/bold green]\n"
        f"[cyan]API:[/cyan] http://{host}:{port}\n"
        f"[cyan]Docs:[/cyan] http://{host}:{port}/docs\n"
        f"[cyan]AI Remediation:[/cyan] {'✅ enabled' if settings.anthropic_api_key else '❌ disabled (set ANTHROPIC_API_KEY)'}",
        title="🔐 Security Analyzer",
        border_style="green",
    ))
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ── CLI scan commands ─────────────────────────────────────────────────────────

@cli.group()
def scan():
    """Network scanning commands."""
    pass


@scan.command("run")
@click.argument("target")
@click.option("--type", "scan_type",
              type=click.Choice(["discovery","basic","vuln","web","full","local"]),
              default="basic")
@click.option("--ports", default="1-1000", help="Port range, e.g. 1-1000 or 80,443")
@click.option("--remediate", is_flag=True, default=False,
              help="Generate AI remediation playbooks")
@click.option("--output", type=click.Path(), default=None,
              help="Save JSON results to file")
def run_scan(target: str, scan_type: str, ports: str,
              remediate: bool, output: str):
    """Run a network scan against TARGET."""
    from core.scanner import NetworkScanner
    import uuid

    async def _run():
        sc = NetworkScanner()
        scan_id = str(uuid.uuid4())[:8]
        console.print(f"[bold cyan]Starting {scan_type} scan on {target}…[/bold cyan]")

        scan_map = {
            "discovery": lambda: sc.discovery_scan(target, scan_id),
            "basic":     lambda: sc.basic_scan(target, scan_id, ports),
            "vuln":      lambda: sc.vulnerability_scan(target, scan_id, ports),
            "web":       lambda: sc.web_scan(target, scan_id),
            "full":      lambda: sc.full_scan(target, scan_id),
            "local":     lambda: sc.local_network_scan(scan_id),
        }
        result = await scan_map[scan_type]()

        _print_scan_summary(result)

        if remediate and result.hosts:
            from core.remediation import RemediationEngine
            eng = RemediationEngine()
            all_vulns = []
            for h in result.hosts:
                for v in h.vulnerabilities:
                    v["os"] = h.os_match
                    all_vulns.append(v)
            if all_vulns:
                console.print(f"\n[bold yellow]Generating {len(all_vulns)} remediation playbooks…[/bold yellow]")
                bundle = await eng.generate_bundle(scan_id, target, all_vulns)
                _print_playbooks(bundle)

        if output:
            Path(output).write_text(
                json.dumps(result.to_dict(), indent=2, default=str)
            )
            console.print(f"\n[green]Results saved to {output}[/green]")

    asyncio.run(_run())


# ── CLI OSINT commands ────────────────────────────────────────────────────────

@cli.group()
def osint():
    """OSINT reconnaissance commands."""
    pass


@osint.command("run")
@click.argument("domain")
@click.option("--output", type=click.Path(), default=None)
def run_osint(domain: str, output: str):
    """Full passive OSINT for DOMAIN."""
    from core.osint import OSINTEngine
    import uuid

    async def _run():
        eng = OSINTEngine()
        scan_id = str(uuid.uuid4())[:8]
        console.print(f"[bold cyan]Starting OSINT for {domain}…[/bold cyan]")
        result = await eng.full_osint(domain, scan_id)
        _print_osint_summary(result)
        if output:
            Path(output).write_text(
                json.dumps(result.to_dict(), indent=2, default=str)
            )
            console.print(f"\n[green]Results saved to {output}[/green]")

    asyncio.run(_run())


# ── CLI Shadow IT commands ────────────────────────────────────────────────────

@cli.group("shadow")
def shadow():
    """Shadow IT / forgotten asset discovery."""
    pass


@shadow.command("run")
@click.argument("domain")
@click.option("--output", type=click.Path(), default=None)
def run_shadow(domain: str, output: str):
    """Shadow IT discovery for DOMAIN."""
    from core.shadow_it import ShadowITDiscovery
    import uuid

    async def _run():
        eng = ShadowITDiscovery()
        scan_id = str(uuid.uuid4())[:8]
        console.print(f"[bold cyan]Starting Shadow IT discovery for {domain}…[/bold cyan]")
        result = await eng.discover(domain, scan_id)
        _print_shadow_summary(result)
        if output:
            Path(output).write_text(
                json.dumps(result.to_dict(), indent=2, default=str)
            )
            console.print(f"\n[green]Results saved to {output}[/green]")

    asyncio.run(_run())


# ── Print helpers ─────────────────────────────────────────────────────────────

def _print_scan_summary(result):
    s = result.summary
    console.print(Panel(
        f"Hosts up: [green]{s.get('hosts_up', 0)}[/green]  |  "
        f"Open ports: [cyan]{s.get('total_open_ports', 0)}[/cyan]  |  "
        f"Vulnerabilities: [red]{s.get('total_vulnerabilities', 0)}[/red]",
        title=f"Scan Complete – {result.target}",
    ))

    for host in result.hosts:
        if not host.ports:
            continue
        t = Table(title=f"[bold]{host.ip}[/bold] ({host.hostname}) – {host.os_match}")
        t.add_column("Port", style="cyan")
        t.add_column("Service")
        t.add_column("Version")
        t.add_column("Risk", style="red")
        for p in sorted(host.ports, key=lambda x: x.port):
            t.add_row(str(p.port), p.service, p.version, p.risk_level)
        console.print(t)

    if any(h.vulnerabilities for h in result.hosts):
        vt = Table(title="[bold red]Vulnerabilities Found[/bold red]")
        vt.add_column("Host")
        vt.add_column("Port")
        vt.add_column("CVEs")
        vt.add_column("CVSS")
        vt.add_column("Script")
        for h in result.hosts:
            for v in h.vulnerabilities:
                vt.add_row(
                    v.get("ip", ""),
                    str(v.get("port", "")),
                    ", ".join(v.get("cves", [])) or "—",
                    str(v.get("cvss_score", "")),
                    v.get("script", ""),
                )
        console.print(vt)


def _print_osint_summary(result):
    console.print(Panel(
        f"Subdomains: [green]{len(result.subdomains)}[/green]  |  "
        f"Emails: [cyan]{len(result.emails)}[/cyan]  |  "
        f"DNS records: [cyan]{len(result.dns_records)}[/cyan]",
        title=f"OSINT Complete – {result.domain}",
    ))
    for s in result.subdomains[:20]:
        status = f"HTTP {s.http_status}" if s.http_status else "no response"
        ips = ", ".join(s.ip_addresses[:2]) if s.ip_addresses else "unresolved"
        console.print(f"  [cyan]{s.subdomain}[/cyan] → {ips} [{status}]")
    if len(result.subdomains) > 20:
        console.print(f"  … and {len(result.subdomains) - 20} more")


def _print_shadow_summary(result):
    console.print(Panel(
        f"GitHub leaks: [red]{len(result.github_leaks)}[/red]  |  "
        f"Open buckets: [red]{sum(1 for b in result.cloud_buckets if b.is_public)}[/red]  |  "
        f"Pastebin hits: [yellow]{len(result.pastebin_hits)}[/yellow]  |  "
        f"Risk score: [bold red]{result.risk_score:.1f}/100[/bold red]",
        title=f"Shadow IT Discovery – {result.domain}",
    ))
    if result.ai_correlation:
        console.print(Panel(result.ai_correlation, title="AI Analysis",
                             border_style="yellow"))


def _print_playbooks(bundle):
    t = Table(title="Remediation Playbooks")
    t.add_column("ID")
    t.add_column("Vulnerability")
    t.add_column("Severity")
    t.add_column("Steps")
    t.add_column("Automation")
    t.add_column("Path")
    for pb in bundle.playbooks:
        t.add_row(
            pb.playbook_id,
            pb.vuln_name[:40],
            pb.severity,
            str(len(pb.steps)),
            pb.automation_level,
            pb.file_path or "—",
        )
    console.print(t)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Default: start the server
        sys.argv.append("server")
    cli()
