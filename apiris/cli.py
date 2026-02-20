"""
Apiris CLI - AI Reliability Intelligence SDK

Production-grade command-line interface for Apiris SDK.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.tree import Tree
from rich import box

from .client import CADClient
from .config import load_config

__version__ = "1.0.1"

def get_package_models_dir() -> Path:
    """Get the models directory from the installed package."""
    return Path(__file__).parent / "models"

app = typer.Typer(
    name="Apiris",
    help="Apiris - Deterministic AI Reliability Intelligence SDK",
    add_completion=False,
)
console = Console()


@app.command()
def version():
    """
    Display Apiris SDK version information.
    """
    console.print(f"[bold cyan]Apiris SDK[/bold cyan] version [bold green]1.0.0[/bold green]")
    console.print("Deterministic AI Reliability Intelligence")
    console.print("https://github.com/Tarunvoff/apiris-sdk")


@app.command()
def check(
    url: str = typer.Argument(..., help="URL endpoint to check"),
    config: Optional[str] = typer.Option(None, "--config", help="Path to config.yaml file"),
    policy: Optional[str] = typer.Option(None, "--policy", help="Path to policy.yaml file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    show_cve: bool = typer.Option(True, "--show-cve/--no-cve", help="Show CVE advisory information"),
):
    """
    Check an AI service endpoint and evaluate reliability.
    
    Example:
        Apiris check https://api.openai.com/v1/chat/completions
    """
    try:
        # Load configuration
        config_path = config or "config.yaml"
        if not Path(config_path).exists():
            console.print(f"[bold yellow]Warning:[/bold yellow] Config file not found: {config_path}")
            console.print("Using default configuration...\n")
        
        # Initialize client
        with console.status("[bold green]Initializing Apiris client...", spinner="dots"):
            client = CADClient(config_path=config_path, policy_path=policy)
        
        # Make request
        with console.status(f"[bold green]Checking {url}...", spinner="dots"):
            response = client.get(url)
        
        # Display header
        console.print("\n")
        console.print(Panel.fit(
            "[bold cyan]Apiris Reliability Analysis[/bold cyan]",
            border_style="cyan"
        ))
        
        # Display CIA scores with progress bars
        console.print("\n[bold cyan]━━━ CIA Security Triad Scores ━━━[/bold cyan]\n")
        
        cad_scores = response.cad_summary.cad_scores
        c_score = cad_scores.get("C_score", 0.0)
        a_score = cad_scores.get("A_score", 0.0)
        d_score = cad_scores.get("D_score", 0.0)
        
        def score_color(score: float) -> str:
            if score >= 0.8:
                return "green"
            elif score >= 0.5:
                return "yellow"
            else:
                return "red"
        
        def score_status(score: float) -> str:
            if score >= 0.8:
                return "✓ Good"
            elif score >= 0.5:
                return "⚠ Warning"
            else:
                return "✗ Poor"
        
        # Create progress bars for scores
        table = Table(box=None, show_header=False, padding=(0, 2))
        table.add_column("Label", style="bold", width=20)
        table.add_column("Bar", width=40)
        table.add_column("Score", width=10, justify="right")
        table.add_column("Status", width=15)
        
        for label, score in [("Confidentiality", c_score), ("Availability", a_score), ("Integrity", d_score)]:
            color = score_color(score)
            bar_length = int(score * 30)
            bar = "█" * bar_length + "░" * (30 - bar_length)
            status = score_status(score)
            table.add_row(
                f"[cyan]{label}[/cyan]",
                f"[{color}]{bar}[/{color}]",
                f"[{color}]{score:.3f}[/{color}]",
                f"[{color}]{status}[/{color}]"
            )
        
        console.print(table)
        
        # Risk Classification
        avg_score = (c_score + a_score + d_score) / 3
        if avg_score >= 0.8:
            risk_level = "LOW"
            risk_color = "green"
            risk_icon = "✓"
        elif avg_score >= 0.6:
            risk_level = "MODERATE"
            risk_color = "yellow"
            risk_icon = "⚠"
        elif avg_score >= 0.4:
            risk_level = "HIGH"
            risk_color = "red"
            risk_icon = "✗"
        else:
            risk_level = "CRITICAL"
            risk_color = "red bold"
            risk_icon = "⚠"
        
        console.print(f"\n[bold]Risk Classification:[/bold] [{risk_color}]{risk_icon} {risk_level}[/{risk_color}]\n")
        
        # Features Considered section
        if response.scoring_factors:
            console.print("[bold cyan]━━━ Features Considered in Scoring ━━━[/bold cyan]\n")
            
            factors = response.scoring_factors
            thresholds = factors.get("thresholds", {})
            
            # Build tree for factors
            tree = Tree("📊 Scoring Factors")
            
            # Confidentiality factors
            c_factors = factors.get("confidentiality_factors", [])
            if c_factors:
                c_branch = tree.add(f"[cyan]🔒 Confidentiality ({len(c_factors)} factors)[/cyan]")
                for factor in c_factors:
                    impact_icon = "❌" if factor["impact"] == "negative" else "⚠" if factor["impact"] == "neutral" else "✓"
                    c_branch.add(f"{impact_icon} {factor['name']}: {factor.get('count', factor.get('value', 'detected'))}")
            else:
                tree.add("[green]🔒 Confidentiality (no issues)[/green]")
            
            # Availability factors
            a_factors = factors.get("availability_factors", [])
            if a_factors:
                a_branch = tree.add(f"[cyan]⚡ Availability ({len(a_factors)} factors)[/cyan]")
                for factor in a_factors:
                    impact_icon = "❌" if factor["impact"] == "negative" else "✓"
                    value = factor.get('value', 'detected')
                    if 'budget' in factor:
                        value = f"{value} (budget: {factor['budget']})"
                    a_branch.add(f"{impact_icon} {factor['name']}: {value}")
            else:
                tree.add("[green]⚡ Availability (no issues)[/green]")
            
            # Integrity factors
            i_factors = factors.get("integrity_factors", [])
            if i_factors:
                i_branch = tree.add(f"[cyan]🛡 Integrity ({len(i_factors)} factors)[/cyan]")
                for factor in i_factors:
                    impact_icon = "❌" if factor["impact"] == "negative" else "⚠" if factor["impact"] == "neutral" else "✓"
                    value = factor.get('count', factor.get('value', 'detected'))
                    i_branch.add(f"{impact_icon} {factor['name']}: {value}")
            else:
                tree.add("[green]🛡 Integrity (no issues)[/green]")
            
            console.print(tree)
            console.print()
        
        # Display decision
        console.print("[bold cyan]━━━ Decision Summary ━━━[/bold cyan]\n")
        
        decision_table = Table(box=box.ROUNDED, show_header=False, border_style="blue")
        decision_table.add_column("Key", style="bold blue", width=15)
        decision_table.add_column("Value", style="white")
        
        action_color = "green" if response.decision.action == "pass_through" else "yellow"
        decision_table.add_row("Action", f"[{action_color}]{response.decision.action}[/{action_color}]")
        decision_table.add_row("Tradeoff", response.decision.tradeoff)
        decision_table.add_row("Confidence", f"{response.decision.confidence:.1%}")
        decision_table.add_row("Mode", response.cad_summary.mode)
        
        console.print(decision_table)
        
        # CVE Advisory section
        if show_cve and response.cve_advisory:
            cve = response.cve_advisory
            console.print("\n[bold cyan]━━━ CVE Security Advisory (Advisory Only) ━━━[/bold cyan]\n")
            
            cve_risk_colors = {
                "LOW": "green",
                "MODERATE": "yellow",
                "HIGH": "red",
                "CRITICAL": "red bold"
            }
            cve_risk_color = cve_risk_colors.get(cve.risk_level, "white")
            
            console.print(f"[bold]Vendor:[/bold] {cve.vendor}")
            console.print(f"[bold]Service:[/bold] {cve.service}")
            console.print(f"[bold]Total CVEs:[/bold] {cve.total_cves}")
            console.print(f"[bold]Advisory Score:[/bold] {cve.advisory_score:.2f}")
            console.print(f"[bold]Risk Level:[/bold] [{cve_risk_color}]{cve.risk_level}[/{cve_risk_color}]\n")
            
            if cve.cve_entries:
                cve_table = Table(
                    title=f"CVE Entries (showing {min(5, len(cve.cve_entries))} of {len(cve.cve_entries)})",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                cve_table.add_column("CVE ID", style="cyan")
                cve_table.add_column("Severity", justify="center")
                cve_table.add_column("Score", justify="right")
                cve_table.add_column("Description", max_width=50)
                
                for entry in cve.cve_entries[:5]:
                    severity_colors = {
                        "CRITICAL": "red bold",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "green"
                    }
                    sev_color = severity_colors.get(entry.severity, "white")
                    cve_table.add_row(
                        entry.id,
                        f"[{sev_color}]{entry.severity}[/{sev_color}]",
                        f"{entry.score:.1f}",
                        entry.description[:80] + "..." if len(entry.description) > 80 else entry.description
                    )
                
                console.print(cve_table)
                console.print("\n[dim italic]Note: CVE advisory is for informational purposes only and does not affect runtime decisions.[/dim italic]\n")
        
        if verbose:
            console.print("\n[bold cyan]━━━ Response Details ━━━[/bold cyan]\n")
            console.print(f"[bold]Status Code:[/bold] {response.status_code}")
            console.print(f"[bold]Headers:[/bold] {len(response.headers)} headers")
            if response.raw:
                console.print(f"[bold]Body:[/bold] {len(response.raw)} bytes")
        
        # Exit with appropriate code
        if response.decision.action in ["reject_response", "block"]:
            console.print("\n[bold red]⚠ Service blocked by policy.[/bold red]\n")
            sys.exit(1)
        else:
            console.print("\n[bold green]✓ Service check complete.[/bold green]\n")
            sys.exit(0)
            
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        if verbose:
            console.print_exception()
        sys.exit(1)
        
        if verbose:
            console.print("\n[bold cyan]Response Details[/bold cyan]")
            console.print(f"Status Code: {response.status_code}")
            console.print(f"Headers: {len(response.headers)} headers")
            if response.raw:
                console.print(f"Body: {len(response.raw)} bytes")
        
        # Exit with appropriate code
        if response.decision.action == "block":
            console.print("\n[bold red]⚠ Service blocked by policy.[/bold red]")
            sys.exit(1)
        else:
            console.print("\n[bold green]✓ Service check complete.[/bold green]")
            sys.exit(0)
            
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        if verbose:
            console.print_exception()
        sys.exit(1)


@app.command()
def status(
    config: Optional[str] = typer.Option(None, "--config", help="Path to config.yaml file"),
):
    """
    Display Apiris SDK status and configuration.
    """
    try:
        # Load configuration
        config_path = config or "config.yaml"
        
        console.print("\n")
        console.print(Panel.fit(
            "[bold cyan]Apiris SDK Status[/bold cyan]",
            border_style="cyan"
        ))
        console.print()
        
        # Configuration status
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("Setting", style="cyan", width=20)
        table.add_column("Value", style="white")
        
        if Path(config_path).exists():
            cfg = load_config(config_path)
            table.add_row("Config File", f"[green]✓ {config_path}[/green]")
            table.add_row("Mode", cfg.mode)
            table.add_row("AI Enabled", "Yes" if cfg.enable_ai else "No")
            table.add_row("Log Directory", cfg.log_dir)
            table.add_row("Models Directory", cfg.models_dir)
        else:
            table.add_row("Config File", f"[red]✗ Not found: {config_path}[/red]")
            table.add_row("Status", "[yellow]Using defaults[/yellow]")
        
        console.print(table)
        
        # Check model availability
        console.print("\n[bold cyan]Model Status[/bold cyan]\n")
        model_table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        model_table.add_column("Model", style="cyan")
        model_table.add_column("Status", style="yellow")
        
        models_dir = get_package_models_dir()
        models = [
            ("Anomaly Model", models_dir / "anomaly_model.json"),
            ("Predictive Model", models_dir / "predictive_model.json"),
            ("Tradeoff Model", models_dir / "tradeoff_model.json"),
            ("CVE Database", models_dir / "cve_data.json"),
        ]
        
        for model_name, model_path in models:
            if model_path.exists():
                model_table.add_row(model_name, "[green]✓ Available[/green]")
            else:
                model_table.add_row(model_name, "[yellow]⚠ Not found (optional)[/yellow]")
        
        console.print(model_table)
        
        # CVE Advisory System Status
        from .intelligence.cve_advisory import CVEAdvisorySystem
        cve_system = CVEAdvisorySystem()
        
        console.print("\n[bold cyan]CVE Advisory System[/bold cyan]\n")
        cve_status = Table(box=box.ROUNDED, show_header=False)
        cve_status.add_column("Property", style="cyan", width=20)
        cve_status.add_column("Value", style="white")
        
        if cve_system.enabled:
            vendor_count = len(cve_system.cve_data)
            cve_status.add_row("Status", "[green]✓ Enabled[/green]")
            cve_status.add_row("Vendors Tracked", str(vendor_count))
            cve_status.add_row("Data Source", "Local (offline)")
        else:
            cve_status.add_row("Status", "[yellow]⚠ Disabled (no CVE data file)[/yellow]")
        
        console.print(cve_status)
        
        console.print("\n[bold green]✓ Apiris SDK is ready[/bold green]\n")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


@app.command()
def cve(
    vendor: str = typer.Argument(..., help="Vendor name (e.g., openai, anthropic, google)"),
    service: Optional[str] = typer.Option(None, "--service", help="Optional service name"),
):
    """
    Query CVE advisory information for a vendor/service.
    
    Example:
        Apiris cve openai
        Apiris cve anthropic --service claude-3
    """
    try:
        from .intelligence.cve_advisory import CVEAdvisorySystem
        
        console.print("\n")
        console.print(Panel.fit(
            f"[bold cyan]CVE Advisory for {vendor.upper()}[/bold cyan]",
            border_style="cyan"
        ))
        console.print()
        
        cve_system = CVEAdvisorySystem()
        
        if not cve_system.enabled:
            expected_path = get_package_models_dir() / "cve_data.json"
            console.print("[bold red]Error:[/bold red] CVE advisory system not available (missing CVE data file)")
            console.print(f"[dim]Expected location: {expected_path}[/dim]\n")
            sys.exit(1)
        
        advisory = cve_system.get_advisory(vendor, service)
        
        if not advisory:
            console.print(f"[bold yellow]No CVE data found for vendor: {vendor}[/bold yellow]")
            if service:
                console.print(f"[dim]Service: {service}[/dim]")
            console.print("\n[dim]Available vendors:[/dim]")
            for v in sorted(cve_system.cve_data.keys()):
                console.print(f"  • {v}")
            console.print()
            sys.exit(0)
        
        # Display advisory summary
        cve_risk_colors = {
            "LOW": "green",
            "MODERATE": "yellow",
            "HIGH": "red",
            "CRITICAL": "red bold"
        }
        risk_color = cve_risk_colors.get(advisory.risk_level, "white")
        
        summary = Table(box=box.ROUNDED, show_header=False)
        summary.add_column("Property", style="bold cyan", width=20)
        summary.add_column("Value", style="white")
        
        summary.add_row("Vendor", advisory.vendor)
        summary.add_row("Service", advisory.service)
        summary.add_row("Total CVEs", str(advisory.total_cves))
        summary.add_row("Advisory Score", f"{advisory.advisory_score:.3f}")
        summary.add_row("Risk Level", f"[{risk_color}]{advisory.risk_level}[/{risk_color}]")
        
        console.print(summary)
        
        # Display CVE entries
        if advisory.cve_entries:
            console.print(f"\n[bold cyan]CVE Entries ({len(advisory.cve_entries)} total)[/bold cyan]\n")
            
            cve_table = Table(
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            cve_table.add_column("CVE ID", style="cyan", width=18)
            cve_table.add_column("Severity", justify="center", width=12)
            cve_table.add_column("Score", justify="right", width=8)
            cve_table.add_column("Published", width=12)
            cve_table.add_column("Description", max_width=60)
            
            severity_colors = {
                "CRITICAL": "red bold",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green"
            }
            
            for entry in advisory.cve_entries:
                sev_color = severity_colors.get(entry.severity, "white")
                desc = entry.description[:80] + "..." if len(entry.description) > 80 else entry.description
                cve_table.add_row(
                    entry.id,
                    f"[{sev_color}]{entry.severity}[/{sev_color}]",
                    f"{entry.score:.1f}",
                    entry.published_date[:10] if len(entry.published_date) >= 10 else entry.published_date,
                    desc
                )
            
            console.print(cve_table)
        
        console.print("\n[dim italic]Note: This is advisory information only and does not affect runtime decisions.[/dim italic]\n")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
