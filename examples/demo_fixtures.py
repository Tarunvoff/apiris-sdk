"""
Deterministic Demo Fixtures for Apiris SDK (v1.1.0)

Provides reproducible, rock-solid demonstrations of all 5 standardized risk tiers
(LOW, MODERATE, ELEVATED, HIGH, CRITICAL) independent of transient real-world network fluctuations,
plus an optional live real-internet execution.
"""

from __future__ import annotations

import sys
from typing import Optional

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import responses
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from apiris.cli_ui import classify_risk, get_console, get_risk_badge, print_banner, render_factor_tree
from apiris.client import ApirisClient

console = get_console()


def render_evaluation(url: str, response, scenario_title: str):
    console.print(Panel.fit(
        f"[bold cyan]{scenario_title}[/bold cyan]\n[white]{url}[/white]",
        border_style="cyan",
    ))

    c_score = response.cad_summary.cad_scores.get("C_score", 1.0)
    a_score = response.cad_summary.cad_scores.get("A_score", 1.0)
    d_score = response.cad_summary.cad_scores.get("D_score", 1.0)

    console.print("\n[bold cyan]━━━ CIA Security Triad Scores ━━━[/bold cyan]\n")
    score_table = Table(box=box.ROUNDED, header_style="bold cyan", border_style="cyan")
    score_table.add_column("Pillar", style="cyan", width=22)
    score_table.add_column("Score", justify="right", width=10)
    score_table.add_column("Status", width=18)

    def status_col(score: float) -> str:
        if score >= 0.80:
            return "[green]● Nominal[/green]"
        if score >= 0.40:
            return "[yellow]▲ Borderline[/yellow]"
        return "[red]✗ Degraded[/red]"

    score_table.add_row("🔒 Confidentiality", f"{c_score:.2f}", status_col(c_score))
    score_table.add_row("⚡ Availability", f"{a_score:.2f}", status_col(a_score))
    score_table.add_row("🧩 Integrity", f"{d_score:.2f}", status_col(d_score))
    console.print(score_table)

    risk = classify_risk(
        c_score,
        a_score,
        d_score,
        response.decision.action,
        scoring_factors=response.scoring_factors,
        status_code=response.status_code,
    )
    console.print(f"\n[bold]Risk Classification:[/bold] {get_risk_badge(risk)}\n")

    if response.scoring_factors:
        tree = render_factor_tree(response.scoring_factors, title="Features Considered in Decision")
        console.print(tree)
        console.print()

    console.print("[bold cyan]━━━ Decision Verdict ━━━[/bold cyan]\n")
    dec_table = Table(box=box.ROUNDED, show_header=False, border_style="cyan")
    dec_table.add_column("Property", style="bold cyan", width=18)
    dec_table.add_column("Value", style="white")

    act = response.decision.action
    act_styled = f"[green]{act}[/green]" if act == "pass_through" else f"[bold yellow]{act}[/bold yellow]"
    dec_table.add_row("Action", act_styled)
    dec_table.add_row("Tradeoff", response.decision.tradeoff)
    dec_table.add_row("Confidence", f"{response.decision.confidence:.1%}")
    dec_table.add_row("Enforce Mode", response.cad_summary.mode)
    console.print(dec_table)
    console.print()


def run_deterministic_demo(tier: Optional[str] = None):
    print_banner(console, "Apiris SDK v1.1.0 — Deterministic Reliability Showcase")
    client = ApirisClient()

    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        # Tier 1: LOW
        mock.add(
            responses.GET,
            "https://mock.api.internal/v1/health",
            json={"status": "healthy", "uptime": 99.99, "version": "1.0.0"},
            status=200,
        )

        # Tier 2: MODERATE
        mock.add(
            responses.GET,
            "https://mock.api.weather/v1/forecast",
            json={"location": "US-DC", "temp": 72, "forecast": "Sunny"},
            headers={"Set-Cookie": "session_tracking_id=xyz789"},
            status=200,
        )

        # Tier 3: ELEVATED (2 non-critical exposed headers)
        mock.add(
            responses.GET,
            "https://mock.api.rates/v1/fx",
            json={"base": "USD", "rates": {"EUR": 0.92, "GBP": 0.79}},
            headers={"Set-Cookie": "affiliate_id=promo123", "Authorization": "Bearer public_read_token"},
            status=200,
        )

        # Tier 4: HIGH (Leaked API key / credentials)
        mock.add(
            responses.GET,
            "https://mock.api.auth/v1/user",
            json={"username": "alice", "api_key": "live_sk_987654321"},
            status=200,
        )

        # Tier 5: CRITICAL
        mock.add(
            responses.GET,
            "https://mock.api.nasa/planetary/apod",
            json={"error": {"code": "API_KEY_MISSING", "message": "No api_key was supplied. Get one at https://api.nasa.gov:8080"}},
            status=403,
        )

        if not tier or tier.upper() == "LOW":
            res_low = client.get("https://mock.api.internal/v1/health")
            render_evaluation("https://mock.api.internal/v1/health", res_low, "Tier 1: Nominal Clean Traffic (LOW)")

        if not tier or tier.upper() == "MODERATE":
            res_mod = client.get("https://mock.api.weather/v1/forecast")
            render_evaluation("https://mock.api.weather/v1/forecast", res_mod, "Tier 2: Single Minor Header Exposure (MODERATE)")

        if not tier or tier.upper() == "ELEVATED":
            res_elev = client.get("https://mock.api.rates/v1/fx")
            render_evaluation("https://mock.api.rates/v1/fx", res_elev, "Tier 3: Multi-Header Exposure Warning (ELEVATED)")

        if not tier or tier.upper() == "HIGH":
            res_high = client.get("https://mock.api.auth/v1/user")
            render_evaluation("https://mock.api.auth/v1/user", res_high, "Tier 4: Substantial Confidentiality Leak (HIGH)")

        if not tier or tier.upper() == "CRITICAL":
            res_crit = client.get("https://mock.api.nasa/planetary/apod")
            render_evaluation("https://mock.api.nasa/planetary/apod", res_crit, "Tier 5: Multi-Pillar Failure & HTTP 403 (CRITICAL)")


if __name__ == "__main__":
    tier_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run_deterministic_demo(tier_arg)
