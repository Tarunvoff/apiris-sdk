"""
Shared Rich UI and Typography Components for Apiris CLI
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

# Consistent brand banner
BANNER_TEXT = """[bold cyan]    ___         _      _     
   /   \\ _ __  (_) _ _(_)___ 
  / /\\ /| '_ \\ | || '_| (_-< 
 / /_// | .__/ |_||_| |_/__/ 
/___,'  |_|                  [/bold cyan]
[dim]Deterministic AI Reliability Intelligence[/dim]"""

# Standardized color scheme
RISK_PALETTE = {
    "LOW": "bold green",
    "CLEAN": "bold green",
    "MODERATE": "bold yellow",
    "ELEVATED": "bold dark_orange",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
}

RISK_ICONS = {
    "LOW": "✓",
    "CLEAN": "✓",
    "MODERATE": "⚠",
    "ELEVATED": "▲",
    "HIGH": "✗",
    "CRITICAL": "🚨",
}


def get_console() -> Console:
    return Console(
        legacy_windows=False if sys.platform == "win32" else None,
        no_color=False if sys.stdout.isatty() else None,
    )


def print_banner(console: Console, title: Optional[str] = None):
    console.print(BANNER_TEXT)
    if title:
        console.print(f"[bold cyan]{title}[/bold cyan]\n")
    else:
        console.print()


def get_risk_badge(level: str) -> str:
    lvl_upper = level.upper()
    style = RISK_PALETTE.get(lvl_upper, "white")
    icon = RISK_ICONS.get(lvl_upper, "●")
    if "on red" in style:
        return f"[{style}] {icon} {lvl_upper} [/{style}]"
    return f"[{style}]{icon} {lvl_upper}[/{style}]"


def classify_risk(
    c_score: float,
    a_score: float,
    d_score: float,
    action: str,
    scoring_factors: Optional[Dict[str, Any]] = None,
    status_code: Optional[int] = None,
) -> str:
    """
    Classifies holistic traffic risk into 5 standardized tiers:
    - LOW: Normal clean traffic, no active threats or policy escalations.
    - MODERATE: Isolated single-factor non-critical issue (e.g. 1 header warning, pacing delay, HTTP 200).
    - ELEVATED: Multiple non-critical signals, cache fallback, or moderate latency/schema drift.
    - HIGH: Substantial single-pillar breach (e.g. multiple credentials leaked, deep confidentiality masking).
    - CRITICAL: Multi-pillar failure (e.g. C breach + HTTP 4xx/5xx error), total integrity breach (reject_response), or severe multi-signal attack.
    """
    if action == "reject_response":
        return "CRITICAL"

    c_factors = [f for f in (scoring_factors or {}).get("confidentiality_factors", []) if f.get("impact") == "negative"]
    a_factors = [f for f in (scoring_factors or {}).get("availability_factors", []) if f.get("impact") == "negative"]
    d_factors = [f for f in (scoring_factors or {}).get("integrity_factors", []) if f.get("impact") == "negative"]

    c_count = sum(len(f.get("details", [])) if f.get("details") else f.get("count", 1) for f in c_factors)
    a_count = sum(f.get("count", 1) if isinstance(f.get("count"), int) else 1 for f in a_factors)
    d_count = sum(f.get("count", 1) if isinstance(f.get("count"), int) else 1 for f in d_factors)
    total_signals = c_count + a_count + d_count

    has_http_error = (status_code is not None and status_code >= 400) or any("HTTP" in f.get("name", "") for f in a_factors)
    failing_dims = sum(1 for s in [c_score, a_score, d_score] if s < 0.40)

    # 1. CRITICAL: Hard block, multi-pillar degradation + HTTP error, or severe multi-pillar attack (>=3 failing factors across >=2 dimensions, or >=5 signals total)
    if action == "reject_response" or (failing_dims >= 2 and has_http_error) or (failing_dims >= 2 and total_signals >= 3) or total_signals >= 5:
        return "CRITICAL"

    # 2. HIGH: Substantial confidential credentials leaked (sensitive fields / auth hints) or multiple signals in a single pillar
    has_credentials = any(f.get("name") in {"Sensitive Fields Detected", "Auth Hints in Payload"} for f in c_factors)
    if failing_dims >= 2 or has_credentials or (action == "mask_sensitive_fields" and len(c_factors) >= 2) or total_signals >= 3:
        return "HIGH"

    # 3. ELEVATED: 2 non-critical signals (e.g. 2 exposed headers) or cache fallback
    if action in {"serve_stale_cache", "downgrade_fidelity"} or total_signals == 2:
        return "ELEVATED"

    # 4. MODERATE: 1 isolated minor signal (e.g. 1 header warning on HTTP 200, or delay_response)
    if action in {"mask_sensitive_fields", "delay_response"} or total_signals == 1 or min(c_score, a_score, d_score) < 0.40:
        return "MODERATE"

    return "LOW"


def render_factor_tree(factors: Dict[str, Any], title: str = "📊 Scoring Factors") -> Tree:
    tree = Tree(f"[bold cyan]{title}[/bold cyan]")

    # 1. Confidentiality (🔒)
    c_factors = factors.get("confidentiality_factors", [])
    if c_factors:
        c_branch = tree.add(f"[cyan]🔒 Confidentiality ({len(c_factors)} signal{'s' if len(c_factors) > 1 else ''})[/cyan]")
        for f in c_factors:
            impact = f.get("impact", "neutral")
            icon = "[bold red]✗[/bold red]" if impact == "negative" else "[bold yellow]⚠[/bold yellow]" if impact == "neutral" else "[bold green]✓[/bold green]"
            val = f.get("count", f.get("value", "detected"))
            c_branch.add(f"{icon} {f['name']}: [white]{val}[/white]")
    else:
        tree.add("[green]🔒 Confidentiality (nominal / no leakage)[/green]")

    # 2. Availability (⚡)
    a_factors = factors.get("availability_factors", [])
    if a_factors:
        a_branch = tree.add(f"[cyan]⚡ Availability ({len(a_factors)} signal{'s' if len(a_factors) > 1 else ''})[/cyan]")
        for f in a_factors:
            impact = f.get("impact", "neutral")
            icon = "[bold red]✗[/bold red]" if impact == "negative" else "[bold yellow]⚠[/bold yellow]" if impact == "neutral" else "[bold green]✓[/bold green]"
            val = f.get("value", "detected")
            if "budget" in f:
                val = f"{val} (budget: {f['budget']})"
            a_branch.add(f"{icon} {f['name']}: [white]{val}[/white]")
    else:
        tree.add("[green]⚡ Availability (nominal / responsive)[/green]")

    # 3. Integrity (🧩)
    i_factors = factors.get("integrity_factors", [])
    if i_factors:
        i_branch = tree.add(f"[cyan]🧩 Integrity ({len(i_factors)} signal{'s' if len(i_factors) > 1 else ''})[/cyan]")
        for f in i_factors:
            impact = f.get("impact", "neutral")
            icon = "[bold red]✗[/bold red]" if impact == "negative" else "[bold yellow]⚠[/bold yellow]" if impact == "neutral" else "[bold green]✓[/bold green]"
            val = f.get("count", f.get("value", "detected"))
            i_branch.add(f"{icon} {f['name']}: [white]{val}[/white]")
    else:
        tree.add("[green]🧩 Integrity (nominal / schema consistent)[/green]")

    return tree
