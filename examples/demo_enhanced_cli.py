"""
CAI SDK Enhanced Demo - Beautiful CLI and CVE Advisory

This demo showcases the new features:
1. Rich CLI with progress bars and colorful displays
2. CIA security triad scores with visual feedback
3. Risk classification (LOW, MODERATE, HIGH, CRITICAL)
4. Features considered in scoring (transparency)
5. CVE advisory system (advisory-only, offline)
"""

import subprocess
import sys
from pathlib import Path


def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def run_command(cmd, description):
    """Run a command and display output"""
    print(f"Running: {description}")
    print(f"Command: {cmd}\n")
    print("-" * 70)
    result = subprocess.run(cmd, shell=True, capture_output=False, text=True)
    print("-" * 70)
    return result.returncode


def main():
    print_header("CAI SDK ENHANCED FEATURES DEMO")
    
    print("This demo demonstrates the enhanced CAI SDK with:")
    print("  • Beautiful CLI using rich and typer")
    print("  • CIA score visualization with progress bars")
    print("  • Risk classification (LOW/MODERATE/HIGH/CRITICAL)")
    print("  • Features considered in scoring (transparency)")
    print("  • CVE advisory system (advisory-only, offline)")
    print("")
    
    input("Press Enter to continue...")
    
    # Demo 1: SDK Status
    print_header("DEMO 1: SDK Status Command")
    print("Shows SDK configuration, models, and CVE system status\n")
    run_command("Apiris status", "SDK Status")
    
    input("\nPress Enter to continue to next demo...")
    
    # Demo 2: CVE Advisory Query
    print_header("DEMO 2: CVE Advisory Command")
    print("Query CVE information for a vendor (advisory-only)\n")
    run_command("Apiris cve openai", "CVE Advisory for OpenAI")
    
    input("\nPress Enter to continue to next demo...")
    
    # Demo 3: CVE Advisory with Service
    print_header("DEMO 3: CVE Advisory with Service Filter")
    print("Query CVE information for specific vendor service\n")
    run_command("Apiris cve anthropic", "CVE Advisory for Anthropic")
    
    input("\nPress Enter to continue to next demo...")
    
    # Demo 4: Service Check with Enhanced Display
    print_header("DEMO 4: Enhanced Service Check")
    print("Check an AI service with full CIA scoring, risk classification,")
    print("features considered, and CVE advisory display\n")
    print("Note: This will make a real API call (will likely fail without API key)")
    print("but will demonstrate the enhanced display features\n")
    
    choice = input("Run service check demo? (y/n): ")
    if choice.lower() == 'y':
        run_command(
            "Apiris check https://api.openai.com/v1/models",
            "Service Check with Enhanced Display"
        )
    else:
        print("Skipped.")
    
    # Demo 5: Programmatic Usage
    print_header("DEMO 5: Programmatic SDK Usage")
    print("Using the enhanced SDK programmatically in Python\n")
    
    demo_code = '''
from apiris.client import CADClient

# Initialize client (CVE system loaded automatically)
client = CADClient(config_path="config.yaml")

# Make request (would work with valid API)
# response = client.get("https://api.openai.com/v1/models")

# Access enhanced response fields:
# - response.scoring_factors: Detailed breakdown of CIA scoring
# - response.cve_advisory: CVE information (if vendor identified)
# - response.cad_summary: CIA scores and risk classification
# - response.decision: Runtime decision (deterministic)

print("✓ SDK initialized with CVE advisory system")
print(f"  CVE System Enabled: {client.cve_system.enabled}")
if client.cve_system.enabled:
    vendor_count = len(client.cve_system.cve_data)
    print(f"  Vendors Tracked: {vendor_count}")
'''
    
    print("Example code:")
    print("-" * 70)
    print(demo_code)
    print("-" * 70)
    
    exec(demo_code)
    
    print_header("DEMO COMPLETE")
    
    print("Summary of Enhancements:")
    print("  ✓ Beautiful CLI with rich formatting and progress bars")
    print("  ✓ CIA scores with visual feedback (colors, bars)")
    print("  ✓ Risk classification (LOW/MODERATE/HIGH/CRITICAL)")
    print("  ✓ Scoring transparency - shows all factors considered")
    print("  ✓ CVE advisory system - offline, advisory-only")
    print("  ✓ Backward compatible - existing code works unchanged")
    print("  ✓ Deterministic runtime - no changes to decision logic")
    print("")
    print("New CLI Commands:")
    print("  • Apiris status   - SDK status and configuration")
    print("  • Apiris check    - Enhanced service reliability check")
    print("  • Apiris cve      - Query CVE advisory information")
    print("  • Apiris version  - Display version information")
    print("")
    print("Architecture Guarantees:")
    print("  ✓ Runtime decision engine remains deterministic")
    print("  ✓ CVE logic is advisory-only (never affects decisions)")
    print("  ✓ No live external CVE API calls")
    print("  ✓ SDK functions fully offline")
    print("  ✓ No SaaS dependencies")
    print("")


if __name__ == "__main__":
    main()
