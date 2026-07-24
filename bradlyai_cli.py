#!/usr/bin/env python3
"""
BradlyAI Enterprise Shell CLI Tool // Management & Operations Console
"""

import argparse
import sys
import os
import requests
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Configure API URL
BASE_URL = os.getenv("BRADLY_API_URL", "http://localhost:8000/api/v1")
console = Console()

def display_header():
    console.print("\n[bold cyan]🛡️  BradlyAI - Driverless SOC Operations Shell[/bold cyan]")
    console.print("[green]Autonomous Cyber Security Management Protocol v1.0[/green]\n")

def get_status():
    try:
        res = requests.get(f"{BASE_URL}/asm/assets", timeout=5)
        if res.status_code == 200:
            assets = res.json()
            console.print(Panel(f"[bold green]● DRIVERLESS SOC CORE ACTIVE[/bold green]\n\nConnected to FastAPI Python Engine.\nMonitored Enterprise Assets: [bold cyan]{len(assets)} Active[/bold cyan]", title="System Status", expand=False))
        else:
            console.print(f"[bold red]❌ Server error: Received HTTP {res.status_code}[/bold red]")
    except requests.exceptions.ConnectionError:
        console.print("[bold red]❌ Connection Error: FastAPI Server is not running. Execute 'python run.py' first.[/bold red]")

def list_alerts(severity=None):
    try:
        url = f"{BASE_URL}/alerts"
        if severity:
            url += f"?severity={severity}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            alerts = res.json()
            table = Table(title=f"Enterprise Automated Security Alerts ({severity or 'All'})", show_header=True, header_style="bold cyan")
            table.add_column("Incident ID", style="bold white")
            table.add_column("Severity")
            table.add_column("Endpoint", style="cyan")
            table.add_column("Threat Title")
            table.add_column("MITRE TTP", style="yellow")
            table.add_column("Status", style="green")

            for a in alerts:
                sev_color = "red" if a["severity"] == "CRITICAL" else ("yellow" if a["severity"] == "HIGH" else "blue")
                table.add_row(
                    a["id"],
                    f"[{sev_color}]{a['severity']}[/{sev_color}]",
                    a["endpoint"],
                    a["title"],
                    a["mitre"],
                    a["status"]
                )
            console.print(table)
        else:
            console.print(f"[bold red]❌ Failed to retrieve alerts. HTTP {res.status_code}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]❌ Error: {e}[/bold red]")

def trigger_simulated_attack(scenario_idx):
    try:
        console.print(f"[bold yellow]🚨 Triggering Adversary Simulation Scenario #{scenario_idx}...[/bold yellow]")
        res = requests.post(f"{BASE_URL}/alerts/trigger-simulated-attack", json={"scenario": scenario_idx}, timeout=10)
        if res.status_code == 200:
            data = res.json()
            console.print(Panel(f"[bold green]✨ MITIGATION SUCCESSFUL[/bold green]\n\nAlert ID: [bold white]{data.get('alert_id')}[/bold white]\nAction Executed: [bold cyan]{data.get('action_taken')}[/bold cyan]\nSummary: {data.get('message')}", title="Autonomous AIR Response", border_style="green"))
        else:
            console.print(f"[bold red]❌ Attack simulation failed. HTTP {res.status_code}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]❌ Error: {e}[/bold red]")

def auto_remediate_asset(asset_id):
    try:
        console.print(f"[bold yellow]🛡️  Initiating Autonomous AI Auto-Remediation on Asset #{asset_id}...[/bold yellow]")
        res = requests.post(f"{BASE_URL}/asm/remediate/{asset_id}", timeout=10)
        if res.status_code == 200:
            data = res.json()
            ast = data.get("asset", {})
            console.print(Panel(f"[bold green]✔️ ASSET POSTURE SECURED[/bold green]\n\nAsset Name: [bold white]{ast.get('name')}[/bold white]\nUpdated Risk Score: [bold green]{ast.get('risk_score')}[/bold green]\nStatus: {data.get('message')}", title="BradlyAI Auto-Patch Engine", border_style="cyan"))
        else:
            console.print(f"[bold red]❌ Remediation failed. HTTP {res.status_code}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]❌ Error: {e}[/bold red]")

def main():
    display_header()
    parser = argparse.ArgumentParser(description="BradlyAI Enterprise CLI Management Operations Tool")
    parser.add_argument("--status", action="store_true", help="Display BradlyAI Driverless SOC Server Core Status")
    parser.add_argument("--alerts", nargs="?", const="ALL", help="List Security Alerts. Optionally specify severity: CRITICAL, HIGH, MEDIUM, LOW")
    parser.add_argument("--trigger-attack", type=int, metavar="SCENARIO_ID", help="Trigger an advanced adversary cyber attack simulation (0=Ransomware, 1=Lateral Movement, 2=Exfiltration)")
    parser.add_argument("--remediate-asset", type=int, metavar="ASSET_ID", help="Execute Driverless AI autonomous auto-remediation on a specific target asset ID")

    args = parser.parse_args()

    if args.status:
        get_status()
    elif args.alerts:
        list_alerts(severity=None if args.alerts == "ALL" else args.alerts)
    elif args.trigger_attack is not None:
        trigger_simulated_attack(args.trigger_attack)
    elif args.remediate_asset is not None:
        auto_remediate_asset(args.remediate_asset)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
