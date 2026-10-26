
from pathlib import Path
from datetime import datetime

from autorecon.analyzer import analyze_hosts


def generate_report(hosts: list[dict], output_dir="reports"):
    """Generate a Markdown network reconnaissance report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    report_path = output_path / f"nmap_report_{timestamp}.md"

    analysis = analyze_hosts(hosts)

    lines = [
        "# Network Reconnaissance Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Executive Summary",
        "",
        f"- Total hosts: {analysis['total_hosts']}",
        f"- Total open ports: {analysis['total_open_ports']}",
        "",
        "> An open port does not necessarily indicate a vulnerability.",
        "",
        "## Host Details",
        "",
    ]

    for host in hosts:
        lines.extend([
            f"### Host: {host['ip']}",
            "",
            f"**Status:** {host['status']}",
            "",
            "| Port | Protocol | Service | Product | Version |",
            "|------|----------|---------|---------|---------|",
        ])

        for port in host["ports"]:
            lines.append(
                f"| {port['port']} | {port['protocol']} | "
                f"{port['service']} | {port['product']} | "
                f"{port['version']} |"
            )

        if not host["ports"]:
            lines.append("| - | - | No open ports | - | - |")

        lines.append("")

    lines.extend([
        "## Enumeration Recommendations",
        "",
    ])

    if not analysis["findings"]:
        lines.append("No open services detected.")
    else:
        for finding in analysis["findings"]:
            lines.extend([
                f"### {finding['ip']}:{finding['port']}/{finding['protocol']}",
                "",
                f"**Service:** {finding['service']}",
                "",
                f"**Recommended checks:** {finding['recommendation']}",
                "",
            ])

    report_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return report_path
