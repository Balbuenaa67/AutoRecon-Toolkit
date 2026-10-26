
from pathlib import Path
from datetime import datetime


def generate_report(hosts: list[dict], output_dir="reports"):
    """Generate a Markdown report from parsed Nmap results."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = output_path / f"nmap_report_{timestamp}.md"

    lines = [
        "# Network Reconnaissance Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Total hosts: {len(hosts)}",
        ""
    ]

    for host in hosts:
        lines.extend([
            f"## Host: {host['ip']}",
            "",
            f"**Status:** {host['status']}",
            "",
            "| Port | Protocol | Service | Product | Version |",
            "|------|----------|---------|---------|---------|"
        ])

        for port in host["ports"]:
            lines.append(
                f"| {port['port']} "
                f"| {port['protocol']} "
                f"| {port['service']} "
                f"| {port['product']} "
                f"| {port['version']} |"
            )

        if not host["ports"]:
            lines.append("| - | - | No open ports | - | - |")

        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")

    return report_path
