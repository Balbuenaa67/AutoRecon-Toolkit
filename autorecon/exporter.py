
import json
from datetime import datetime
from pathlib import Path

from autorecon.analyzer import analyze_hosts


def export_json(hosts: list[dict], output_dir="reports") -> Path:
    """Export scan results and analysis to JSON."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    json_file = output_path / f"nmap_results_{timestamp}.json"

    data = {
        "metadata": {
            "tool": "AutoRecon Toolkit",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        "hosts": hosts,
        "analysis": analyze_hosts(hosts),
    }

    json_file.write_text(
        json.dumps(data, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    return json_file
