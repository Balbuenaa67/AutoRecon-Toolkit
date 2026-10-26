
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path


SCAN_PROFILES = {
    "quick": ["--top-ports", "100"],
    "standard": ["--top-ports", "1000"],
    "full": ["-p-"]
}


def run_nmap(
    target: str,
    profile: str = "quick",
    output_dir: str = "reports"
) -> Path:
    """Run Nmap against an authorized lab target."""

    # Validate target IP
    ip = ipaddress.ip_address(target)

    if not (ip.is_private or ip.is_loopback):
        raise ValueError(
            "Only private or loopback IP addresses are allowed."
        )

    if profile not in SCAN_PROFILES:
        raise ValueError(f"Invalid scan profile: {profile}")

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Unique filename for each scan
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    xml_file = output_path / (
        f"scan_{ip}_{profile}_{timestamp}.xml"
    )

    # Build Nmap command
    command = [
        "nmap",
        "-sT",
        "-sV",
        "-Pn",
        *SCAN_PROFILES[profile],
        "-oX",
        str(xml_file),
        str(ip)
    ]

    print(f"\nTarget: {ip}")
    print(f"Profile: {profile}")
    print("Starting Nmap scan...\n")

    subprocess.run(
        command,
        check=True,
        timeout=1800
    )

    return xml_file
