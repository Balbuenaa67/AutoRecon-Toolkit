
from pathlib import Path
import xml.etree.ElementTree as ET


def parse_nmap_xml(file_path: str) -> list[dict]:
    """Parse an Nmap XML file and return host information."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    tree = ET.parse(path)
    root = tree.getroot()

    if root.tag != "nmaprun":
        raise ValueError("Invalid Nmap XML file")

    hosts = []

    for host in root.findall("host"):
        address = host.find("address")
        status = host.find("status")

        if address is None:
            continue

        host_info = {
            "ip": address.get("addr", "Unknown"),
            "status": status.get("state", "Unknown")
            if status is not None else "Unknown",
            "ports": []
        }

        for port in host.findall("./ports/port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")

            host_info["ports"].append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol", "unknown"),
                "service": service.get("name", "unknown")
                if service is not None else "unknown",
                "product": service.get("product", "")
                if service is not None else "",
                "version": service.get("version", "")
                if service is not None else ""
            })

        hosts.append(host_info)

    return hosts
