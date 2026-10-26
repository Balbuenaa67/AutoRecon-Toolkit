
SERVICE_RECOMMENDATIONS = {
    "ssh": "Review SSH configuration, authentication methods and exposed version.",
    "http": "Enumerate web technologies, directories, headers and authentication.",
    "https": "Review TLS configuration, certificates and web application exposure.",
    "ftp": "Check anonymous access, authentication and server configuration.",
    "smb": "Review SMB signing, exposed shares and access permissions.",
    "microsoft-ds": "Review SMB signing, exposed shares and access permissions.",
    "msrpc": "Enumerate exposed RPC services and review access restrictions.",
    "rdp": "Review RDP exposure, authentication and Network Level Authentication.",
    "ms-wbt-server": "Review RDP exposure, authentication and Network Level Authentication.",
    "mysql": "Review database exposure, authentication and access controls.",
    "postgresql": "Review database exposure, authentication and access controls.",
    "domain": "Review DNS configuration, records and recursion settings.",
}


def analyze_hosts(hosts: list[dict]) -> dict:
    """Generate a summary and enumeration recommendations."""

    total_ports = 0
    findings = []

    for host in hosts:
        for port in host["ports"]:
            total_ports += 1

            service = port["service"].lower()

            recommendation = SERVICE_RECOMMENDATIONS.get(
                service,
                "Identify the service and review its configuration and exposure."
            )

            findings.append({
                "ip": host["ip"],
                "port": port["port"],
                "protocol": port["protocol"],
                "service": service,
                "recommendation": recommendation,
            })

    return {
        "total_hosts": len(hosts),
        "total_open_ports": total_ports,
        "findings": findings,
    }
