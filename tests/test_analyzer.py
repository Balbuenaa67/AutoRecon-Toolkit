
from autorecon.analyzer import analyze_hosts


def test_empty_analysis():
    result = analyze_hosts([])

    assert result["total_hosts"] == 0
    assert result["total_open_ports"] == 0
    assert result["findings"] == []


def test_host_without_open_ports():
    hosts = [
        {"ip": "192.168.56.101", "status": "up", "ports": []}
    ]

    result = analyze_hosts(hosts)

    assert result["total_hosts"] == 1
    assert result["total_open_ports"] == 0
    assert result["findings"] == []


def test_service_recommendations():
    hosts = [
        {
            "ip": "192.168.56.101",
            "status": "up",
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6",
                },
                {
                    "port": 445,
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                    "product": "",
                    "version": "",
                },
            ],
        }
    ]

    result = analyze_hosts(hosts)

    assert result["total_open_ports"] == 2
    assert len(result["findings"]) == 2

    ssh = result["findings"][0]
    smb = result["findings"][1]

    assert ssh["port"] == 22
    assert "SSH" in ssh["recommendation"]

    assert smb["port"] == 445
    assert "SMB signing" in smb["recommendation"]


def test_unknown_service():
    hosts = [
        {
            "ip": "127.0.0.1",
            "status": "up",
            "ports": [
                {
                    "port": 9999,
                    "protocol": "tcp",
                    "service": "unknown",
                    "product": "",
                    "version": "",
                }
            ],
        }
    ]

    result = analyze_hosts(hosts)

    assert "Identify the service" in (
        result["findings"][0]["recommendation"]
    )


def test_multiple_hosts():
    hosts = [
        {
            "ip": "192.168.56.101",
            "status": "up",
            "ports": [
                {"port": 80, "protocol": "tcp", "service": "http"}
            ],
        },
        {
            "ip": "192.168.56.102",
            "status": "up",
            "ports": [
                {"port": 22, "protocol": "tcp", "service": "ssh"}
            ],
        },
    ]

    result = analyze_hosts(hosts)

    assert result["total_hosts"] == 2
    assert result["total_open_ports"] == 2
    assert len(result["findings"]) == 2
