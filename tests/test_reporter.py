
from pathlib import Path

from autorecon.reporter import generate_report


def test_report_creation(tmp_path):
    """Verify that a Markdown report is created."""

    hosts = [
        {
            "ip": "192.168.56.101",
            "status": "up",
            "ports": []
        }
    ]

    report = generate_report(hosts, output_dir=tmp_path)

    assert report.exists()
    assert report.suffix == ".md"


def test_report_host_information(tmp_path):
    """Verify that host information is included."""

    hosts = [
        {
            "ip": "192.168.56.101",
            "status": "up",
            "ports": []
        }
    ]

    report = generate_report(hosts, output_dir=tmp_path)
    content = report.read_text(encoding="utf-8")

    assert "192.168.56.101" in content
    assert "**Status:** up" in content
    assert "Total hosts: 1" in content


def test_report_service_information(tmp_path):
    """Verify that open ports and services are reported."""

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
                    "version": "9.6"
                }
            ]
        }
    ]

    report = generate_report(hosts, output_dir=tmp_path)
    content = report.read_text(encoding="utf-8")

    assert "| 22 | tcp | ssh | OpenSSH | 9.6 |" in content


def test_report_no_open_ports(tmp_path):
    """Verify that hosts without open ports are handled."""

    hosts = [
        {
            "ip": "192.168.56.101",
            "status": "up",
            "ports": []
        }
    ]

    report = generate_report(hosts, output_dir=tmp_path)
    content = report.read_text(encoding="utf-8")

    assert "No open ports" in content


def test_empty_scan_report(tmp_path):
    """Verify that empty scan results generate a valid report."""

    report = generate_report([], output_dir=tmp_path)
    content = report.read_text(encoding="utf-8")

    assert "Total hosts: 0" in content
