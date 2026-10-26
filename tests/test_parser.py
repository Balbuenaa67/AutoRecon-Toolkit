
from pathlib import Path

import pytest

from autorecon.parser import parse_nmap_xml


SAMPLE_XML = Path(__file__).parent / "sample_nmap.xml"


def test_parse_host():
    """Verify that the host IP and status are parsed correctly."""
    hosts = parse_nmap_xml(str(SAMPLE_XML))

    assert len(hosts) == 1
    assert hosts[0]["ip"] == "192.168.56.101"
    assert hosts[0]["status"] == "up"


def test_parse_open_ports():
    """Verify that open ports are correctly extracted."""
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    ports = hosts[0]["ports"]

    assert len(ports) == 2
    assert {port["port"] for port in ports} == {22, 80}


def test_ignore_closed_ports():
    """Verify that closed ports are excluded."""
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    ports = hosts[0]["ports"]

    assert 445 not in [port["port"] for port in ports]


def test_parse_services():
    """Verify that service information is extracted."""
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    ports = hosts[0]["ports"]

    ssh = next(port for port in ports if port["port"] == 22)

    assert ssh["protocol"] == "tcp"
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "9.6"


def test_missing_file():
    """Verify that a missing XML file raises an error."""
    with pytest.raises(FileNotFoundError):
        parse_nmap_xml("nonexistent_file.xml")


def test_invalid_xml(tmp_path):
    """Verify that a non-Nmap XML document is rejected."""
    invalid_file = tmp_path / "invalid.xml"
    invalid_file.write_text("<invalid></invalid>", encoding="utf-8")

    with pytest.raises(ValueError):
        parse_nmap_xml(str(invalid_file))


def test_malformed_xml(tmp_path):
    """Verify that malformed XML raises a parsing error."""
    malformed_file = tmp_path / "malformed.xml"
    malformed_file.write_text("<nmaprun><host>", encoding="utf-8")

    with pytest.raises(Exception):
        parse_nmap_xml(str(malformed_file))
