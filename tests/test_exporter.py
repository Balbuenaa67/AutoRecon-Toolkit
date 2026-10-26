
import json

from autorecon.exporter import export_json


def test_json_file_creation(tmp_path):
    hosts = []

    result = export_json(hosts, output_dir=tmp_path)

    assert result.exists()
    assert result.suffix == ".json"


def test_json_metadata(tmp_path):
    result = export_json([], output_dir=tmp_path)

    data = json.loads(result.read_text(encoding="utf-8"))

    assert data["metadata"]["tool"] == "AutoRecon Toolkit"
    assert "generated_at" in data["metadata"]


def test_json_host_data(tmp_path):
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
                }
            ],
        }
    ]

    result = export_json(hosts, output_dir=tmp_path)
    data = json.loads(result.read_text(encoding="utf-8"))

    assert data["hosts"] == hosts
    assert data["hosts"][0]["ports"][0]["port"] == 22


def test_json_analysis(tmp_path):
    hosts = [
        {
            "ip": "127.0.0.1",
            "status": "up",
            "ports": [
                {
                    "port": 445,
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                    "product": "",
                    "version": "",
                }
            ],
        }
    ]

    result = export_json(hosts, output_dir=tmp_path)
    data = json.loads(result.read_text(encoding="utf-8"))

    assert data["analysis"]["total_hosts"] == 1
    assert data["analysis"]["total_open_ports"] == 1
    assert "SMB signing" in (
        data["analysis"]["findings"][0]["recommendation"]
    )


def test_empty_json_scan(tmp_path):
    result = export_json([], output_dir=tmp_path)
    data = json.loads(result.read_text(encoding="utf-8"))

    assert data["hosts"] == []
    assert data["analysis"]["total_hosts"] == 0
    assert data["analysis"]["total_open_ports"] == 0
