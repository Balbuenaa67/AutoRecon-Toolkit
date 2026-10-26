
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from main import main


SAMPLE_XML = Path(__file__).parent / "sample_nmap.xml"


def run_cli(monkeypatch, args):
    """Simulate command-line arguments."""
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    main()


def test_cli_requires_source(monkeypatch):
    with pytest.raises(SystemExit) as error:
        run_cli(monkeypatch, [])

    assert error.value.code == 2


def test_cli_rejects_both_sources(monkeypatch):
    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            ["--target", "127.0.0.1", "--xml", str(SAMPLE_XML)]
        )

    assert error.value.code == 2


def test_cli_invalid_profile(monkeypatch):
    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            ["--target", "127.0.0.1", "--profile", "invalid"]
        )

    assert error.value.code == 2


@pytest.mark.parametrize("format_name", ["markdown", "json", "both"])
def test_cli_export_formats(monkeypatch, tmp_path, format_name):
    with patch("main.generate_report") as mock_markdown, \
         patch("main.export_json") as mock_json:

        mock_markdown.return_value = tmp_path / "report.md"
        mock_json.return_value = tmp_path / "report.json"

        run_cli(
            monkeypatch,
            [
                "--xml", str(SAMPLE_XML),
                "--format", format_name,
                "--output", str(tmp_path),
            ]
        )

        assert mock_markdown.called == (
            format_name in ("markdown", "both")
        )

        assert mock_json.called == (
            format_name in ("json", "both")
        )


def test_cli_missing_xml(monkeypatch, tmp_path):
    with pytest.raises(SystemExit) as error:
        run_cli(
            monkeypatch,
            ["--xml", str(tmp_path / "missing.xml")]
        )

    assert error.value.code == 1


def test_cli_scanner_error(monkeypatch, tmp_path):
    with patch(
        "main.run_nmap",
        side_effect=subprocess.CalledProcessError(1, "nmap"),
    ):
        with pytest.raises(SystemExit) as error:
            run_cli(
                monkeypatch,
                ["--target", "127.0.0.1", "--output", str(tmp_path)]
            )

    assert error.value.code == 1


def test_cli_target_scan(monkeypatch, tmp_path):
    with patch("main.run_nmap", return_value=SAMPLE_XML) as mock_scan, \
         patch("main.generate_report", return_value=tmp_path / "report.md"):

        run_cli(
            monkeypatch,
            [
                "--target", "127.0.0.1",
                "--profile", "standard",
                "--output", str(tmp_path),
            ]
        )

    mock_scan.assert_called_once_with(
        target="127.0.0.1",
        profile="standard",
        output_dir=str(tmp_path),
    )



def test_cli_report_permission_error(monkeypatch, tmp_path, capsys):
    """Verify that report write errors are handled gracefully."""
    with patch(
        "main.generate_report",
        side_effect=PermissionError("Access denied"),
    ):
        with pytest.raises(SystemExit) as error:
            run_cli(
                monkeypatch,
                [
                    "--xml", str(SAMPLE_XML),
                    "--format", "markdown",
                    "--output", str(tmp_path),
                ],
            )

    assert error.value.code == 1
    assert "Access denied" in capsys.readouterr().err


def test_cli_json_permission_error(monkeypatch, tmp_path, capsys):
    """Verify that JSON export errors are handled gracefully."""
    with patch(
        "main.export_json",
        side_effect=PermissionError("Access denied"),
    ):
        with pytest.raises(SystemExit) as error:
            run_cli(
                monkeypatch,
                [
                    "--xml", str(SAMPLE_XML),
                    "--format", "json",
                    "--output", str(tmp_path),
                ],
            )

    assert error.value.code == 1
    assert "Access denied" in capsys.readouterr().err
