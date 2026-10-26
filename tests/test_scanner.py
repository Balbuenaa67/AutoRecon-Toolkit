
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from autorecon.scanner import run_nmap


@pytest.mark.parametrize(
    "profile,expected_args",
    [
        ("quick", ["--top-ports", "100"]),
        ("standard", ["--top-ports", "1000"]),
        ("full", ["-p-"]),
    ],
)
def test_scan_profiles(tmp_path, profile, expected_args):
    """Verify that each profile builds the expected Nmap command."""

    with patch("autorecon.scanner.subprocess.run") as mock_run:
        result = run_nmap(
            target="127.0.0.1",
            profile=profile,
            output_dir=str(tmp_path),
        )

    mock_run.assert_called_once()

    command = mock_run.call_args.args[0]

    assert command[0] == "nmap"
    assert "-sT" in command
    assert "-sV" in command
    assert "-Pn" in command
    assert command[-1] == "127.0.0.1"
    assert all(arg in command for arg in expected_args)

    assert isinstance(result, Path)
    assert result.suffix == ".xml"
    assert profile in result.name
    assert str(result) in command


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "1.1.1.1",
        "invalid-ip",
        "127.0.0.1;whoami",
    ],
)
def test_invalid_targets(tmp_path, target):
    """Verify that invalid or disallowed targets are rejected."""

    with patch("autorecon.scanner.subprocess.run") as mock_run:
        with pytest.raises(ValueError):
            run_nmap(target, output_dir=str(tmp_path))

    mock_run.assert_not_called()


def test_invalid_profile(tmp_path):
    """Verify that unsupported scan profiles are rejected."""

    with patch("autorecon.scanner.subprocess.run") as mock_run:
        with pytest.raises(ValueError):
            run_nmap(
                "127.0.0.1",
                profile="aggressive",
                output_dir=str(tmp_path),
            )

    mock_run.assert_not_called()


def test_nmap_execution_error(tmp_path):
    """Verify that Nmap execution errors are propagated."""

    with patch(
        "autorecon.scanner.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "nmap"),
    ):
        with pytest.raises(subprocess.CalledProcessError):
            run_nmap("127.0.0.1", output_dir=str(tmp_path))


def test_nmap_timeout(tmp_path):
    """Verify that scan timeouts are propagated."""

    with patch(
        "autorecon.scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired("nmap", 1800),
    ):
        with pytest.raises(subprocess.TimeoutExpired):
            run_nmap("127.0.0.1", output_dir=str(tmp_path))


def test_nmap_not_installed(tmp_path):
    """Verify that a missing Nmap executable is handled."""

    with patch(
        "autorecon.scanner.subprocess.run",
        side_effect=FileNotFoundError("nmap not found"),
    ):
        with pytest.raises(FileNotFoundError):
            run_nmap("127.0.0.1", output_dir=str(tmp_path))
