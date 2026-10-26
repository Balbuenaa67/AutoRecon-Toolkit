
import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from autorecon.scanner import run_nmap
from autorecon.parser import parse_nmap_xml
from autorecon.reporter import generate_report
from autorecon.exporter import export_json


def main():
    parser = argparse.ArgumentParser(
        description="AutoRecon Toolkit - Network reconnaissance"
    )

    source = parser.add_mutually_exclusive_group(required=True)

    source.add_argument(
        "--target",
        help="Authorized target IP address"
    )

    source.add_argument(
        "--xml",
        type=Path,
        help="Import an existing Nmap XML scan"
    )

    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "full"],
        default="quick",
        help="Scan profile (default: quick)"
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory (default: reports)"
    )

    parser.add_argument(
        "--format",
        choices=["markdown", "json", "both"],
        default="markdown",
        help="Report format (default: markdown)"
    )

    args = parser.parse_args()

    try:
        if args.xml:
            xml_file = args.xml
            print(f"Importing Nmap XML: {xml_file}")
        else:
            xml_file = run_nmap(
                target=args.target,
                profile=args.profile,
                output_dir=args.output
            )

        hosts = parse_nmap_xml(str(xml_file))

        for host in hosts:
            print(f"\nHost: {host['ip']}")
            print(f"Status: {host['status']}")

            for port in host["ports"]:
                print(
                    f"{port['port']}/{port['protocol']} | "
                    f"{port['service']} | "
                    f"{port['product']} {port['version']}"
                )

        
        if args.format in ("markdown", "both"):
            report_path = generate_report(
                hosts,
                output_dir=args.output
            )
            print(f"\nMarkdown report: {report_path}")

        if args.format in ("json", "both"):
            json_path = export_json(
                hosts,
                output_dir=args.output
            )
            print(f"\nJSON report: {json_path}")

    except ET.ParseError as error:
        print(f"Error: Invalid or malformed XML file: {error}", file=sys.stderr)
        sys.exit(1)

    except (ValueError, FileNotFoundError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    except subprocess.TimeoutExpired:
        print("Error: Nmap scan timed out.", file=sys.stderr)
        sys.exit(1)

    except subprocess.CalledProcessError as error:
        print(f"Nmap execution failed: {error}", file=sys.stderr)
        sys.exit(1)

    
    except OSError as error:
        print(
            f"Error: File system or execution error: {error}",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
