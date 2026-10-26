
import argparse
import subprocess
import sys

from autorecon.scanner import run_nmap
from autorecon.parser import parse_nmap_xml
from autorecon.reporter import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="AutoRecon Toolkit - Network reconnaissance"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Authorized target IP address"
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
    help="Output directory for scan results (default: reports)"
)

    args = parser.parse_args()

    try:
        xml_file = run_nmap(
            target=args.target,
            profile=args.profile,
            output_dir=args.output
        )
        hosts = parse_nmap_xml(xml_file)

        for host in hosts:
            print(f"\nHost: {host['ip']}")
            print(f"Status: {host['status']}")

            for port in host["ports"]:
                print(
                    f"{port['port']}/{port['protocol']} | "
                    f"{port['service']} | "
                    f"{port['product']} {port['version']}"
                )

        report_path = generate_report(
            hosts,
            output_dir=args.output
        )
        
        print(f"\nReport generated: {report_path}")

    except ValueError as error:
        print(f"Invalid target: {error}", file=sys.stderr)
        sys.exit(1)

    except FileNotFoundError:
        print("Error: Nmap executable not found.", file=sys.stderr)
        sys.exit(1)

    except subprocess.TimeoutExpired:
        print("Error: Nmap scan timed out.", file=sys.stderr)
        sys.exit(1)

    except subprocess.CalledProcessError as error:
        print(f"Nmap execution failed: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
