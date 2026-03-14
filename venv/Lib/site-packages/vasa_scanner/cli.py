import argparse
from .scanner import run_full_scan


def main():
    """
    CLI entry point for VASA Scanner
    """

    parser = argparse.ArgumentParser(
        description="VASA Security Scanner - Web Application Security Testing Tool"
    )

    parser.add_argument(
        "url",
        help="Target URL to scan (example: https://example.com)"
    )

    args = parser.parse_args()

    target_url = args.url

    run_full_scan(target_url)


if __name__ == "__main__":
    main()