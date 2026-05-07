#!/usr/bin/env python3
import argparse
import json
import re
import sys

import requests

URL = "https://login.tailscale.com/admin/api/machines"
def build_headers() -> dict[str, str]:
    return {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/144.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch /admin/machines using a tailcontrol cookie via Python requests."
    )
    parser.add_argument(
        "--tailcontrol",
        required=True,
        help="tailcontrol cookie value (omit the 'tailcontrol=' prefix).",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write the response body.",
    )
    parser.add_argument(
        "--show-headers",
        action="store_true",
        help="Print response headers to stdout.",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print raw response body instead of extracting /machines JSON.",
    )
    args = parser.parse_args()

    try:
        response = requests.get(
            URL,
            headers=build_headers(),
            cookies={"tailcontrol": args.tailcontrol},
            timeout=30,
        )
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    if args.show_headers:
        for key, value in response.headers.items():
            print(f"{key}: {value}")

    body_text = response.text or ""
    output_text = body_text

    if not args.raw:
        parsed = None
        try:
            parsed = json.loads(body_text)
        except json.JSONDecodeError:
            parsed = None

        if isinstance(parsed, dict):
            if isinstance(parsed.get("data"), dict) and "machines" in parsed["data"]:
                output_text = json.dumps(parsed["data"], indent=2, sort_keys=True)
            elif "machines" in parsed:
                output_text = json.dumps(parsed, indent=2, sort_keys=True)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output_text)
        except OSError as exc:
            print(f"Failed to write output: {exc}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(output_text)
    return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
