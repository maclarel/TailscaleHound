#!/usr/bin/env python3
"""
Upload OpenGraph extension schema to BloodHound CE.

Precedence:
1) CLI args (--url/--username/--secret/--file)
2) .env
3) Process environment
"""

import argparse
import json
import logging
import os
import sys
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


def load_payload(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"[!] Error: {path} not found")
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] Error parsing {path}: {e}")

    if not isinstance(payload, dict):
        raise SystemExit(f"[!] Payload in {path} must be a JSON object")

    required_keys = ("schema", "node_kinds", "relationship_kinds")
    missing = [key for key in required_keys if key not in payload]
    if missing:
        raise SystemExit(
            f"[!] Payload in {path} is missing required key(s): {', '.join(missing)}"
        )

    schema = payload.get("schema")
    if not isinstance(schema, dict) or not schema.get("name") or not schema.get("namespace"):
        raise SystemExit("[!] Payload schema must include at least 'name' and 'namespace'")

    if not isinstance(payload.get("node_kinds"), list):
        raise SystemExit("[!] Payload 'node_kinds' must be a list")
    if not isinstance(payload.get("relationship_kinds"), list):
        raise SystemExit("[!] Payload 'relationship_kinds' must be a list")

    return payload


def login(base_url: str, username: str, secret: str, timeout: int, verify: bool) -> Optional[str]:
    api_url = f"{base_url.rstrip('/')}/api/v2/login"
    body = {
        "login_method": "secret",
        "username": username,
        "secret": secret,
    }

    try:
        logger.debug(f"POST {api_url}")
        resp = requests.post(api_url, json=body, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if not (200 <= resp.status_code < 300):
            if resp.text:
                logger.debug(f"Body: {resp.text}")
            return None
        data = resp.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing login response: {e}")
        return None

    token = data.get("data", {}).get("session_token")
    auth_expired = data.get("data", {}).get("auth_expired", True)
    if auth_expired:
        logger.error("Login failed: credentials expired or invalid.")
        return None
    if not token:
        logger.error("Login succeeded but no session token found in response.")
        return None
    logger.debug("Login succeeded and token received.")
    return token


def upload_schema(
    base_url: str,
    token: str,
    payload: dict,
    timeout: int = 30,
    verify: bool = True,
    wait: int = 0,
) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/extensions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Prefer": f"wait={wait}",
    }

    try:
        logger.debug(f"PUT {api_url}")
        resp = requests.put(api_url, headers=headers, json=payload, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")

        return 200 <= resp.status_code < 300
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Upload OpenGraph extension schema to BloodHound CE")
    parser.add_argument("--url", help="BloodHound base URL (or set BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or set BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or set BLOODHOUND_SECRET)")
    parser.add_argument("--file", default="schema.json", help="Schema JSON file (default: schema.json)")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    parser.add_argument("--wait", type=int, default=0, help="Prefer wait seconds for upload (default: 0)")
    parser.add_argument("--verbose", action="store_true", help="Enable informational logging")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging. Debug mode may log sensitive API response bodies.",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")

    args = parser.parse_args()
    if args.wait < 0:
        parser.error("--wait must be 0 or greater")

    log_level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")
    if args.debug:
        logger.warning("Debug logging is enabled and may include sensitive API response bodies.")

    url = args.url or os.getenv("BLOODHOUND_URL")
    username = args.username or os.getenv("BLOODHOUND_USERNAME")
    secret = args.secret or os.getenv("BLOODHOUND_SECRET")
    verify = not args.insecure

    if not url:
        logger.error("Missing URL. Provide --url or set BLOODHOUND_URL (.env supported)")
        sys.exit(1)

    if username and secret:
        token = login(url, username, secret, timeout=args.timeout, verify=verify)
        if not token:
            sys.exit(1)
    else:
        logger.error("Missing credentials. Provide --username/--secret or set BLOODHOUND_USERNAME/BLOODHOUND_SECRET.")
        sys.exit(1)

    payload = load_payload(args.file)
    schema = payload.get("schema", {})
    logger.info(
        "Uploading schema %s (%s)",
        schema.get("name", "unknown"),
        schema.get("namespace", "unknown"),
    )

    ok = upload_schema(
        url,
        token,
        payload,
        timeout=args.timeout,
        verify=verify,
        wait=args.wait,
    )
    if ok:
        logger.info("Schema upload complete.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
