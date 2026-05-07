#!/usr/bin/env python3
"""
Upload OpenGraph custom node type icons to BloodHound CE

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
from urllib.parse import quote
from typing import List, Optional

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

    # Expect {"custom_types": {...}}
    if not isinstance(payload, dict) or "custom_types" not in payload:
        raise SystemExit(
            "[!] Payload must be a JSON object with a top-level 'custom_types' key.\n"
            "    Example: {\"custom_types\": {\"person\": {\"icon\": {...}}}}"
        )
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

    token = (
        data.get("data", {}).get("session_token")
    )
    auth_expired = data.get("data", {}).get("auth_expired", True)
    if auth_expired:
        logger.error("Login failed: credentials expired or invalid.")
        return None
    if not token:
        logger.error("Login succeeded but no session token found in response.")
        return None
    logger.debug("Login succeeded and token received.")
    return token


def list_custom_nodes(base_url: str, token: str, timeout: int, verify: bool) -> Optional[List[str]]:
    api_url = f"{base_url.rstrip('/')}/api/v2/custom-nodes"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    try:
        logger.debug(f"GET {api_url}")
        resp = requests.get(api_url, headers=headers, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")
        if not (200 <= resp.status_code < 300):
            return None
        data = resp.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing custom nodes response: {e}")
        return None
    kinds = []
    for item in data.get("data", []):
        kind_name = item.get("kindName")
        if kind_name:
            kinds.append(kind_name)

    logger.debug(f"Custom nodes returned: {kinds}")
    return kinds


def delete_custom_node(base_url: str, token: str, kind: str, timeout: int, verify: bool) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/custom-nodes/{quote(kind, safe='')}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    try:
        logger.debug(f"DELETE {api_url}")
        resp = requests.delete(api_url, headers=headers, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")
        return 200 <= resp.status_code < 300
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return False


def upload_custom_icons(base_url: str, token: str, payload: dict, timeout: int = 30, verify: bool = True) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/custom-nodes"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Prefer": "wait=0",
    }

    try:
        logger.debug(f"POST {api_url}")
        resp = requests.post(api_url, headers=headers, json=payload, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")

        return 200 <= resp.status_code < 300
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Upload OpenGraph custom icons to BloodHound CE")
    parser.add_argument("--url", help="BloodHound base URL (or set BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or set BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or set BLOODHOUND_SECRET)")
    parser.add_argument("--file", default="custom_types.json", help="JSON payload file (default: custom_types.json)")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    parser.add_argument("--verbose", action="store_true", help="Enable informational logging")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging. Debug mode may log sensitive API response bodies.",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")

    args = parser.parse_args()

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

    kinds = list_custom_nodes(url, token, timeout=args.timeout, verify=verify)
    if kinds is None:
        sys.exit(1)

    if kinds:
        logger.info(f"Removing custom node types: {', '.join(kinds)}")

    for kind in kinds:
        if not delete_custom_node(url, token, kind, timeout=args.timeout, verify=verify):
            logger.error(f"Failed to delete existing custom node type: {kind}")
            sys.exit(1)

    ok = upload_custom_icons(url, token, payload, timeout=args.timeout, verify=verify)
    if ok:
        created = list(payload.get("custom_types", {}).keys())
        if created:
            logger.info(f"Created custom node types: {', '.join(created)}")
        logger.debug(f"Custom node types created: {created}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
