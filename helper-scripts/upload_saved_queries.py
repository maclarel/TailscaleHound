#!/usr/bin/env python3
"""
Sync saved Cypher queries to BloodHound CE.

Deletes all owned saved queries, then uploads all JSON files
from the SavedQueries folder.

Precedence:
1) CLI args (--url/--username/--secret)
2) .env
3) Process environment
"""

import argparse
import glob
import json
import logging
import os
import sys
from typing import List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


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


def list_saved_queries(base_url: str, token: str, timeout: int, verify: bool) -> Optional[List[dict]]:
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    params = {"scope": "owned"}
    try:
        logger.debug(f"GET {api_url} params={params}")
        resp = requests.get(api_url, headers=headers, params=params, timeout=timeout, verify=verify)
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
        logger.error(f"Error parsing saved queries response: {e}")
        return None

    return data.get("data", [])


def delete_saved_query(base_url: str, token: str, query_id: str, timeout: int, verify: bool) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries/{query_id}"
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


def load_saved_queries(folder: str) -> List[dict]:
    payloads = []
    pattern = os.path.join(folder, "*.json")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            raise SystemExit(f"[!] Error: {path} not found")
        except json.JSONDecodeError as e:
            raise SystemExit(f"[!] Error parsing {path}: {e}")

        if not isinstance(data, dict):
            raise SystemExit(f"[!] Payload in {path} must be a JSON object")

        name = data.get("name")
        query = data.get("query")
        if not name or not query:
            raise SystemExit(f"[!] Payload in {path} requires 'name' and 'query'")

        payload = {"name": name, "query": query}
        description = data.get("description")
        if description:
            payload["description"] = description
        scope = data.get("scope")
        if scope:
            payload["scope"] = scope

        payloads.append(payload)

    return payloads


def create_saved_query(base_url: str, token: str, payload: dict, timeout: int, verify: bool) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
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
    parser = argparse.ArgumentParser(description="Sync saved Cypher queries to BloodHound CE")
    parser.add_argument("--url", help="BloodHound base URL (or set BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or set BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or set BLOODHOUND_SECRET)")
    parser.add_argument("--folder", default="SavedQueries", help="Folder of saved queries (default: SavedQueries)")
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

    existing = list_saved_queries(url, token, timeout=args.timeout, verify=verify)
    if existing is None:
        sys.exit(1)

    if existing:
        logger.info(f"Deleting {len(existing)} owned saved queries")
    for item in existing:
        query_id = item.get("id")
        if not query_id:
            continue
        if not delete_saved_query(url, token, query_id, timeout=args.timeout, verify=verify):
            logger.error(f"Failed to delete saved query id: {query_id}")
            sys.exit(1)

    payloads = load_saved_queries(args.folder)
    if not payloads:
        logger.error(f"No saved queries found in folder: {args.folder}")
        sys.exit(1)

    logger.info(f"Uploading {len(payloads)} saved queries from {args.folder}")
    for payload in payloads:
        if not create_saved_query(url, token, payload, timeout=args.timeout, verify=verify):
            logger.error(f"Failed to create saved query: {payload.get('name')}")
            sys.exit(1)

    logger.info("Saved queries sync complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
