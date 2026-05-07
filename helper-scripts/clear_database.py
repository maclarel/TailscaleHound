#!/usr/bin/env python3
"""
Clear BloodHound CE database data.

Precedence:
1) CLI args (--url/--username/--secret)
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


def login(base_url: str, username: str, secret: str, timeout: int, verify: bool) -> Optional[str]:
    api_url = f"{base_url.rstrip('/')}/api/v2/login"
    body = {
        "login_method": "secret",
        "username": username,
        "secret": secret,
    }

    try:
        logger.info(f"Authenticating to BloodHound at {base_url.rstrip('/')}")
        logger.debug(f"POST {api_url}")
        resp = requests.post(api_url, json=body, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if not (200 <= resp.status_code < 300):
            logger.error(f"Login request failed with status {resp.status_code}.")
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
    logger.info("Login succeeded.")
    logger.debug("Session token received.")
    return token


def clear_database(
    base_url: str,
    token: str,
    timeout: int,
    wait: int,
    verify: bool,
    delete_collected_graph_data: bool,
    delete_file_ingest_history: bool,
    delete_data_quality_history: bool,
    delete_asset_group_selectors: Optional[list[int]],
) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/clear-database"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
        "Content-Type": "application/json",
        "Prefer": f"wait={wait}",
    }
    payload = {
        "deleteCollectedGraphData": delete_collected_graph_data,
        "deleteFileIngestHistory": delete_file_ingest_history,
        "deleteDataQualityHistory": delete_data_quality_history,
    }
    if delete_asset_group_selectors is not None:
        payload["deleteAssetGroupSelectors"] = delete_asset_group_selectors

    try:
        logger.info(f"Clearing BloodHound database at {base_url.rstrip('/')}")
        logger.info(
            "Clear options: collected graph data=%s, file ingest history=%s, "
            "data quality history=%s, asset group selectors=%s",
            delete_collected_graph_data,
            delete_file_ingest_history,
            delete_data_quality_history,
            delete_asset_group_selectors,
        )
        logger.debug(f"POST {api_url}")
        resp = requests.post(api_url, headers=headers, json=payload, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")
        if not (200 <= resp.status_code < 300):
            logger.error(f"Clear database request failed with status {resp.status_code}.")
            if resp.text:
                logger.error("Re-run with --debug to include the response body.")
            return False
        logger.info("Clear database request completed successfully.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Clear BloodHound CE database data")
    parser.add_argument("--url", help="BloodHound base URL (or set BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or set BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or set BLOODHOUND_SECRET)")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    parser.add_argument("--wait", type=int, default=0, help="Prefer wait seconds for clear operation (default: 0)")
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

    ok = clear_database(
        url,
        token,
        timeout=args.timeout,
        wait=args.wait,
        verify=verify,
        delete_collected_graph_data=True,
        delete_file_ingest_history=True,
        delete_data_quality_history=True,
        delete_asset_group_selectors=[0],
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
