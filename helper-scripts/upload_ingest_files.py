#!/usr/bin/env python3
"""
Upload one or more BloodHound collection JSON files for ingest.

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
import time
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

JOB_STATUS_NAMES = {
    -1: "invalid",
    0: "ready",
    1: "running",
    2: "complete",
    3: "canceled",
    4: "timed out",
    5: "failed",
    6: "ingesting",
    7: "analyzing",
    8: "partially complete",
}
TERMINAL_JOB_STATUSES = {2, 3, 4, 5, 8}
SUCCESS_JOB_STATUSES = {2}


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


def start_file_upload_job(base_url: str, token: str, timeout: int, wait: int, verify: bool) -> Optional[int]:
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/start"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": f"wait={wait}",
    }

    try:
        logger.info("Starting BloodHound file upload job")
        logger.debug(f"POST {api_url}")
        resp = requests.post(api_url, headers=headers, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")
        if not (200 <= resp.status_code < 300):
            logger.error(f"Start file upload job request failed with status {resp.status_code}.")
            return None
        payload = resp.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing file upload job response: {e}")
        return None

    job_id = payload.get("data", {}).get("id")
    if not isinstance(job_id, int):
        logger.error("Start file upload job response did not include data.id.")
        return None

    logger.info(f"Started file upload job {job_id}.")
    return job_id


def upload_file_to_job(
    base_url: str,
    token: str,
    job_id: int,
    path: Path,
    timeout: int,
    wait: int,
    verify: bool,
) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/{job_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
        "Content-Type": "application/json",
        "Prefer": f"wait={wait}",
        "X-File-Upload-Name": path.name,
    }

    try:
        logger.info(f"Uploading {path}")
        logger.debug(f"POST {api_url}")
        with path.open("rb") as handle:
            resp = requests.post(api_url, headers=headers, data=handle, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")
        if not (200 <= resp.status_code < 300):
            logger.error(f"Upload failed for {path} with status {resp.status_code}.")
            if resp.text:
                logger.error("Re-run with --debug to include the response body.")
            return False
        logger.info(f"Uploaded {path.name}.")
        return True
    except OSError as e:
        logger.error(f"Error reading {path}: {e}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while uploading {path}: {e}")
        return False


def end_file_upload_job(base_url: str, token: str, job_id: int, timeout: int, wait: int, verify: bool) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/{job_id}/end"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
        "Prefer": f"wait={wait}",
    }

    try:
        logger.info(f"Ending BloodHound file upload job {job_id}")
        logger.debug(f"POST {api_url}")
        resp = requests.post(api_url, headers=headers, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")
        if not (200 <= resp.status_code < 300):
            logger.error(f"End file upload job request failed with status {resp.status_code}.")
            if resp.text:
                logger.error("Re-run with --debug to include the response body.")
            return False
        logger.info("File upload job ended successfully.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return False


def get_file_upload_job(
    base_url: str,
    token: str,
    job_id: int,
    timeout: int,
    wait: int,
    verify: bool,
) -> Optional[dict]:
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": f"wait={wait}",
    }
    params = {
        "id": f"eq:{job_id}",
        "limit": 1,
    }

    try:
        logger.debug(f"GET {api_url}")
        resp = requests.get(api_url, headers=headers, params=params, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text}")
        if not (200 <= resp.status_code < 300):
            logger.error(f"File upload job status request failed with status {resp.status_code}.")
            return None
        payload = resp.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while checking file upload job {job_id}: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing file upload job status response: {e}")
        return None

    jobs = payload.get("data")
    if not isinstance(jobs, list):
        logger.error("File upload job status response did not include a data list.")
        return None
    for job in jobs:
        if isinstance(job, dict) and job.get("id") == job_id:
            return job

    logger.error(f"File upload job {job_id} was not found in status response.")
    return None


def job_status_name(status: object) -> str:
    if isinstance(status, int):
        return JOB_STATUS_NAMES.get(status, f"unknown ({status})")
    return "unknown"


def format_job_status(job: dict) -> str:
    status = job.get("status")
    status_text = job_status_name(status)
    total_files = job.get("total_files")
    failed_files = job.get("failed_files")
    status_message = job.get("status_message")
    parts = [f"status={status_text}"]
    if isinstance(total_files, int):
        parts.append(f"total_files={total_files}")
    if isinstance(failed_files, int):
        parts.append(f"failed_files={failed_files}")
    if status_message:
        parts.append(f"message={status_message}")
    return ", ".join(parts)


def wait_for_ingest_completion(
    base_url: str,
    token: str,
    job_id: int,
    timeout: int,
    wait: int,
    verify: bool,
    poll_interval: int,
    poll_timeout: int,
) -> bool:
    deadline = time.monotonic() + poll_timeout if poll_timeout > 0 else None

    print(f"Waiting for BloodHound ingest job {job_id} to complete...", flush=True)
    while True:
        job = get_file_upload_job(base_url, token, job_id, timeout=timeout, wait=wait, verify=verify)
        if job is None:
            return False

        print(f"Job {job_id}: {format_job_status(job)}", flush=True)

        status = job.get("status")
        if status in TERMINAL_JOB_STATUSES:
            failed_files = job.get("failed_files")
            if status in SUCCESS_JOB_STATUSES and (not isinstance(failed_files, int) or failed_files == 0):
                print(f"Job {job_id}: ingest completed.", flush=True)
                return True
            print(f"Job {job_id}: ingest finished unsuccessfully.", flush=True)
            return False

        if deadline is not None and time.monotonic() >= deadline:
            logger.error(f"Timed out waiting for file upload job {job_id} to complete.")
            return False

        time.sleep(poll_interval)


def validate_json_files(paths: list[str]) -> list[Path]:
    validated = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            raise SystemExit(f"[!] Error: {raw_path} is not a file")
        if path.suffix.lower() != ".json":
            raise SystemExit(f"[!] Error: {raw_path} must be a .json file")
        validated.append(path)
    return validated


def upload_ingest_files(
    base_url: str,
    token: str,
    paths: list[Path],
    timeout: int,
    wait: int,
    verify: bool,
    poll_interval: int,
    poll_timeout: int,
) -> bool:
    job_id = start_file_upload_job(base_url, token, timeout=timeout, wait=wait, verify=verify)
    if job_id is None:
        return False

    for path in paths:
        if not upload_file_to_job(
            base_url,
            token,
            job_id,
            path,
            timeout=timeout,
            wait=wait,
            verify=verify,
        ):
            logger.error(f"Upload job {job_id} was not ended because at least one file failed.")
            return False

    if not end_file_upload_job(base_url, token, job_id, timeout=timeout, wait=wait, verify=verify):
        return False

    return wait_for_ingest_completion(
        base_url,
        token,
        job_id,
        timeout=timeout,
        wait=wait,
        verify=verify,
        poll_interval=poll_interval,
        poll_timeout=poll_timeout,
    )


def main():
    parser = argparse.ArgumentParser(description="Upload one or more BloodHound collection JSON files for ingest")
    parser.add_argument("files", nargs="+", help="Collection JSON file(s) to upload")
    parser.add_argument("--url", help="BloodHound base URL (or set BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or set BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or set BLOODHOUND_SECRET)")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    parser.add_argument("--wait", type=int, default=30, help="Prefer wait seconds for upload requests (default: 30)")
    parser.add_argument("--poll-interval", type=int, default=5, help="Seconds between ingest status checks (default: 5)")
    parser.add_argument("--poll-timeout", type=int, default=0, help="Maximum seconds to wait for ingest completion; 0 waits forever (default: 0)")
    parser.add_argument("--verbose", action="store_true", help="Enable informational logging")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging. Debug mode may log sensitive API response bodies.",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")

    args = parser.parse_args()
    if args.wait < -1:
        parser.error("--wait must be -1 or greater")
    if args.poll_interval < 1:
        parser.error("--poll-interval must be 1 or greater")
    if args.poll_timeout < 0:
        parser.error("--poll-timeout must be 0 or greater")

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

    paths = validate_json_files(args.files)

    if username and secret:
        token = login(url, username, secret, timeout=args.timeout, verify=verify)
        if not token:
            sys.exit(1)
    else:
        logger.error("Missing credentials. Provide --username/--secret or set BLOODHOUND_USERNAME/BLOODHOUND_SECRET.")
        sys.exit(1)

    ok = upload_ingest_files(
        url,
        token,
        paths,
        timeout=args.timeout,
        wait=args.wait,
        verify=verify,
        poll_interval=args.poll_interval,
        poll_timeout=args.poll_timeout,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
