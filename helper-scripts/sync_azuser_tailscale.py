#!/usr/bin/env python3
"""
Query AZUsers from BloodHound and generate TS_AZUserSyncedToUser edges
by matching AZUser.userprincipalname to TS_User.LoginName in BloodHound.
An OpenGraph file can be supplied as an offline fallback.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node as OpenGraphNode
from bhopengraph.Edge import Edge as OpenGraphEdge
from bhopengraph.Properties import Properties as OpenGraphProperties
from tailscalehound.names import apply_bloodhound_names, bloodhound_kind

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


def node_kinds(node: dict) -> List[str]:
    kinds = []
    for key in ("kinds", "labels"):
        value = node.get(key)
        if isinstance(value, list):
            kinds.extend(str(item) for item in value if item)
        elif isinstance(value, str):
            kinds.append(value)
    for key in ("kind", "label", "kindName"):
        value = node.get(key)
        if isinstance(value, str) and value:
            kinds.append(value)
    return kinds


def kind_matches(kind: str, expected_kind: str) -> bool:
    return kind == expected_kind or bloodhound_kind(kind) == expected_kind


def node_properties(node: dict) -> dict:
    props = node.get("properties")
    if isinstance(props, dict):
        return props

    merged = {}
    for key in ("identityProperties", "systemProperties"):
        value = node.get(key)
        if isinstance(value, dict):
            merged.update(value)
    return merged


def property_value(props: dict, *names: str):
    for name in names:
        if name in props:
            return props[name]
    normalized = {str(key).lower(): value for key, value in props.items()}
    for name in names:
        value = normalized.get(name.lower())
        if value is not None:
            return value
    return None


def node_id(node: dict) -> Optional[str]:
    props = node_properties(node)
    for source in (node, props):
        for key in ("id", "objectid", "objectId", "objectID", "ObjectID"):
            value = source.get(key)
            if value is not None and value != "":
                return str(value)
    return None


def extract_nodes_from_payload(payload, expected_kind: str) -> List[dict]:
    nodes = []
    seen = set()

    def walk(value) -> None:
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        if not isinstance(value, dict):
            return

        if any(kind_matches(kind, expected_kind) for kind in node_kinds(value)):
            item_id = node_id(value) or str(id(value))
            if item_id not in seen:
                seen.add(item_id)
                nodes.append(value)

        for item in value.values():
            walk(item)

    walk(payload)
    return nodes


def query_bh_nodes(base_url: str, token: str, kind: str, timeout: int, verify: bool) -> List[dict]:
    api_url = f"{base_url.rstrip('/')}/api/v2/graphs/cypher"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = {
        "query": f"MATCH (n:{kind}) RETURN n",
        "include_properties": True,
    }
    try:
        logger.debug(f"POST {api_url}")
        resp = requests.post(api_url, headers=headers, json=body, timeout=timeout, verify=verify)
        logger.debug(f"Status: {resp.status_code}")
        if resp.text:
            logger.debug(f"Body: {resp.text[:200]}...")
        if not (200 <= resp.status_code < 300):
            return []
        payload = resp.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing {kind} response: {e}")
        return []

    return extract_nodes_from_payload(payload.get("data", payload), kind)


def query_azusers(base_url: str, token: str, timeout: int, verify: bool) -> List[dict]:
    return query_bh_nodes(base_url, token, "AZUser", timeout, verify)


def normalize_props(props: dict) -> dict:
    return {str(k).lower(): v for k, v in (props or {}).items()}


def extract_azuser_info(node: dict) -> Tuple[Optional[str], Optional[str], dict, List[str]]:
    item_id = node_id(node)
    kinds = node_kinds(node) or ["AZUser"]
    props = node_properties(node)
    normalized = normalize_props(props)
    upn = normalized.get("userprincipalname") or normalized.get("userprincipal_name")
    name = (
        normalized.get("name")
        or normalized.get("displayname")
        or normalized.get("display_name")
        or upn
    )
    return item_id, name, props, kinds


def extract_tailscale_users_from_nodes(nodes: List[dict]) -> Dict[str, dict]:
    users = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        kinds = node_kinds(node)
        normalized_kinds = {bloodhound_kind(kind) for kind in kinds}
        if bloodhound_kind("TailscaleUser") not in normalized_kinds and "TailscaleUser" not in kinds:
            continue
        props = node_properties(node)
        login = property_value(props, "LoginName", "loginname", "login_name")
        if not isinstance(login, str) or not login.strip():
            continue
        users[login.strip().lower()] = node
    return users


def extract_tailscale_users(opengraph: dict) -> Dict[str, dict]:
    nodes = opengraph.get("nodes")
    if nodes is None and isinstance(opengraph.get("graph"), dict):
        nodes = opengraph["graph"].get("nodes")
    if nodes is None:
        nodes = []
    return extract_tailscale_users_from_nodes(nodes)


def query_tailscale_users(base_url: str, token: str, timeout: int, verify: bool) -> Dict[str, dict]:
    nodes = query_bh_nodes(base_url, token, bloodhound_kind("TailscaleUser"), timeout, verify)
    return extract_tailscale_users_from_nodes(nodes)


def build_edges(
    az_nodes: List[dict],
    ts_users: Dict[str, dict],
) -> Tuple[OpenGraph, int]:
    og = OpenGraph()
    edge_count = 0

    for az_node in az_nodes:
        az_node_id, name, props, kinds = extract_azuser_info(az_node)
        if not az_node_id:
            continue
        normalized = normalize_props(props)
        upn = normalized.get("userprincipalname") or normalized.get("userprincipal_name")
        if not isinstance(upn, str) or not upn.strip():
            continue
        ts_node = ts_users.get(upn.strip().lower())
        if not ts_node:
            continue

        ts_node_id = node_id(ts_node)
        if not ts_node_id:
            continue

        az_props = {}
        if name:
            az_props["name"] = name
        az_node_obj = OpenGraphNode(
            id=az_node_id,
            kinds=["AZUser"],
            properties=OpenGraphProperties(**az_props),
        )
        og.add_node(az_node_obj)

        ts_props = {}
        ts_node_props = node_properties(ts_node)
        ts_login = property_value(ts_node_props, "LoginName", "loginname", "login_name")
        ts_display = property_value(ts_node_props, "DisplayName", "displayname", "display_name", "name")
        ts_name = ts_display or ts_login
        if ts_name:
            ts_props["name"] = ts_name
        ts_kinds = node_kinds(ts_node) or [bloodhound_kind("TailscaleUser")]
        ts_node_obj = OpenGraphNode(
            id=ts_node_id,
            kinds=[bloodhound_kind(kind) for kind in ts_kinds],
            properties=OpenGraphProperties(**ts_props),
        )
        og.add_node(ts_node_obj)

        og.add_edge(
            OpenGraphEdge(
                start_node=az_node_id,
                end_node=ts_node_id,
                kind=bloodhound_kind("AZUserSyncedToUser"),
                properties=OpenGraphProperties(
                    MatchField="LoginName",
                    MatchValue=upn.strip(),
                ),
            )
        )
        edge_count += 1

    return og, edge_count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create TS_AZUserSyncedToUser edges by matching AZUser UPN to Tailscale LoginName."
    )
    parser.add_argument("--url", help="BloodHound base URL (or set BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or set BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or set BLOODHOUND_SECRET)")
    parser.add_argument(
        "--opengraph",
        help="Optional TailscaleHound OpenGraph output JSON. If omitted, TS_User is queried from BloodHound.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output path for generated OpenGraph JSON.",
    )
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
        return 1
    if not (username and secret):
        logger.error("Missing credentials. Provide --username/--secret or set BLOODHOUND_USERNAME/BLOODHOUND_SECRET.")
        return 1

    token = login(url, username, secret, timeout=args.timeout, verify=verify)
    if not token:
        return 1

    az_nodes = query_azusers(url, token, timeout=args.timeout, verify=verify)
    logger.info(f"Retrieved {len(az_nodes)} AZUser nodes")

    if args.opengraph:
        try:
            with open(args.opengraph, "r", encoding="utf-8") as handle:
                opengraph_json = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error(f"Failed to read opengraph JSON: {exc}")
            return 1
        ts_users = extract_tailscale_users(opengraph_json)
        logger.info(f"Loaded {len(ts_users)} Tailscale users from {args.opengraph}")
    else:
        ts_users = query_tailscale_users(url, token, timeout=args.timeout, verify=verify)
        logger.info(f"Retrieved {len(ts_users)} TS_User nodes")

    og, edge_count = build_edges(az_nodes, ts_users)
    logger.info(f"Created {edge_count} {bloodhound_kind('AZUserSyncedToUser')} edges")

    output_path = args.output
    output_dir = os.path.dirname(os.path.abspath(output_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    try:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(apply_bloodhound_names(og.export_to_dict()), handle, indent=2)
    except OSError as exc:
        logger.error(f"Failed to write output: {exc}")
        return 1

    print(f"✓ Exported to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
