import json, time, logging, argparse, datetime, sys, os
from typing import Dict, List, Optional

import requests
from dotenv import load_dotenv
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node as OpenGraphNode
from bhopengraph.Edge import Edge as OpenGraphEdge
from bhopengraph.Properties import Properties as OpenGraphProperties
from tailscalehound.names import apply_bloodhound_names, bloodhound_kind
from tailscalehound.local.parser import Parser as LocalParser
from tailscalehound.remote.parser import RemoteParser, fetch_oauth_access_token

DEFAULT_API_BASE_URL = "https://api.tailscale.com/api/v2"


class TailscaleHound():
    def __init__(self):
        logging.basicConfig(level=logging.INFO)


def _env_value(*names: str) -> Optional[str]:
    for name in names:
        value = os.getenv(name)
        if value is not None and value != "":
            return value
    return None


def _arg_or_env(value: Optional[str], *names: str) -> Optional[str]:
    if value is not None and value != "":
        return value
    return _env_value(*names)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _missing_message(option: str, env_name: str) -> str:
    return f"{option} (or {env_name})"


def _apply_env_defaults(args) -> None:
    args.status_file = _arg_or_env(args.status_file, "TAILSCALEHOUND_STATUS")
    args.access_policy_file = _arg_or_env(
        args.access_policy_file,
        "TAILSCALEHOUND_ACCESS_POLICY",
        "TAILSCALEHOUND_ACCESS_POLICY_FILE",
    )
    args.ts_api_key = _arg_or_env(args.ts_api_key, "TAILSCALE_API_KEY")
    args.ts_client_id = _arg_or_env(args.ts_client_id, "TAILSCALE_CLIENT_ID")
    args.ts_oauth_secret = _arg_or_env(args.ts_oauth_secret, "TAILSCALE_OAUTH_SECRET")
    args.tailnet = _arg_or_env(args.tailnet, "TAILSCALE_TAILNET")
    args.tailcontrol = _arg_or_env(args.tailcontrol, "TAILCONTROL_COOKIE", "TAILSCALE_TAILCONTROL")
    args.api_base_url = _arg_or_env(args.api_base_url, "TAILSCALE_API_BASE_URL") or DEFAULT_API_BASE_URL
    args.output = _arg_or_env(args.output, "TAILSCALEHOUND_OUTPUT")
    args.hybrid_attacks = _arg_or_env(args.hybrid_attacks, "TAILSCALEHOUND_HYBRID_ATTACKS")
    args.bh_url = _arg_or_env(args.bh_url, "BLOODHOUND_URL")
    args.bh_user = _arg_or_env(args.bh_user, "BLOODHOUND_USERNAME")
    args.bh_password = _arg_or_env(args.bh_password, "BLOODHOUND_SECRET")
    args.tailscalehound_file = _arg_or_env(args.tailscalehound_file, "TAILSCALEHOUND_FILE")

    args.include_network_logs = args.include_network_logs or _env_bool("TAILSCALEHOUND_INCLUDE_NETWORK_LOGS")
    args.insecure = args.insecure or _env_bool("TAILSCALEHOUND_INSECURE")
    args.verbose = args.verbose or _env_bool("TAILSCALEHOUND_VERBOSE")
    args.debug = args.debug or _env_bool("TAILSCALEHOUND_DEBUG")


def _validate_args(args, logger: logging.Logger) -> bool:
    missing = []
    invalid = []
    if not args.output:
        missing.append(_missing_message("--output", "TAILSCALEHOUND_OUTPUT"))

    if args.hybrid_attacks:
        required = [
            (args.bh_url, "--bh-url", "BLOODHOUND_URL"),
            (args.bh_user, "--bh-user", "BLOODHOUND_USERNAME"),
            (args.bh_password, "--bh-password", "BLOODHOUND_SECRET"),
        ]
        missing.extend(_missing_message(option, env_name) for value, option, env_name in required if not value)
    else:
        has_status_file = bool(args.status_file)
        has_api_key = bool(args.ts_api_key)
        has_oauth_client = bool(args.ts_client_id)
        has_oauth_secret = bool(args.ts_oauth_secret)
        if args.access_policy_file and not has_status_file:
            invalid.append("--access-policy-file requires --status-file.")
        if has_oauth_client != has_oauth_secret:
            if not has_oauth_client:
                missing.append(_missing_message("--ts-client-id", "TAILSCALE_CLIENT_ID"))
            if not has_oauth_secret:
                missing.append(_missing_message("--ts-oauth-secret", "TAILSCALE_OAUTH_SECRET"))
        elif not (has_status_file or has_api_key or (has_oauth_client and has_oauth_secret)):
            missing.append(
                "--status-file (or TAILSCALEHOUND_STATUS), --ts-api-key (or TAILSCALE_API_KEY), "
                "or both --ts-client-id/--ts-oauth-secret "
                "(or TAILSCALE_CLIENT_ID/TAILSCALE_OAUTH_SECRET)"
            )

    if missing:
        logger.error("Missing required configuration:")
        for item in missing:
            logger.error(f"  {item}")
    if invalid:
        logger.error("Invalid configuration:")
        for item in invalid:
            logger.error(f"  {item}")
    if missing or invalid:
        return False
    return True

def _bh_login(base_url: str, username: str, secret: str, timeout: int, verify: bool, logger: logging.Logger) -> Optional[str]:
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


def _node_kinds(node: dict) -> List[str]:
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


def _kind_matches(kind: str, expected_kind: str) -> bool:
    return kind == expected_kind or bloodhound_kind(kind) == expected_kind


def _node_properties(node: dict) -> dict:
    props = node.get("properties")
    if isinstance(props, dict):
        return props

    merged = {}
    for key in ("identityProperties", "systemProperties"):
        value = node.get(key)
        if isinstance(value, dict):
            merged.update(value)
    return merged


def _property_value(props: dict, *names: str):
    for name in names:
        if name in props:
            return props[name]
    normalized = {str(key).lower(): value for key, value in props.items()}
    for name in names:
        value = normalized.get(name.lower())
        if value is not None:
            return value
    return None


def _node_id(node: dict) -> Optional[str]:
    props = _node_properties(node)
    for source in (node, props):
        for key in ("id", "objectid", "objectId", "objectID", "ObjectID"):
            value = source.get(key)
            if value is not None and value != "":
                return str(value)
    return None


def _extract_nodes_from_payload(payload, expected_kind: str) -> List[dict]:
    nodes = []
    seen = set()

    def walk(value) -> None:
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        if not isinstance(value, dict):
            return

        if any(_kind_matches(kind, expected_kind) for kind in _node_kinds(value)):
            node_id = _node_id(value) or str(id(value))
            if node_id not in seen:
                seen.add(node_id)
                nodes.append(value)

        for item in value.values():
            walk(item)

    walk(payload)
    return nodes


def _query_bh_nodes(
    base_url: str,
    token: str,
    kind: str,
    timeout: int,
    verify: bool,
    logger: logging.Logger,
) -> List[dict]:
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

    nodes = _extract_nodes_from_payload(payload.get("data", payload), kind)
    if not nodes:
        logger.debug(f"No {kind} nodes found in query response.")
    return nodes


def _query_azusers(base_url: str, token: str, timeout: int, verify: bool, logger: logging.Logger) -> List[dict]:
    # TODO: When hybrid-attacks targets Apple, Google, GitHub, Okta, or OneLogin,
    # swap this query to the appropriate provider-specific identity type.
    return _query_bh_nodes(base_url, token, "AZUser", timeout, verify, logger)


def _extract_tailscale_users_from_nodes(nodes: List[dict]) -> Dict[str, dict]:
    users = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        kinds = _node_kinds(node)
        normalized_kinds = {bloodhound_kind(kind) for kind in kinds}
        if bloodhound_kind("TailscaleUser") not in normalized_kinds and "TailscaleUser" not in kinds:
            continue
        props = _node_properties(node)
        login = _property_value(props, "LoginName", "loginname", "login_name")
        if not isinstance(login, str) or not login.strip():
            continue
        users[login.strip().lower()] = node
    return users


def _extract_tailscale_users(opengraph: dict) -> Dict[str, dict]:
    nodes = opengraph.get("nodes")
    if nodes is None and isinstance(opengraph.get("graph"), dict):
        nodes = opengraph["graph"].get("nodes")
    if nodes is None:
        nodes = []
    return _extract_tailscale_users_from_nodes(nodes)


def _query_tailscale_users(base_url: str, token: str, timeout: int, verify: bool, logger: logging.Logger) -> Dict[str, dict]:
    nodes = _query_bh_nodes(base_url, token, bloodhound_kind("TailscaleUser"), timeout, verify, logger)
    return _extract_tailscale_users_from_nodes(nodes)


def _build_hybrid_edges(az_nodes: List[dict], ts_users: Dict[str, dict]) -> tuple[OpenGraph, int]:
    og = OpenGraph()
    edge_count = 0

    for az_node in az_nodes:
        node_id = _node_id(az_node)
        if node_id is None:
            continue
        props = _node_properties(az_node)
        normalized = {str(k).lower(): v for k, v in props.items()}
        upn = normalized.get("userprincipalname") or normalized.get("userprincipal_name")
        if not isinstance(upn, str) or not upn.strip():
            continue
        ts_node = ts_users.get(upn.strip().lower())
        if not ts_node:
            continue
        ts_node_id = _node_id(ts_node)
        if not ts_node_id:
            continue

        name = normalized.get("name") or normalized.get("displayname") or upn
        az_props = {"name": name} if name else {}
        og.add_node(
            OpenGraphNode(
                id=str(node_id),
                kinds=["AZUser"],
                properties=OpenGraphProperties(**az_props),
            )
        )
        ts_node_props = _node_properties(ts_node)
        ts_login = _property_value(ts_node_props, "LoginName", "loginname", "login_name")
        ts_display = _property_value(ts_node_props, "DisplayName", "displayname", "display_name", "name")
        ts_name = ts_display or ts_login
        ts_props = {"name": ts_name} if ts_name else {}
        og.add_node(
            OpenGraphNode(
                id=ts_node_id,
                kinds=[bloodhound_kind("TailscaleUser")],
                properties=OpenGraphProperties(**ts_props),
            )
        )

        og.add_edge(
            OpenGraphEdge(
                start_node=str(node_id),
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


def _ensure_output_dir(path: str) -> str:
    output_dir = os.path.abspath(os.path.expanduser(path))
    os.makedirs(output_dir, exist_ok=True)
    if not os.path.isdir(output_dir):
        raise OSError(f"Output path is not a directory: {output_dir}")
    return output_dir


def _strip_json_comments(text: str) -> str:
    result = []
    i = 0
    in_string = False
    escape = False
    line_comment = False
    block_comment = False

    while i < len(text):
        char = text[i]
        next_char = text[i + 1] if i + 1 < len(text) else ""

        if line_comment:
            if char in "\r\n":
                line_comment = False
                result.append(char)
            i += 1
            continue

        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                i += 2
                continue
            if char in "\r\n":
                result.append(char)
            i += 1
            continue

        if in_string:
            result.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            i += 1
            continue

        if char == '"':
            in_string = True
            result.append(char)
        elif char == "/" and next_char == "/":
            line_comment = True
            i += 1
        elif char == "/" and next_char == "*":
            block_comment = True
            i += 1
        else:
            result.append(char)
        i += 1

    return "".join(result)


def _remove_trailing_json_commas(text: str) -> str:
    result = []
    i = 0
    in_string = False
    escape = False

    while i < len(text):
        char = text[i]
        if in_string:
            result.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            i += 1
            continue

        if char == '"':
            in_string = True
            result.append(char)
        elif char == ",":
            j = i + 1
            while j < len(text) and text[j].isspace():
                j += 1
            if j < len(text) and text[j] in "}]":
                i += 1
                continue
            result.append(char)
        else:
            result.append(char)
        i += 1

    return "".join(result)


def _read_text_file(path: str, logger: logging.Logger, label: str) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        logger.error(f"Failed to read {label} file: {exc}")
        return None

    encodings = ["utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"]
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings = ["utf-16", "utf-8-sig", "utf-16-le", "utf-16-be"]

    last_error = None
    for encoding in encodings:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError as exc:
            last_error = exc

    logger.error(f"Failed to decode {label} file as UTF-8 or UTF-16: {last_error}")
    return None


def _load_access_policy_file(path: str, logger: logging.Logger) -> Optional[dict]:
    raw_policy = _read_text_file(path, logger, "Access Policy")
    if raw_policy is None:
        return None

    try:
        policy = json.loads(raw_policy)
    except json.JSONDecodeError as original_exc:
        try:
            relaxed_policy = _remove_trailing_json_commas(_strip_json_comments(raw_policy))
            policy = json.loads(relaxed_policy)
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in Access Policy file: {original_exc}")
            return None

    if not isinstance(policy, dict):
        logger.error("Access Policy file must contain a JSON object.")
        return None

    logger.info(f"Loaded Access Policy file: {path}")
    return policy


def _run_hybrid_windows(args, logger: logging.Logger) -> int:
    token = _bh_login(args.bh_url, args.bh_user, args.bh_password, timeout=30, verify=not args.insecure, logger=logger)
    if not token:
        return 1
    az_nodes = _query_azusers(args.bh_url, token, timeout=30, verify=not args.insecure, logger=logger)
    logger.info(f"Retrieved {len(az_nodes)} AZUser nodes")

    if args.tailscalehound_file:
        try:
            with open(args.tailscalehound_file, "r", encoding="utf-8") as handle:
                opengraph_json = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error(f"Failed to read TailscaleHound file: {exc}")
            return 1
        ts_users = _extract_tailscale_users(opengraph_json)
        logger.info(f"Loaded {len(ts_users)} Tailscale users from {args.tailscalehound_file}")
    else:
        ts_users = _query_tailscale_users(args.bh_url, token, timeout=30, verify=not args.insecure, logger=logger)
        logger.info(f"Retrieved {len(ts_users)} TS_User nodes")

    og, edge_count = _build_hybrid_edges(az_nodes, ts_users)
    logger.info(f"Created {edge_count} {bloodhound_kind('AZUserSyncedToUser')} edges")

    output_dir = args.output
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    output_path = os.path.join(output_dir, f"tailscale_hybrid_paths_{timestamp}.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(apply_bloodhound_names(og.export_to_dict()), handle, indent=2)
    print(f"Exported to: {output_path}")
    return 0

def main():
    load_dotenv()

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    arg_parser = argparse.ArgumentParser(description="TailscaleHound - Open Graph Collector for Tailscale")
    arg_parser.add_argument(
        '--status-file',
        type=str,
        help='Path to Tailscale CLI "status" output (env: TAILSCALEHOUND_STATUS)',
    )
    arg_parser.add_argument(
        '--access-policy-file',
        '--policy-file',
        dest='access_policy_file',
        type=str,
        help='Path to Tailscale Access Policy JSON/HuJSON for local status enrichment (env: TAILSCALEHOUND_ACCESS_POLICY)',
    )
    arg_parser.add_argument('--ts-api-key', type=str, help='Tailscale API Key (env: TAILSCALE_API_KEY)')
    arg_parser.add_argument('--ts-client-id', type=str, help='Tailscale OAuth client ID (env: TAILSCALE_CLIENT_ID)')
    arg_parser.add_argument('--ts-oauth-secret', type=str, help='Tailscale OAuth client secret (env: TAILSCALE_OAUTH_SECRET)')
    arg_parser.add_argument('--tailnet', type=str, help='Tailnet name for API requests (env: TAILSCALE_TAILNET)')
    arg_parser.add_argument('--tailcontrol', type=str, help='Tailcontrol cookie value for admin machines (env: TAILCONTROL_COOKIE)')
    arg_parser.add_argument('--api-base-url', type=str,
                            help='Tailscale API base URL (env: TAILSCALE_API_BASE_URL)')
    arg_parser.add_argument('--output', type=str,
                            help='Directory to write generated OpenGraph and ACL output files (env: TAILSCALEHOUND_OUTPUT)')
    arg_parser.add_argument('--include-network-logs', action='store_true',
                            help='Include /logging/network results (env: TAILSCALEHOUND_INCLUDE_NETWORK_LOGS)')
    arg_parser.add_argument('--insecure', action='store_true',
                            help='Disable TLS verification for API requests (env: TAILSCALEHOUND_INSECURE)')
    arg_parser.add_argument('--verbose', action='store_true', help='Enable informational logging (env: TAILSCALEHOUND_VERBOSE)')
    arg_parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging. Debug mode may log sensitive API response bodies. (env: TAILSCALEHOUND_DEBUG)',
    )
    arg_parser.add_argument('--hybrid-attacks', type=str, help='Enable hybrid attack mapping (env: TAILSCALEHOUND_HYBRID_ATTACKS)')
    arg_parser.add_argument('--bh-url', type=str, help='BloodHound base URL for hybrid mapping (env: BLOODHOUND_URL)')
    arg_parser.add_argument('--bh-user', type=str, help='BloodHound username for hybrid mapping (env: BLOODHOUND_USERNAME)')
    arg_parser.add_argument('--bh-password', type=str, help='BloodHound password/secret for hybrid mapping (env: BLOODHOUND_SECRET)')
    arg_parser.add_argument(
        '--tailscalehound-file',
        type=str,
        help='Optional TailscaleHound OpenGraph JSON for pre-ingest hybrid mapping (env: TAILSCALEHOUND_FILE)',
    )
    args = arg_parser.parse_args()
    _apply_env_defaults(args)

    log_level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logger.setLevel(log_level)
    stream.setLevel(log_level)

    logger.info("Starting TailscaleHound...")
    if args.debug:
        logger.warning("Debug logging is enabled and may include sensitive API response bodies.")

    if not _validate_args(args, logger):
        return 1

    try:
        args.output = _ensure_output_dir(args.output)
    except OSError as exc:
        logger.error(f"Failed to prepare output directory: {exc}")
        return 1

    if args.hybrid_attacks:
        if not (args.bh_url and args.bh_user and args.bh_password):
            logger.error("Hybrid mapping requires --bh-url, --bh-user, and --bh-password.")
            return 1
        hybrid = args.hybrid_attacks.strip().lower()
        if hybrid != "windows":
            logger.error(f"Unsupported hybrid-attacks value: {args.hybrid_attacks}")
            return 1
        return _run_hybrid_windows(args, logger)

    # Add more initialization code here
    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + "_"
    
    oauth_client_id = args.ts_client_id
    oauth_secret = args.ts_oauth_secret
    if (oauth_client_id and not oauth_secret) or (oauth_secret and not oauth_client_id):
        logger.error("Both --ts-client-id and --ts-oauth-secret are required to use OAuth.")
        return 1

    api_token = None
    if args.ts_api_key:
        api_token = args.ts_api_key
        logger.info("Using Tailscale API (remote parser) with API key")
    elif oauth_client_id and oauth_secret:
        logger.info("Requesting Tailscale OAuth access token...")
        api_token = fetch_oauth_access_token(
            client_id=oauth_client_id,
            client_secret=oauth_secret,
            api_base_url=args.api_base_url,
            verify=not args.insecure,
            logger=logger,
        )
        if not api_token:
            logger.error("Failed to fetch Tailscale OAuth access token.")
            return 1
        logger.info("Using Tailscale API (remote parser) with OAuth access token")

    if api_token:
        output_file = os.path.join(args.output, f"tailscalehound_remote_opengraph_{timestamp}output.json")
        acl_file = os.path.join(args.output, f"tailscalehound_remote_acl_{timestamp}policy.json")
        ts_parser = RemoteParser(
            api_key=api_token,
            tailnet=args.tailnet,
            api_base_url=args.api_base_url,
            verify=not args.insecure,
            include_network_logs=args.include_network_logs,
            tailcontrol=args.tailcontrol,
        )
        if not ts_parser.save_acl_policy(acl_file):
            logger.warning("Failed to save ACL policy; continuing with OpenGraph export.")
        network = ts_parser.parse()
        if not network:
            print("Remote parse failed!")
            return 1
        exporter = LocalParser("remote", timestamp)
        exporter.network = network
        exporter._tailnet_key_cache = None
        if exporter.save_opengraph(output_file):
            print(f"Exported to: {output_file}")
            print()
            print("Upload to BloodHound and query with:")
            print(f"  MATCH (n:{bloodhound_kind('TailscaleUser')}) RETURN n")
            return 0
        print("Export failed!")
        return 1
    elif args.status_file:
        output_file = os.path.join(args.output, f"tailscalehound_local_opengraph_{timestamp}output.json")
        logger.info(f"Using status file: {args.status_file}")
        # parse status file using Parser
        ts_parser = LocalParser(args.status_file, timestamp)
 
        network = ts_parser.parse()
        if not network:
            print("Local parse failed!")
            return 1

        if args.access_policy_file:
            acl_policy = _load_access_policy_file(args.access_policy_file, logger)
            if acl_policy is None:
                return 1
            network.acl_policy = acl_policy
            ts_parser.network = network
            ts_parser._tailnet_key_cache = None

        #network_dict = network.to_dict()

        if ts_parser.save_opengraph(output_file):
            print(f"Exported to: {output_file}")
            print()
            print("Upload to BloodHound and query with:")
            print(f"  MATCH (n:{bloodhound_kind('TailscaleUser')}) RETURN n")
            return 0
        else:
            print("Export failed!")
            return 1

        # Print summary
        ts_parser.print_network_summary(network)
        #logger.info(f"Status file loaded: {status_file}")
        
    else:
        logger.error("No collection source configured.")
        return 1

if __name__ == "__main__":
    main()
