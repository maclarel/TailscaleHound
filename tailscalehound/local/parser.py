import ipaddress
import json
import logging
import re
from typing import List, Optional

from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node as OpenGraphNode
from bhopengraph.Properties import Properties as OpenGraphProperties
from bhopengraph.Edge import Edge as OpenGraphEdge

from ..names import BASE_KIND, apply_bloodhound_names, bloodhound_kind
from ..models import (
    User,
    Node,
    TailscaleNetwork,
    TailnetKey,
    TailnetWebhook,
    TailnetService,
    TailnetUserInvite,
    TailnetDeviceInvite,
)

class Parser:
    """
    Parser for Tailscale status JSON output
    Converts raw JSON into structured User and Node objects
    Can also export to BloodHound OpenGraph format
    """
    
    def __init__(self, config_path: str, timestamp: str):
        self.config_path = config_path
        self.timestamp = timestamp
        self.logger = logging.getLogger(__name__)
        self.network = None  # Store the parsed network
        self._tailnet_key_cache = None

    def _tailnet_key(self) -> str:
        if self._tailnet_key_cache:
            return self._tailnet_key_cache
        if not self.network:
            return "tailscale"
        raw = (
            self.network.tailnet_id
            or self.network.tailnet_name
            or self.network.tailnet_magic_dns_suffix
            or self.network.magic_dns_suffix
            or "tailscale"
        )
        key = raw.strip().lower().rstrip(".")
        key = re.sub(r"[^a-z0-9]+", "_", key).strip("_")
        if not key:
            key = "tailscale"
        self._tailnet_key_cache = key
        return key

    def _slug(self, value: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
        return slug or "item"

    def _tailnet_node_id(self) -> str:
        return f"tailnet_{self._tailnet_key()}"

    def _user_node_id(self, user: User) -> str:
        return f"{self._tailnet_key()}_user_{user.id}"

    def _device_node_id(self, node: Node) -> str:
        return f"{self._tailnet_key()}_node_{node.id}"

    def _key_node_id(self, key: TailnetKey) -> str:
        return f"{self._tailnet_key()}_key_{key.id}"

    def _webhook_node_id(self, webhook: TailnetWebhook) -> str:
        return f"{self._tailnet_key()}_webhook_{webhook.endpoint_id}"

    def _service_node_id(self, service: TailnetService) -> str:
        return f"{self._tailnet_key()}_service_{service.name}"

    def _idp_node_id(self, provider: str) -> str:
        return f"{self._tailnet_key()}_idp_{self._slug(provider)}"

    def _external_tailnet_node_id(self, tailnet: str) -> str:
        return f"{self._tailnet_key()}_external_tailnet_{self._slug(tailnet)}"

    def _external_tag_node_id(self, tailnet: str, tag: str) -> str:
        return f"{self._tailnet_key()}_external_tag_{self._slug(tailnet)}_{self._slug(tag)}"

    def _external_tailnet_from_fqdn(self, fqdn: str) -> Optional[str]:
        if not isinstance(fqdn, str):
            return None
        raw = fqdn.strip().strip(".")
        if not raw or "." not in raw:
            return None
        # <hostname>.<tailnet>.ts.net -> return <tailnet>.ts.net
        parts = raw.split(".", 1)
        if len(parts) < 2:
            return None
        tailnet = parts[1].strip(".")
        return tailnet or None

    def _external_tailnet_for_node(self, node: Node) -> Optional[str]:
        if not node or not node.is_external:
            return None
        for value in (node.fqdn, node.dns_name):
            tailnet = self._external_tailnet_from_fqdn(value or "")
            if tailnet:
                return tailnet
        if isinstance(node.domain, str) and node.domain.strip():
            return node.domain.strip().lower().rstrip(".")
        return "unknown-external-tailnet"

    def _acl_node_id(self, kind: str, value: str) -> str:
        return f"{self._tailnet_key()}_acl_{kind}_{self._slug(value)}"

    def _acl_rule_node_id(self, kind: str, index: int) -> str:
        return f"{self._tailnet_key()}_acl_{kind}_{index}"

    def _user_invite_node_id(self, invite: TailnetUserInvite) -> str:
        return f"{self._tailnet_key()}_user_invite_{invite.id}"

    def _device_invite_node_id(self, invite: TailnetDeviceInvite) -> str:
        return f"{self._tailnet_key()}_device_invite_{invite.id}"

    def _route_node_id(self, route: str) -> str:
        return f"{self._tailnet_key()}_route_{self._slug(route)}"

    def _app_connector_node_id(self, name: str, index: int) -> str:
        return f"{self._tailnet_key()}_app_connector_{self._slug(name)}_{index}"

    def _iter_app_connectors(self, policy: dict) -> List[dict]:
        if not isinstance(policy, dict):
            return []
        node_attrs = policy.get("nodeAttrs", []) or []
        if not isinstance(node_attrs, list):
            return []

        app_connectors = []
        index = 0
        for node_attr in node_attrs:
            if not isinstance(node_attr, dict):
                continue
            app = node_attr.get("app")
            if not isinstance(app, dict):
                continue
            configs = app.get("tailscale.com/app-connectors")
            if not isinstance(configs, list):
                continue
            for config in configs:
                if not isinstance(config, dict):
                    continue
                index += 1
                name = config.get("name")
                if not isinstance(name, str) or not name.strip():
                    name = f"app-connector-{index}"
                name = name.strip()
                app_connectors.append(
                    {
                        "index": index,
                        "name": name,
                        "node_id": self._app_connector_node_id(name, index),
                        "entry": config,
                        "connectors": config.get("connectors"),
                        "target": node_attr.get("target"),
                    }
                )
        return app_connectors

    def _all_nodes(self, network: Optional[TailscaleNetwork] = None) -> List[Node]:
        network = network or self.network
        if not network:
            return []
        nodes = []
        if network.self_node:
            nodes.append(network.self_node)
        nodes.extend([node for node in network.peers if node])
        return nodes

    def _normalize_tailnet_suffix(self, value: Optional[str]) -> Optional[str]:
        if not isinstance(value, str):
            return None
        value = value.strip().lower().rstrip(".")
        return value or None

    def _annotate_local_status_nodes(self, network: TailscaleNetwork) -> None:
        current_tailnet = self._normalize_tailnet_suffix(
            network.tailnet_magic_dns_suffix or network.magic_dns_suffix
        )
        for node in self._all_nodes(network):
            if not node:
                continue
            if not node.fqdn and node.dns_name:
                node.fqdn = node.dns_name.strip().rstrip(".")
            if not node.stable_id and node.id:
                node.stable_id = node.id
            if node.is_external is not None:
                continue
            node_tailnet = self._normalize_tailnet_suffix(
                self._external_tailnet_from_fqdn(node.fqdn or node.dns_name or "")
            )
            node.is_external = bool(
                current_tailnet and node_tailnet and node_tailnet != current_tailnet
            )

    def _is_tagged_devices_user(self, user: Optional[User]) -> bool:
        if not user:
            return False
        login_name = (user.login_name or "").strip().lower()
        display_name = (user.display_name or "").strip().lower()
        return login_name == "tagged-devices" or display_name == "tagged devices"

    def _is_graph_user(self, user: Optional[User]) -> bool:
        return bool(user and not user.is_system)

    def _classify_local_status_users(self, network: TailscaleNetwork) -> None:
        nodes_by_user_id = {}
        for node in self._all_nodes(network):
            if not node or node.user_id is None:
                continue
            nodes_by_user_id.setdefault(str(node.user_id), []).append(node)

        for user in network.users:
            if not user:
                continue
            if self._is_tagged_devices_user(user):
                user.is_system = True
                user.user_type = user.user_type or "system"
                self.logger.debug(
                    "Skipping synthetic Tailscale tagged-devices identity as a user node."
                )
                continue

            associated_nodes = nodes_by_user_id.get(str(user.id), [])
            if not associated_nodes:
                continue

            user.is_external = all(bool(node.is_external) for node in associated_nodes)
            if user.is_external:
                self.logger.debug(
                    f"Classified external user: {user.display_name} ({user.login_name})"
                )

    def _iter_status_app_connectors(self) -> List[dict]:
        app_connectors = []
        seen = set()
        index = 0
        for node in self._all_nodes():
            if node and node.is_external:
                continue
            cap_map = node.cap_map if isinstance(node.cap_map, dict) else {}
            configs = cap_map.get("tailscale.com/app-connectors")
            if not isinstance(configs, list):
                continue
            for config in configs:
                if not isinstance(config, dict):
                    continue
                name = config.get("name")
                if not isinstance(name, str) or not name.strip():
                    name = f"app-connector-{index + 1}"
                name = name.strip()
                connectors = tuple(
                    c.strip()
                    for c in (config.get("connectors") or [])
                    if isinstance(c, str) and c.strip()
                )
                domains = tuple(
                    d.strip()
                    for d in (config.get("domains") or [])
                    if isinstance(d, str) and d.strip()
                )
                key = (name, connectors, domains)
                if key in seen:
                    continue
                seen.add(key)
                index += 1
                app_connectors.append(
                    {
                        "index": index,
                        "name": name,
                        "node_id": self._app_connector_node_id(name, index),
                        "entry": config,
                        "connectors": list(connectors),
                        "domains": list(domains),
                    }
                )
        return app_connectors

    def _combined_app_connectors(self, policy: Optional[dict] = None) -> List[dict]:
        combined = []
        seen = set()
        app_connectors = (
            self._iter_app_connectors(policy or {}) + self._iter_status_app_connectors()
        )
        for app_connector in app_connectors:
            node_id = app_connector.get("node_id")
            if not node_id or node_id in seen:
                continue
            seen.add(node_id)
            combined.append(app_connector)
        return combined

    def _local_status_tags(self) -> set[str]:
        tags = set()
        for node in self._all_nodes():
            if node and node.is_external:
                continue
            for tag in node.tags or []:
                if isinstance(tag, str) and tag.strip():
                    tags.add(tag.strip())
        return tags

    def _node_route_values(self, node: Node) -> List[str]:
        if not node:
            return []

        routes = set()
        explicit_routes = set()
        for route_list in (
            node.enabled_routes,
            node.primary_routes,
            node.advertised_routes,
        ):
            for route in route_list or []:
                if isinstance(route, str) and route.strip():
                    route_value = route.strip()
                    routes.add(route_value)
                    explicit_routes.add(route_value)

        own_ip_networks = set()
        for ip_value in node.tailscale_ips or []:
            if not isinstance(ip_value, str) or not ip_value.strip():
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_value.strip())
            except ValueError:
                continue
            prefix = 32 if ip_obj.version == 4 else 128
            own_ip_networks.add(
                str(ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False))
            )

        for route in node.allowed_ips or []:
            if not isinstance(route, str) or not route.strip():
                continue
            route_value = route.strip()
            try:
                route_network = ipaddress.ip_network(route_value, strict=False)
            except ValueError:
                if route_value in explicit_routes:
                    routes.add(route_value)
                continue
            if str(route_network) in own_ip_networks and route_value not in explicit_routes:
                continue
            routes.add(route_value)

        return sorted(routes)

    def _node_advertises_exit_node(self, node: Node) -> bool:
        if not node:
            return False
        default_routes = {"0.0.0.0/0", "::/0"}
        if node.exit_node or node.exit_node_option:
            return True
        if node.has_exit_node or node.advertised_exit_node:
            return True
        return any(route in default_routes for route in self._node_route_values(node))

    def _load_json_file(self, path: str) -> dict:
        with open(path, "rb") as f:
            raw = f.read()

        encodings = ["utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"]
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            encodings = ["utf-16", "utf-8-sig", "utf-16-le", "utf-16-be"]

        last_decode_error = None
        last_json_error = None
        for encoding in encodings:
            try:
                text = raw.decode(encoding)
            except UnicodeDecodeError as e:
                last_decode_error = e
                continue

            try:
                return json.loads(text)
            except json.JSONDecodeError as e:
                last_json_error = e

        if last_json_error:
            raise last_json_error
        if last_decode_error:
            raise last_decode_error
        raise json.JSONDecodeError("Expecting value", "", 0)
    
    def parse(self) -> Optional[TailscaleNetwork]:
        """
        Parse Tailscale status JSON file and return TailscaleNetwork object
        
        Returns:
            TailscaleNetwork object containing users and nodes, or None if parsing fails
        """
        try:
            data = self._load_json_file(self.config_path)
            self.logger.info(f"Successfully loaded JSON from: {self.config_path}")
            
            # Parse the data into structured objects
            network = self._parse_network(data)
            
            online_peers = len(network.get_online_peers())
            online_total = online_peers + (1 if network.self_node and network.self_node.online else 0)
            graph_users = [user for user in network.users if self._is_graph_user(user)]
            external_users = sum(1 for user in graph_users if user.is_external)
            skipped_users = len(network.users) - len(graph_users)
            user_summary = f"{len(graph_users)} users"
            if external_users:
                user_summary += f" ({external_users} external)"
            if skipped_users:
                user_summary += f", {skipped_users} synthetic skipped"
            self.logger.info(f"Parsed network: {user_summary}, "
                             f"{len(network.peers)} peers, "
                             f"{online_total} online (including self)")
            
            # Store the network for later use (e.g., export)
            self.network = network
            self._tailnet_key_cache = None
            
            return network
            
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {self.config_path}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in configuration file: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to parse configuration file: {e}", exc_info=True)
            return None
    
    def _parse_network(self, data: dict) -> TailscaleNetwork:
        """Parse the entire network structure"""
        network = TailscaleNetwork(
            version=data.get('Version', 'unknown'),
            backend_state=data.get('BackendState', 'unknown'),
            magic_dns_suffix=data.get('MagicDNSSuffix')
        )

        current_tailnet = data.get('CurrentTailnet')
        if isinstance(current_tailnet, dict):
            network.tailnet_name = current_tailnet.get('Name')
            network.tailnet_magic_dns_suffix = current_tailnet.get('MagicDNSSuffix') or network.magic_dns_suffix
            if 'MagicDNSEnabled' in current_tailnet:
                network.tailnet_magic_dns_enabled = current_tailnet.get('MagicDNSEnabled')
        
        # Parse users
        users_data = data.get('User', {})
        network.users = self._parse_users(users_data)
        self.logger.debug(f"Parsed {len(network.users)} users")
        
        # Parse self node (current machine)
        if 'Self' in data and data['Self']:
            network.self_node = self._parse_node(data['Self'])
            status = "online" if network.self_node.online else "offline"
            self.logger.debug(f"Parsed self node: {network.self_node.hostname} - {status}")
        
        # Parse peer nodes
        peers_data = data.get('Peer', {})
        network.peers = self._parse_peers(peers_data)
        self.logger.debug(f"Parsed {len(network.peers)} peers")

        self._annotate_local_status_nodes(network)
        self._classify_local_status_users(network)
        
        return network
    
    def _parse_users(self, users_data: dict) -> list[User]:
        """
        Parse users from the User section of Tailscale status
        
        Args:
            users_data: Dictionary mapping user IDs to user info
            
        Returns:
            List of User objects
        """
        users = []
        
        for user_id_str, user_info in users_data.items():
            user = User(
                id=user_info.get('ID'),
                login_name=user_info.get('LoginName', ''),
                display_name=user_info.get('DisplayName', ''),
                profile_pic_url=user_info.get('ProfilePicURL')
            )
            if self._is_tagged_devices_user(user):
                user.is_system = True
                user.user_type = "system"
            users.append(user)
            self.logger.debug(f"Parsed user: {user.display_name} ({user.login_name})")
        
        return users
    
    def _parse_peers(self, peers_data: dict) -> list[Node]:
        """
        Parse peer nodes from the Peer section of Tailscale status
        
        Args:
            peers_data: Dictionary mapping public keys to peer info
            
        Returns:
            List of Node objects
        """
        peers = []
        
        for public_key, peer_info in peers_data.items():
            node = self._parse_node(peer_info)
            peers.append(node)
            
            status = "online" if node.online else "offline"
            self.logger.debug(f"Parsed peer: {node.hostname} ({node.os}) - {status}")
        
        return peers
    
    def _parse_node(self, node_data: dict) -> Node:
        """
        Parse a single node (peer or self) from Tailscale status
        
        Args:
            node_data: Dictionary containing node information
            
        Returns:
            Node object
        """
        advertised_routes = node_data.get('AdvertisedRoutes') or []
        enabled_routes = node_data.get('EnabledRoutes') or []
        primary_routes = node_data.get('PrimaryRoutes') or []
        default_routes = {"0.0.0.0/0", "::/0"}
        router = any(
            route and route not in default_routes
            for route in (primary_routes + advertised_routes + enabled_routes)
        )

        node = Node(
            id=node_data.get('ID', ''),
            public_key=node_data.get('PublicKey', ''),
            hostname=node_data.get('HostName', ''),
            dns_name=node_data.get('DNSName', ''),
            os=node_data.get('OS', ''),
            user_id=node_data.get('UserID', 0),
            tailscale_ips=node_data.get('TailscaleIPs', []),
            allowed_ips=node_data.get('AllowedIPs', []),
            primary_routes=primary_routes,
            advertised_routes=advertised_routes,
            enabled_routes=enabled_routes,
            online=node_data.get('Online', False),
            exit_node=node_data.get('ExitNode', False),
            exit_node_option=node_data.get('ExitNodeOption', False),
            tags=node_data.get('Tags', []),
            created=node_data.get('Created'),
            last_seen=node_data.get('LastSeen'),
            last_write=node_data.get('LastWrite'),
            last_handshake=node_data.get('LastHandshake'),
            key_expiry=node_data.get('KeyExpiry'),
            router=router,
            addrs=node_data.get('Addrs', []),
            relay=node_data.get('Relay'),
            peer_relay=node_data.get('PeerRelay'),
            cur_addr=node_data.get('CurAddr'),
            rx_bytes=node_data.get('RxBytes', 0),
            tx_bytes=node_data.get('TxBytes', 0),
            active=node_data.get('Active', False),
            ssh_host_keys=node_data.get('sshHostKeys', []),
            peer_api_url=node_data.get('PeerAPIURL', []),
            taildrop_target=node_data.get('TaildropTarget', 0),
            no_file_sharing_reason=node_data.get('NoFileSharingReason'),
            capabilities=node_data.get('Capabilities', []),
            cap_map=node_data.get('CapMap', {}),
            in_network_map=node_data.get('InNetworkMap', False),
            in_magic_sock=node_data.get('InMagicSock', False),
            in_engine=node_data.get('InEngine', False)
        )
        
        return node
    
    def print_network_summary(self, network: TailscaleNetwork):
        """
        Print a human-readable summary of the network
        
        Args:
            network: TailscaleNetwork object to summarize
        """
        print("\n" + "="*60)
        print(f"Tailscale Network Summary")
        print("="*60)
        print(f"Version: {network.version}")
        print(f"Backend State: {network.backend_state}")
        print(f"Magic DNS Suffix: {network.magic_dns_suffix}")
        print()
        
        # Print self node
        if network.self_node:
            print(f"Self Node:")
            print(f"  Hostname: {network.self_node.hostname}")
            print(f"  OS: {network.self_node.os}")
            print(f"  IP: {network.self_node.primary_ip}")
            print()
        
        # Print users
        graph_users = [user for user in network.users if self._is_graph_user(user)]
        print(f"Users ({len(graph_users)}):")
        for user in graph_users:
            print(f"  - {user.display_name} ({user.login_name})")
        print()
        
        # Print online peers
        online_peers = network.get_online_peers()
        print(f"Online Peers ({len(online_peers)}):")
        for peer in online_peers:
            user = network.get_user_by_id(peer.user_id)
            user_name = user.display_name if user else "Unknown User"
            exit_marker = " [EXIT NODE]" if peer.exit_node else ""
            print(f"  - {peer.hostname} ({peer.os}) - {peer.primary_ip} - {user_name}{exit_marker}")
        print()
        
        # Print offline peers
        offline_peers = network.get_offline_peers()
        if offline_peers:
            print(f"Offline Peers ({len(offline_peers)}):")
            for peer in offline_peers:
                print(f"  - {peer.hostname} ({peer.os})")
            print()
        
        # Print exit nodes
        exit_nodes = network.get_exit_nodes()
        if exit_nodes:
            print(f"Exit Nodes ({len(exit_nodes)}):")
            for node in exit_nodes:
                print(f"  - {node.hostname} - {node.primary_ip}")
            print()
        
        print("="*60 + "\n")
    
    def export_to_opengraph(self, source_kind: Optional[str] = BASE_KIND) -> Optional[dict]:
        """
        Export users and nodes to BloodHound OpenGraph format
        
        Args:
            source_kind: Optional source kind to add to metadata
            
        Returns:
            Dictionary in BloodHound OpenGraph format, or None if no network parsed
        """
        if not self.network:
            self.logger.error("No network data available. Run parse() first.")
            return None
        
        opengraph = OpenGraph(source_kind=source_kind)

        tailnet_name = (self.network.tailnet_name or
                        self.network.tailnet_magic_dns_suffix or
                        self.network.magic_dns_suffix or
                        self.network.tailnet_id or
                        "TailscaleNetwork")
        tailnet_properties = {
            "name": tailnet_name,
            "TailnetName": self.network.tailnet_name,
            "TailnetID": self.network.tailnet_id,
            "MagicDNSSuffix": self.network.tailnet_magic_dns_suffix or self.network.magic_dns_suffix,
            "MagicDNSEnabled": self.network.tailnet_magic_dns_enabled,
            "Version": self.network.version,
            "BackendState": self.network.backend_state
        }
        if self.network.dns_nameservers:
            tailnet_properties["DnsNameservers"] = self.network.dns_nameservers
        if self.network.dns_search_paths:
            tailnet_properties["DnsSearchPaths"] = self.network.dns_search_paths
        if self.network.dns_magic_dns is not None:
            tailnet_properties["DnsMagicDNS"] = self.network.dns_magic_dns
        if self.network.dns_split_dns:
            tailnet_properties["DnsSplitDNS"] = json.dumps(self.network.dns_split_dns, sort_keys=True)
        if self.network.dns_configuration:
            tailnet_properties["DnsConfiguration"] = json.dumps(self.network.dns_configuration, sort_keys=True)
        if isinstance(self.network.tailnet_settings, dict):
            for key, value in self.network.tailnet_settings.items():
                if value is None:
                    continue
                if isinstance(value, (dict, list)):
                    tailnet_properties[key] = json.dumps(value, sort_keys=True)
                else:
                    tailnet_properties[key] = value
        if self.network.logging_configuration:
            tailnet_properties["LoggingConfiguration"] = json.dumps(
                self.network.logging_configuration, sort_keys=True
            )
        if self.network.logging_network:
            tailnet_properties["LoggingNetwork"] = json.dumps(
                self.network.logging_network, sort_keys=True
            )
        if self.network.logstream_configuration:
            tailnet_properties["LogstreamConfiguration"] = json.dumps(
                self.network.logstream_configuration, sort_keys=True
            )
        if self.network.logstream_status:
            tailnet_properties["LogstreamStatus"] = json.dumps(
                self.network.logstream_status, sort_keys=True
            )
        if self.network.contacts:
            tailnet_properties["Contacts"] = json.dumps(
                self.network.contacts, sort_keys=True
            )
        tailnet_properties = {k: v for k, v in tailnet_properties.items() if v is not None}
        tailnet_node = OpenGraphNode(
            id=self._tailnet_node_id(),
            kinds=["TailscaleNetwork"],
            properties=OpenGraphProperties(**tailnet_properties)
        )
        opengraph.add_node(tailnet_node)

        # Create IDP node + edge when provider is known (admin tailnet settings).
        provider = None
        if isinstance(self.network.tailnet_settings, dict):
            provider = self.network.tailnet_settings.get("provider")
        if isinstance(provider, str) and provider.strip():
            provider = provider.strip()
            idp_node = OpenGraphNode(
                id=self._idp_node_id(provider),
                kinds=["TailscaleIDP"],
                properties=OpenGraphProperties(
                    name=provider,
                    Provider=provider,
                ),
            )
            opengraph.add_node(idp_node)

        # Create ACL policy nodes (remote parser only)
        self._add_acl_nodes(opengraph)
        
        # Create nodes for each user
        for user in self.network.users:
            if not self._is_graph_user(user):
                continue
            properties = {
                "name": user.display_name,  # This is what displays in BloodHound
                "ID": user.id,
                "LoginName": user.login_name,
                "DisplayName": user.display_name,
            }
            if user.user_id is not None:
                properties["UserID"] = user.user_id
            if user.stable_id:
                properties["StableID"] = user.stable_id

            if user.profile_pic_url:
                properties["ProfilePicURL"] = user.profile_pic_url
            if user.role:
                properties["Role"] = user.role
            if user.is_admin is not None:
                properties["IsAdmin"] = user.is_admin
            if user.is_owner is not None:
                properties["IsOwner"] = user.is_owner
            if user.status:
                properties["Status"] = user.status
            if user.tailnet_id:
                properties["TailnetID"] = user.tailnet_id
            if user.org_tailnet_id:
                properties["OrgTailnetID"] = user.org_tailnet_id
            if user.created:
                properties["Created"] = user.created
            if user.last_seen:
                properties["LastSeen"] = user.last_seen
            if user.currently_connected is not None:
                properties["CurrentlyConnected"] = user.currently_connected
            if user.device_count is not None:
                properties["DeviceCount"] = user.device_count
            if user.user_type:
                properties["Type"] = user.user_type
            if user.domain_name:
                properties["DomainName"] = user.domain_name
            if user.shared_domain is not None:
                properties["SharedDomain"] = user.shared_domain
            if user.can_edit_billing is not None:
                properties["CanEditBilling"] = user.can_edit_billing
            if user.needs_onboarding is not None:
                properties["NeedsOnboarding"] = user.needs_onboarding
            if user.use_business_pricing is not None:
                properties["UseBusinessPricing"] = user.use_business_pricing
            if user.no_longer_provisioned is not None:
                properties["NoLongerProvisioned"] = user.no_longer_provisioned
            if user.is_external is not None:
                properties["IsExternal"] = user.is_external

            node = OpenGraphNode(
                id=self._user_node_id(user),
                kinds=["TailscaleExternalUser" if user.is_external else "TailscaleUser"],
                properties=OpenGraphProperties(**properties)
            )
            opengraph.add_node(node)

        # Create nodes for each tailnet key (remote parser only)
        if getattr(self.network, "keys", None):
            for key in self.network.keys:
                key_type_kind = None
                if isinstance(key.key_type, str):
                    kind_lookup = {
                        "auth": "TailnetAuthKey",
                        "client": "TailnetClientKey",
                        "federated": "TailnetFederatedKey",
                        "api": "TailnetAPIKey",
                    }
                    key_type_kind = kind_lookup.get(key.key_type.strip().lower())
                key_props = {
                    "name": key.id,
                    "KeyID": key.id,
                }
                if key.key:
                    key_props["Key"] = key.key
                if key.key_type:
                    key_props["KeyType"] = key.key_type
                if key.description:
                    key_props["Description"] = key.description
                if key.creator:
                    key_props["Creator"] = key.creator
                if key.user_id:
                    key_props["UserID"] = key.user_id
                if key.created:
                    key_props["Created"] = key.created
                if key.updated:
                    key_props["Updated"] = key.updated
                if key.expires:
                    key_props["Expires"] = key.expires
                if key.revoked:
                    key_props["Revoked"] = key.revoked
                if key.expiry_seconds is not None:
                    key_props["ExpirySeconds"] = key.expiry_seconds
                if key.scopes:
                    key_props["Scopes"] = key.scopes
                if key.tags:
                    key_props["Tags"] = key.tags
                if key.invalid is not None:
                    key_props["Invalid"] = key.invalid
                if key.capabilities:
                    key_props["Capabilities"] = json.dumps(key.capabilities, sort_keys=True)
                if key.audience:
                    key_props["Audience"] = key.audience
                if key.issuer:
                    key_props["Issuer"] = key.issuer
                if key.subject:
                    key_props["Subject"] = key.subject
                if key.custom_claim_rules:
                    key_props["CustomClaimRules"] = json.dumps(key.custom_claim_rules, sort_keys=True)
                if key.authkey:
                    key_props["AuthKey"] = json.dumps(key.authkey, sort_keys=True)
                if key.apikey:
                    key_props["ApiKey"] = json.dumps(key.apikey, sort_keys=True)
                if key.oauthclient:
                    key_props["OAuthClient"] = json.dumps(key.oauthclient, sort_keys=True)

                kinds = [key_type_kind] if key_type_kind else ["TailnetUnknownKey"]
                key_node = OpenGraphNode(
                    id=self._key_node_id(key),
                    kinds=kinds,
                    properties=OpenGraphProperties(**key_props)
                )
                opengraph.add_node(key_node)

        # Create nodes for each webhook (remote parser only)
        if getattr(self.network, "webhooks", None):
            for webhook in self.network.webhooks:
                wh_props = {
                    "name": webhook.endpoint_id,
                    "EndpointID": webhook.endpoint_id,
                }
                if webhook.endpoint_url:
                    wh_props["EndpointURL"] = webhook.endpoint_url
                if webhook.provider_type:
                    wh_props["ProviderType"] = webhook.provider_type
                if webhook.creator_login_name:
                    wh_props["CreatorLoginName"] = webhook.creator_login_name
                if webhook.created:
                    wh_props["Created"] = webhook.created
                if webhook.last_modified:
                    wh_props["LastModified"] = webhook.last_modified
                if webhook.subscriptions:
                    wh_props["Subscriptions"] = webhook.subscriptions
                if webhook.secret:
                    wh_props["Secret"] = webhook.secret

                wh_node = OpenGraphNode(
                    id=self._webhook_node_id(webhook),
                    kinds=["TailscaleWebhook"],
                    properties=OpenGraphProperties(**wh_props)
                )
                opengraph.add_node(wh_node)

        # Create nodes for each service (remote parser only)
        if getattr(self.network, "services", None):
            for service in self.network.services:
                svc_props = {
                    "name": service.name,
                    "ServiceName": service.name,
                }
                if service.addrs:
                    svc_props["Addrs"] = service.addrs
                if service.comment:
                    svc_props["Comment"] = service.comment
                if service.ports:
                    svc_props["Ports"] = service.ports
                if service.tags:
                    svc_props["Tags"] = service.tags

                svc_node = OpenGraphNode(
                    id=self._service_node_id(service),
                    kinds=["TailscaleService"],
                    properties=OpenGraphProperties(**svc_props)
                )
                opengraph.add_node(svc_node)

        # Create nodes for user invites (remote parser only)
        if getattr(self.network, "user_invites", None):
            for invite in self.network.user_invites:
                props = {
                    "name": invite.id,
                    "InviteID": invite.id,
                }
                if invite.role:
                    props["Role"] = invite.role
                if invite.tailnet_id:
                    props["TailnetID"] = invite.tailnet_id
                if invite.inviter_id:
                    props["InviterID"] = invite.inviter_id
                if invite.email:
                    props["Email"] = invite.email
                if invite.last_email_sent_at:
                    props["LastEmailSentAt"] = invite.last_email_sent_at
                if invite.invite_url:
                    props["InviteURL"] = invite.invite_url

                invite_node = OpenGraphNode(
                    id=self._user_invite_node_id(invite),
                    kinds=["TailscaleUserInvite"],
                    properties=OpenGraphProperties(**props)
                )
                opengraph.add_node(invite_node)

        # Create nodes for device invites (remote parser only)
        if getattr(self.network, "device_invites", None):
            for invite in self.network.device_invites:
                props = {
                    "name": invite.id,
                    "InviteID": invite.id,
                }
                if invite.created:
                    props["Created"] = invite.created
                if invite.tailnet_id:
                    props["TailnetID"] = invite.tailnet_id
                if invite.device_id:
                    props["DeviceID"] = invite.device_id
                if invite.sharer_id:
                    props["SharerID"] = invite.sharer_id
                if invite.multi_use is not None:
                    props["MultiUse"] = invite.multi_use
                if invite.allow_exit_node is not None:
                    props["AllowExitNode"] = invite.allow_exit_node
                if invite.email:
                    props["Email"] = invite.email
                if invite.last_email_sent_at:
                    props["LastEmailSentAt"] = invite.last_email_sent_at
                if invite.invite_url:
                    props["InviteURL"] = invite.invite_url
                if invite.accepted is not None:
                    props["Accepted"] = invite.accepted
                if invite.accepted_by:
                    props["AcceptedBy"] = json.dumps(invite.accepted_by, sort_keys=True)

                invite_node = OpenGraphNode(
                    id=self._device_invite_node_id(invite),
                    kinds=["TailscaleDeviceInvite"],
                    properties=OpenGraphProperties(**props)
                )
                opengraph.add_node(invite_node)

        added_node_ids = set()

        # Add self node if it exists
        if self.network.self_node:
            node_id = self._device_node_id(self.network.self_node)
            if node_id and node_id in added_node_ids:
                self.logger.debug(f"Skipping duplicate self node with id: {node_id}")
            else:
                self._add_node_to_opengraph(opengraph, self.network.self_node, is_self=True)
                if node_id:
                    added_node_ids.add(node_id)

        # Add all peer nodes, skipping duplicates
        for peer in self.network.peers:
            node_id = self._device_node_id(peer)
            if node_id and node_id in added_node_ids:
                self.logger.debug(f"Skipping duplicate peer node with id: {node_id}")
                continue
            self._add_node_to_opengraph(opengraph, peer, is_self=False)
            if node_id:
                added_node_ids.add(node_id)
        
        self.build_edges(opengraph)

        node_count = opengraph.get_node_count()
        edge_count = opengraph.get_edge_count()
        self.logger.info(f"Generated OpenGraph with {node_count} nodes and {edge_count} edges")
        export_dict = apply_bloodhound_names(opengraph.export_to_dict())
        if not source_kind:
            export_dict.pop("metadata", None)
        return export_dict
    
    def _add_node_to_opengraph(self, opengraph: OpenGraph, node: Node, is_self: bool):
        """
        Add a Tailscale node to the OpenGraph structure
        
        Args:
            opengraph: The OpenGraph instance to add to
            node: The Node object to add
            is_self: Whether this is the self node
        """
        # Create the node kinds
        kinds = ["TailscaleExternalDevice"] if node.is_external else ["TailscaleDevice"]
        
        # Build properties
        properties = {
            "name": node.hostname,
            "HostName": node.hostname,
            "DNSName": node.dns_name,
            "OS": node.os,
            "Online": node.online,
            "PrimaryIP": node.primary_ip or "",
            "TailscaleIPs": node.tailscale_ips,
            "ExitNode": node.exit_node,
            "ExitNodeOption": node.exit_node_option,
        }
        if node.device_id:
            properties["DeviceID"] = node.device_id
        if is_self:
            properties["SelfNode"] = True
        
        # Add optional properties if they exist
        if node.created:
            properties["Created"] = node.created
        if node.last_seen:
            properties["LastSeen"] = node.last_seen
        if node.last_write:
            properties["LastWrite"] = node.last_write
        if node.last_handshake:
            properties["LastHandshake"] = node.last_handshake
        if node.key_expiry:
            properties["KeyExpiry"] = node.key_expiry
        if node.fqdn:
            properties["FQDN"] = node.fqdn
        if node.stable_id:
            properties["StableID"] = node.stable_id
        if node.machine_name:
            properties["MachineName"] = node.machine_name
        if node.os_version:
            properties["OSVersion"] = node.os_version
        if node.parsed_os_version:
            properties["ParsedOSVersion"] = node.parsed_os_version
        if node.ipn_version:
            properties["IPNVersion"] = node.ipn_version
        if node.creator:
            properties["Creator"] = node.creator
        if node.domain:
            properties["Domain"] = node.domain
        if node.available_update_version:
            properties["AvailableUpdateVersion"] = node.available_update_version
        if node.automatic_name_mode is not None:
            properties["AutomaticNameMode"] = node.automatic_name_mode
        if node.auto_updates_enabled is not None:
            properties["AutoUpdatesEnabled"] = node.auto_updates_enabled
        if node.can_nat is not None:
            properties["CanNat"] = node.can_nat
        if node.endpoints:
            properties["Endpoints"] = node.endpoints
        if node.extra_ips:
            properties["ExtraIPs"] = node.extra_ips
        if node.allowed_tags:
            properties["AllowedTags"] = node.allowed_tags
        if node.invalid_tags:
            properties["InvalidTags"] = node.invalid_tags
        if node.advertised_ips:
            properties["AdvertisedIPs"] = node.advertised_ips
        if node.allowed_ips:
            properties["AllowedIPs"] = node.allowed_ips
        if node.accepted_share_count is not None:
            properties["AcceptedShareCount"] = node.accepted_share_count
        if node.share_id:
            properties["ShareID"] = node.share_id
        if node.has_exit_node is not None:
            properties["HasExitNode"] = node.has_exit_node
        if node.advertised_exit_node is not None:
            properties["AdvertisedExitNode"] = node.advertised_exit_node
        if node.allowed_exit_node is not None:
            properties["AllowedExitNode"] = node.allowed_exit_node
        if node.has_subnets is not None:
            properties["HasSubnets"] = node.has_subnets
        if node.ssh_usernames:
            properties["SSHUsernames"] = node.ssh_usernames
        if node.other_ssh_usernames_allowed is not None:
            properties["OtherSSHUsernamesAllowed"] = node.other_ssh_usernames_allowed
        if node.funnel_enabled is not None:
            properties["FunnelEnabled"] = node.funnel_enabled
        if node.never_expires is not None:
            properties["NeverExpires"] = node.never_expires
        if node.router is not None:
            properties["Router"] = node.router
        if node.key_expiry_disabled is not None:
            properties["KeyExpiryDisabled"] = node.key_expiry_disabled
        if node.authorized is not None:
            properties["Authorized"] = node.authorized
        if node.is_external is not None:
            properties["IsExternal"] = node.is_external
        if node.blocks_incoming_connections is not None:
            properties["BlocksIncomingConnections"] = node.blocks_incoming_connections
        if node.multiple_connections is not None:
            properties["MultipleConnections"] = node.multiple_connections
        if node.machine_key:
            properties["MachineKey"] = node.machine_key
        if node.tailnet_lock_error:
            properties["TailnetLockError"] = node.tailnet_lock_error
        if node.tailnet_lock_key:
            properties["TailnetLockKey"] = node.tailnet_lock_key
        if node.ssh_enabled is not None:
            properties["SshEnabled"] = node.ssh_enabled
        if node.is_ephemeral is not None:
            properties["IsEphemeral"] = node.is_ephemeral
        if node.client_version:
            properties["ClientVersion"] = node.client_version
        if node.update_available is not None:
            properties["UpdateAvailable"] = node.update_available
        if node.connected_to_control is not None:
            properties["ConnectedToControl"] = node.connected_to_control
        if node.distro_name:
            properties["DistroName"] = node.distro_name
        if node.distro_version:
            properties["DistroVersion"] = node.distro_version
        if node.distro_code_name:
            properties["DistroCodeName"] = node.distro_code_name
        if node.client_connectivity_latency:
            properties["ClientConnectivityLatency"] = json.dumps(
                node.client_connectivity_latency, sort_keys=True
            )
        if node.client_connectivity_supports:
            properties["ClientConnectivitySupports"] = json.dumps(
                node.client_connectivity_supports, sort_keys=True
            )
        if node.posture_attributes:
            properties["PostureAttributes"] = json.dumps(
                node.posture_attributes, sort_keys=True
            )
        if node.posture_expiries:
            properties["PostureAttributeExpiries"] = json.dumps(
                node.posture_expiries, sort_keys=True
            )
        if node.relay:
            properties["Relay"] = node.relay
        if node.peer_relay:
            properties["PeerRelay"] = node.peer_relay
        if node.tags:
            properties["Tags"] = node.tags
        if node.addrs:
            properties["Addrs"] = node.addrs
        if node.primary_routes:
            properties["PrimaryRoutes"] = node.primary_routes
        if node.advertised_routes:
            properties["AdvertisedRoutes"] = node.advertised_routes
        if node.enabled_routes:
            properties["EnabledRoutes"] = node.enabled_routes
        if node.capabilities:
            properties["Capabilities"] = node.capabilities
        if node.cap_map:
            properties["CapMap"] = json.dumps(node.cap_map, sort_keys=True)
        
        properties["Active"] = node.active
        properties["InNetworkMap"] = node.in_network_map
        properties["InMagicSock"] = node.in_magic_sock
        properties["InEngine"] = node.in_engine
        properties["RxBytes"] = node.rx_bytes
        properties["TxBytes"] = node.tx_bytes
        
        graph_node = OpenGraphNode(
            id=self._device_node_id(node),
            kinds=kinds,
            properties=OpenGraphProperties(**properties)
        )
        
        opengraph.add_node(graph_node)
        # Edges are added separately in build_edges().

    def _add_acl_nodes(self, opengraph: OpenGraph):
        policy = getattr(self.network, "acl_policy", None)
        if not isinstance(policy, dict):
            policy = {}

        groups = policy.get("groups", {}) or {}
        tag_owners = policy.get("tagOwners", {}) or {}
        grants = policy.get("grants", []) or []
        acls = policy.get("acls", []) or []
        ssh_rules = policy.get("ssh", []) or []
        ssh_tests = policy.get("sshTests", []) or []
        default_src_posture = policy.get("defaultSrcPosture", []) or []
        postures = policy.get("postures", {}) or {}
        node_attrs = policy.get("nodeAttrs", []) or []
        hosts = policy.get("hosts", {}) or {}
        tests = policy.get("tests", []) or []
        auto_approvers = policy.get("autoApprovers", {}) or {}
        app_connectors = self._combined_app_connectors(policy)

        group_names = set(groups.keys())
        tag_names = set(tag_owners.keys())
        tag_names.update(self._local_status_tags())
        autogroups = set()
        cidrs = set()
        port_specs = set()
        wildcards = set()
        ssh_users = set()
        attr_values = set()
        posture_names = set()
        ipset_names = set()

        if isinstance(postures, dict):
            posture_names.update(
                [p for p in postures.keys() if isinstance(p, str) and p.strip()]
            )
        if isinstance(default_src_posture, list):
            for posture in default_src_posture:
                if isinstance(posture, str) and posture.strip():
                    posture_names.add(posture.strip())

        def scan_values(values, allow_ports: bool = True):
            for val in values or []:
                if not isinstance(val, str):
                    continue
                if val.startswith("ipset:"):
                    ipset_names.add(val)
                    continue
                if val == "*":
                    wildcards.add(val)
                elif val.startswith("autogroup:"):
                    autogroups.add(val)
                elif val.startswith("group:"):
                    group_names.add(val)
                elif val.startswith("tag:"):
                    tag_names.add(val)
                elif "@" in val:
                    # User or domain-based autogroups; skip port parsing.
                    continue
                elif "/" in val:
                    cidrs.add(val)
                elif allow_ports and ":" in val:
                    port_specs.add(val)

        # Include tags referenced by tailnet keys (auth/API/OAuth/federated).
        if getattr(self.network, "keys", None):
            for key in self.network.keys:
                for tag in key.tags or []:
                    if isinstance(tag, str) and tag.strip():
                        tag_names.add(tag.strip())
        # Include tags referenced by tailnet services.
        if getattr(self.network, "services", None):
            for service in self.network.services:
                for tag in service.tags or []:
                    if isinstance(tag, str) and tag.strip():
                        tag_names.add(tag.strip())

        ipsets = policy.get("ipsets") or policy.get("ipSets") or {}
        if isinstance(ipsets, dict):
            for name in ipsets.keys():
                if not isinstance(name, str) or not name.strip():
                    continue
                if name.startswith("ipset:"):
                    ipset_names.add(name)
                else:
                    ipset_names.add(f"ipset:{name.strip()}")

        def split_acl_dst(value: str) -> tuple[Optional[str], List[str]]:
            if not isinstance(value, str):
                return None, []
            raw = value.strip()
            if not raw:
                return None, []
            host = raw
            ports_part = None

            if raw.startswith("["):
                end = raw.find("]")
                if end != -1:
                    host = raw[1:end]
                    remainder = raw[end + 1 :]
                    if remainder.startswith(":"):
                        ports_part = remainder[1:]
                return host, [p.strip() for p in (ports_part or "").split(",") if p.strip()]

            if ":" in raw:
                host, ports_part = raw.rsplit(":", 1)
            ports = []
            if ports_part:
                ports = [p.strip() for p in ports_part.split(",") if p.strip()]
            return host, ports

        for owners in tag_owners.values():
            scan_values(owners)

        for grant in grants:
            if not isinstance(grant, dict):
                continue
            scan_values(grant.get("src"))
            scan_values(grant.get("dst"))
            scan_values(grant.get("ip"))
            for ip_val in grant.get("ip") or []:
                if isinstance(ip_val, str) and ip_val.strip() == "*":
                    port_specs.add("*")
            scan_values(grant.get("via"))
            for posture in grant.get("srcPosture") or []:
                if isinstance(posture, str) and posture.strip():
                    posture_names.add(posture.strip())

        for rule in acls:
            if not isinstance(rule, dict):
                continue
            scan_values(rule.get("src"))
            scan_values(rule.get("users"))
            for posture in rule.get("srcPosture") or []:
                if isinstance(posture, str) and posture.strip():
                    posture_names.add(posture.strip())
            for dst in (rule.get("dst") or []):
                host, ports = split_acl_dst(dst)
                if host:
                    scan_values([host], allow_ports=False)
                for port in ports:
                    port_specs.add(port)
            for dst in (rule.get("ports") or []):
                host, ports = split_acl_dst(dst)
                if host:
                    scan_values([host], allow_ports=False)
                for port in ports:
                    port_specs.add(port)

        for rule in ssh_rules:
            if not isinstance(rule, dict):
                continue
            scan_values(rule.get("src"))
            scan_values(rule.get("dst"))
            for user_val in rule.get("users") or []:
                if not isinstance(user_val, str):
                    continue
                ssh_users.add(user_val)

        for test in ssh_tests:
            if not isinstance(test, dict):
                continue
            for key in ("accept", "check", "deny"):
                values = test.get(key) or []
                for user_val in values:
                    if isinstance(user_val, str):
                        ssh_users.add(user_val)

        for test in tests:
            if not isinstance(test, dict):
                continue
            src = test.get("src")
            if isinstance(src, str):
                scan_values([src])
            for key in ("accept", "deny"):
                values = test.get(key) or []
                if not isinstance(values, list):
                    continue
                for value in values:
                    if not isinstance(value, str):
                        continue
                    host, ports = split_acl_dst(value)
                    if host:
                        scan_values([host], allow_ports=False)
                    for port in ports:
                        if port:
                            port_specs.add(port)

        for na in node_attrs:
            if not isinstance(na, dict):
                continue
            scan_values(na.get("target"))
            for attr in na.get("attr") or []:
                if isinstance(attr, str):
                    attr_values.add(attr)

        if isinstance(auto_approvers, dict):
            exit_approvers = auto_approvers.get("exitNode") or []
            if isinstance(exit_approvers, list):
                scan_values(exit_approvers)
            routes = auto_approvers.get("routes") or {}
            if isinstance(routes, dict):
                for route, approvers in routes.items():
                    if isinstance(route, str) and route.strip():
                        scan_values([route], allow_ports=False)
                    if isinstance(approvers, list):
                        scan_values(approvers)

        # Groups
        for group in sorted(group_names):
            props = {
                "name": group,
                "GroupName": group,
            }
            members = groups.get(group)
            if isinstance(members, list):
                props["Members"] = members
            node = OpenGraphNode(
                id=self._acl_node_id("group", group),
                kinds=["TailscaleGroup"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Tags
        for tag in sorted(tag_names):
            props = {
                "name": tag,
                "TagName": tag,
            }
            owners = tag_owners.get(tag)
            if isinstance(owners, list):
                props["Owners"] = owners
            node = OpenGraphNode(
                id=self._acl_node_id("tag", tag),
                kinds=["TailscaleTag"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Autogroups
        for ag in sorted(autogroups):
            props = {
                "name": ag,
                "AutoGroup": ag,
            }
            node = OpenGraphNode(
                id=self._acl_node_id("autogroup", ag),
                kinds=["TailscaleAutoGroup"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # CIDRs
        for cidr in sorted(cidrs):
            props = {
                "name": cidr,
                "CIDR": cidr,
            }
            node = OpenGraphNode(
                id=self._acl_node_id("cidr", cidr),
                kinds=["TailscaleCidr"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Port specs
        for spec in sorted(port_specs):
            props = {
                "name": spec,
                "PortSpec": spec,
            }
            node = OpenGraphNode(
                id=self._acl_node_id("port", spec),
                kinds=["TailscalePortSpec"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Wildcards
        for wc in sorted(wildcards):
            props = {
                "name": wc,
                "Wildcard": wc,
            }
            node = OpenGraphNode(
                id=self._acl_node_id("wildcard", wc),
                kinds=["TailscaleWildcard"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # SSH users
        for ssh_user in sorted(ssh_users):
            props = {
                "name": ssh_user,
                "SshUser": ssh_user,
            }
            node = OpenGraphNode(
                id=self._acl_node_id("sshuser", ssh_user),
                kinds=["TailscaleSSHUser"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Attribute values
        for attr in sorted(attr_values):
            props = {
                "name": attr,
                "Attr": attr,
            }
            node = OpenGraphNode(
                id=self._acl_node_id("attr", attr),
                kinds=["TailscaleAttr"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # IPSets
        for ipset in sorted(ipset_names):
            props = {
                "name": ipset,
                "IPSetName": ipset,
            }
            routes = None
            if isinstance(ipsets, dict):
                routes = ipsets.get(ipset) or ipsets.get(ipset.split(":", 1)[1])
            if isinstance(routes, list):
                props["Routes"] = [r for r in routes if isinstance(r, str)]
            node = OpenGraphNode(
                id=self._acl_node_id("ipset", ipset),
                kinds=["TailscaleIPSet"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Postures
        for posture in sorted(posture_names):
            props = {
                "name": posture,
                "PostureName": posture,
            }
            if isinstance(postures, dict):
                expressions = postures.get(posture)
                if isinstance(expressions, list):
                    props["Expressions"] = expressions
            node = OpenGraphNode(
                id=self._acl_node_id("posture", posture),
                kinds=["TailscalePosture"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Default source posture
        if isinstance(default_src_posture, list) and default_src_posture:
            props = {
                "name": "defaultSrcPosture",
                "DefaultSrcPosture": [
                    p for p in default_src_posture if isinstance(p, str) and p.strip()
                ],
            }
            node = OpenGraphNode(
                id=self._acl_node_id("defaultsrcposture", "default"),
                kinds=["TailscaleDefaultSrcPosture"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        if isinstance(auto_approvers, dict):
            exit_approvers = auto_approvers.get("exitNode") or []
            if isinstance(exit_approvers, list) and exit_approvers:
                props = {
                    "name": "autoApproverExitNode",
                    "AutoApproverType": "exitNode",
                    "Approvers": [a for a in exit_approvers if isinstance(a, str)],
                }
                node = OpenGraphNode(
                    id=self._acl_node_id("autoapprover", "exitnode"),
                    kinds=["TailscaleAutoApproverExitNode"],
                    properties=OpenGraphProperties(**props),
                )
                opengraph.add_node(node)
            routes = auto_approvers.get("routes") or {}
            if isinstance(routes, dict):
                for route, approvers in routes.items():
                    if not isinstance(route, str) or not route.strip():
                        continue
                    route_value = route.strip()
                    props = {
                        "name": f"autoApproverRoute_{route_value}",
                        "AutoApproverType": "route",
                        "Route": route_value,
                    }
                    if isinstance(approvers, list):
                        props["Approvers"] = [a for a in approvers if isinstance(a, str)]
                    node = OpenGraphNode(
                        id=self._acl_node_id("autoapproverroute", route_value),
                        kinds=["TailscaleAutoApproverRoute"],
                        properties=OpenGraphProperties(**props),
                    )
                    opengraph.add_node(node)

        # Host aliases
        if isinstance(hosts, dict):
            for alias, target in hosts.items():
                if not isinstance(alias, str) or not alias.strip():
                    continue
                alias = alias.strip()
                props = {
                    "name": alias,
                    "HostAlias": alias,
                }
                if isinstance(target, list):
                    props["Targets"] = [t for t in target if isinstance(t, str)]
                elif isinstance(target, str):
                    props["Targets"] = [target]
                else:
                    props["Targets"] = []
                node = OpenGraphNode(
                    id=self._acl_node_id("hostalias", alias),
                    kinds=["TailscaleHostAlias"],
                    properties=OpenGraphProperties(**props),
                )
                opengraph.add_node(node)

        # ACL tests
        if isinstance(tests, list):
            for idx, test in enumerate(tests, start=1):
                if not isinstance(test, dict):
                    continue
                props = {"name": f"test_{idx}", "Index": idx}
                if isinstance(test.get("src"), str):
                    props["Src"] = test.get("src")
                if isinstance(test.get("accept"), list):
                    props["Accept"] = test.get("accept")
                if isinstance(test.get("deny"), list):
                    props["Deny"] = test.get("deny")
                if test.get("proto"):
                    props["Proto"] = test.get("proto")
                if isinstance(test.get("srcPostureAttrs"), dict):
                    props["SrcPostureAttrs"] = test.get("srcPostureAttrs")
                node = OpenGraphNode(
                    id=self._acl_rule_node_id("test", idx),
                    kinds=["TailscaleACLTest"],
                    properties=OpenGraphProperties(**props),
                )
                opengraph.add_node(node)

        # SSH tests
        if isinstance(ssh_tests, list):
            for idx, test in enumerate(ssh_tests, start=1):
                if not isinstance(test, dict):
                    continue
                props = {"name": f"ssh_test_{idx}", "Index": idx}
                if isinstance(test.get("src"), str):
                    props["Src"] = test.get("src")
                if isinstance(test.get("dst"), list):
                    props["Dst"] = test.get("dst")
                if isinstance(test.get("accept"), list):
                    props["Accept"] = test.get("accept")
                if isinstance(test.get("check"), list):
                    props["Check"] = test.get("check")
                if isinstance(test.get("deny"), list):
                    props["Deny"] = test.get("deny")
                if isinstance(test.get("srcPostureAttrs"), dict):
                    props["SrcPostureAttrs"] = test.get("srcPostureAttrs")
                node = OpenGraphNode(
                    id=self._acl_rule_node_id("sshtest", idx),
                    kinds=["TailscaleSSHTest"],
                    properties=OpenGraphProperties(**props),
                )
                opengraph.add_node(node)

        # App connectors
        for app_connector in app_connectors:
            entry = app_connector.get("entry") or {}
            name = app_connector.get("name") or f"app-connector-{app_connector.get('index')}"
            props = {
                "name": name,
                "AppConnectorName": name,
            }
            if isinstance(entry, dict):
                for key, value in entry.items():
                    props[key] = value
            node = OpenGraphNode(
                id=app_connector["node_id"],
                kinds=["TailscaleAppConnector"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Grants
        for idx, grant in enumerate(grants, start=1):
            if not isinstance(grant, dict):
                continue
            props = {"name": f"grant_{idx}", "Index": idx}
            if isinstance(grant.get("src"), list):
                props["Src"] = grant.get("src")
            if isinstance(grant.get("dst"), list):
                props["Dst"] = grant.get("dst")
            if isinstance(grant.get("ip"), list):
                props["IP"] = grant.get("ip")
            if isinstance(grant.get("via"), list):
                props["Via"] = grant.get("via")
            if isinstance(grant.get("srcPosture"), list):
                props["SrcPosture"] = grant.get("srcPosture")
            node = OpenGraphNode(
                id=self._acl_rule_node_id("grant", idx),
                kinds=["TailscaleGrant"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # ACLs
        for idx, rule in enumerate(acls, start=1):
            if not isinstance(rule, dict):
                continue
            props = {"name": f"acl_{idx}", "Index": idx}
            if rule.get("action"):
                props["Action"] = rule.get("action")
            if rule.get("proto"):
                props["Proto"] = rule.get("proto")
            if isinstance(rule.get("src"), list):
                props["Src"] = rule.get("src")
            if isinstance(rule.get("dst"), list):
                props["Dst"] = rule.get("dst")
            if isinstance(rule.get("users"), list):
                props["Users"] = rule.get("users")
            if isinstance(rule.get("ports"), list):
                props["Ports"] = rule.get("ports")
            if isinstance(rule.get("srcPosture"), list):
                props["SrcPosture"] = rule.get("srcPosture")
            node = OpenGraphNode(
                id=self._acl_rule_node_id("acl", idx),
                kinds=["TailscaleACL"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # SSH rules
        for idx, rule in enumerate(ssh_rules, start=1):
            if not isinstance(rule, dict):
                continue
            props = {"name": f"ssh_{idx}", "Index": idx}
            if rule.get("action"):
                props["Action"] = rule.get("action")
            if isinstance(rule.get("src"), list):
                props["Src"] = rule.get("src")
            if isinstance(rule.get("dst"), list):
                props["Dst"] = rule.get("dst")
            if isinstance(rule.get("users"), list):
                props["Users"] = rule.get("users")
            node = OpenGraphNode(
                id=self._acl_rule_node_id("ssh", idx),
                kinds=["TailscaleSSHRule"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

        # Node attribute rules
        for idx, rule in enumerate(node_attrs, start=1):
            if not isinstance(rule, dict):
                continue
            props = {"name": f"nodeattr_{idx}", "Index": idx}
            if isinstance(rule.get("target"), list):
                props["Target"] = rule.get("target")
            if isinstance(rule.get("attr"), list):
                props["Attr"] = rule.get("attr")
            node = OpenGraphNode(
                id=self._acl_rule_node_id("nodeattr", idx),
                kinds=["TailscaleNodeAttr"],
                properties=OpenGraphProperties(**props),
            )
            opengraph.add_node(node)

    def _resolve_acl_ref(self, value: str) -> Optional[str]:
        if not isinstance(value, str):
            return None
        if value == "*":
            return self._acl_node_id("wildcard", value)
        if value.startswith("ipset:"):
            return self._acl_node_id("ipset", value)
        if value.startswith("group:"):
            return self._acl_node_id("group", value)
        if value.startswith("tag:"):
            return self._acl_node_id("tag", value)
        if value.startswith("autogroup:"):
            return self._acl_node_id("autogroup", value)
        if "@" in value:
            user = self.network.get_user_by_id(value)
            if self._is_graph_user(user):
                return self._user_node_id(user)
            return None
        if "/" in value:
            return self._acl_node_id("cidr", value)
        if ":" in value:
            return self._acl_node_id("port", value)
        return None

    def _resolve_acl_attr(self, value: str) -> Optional[str]:
        if not isinstance(value, str):
            return None
        return self._acl_node_id("attr", value)

    def _resolve_acl_ssh_user(self, value: str) -> Optional[str]:
        if not isinstance(value, str):
            return None
        return self._acl_node_id("sshuser", value)

    def _add_edge(
        self,
        opengraph: OpenGraph,
        seen_edges: set,
        start_node_id: str,
        end_node_id: str,
        kind: str,
        description: str,
        properties: Optional[OpenGraphProperties] = None,
    ) -> bool:
        edge_key = (start_node_id, end_node_id, kind)
        if edge_key in seen_edges:
            return False
        seen_edges.add(edge_key)
        self.logger.debug(f"Creating {bloodhound_kind(kind)} edge: {description}")
        opengraph.add_edge(
            OpenGraphEdge(
                start_node=start_node_id,
                end_node=end_node_id,
                kind=kind,
                properties=properties,
            )
        )
        return True

    def _add_acl_edges(self, opengraph: OpenGraph, seen_edges: set):
        policy = getattr(self.network, "acl_policy", None)
        if not isinstance(policy, dict) or not policy:
            return

        groups = policy.get("groups", {}) or {}
        tag_owners = policy.get("tagOwners", {}) or {}
        grants = policy.get("grants", []) or []
        acls = policy.get("acls", []) or []
        ssh_rules = policy.get("ssh", []) or []
        tests = policy.get("tests", []) or []
        ssh_tests = policy.get("sshTests", []) or []
        node_attrs = policy.get("nodeAttrs", []) or []
        hosts = policy.get("hosts", {}) or {}
        default_src_posture = policy.get("defaultSrcPosture", []) or []
        postures = policy.get("postures", {}) or {}
        ipsets = policy.get("ipsets") or policy.get("ipSets") or {}
        auto_approvers = policy.get("autoApprovers", {}) or {}
        app_connectors = self._iter_app_connectors(policy)
        app_connectors_by_tag: dict[str, List[dict]] = {}
        if app_connectors:
            for app in app_connectors:
                connectors = app.get("connectors")
                if not isinstance(connectors, list):
                    continue
                for connector in connectors:
                    if not isinstance(connector, str):
                        continue
                    connector = connector.strip()
                    if not connector.startswith("tag:"):
                        continue
                    app_connectors_by_tag.setdefault(connector, []).append(app)

        # Group membership
        for group, members in groups.items():
            if not isinstance(members, list):
                continue
            group_id = self._acl_node_id("group", group)
            for member in members:
                if not isinstance(member, str):
                    continue
                user = self.network.get_user_by_id(member)
                if not self._is_graph_user(user):
                    continue
                self._add_edge(opengraph, seen_edges, 
                    self._user_node_id(user),
                    group_id,
                    "TailscaleIsMemberOf",
                    f"{user.display_name} -> {group}"
                )

        # Tag ownership
        for tag, owners in tag_owners.items():
            if not isinstance(owners, list):
                continue
            tag_id = self._acl_node_id("tag", tag)
            for owner in owners:
                target_id = self._resolve_acl_ref(owner)
                if not target_id:
                    continue
                self._add_edge(opengraph, seen_edges, 
                    tag_id,
                    target_id,
                    "TailscaleOwnedBy",
                    f"{tag} -> {owner}"
                )

        # Default source posture edges
        default_postures = []
        if isinstance(default_src_posture, list):
            default_postures = [
                p for p in default_src_posture if isinstance(p, str) and p.strip()
            ]
        if default_postures:
            default_node_id = self._acl_node_id("defaultsrcposture", "default")
            self._add_edge(
                opengraph,
                seen_edges,
                self._tailnet_node_id(),
                default_node_id,
                "TailscaleHasDefaultSrcPosture",
                "tailnet -> defaultSrcPosture",
            )
            for posture in default_postures:
                self._add_edge(
                    opengraph,
                    seen_edges,
                    default_node_id,
                    self._acl_node_id("posture", posture),
                    "TailscaleDefaultSrcPostureIncludes",
                    f"defaultSrcPosture -> {posture}",
                )

        # Auto approvers (exit nodes + routes)
        if isinstance(auto_approvers, dict):
            exit_approvers = auto_approvers.get("exitNode") or []
            if isinstance(exit_approvers, list) and exit_approvers:
                exit_node_id = self._acl_node_id("autoapprover", "exitnode")
                self._add_edge(
                    opengraph,
                    seen_edges,
                    self._tailnet_node_id(),
                    exit_node_id,
                    "TailscaleHasAutoApproverExitNode",
                    "tailnet -> autoApprover exitNode",
                )
                for approver in exit_approvers:
                    if not isinstance(approver, str):
                        continue
                    approver_id = self._resolve_acl_ref(approver)
                    if not approver_id:
                        continue
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        exit_node_id,
                        approver_id,
                        "TailscaleAutoApproverIncludes",
                        f"autoApprover exitNode -> {approver}",
                    )
            routes = auto_approvers.get("routes") or {}
            if isinstance(routes, dict):
                for route, approvers in routes.items():
                    if not isinstance(route, str) or not route.strip():
                        continue
                    route_value = route.strip()
                    route_node_id = self._acl_node_id("autoapproverroute", route_value)
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._tailnet_node_id(),
                        route_node_id,
                        "TailscaleHasAutoApproverRoute",
                        f"tailnet -> autoApprover route {route_value}",
                    )
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        route_node_id,
                        self._acl_node_id("cidr", route_value),
                        "TailscaleAutoApproverRouteTargets",
                        f"autoApprover route -> {route_value}",
                    )
                    if isinstance(approvers, list):
                        for approver in approvers:
                            if not isinstance(approver, str):
                                continue
                            approver_id = self._resolve_acl_ref(approver)
                            if not approver_id:
                                continue
                            self._add_edge(
                                opengraph,
                                seen_edges,
                                route_node_id,
                                approver_id,
                                "TailscaleAutoApproverIncludes",
                                f"autoApprover route -> {approver}",
                            )

        # Grant rules (nodes only)
        for idx, grant in enumerate(grants, start=1):
            if not isinstance(grant, dict):
                continue
            self._acl_rule_node_id("grant", idx)

        # Posture requirements for grant/ACL rules
        def add_rule_posture_edges(
            rule_kind: str,
            idx: int,
            src_posture: list,
        ) -> None:
            if src_posture:
                for posture in src_posture:
                    if not isinstance(posture, str) or not posture.strip():
                        continue
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._acl_rule_node_id(rule_kind, idx),
                        self._acl_node_id("posture", posture.strip()),
                        "TailscaleRequiresPosture",
                        f"{rule_kind}_{idx} -> {posture.strip()}",
                    )
            elif default_postures:
                self._add_edge(
                    opengraph,
                    seen_edges,
                    self._acl_rule_node_id(rule_kind, idx),
                    self._acl_node_id("defaultsrcposture", "default"),
                    "TailscaleUsesDefaultSrcPosture",
                    f"{rule_kind}_{idx} -> defaultSrcPosture",
                )

        for idx, grant in enumerate(grants, start=1):
            if not isinstance(grant, dict):
                continue
            src_posture = grant.get("srcPosture") or []
            if isinstance(src_posture, list):
                add_rule_posture_edges("grant", idx, src_posture)

        for idx, rule in enumerate(acls, start=1):
            if not isinstance(rule, dict):
                continue
            action = (rule.get("action") or "accept").strip().lower()
            if action not in ("accept", "allow"):
                continue
            src_posture = rule.get("srcPosture") or []
            if isinstance(src_posture, list):
                add_rule_posture_edges("acl", idx, src_posture)

        def split_acl_dst(value: str) -> tuple[Optional[str], List[str]]:
            if not isinstance(value, str):
                return None, []
            raw = value.strip()
            if not raw:
                return None, []
            host = raw
            ports_part = None

            if raw.startswith("["):
                end = raw.find("]")
                if end != -1:
                    host = raw[1:end]
                    remainder = raw[end + 1 :]
                    if remainder.startswith(":"):
                        ports_part = remainder[1:]
                return host, [p.strip() for p in (ports_part or "").split(",") if p.strip()]

            if ":" in raw:
                host, ports_part = raw.rsplit(":", 1)
            ports = []
            if ports_part:
                ports = [p.strip() for p in ports_part.split(",") if p.strip()]
            return host, ports

        # Common resolution helpers for grant/ACL/SSH ACLs + node attributes
        if grants or acls or ssh_rules or node_attrs or hosts or ipsets or tests or ssh_tests:
            all_users = [u for u in self.network.users if self._is_graph_user(u)]
            tailnet_users = [u for u in all_users if not u.is_external]
            all_nodes = [n for n in [self.network.self_node] + self.network.peers if n]
            tailnet_nodes = [n for n in all_nodes if not n.is_external]
            external_nodes = [n for n in all_nodes if n.is_external]
            devices_by_user_id = {}
            for node in all_nodes:
                devices_by_user_id.setdefault(str(node.user_id), []).append(node)
            if not isinstance(ipsets, dict):
                ipsets = {}
            route_node_cache = {}
            all_enabled_routes = set()
            for node in tailnet_nodes:
                if not node:
                    continue
                for route in self._node_route_values(node):
                    if isinstance(route, str) and route.strip():
                        route_value = route.strip()
                        all_enabled_routes.add(route_value)

            def normalize_role(user_role: Optional[str]) -> str:
                if not user_role:
                    return ""
                return user_role.strip().lower().replace("_", "-")

            def has_role(user: User, role_key: str) -> bool:
                role_val = normalize_role(user.role)
                if role_key == "owner":
                    return bool(user.is_owner) or role_val == "owner"
                if role_key == "admin":
                    return bool(user.is_admin) or role_val in ("admin", "owner")
                return role_val == role_key

            def resolve_users_from_ref(ref: str) -> List[User]:
                if not isinstance(ref, str):
                    return []
                ref = ref.strip()
                if not ref:
                    return []
                if ref == "*":
                    return all_users
                if ref.startswith("group:"):
                    members = groups.get(ref, []) or []
                    resolved = []
                    for member in members:
                        user = self.network.get_user_by_id(member)
                        if self._is_graph_user(user):
                            resolved.append(user)
                    return resolved
                if ref.startswith("autogroup:"):
                    if ref == "autogroup:shared":
                        return []
                    if ref == "autogroup:owner":
                        return [u for u in tailnet_users if has_role(u, "owner")]
                    if ref == "autogroup:admin":
                        return [u for u in tailnet_users if has_role(u, "admin")]
                    if ref == "autogroup:it-admin":
                        return [u for u in tailnet_users if has_role(u, "it-admin")]
                    if ref == "autogroup:billing-admin":
                        return [u for u in tailnet_users if has_role(u, "billing-admin")]
                    if ref == "autogroup:network-admin":
                        return [u for u in tailnet_users if has_role(u, "network-admin")]
                    if ref == "autogroup:auditor":
                        return [u for u in tailnet_users if has_role(u, "auditor")]
                    if ref in ("autogroup:member", "autogroup:members"):
                        return tailnet_users
                    return []
                user = self.network.get_user_by_id(ref)
                return [user] if self._is_graph_user(user) else []

            def add_autogroup_membership_edges(ref: str) -> None:
                if not isinstance(ref, str):
                    return
                ref = ref.strip()
                if not ref.startswith("autogroup:"):
                    return
                ref_id = self._resolve_acl_ref(ref)
                if not ref_id:
                    return
                for user in resolve_users_from_ref(ref):
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._user_node_id(user),
                        ref_id,
                        "TailscaleIsMemberOf",
                        f"{user.display_name} -> {ref}",
                    )

            def resolve_devices_from_ref(
                ref: str,
                src_user: Optional[User],
                include_route_matches: bool = True,
            ) -> List[Node]:
                if not isinstance(ref, str):
                    return []
                ref = ref.strip()
                if not ref:
                    return []
                if ref == "*":
                    return tailnet_nodes
                if ref.startswith("tag:"):
                    return [n for n in tailnet_nodes if ref in (n.tags or [])]
                if ref.startswith("group:"):
                    users = resolve_users_from_ref(ref)
                    nodes = []
                    for user in users:
                        nodes.extend(devices_by_user_id.get(str(user.id), []))
                    return nodes
                if ref.startswith("autogroup:"):
                    if ref == "autogroup:self" and src_user:
                        return devices_by_user_id.get(str(src_user.id), [])
                    if ref == "autogroup:shared":
                        return external_nodes
                    if ref == "autogroup:admin":
                        nodes = []
                        for user in tailnet_users:
                            if has_role(user, "admin"):
                                nodes.extend(devices_by_user_id.get(str(user.id), []))
                        return nodes
                    if ref == "autogroup:owner":
                        nodes = []
                        for user in tailnet_users:
                            if has_role(user, "owner"):
                                nodes.extend(devices_by_user_id.get(str(user.id), []))
                        return nodes
                    if ref == "autogroup:it-admin":
                        nodes = []
                        for user in tailnet_users:
                            if has_role(user, "it-admin"):
                                nodes.extend(devices_by_user_id.get(str(user.id), []))
                        return nodes
                    if ref == "autogroup:billing-admin":
                        nodes = []
                        for user in tailnet_users:
                            if has_role(user, "billing-admin"):
                                nodes.extend(devices_by_user_id.get(str(user.id), []))
                        return nodes
                    if ref == "autogroup:network-admin":
                        nodes = []
                        for user in tailnet_users:
                            if has_role(user, "network-admin"):
                                nodes.extend(devices_by_user_id.get(str(user.id), []))
                        return nodes
                    if ref == "autogroup:auditor":
                        nodes = []
                        for user in tailnet_users:
                            if has_role(user, "auditor"):
                                nodes.extend(devices_by_user_id.get(str(user.id), []))
                        return nodes
                    if ref in ("autogroup:member", "autogroup:members"):
                        return tailnet_nodes
                    return []

                # IP or CIDR target
                target_ip = None
                target_net = None
                try:
                    if "/" in ref:
                        target_net = ipaddress.ip_network(ref, strict=False)
                    else:
                        target_ip = ipaddress.ip_address(ref)
                except ValueError:
                    target_ip = None
                    target_net = None

                if target_ip or target_net:
                    matched = []
                    for node in tailnet_nodes:
                        candidates = []
                        candidates.extend(node.tailscale_ips or [])
                        if include_route_matches:
                            candidates.extend(node.allowed_ips or [])
                            candidates.extend(node.primary_routes or [])
                            candidates.extend(node.advertised_routes or [])
                            candidates.extend(node.enabled_routes or [])
                        for value in candidates:
                            if not value:
                                continue
                            try:
                                if "/" in value:
                                    net = ipaddress.ip_network(value, strict=False)
                                else:
                                    ip_val = ipaddress.ip_address(value)
                                    net = ipaddress.ip_network(f"{ip_val}/32" if ip_val.version == 4 else f"{ip_val}/128", strict=False)
                            except ValueError:
                                continue
                            if target_ip and target_ip in net:
                                matched.append(node)
                                break
                            if target_net and net.overlaps(target_net):
                                matched.append(node)
                                break
                    return matched

                user = self.network.get_user_by_id(ref)
                if self._is_graph_user(user):
                    return devices_by_user_id.get(str(user.id), [])
                return []

            def resolve_ipset_routes(value: str) -> List[str]:
                if not isinstance(value, str) or not value.startswith("ipset:"):
                    return []
                key = value.split(":", 1)[1]
                candidates = []
                for name in (value, key):
                    routes = ipsets.get(name)
                    if isinstance(routes, list):
                        candidates.extend([r for r in routes if isinstance(r, str)])
                return candidates

            def ensure_route_node(route_value: str) -> str:
                node_id = route_node_cache.get(route_value)
                if node_id:
                    return node_id
                node_id = self._route_node_id(route_value)
                route_node = OpenGraphNode(
                    id=node_id,
                    kinds=["TailscaleRoute"],
                    properties=OpenGraphProperties(
                        name=route_value,
                        Route=route_value,
                    ),
                )
                opengraph.add_node(route_node)
                route_node_cache[route_value] = node_id
                return node_id

            def resolve_app_connectors_from_target(value: str) -> List[dict]:
                if not isinstance(value, str):
                    return []
                value = value.strip()
                if not value:
                    return []
                if value in ("*", "autogroup:internet"):
                    return app_connectors
                if value.startswith("tag:"):
                    return app_connectors_by_tag.get(value, [])
                return []

            # IPSet -> Route edges
            if isinstance(ipsets, dict):
                for name, routes in ipsets.items():
                    if not isinstance(name, str) or not name.strip():
                        continue
                    ipset_name = name if name.startswith("ipset:") else f"ipset:{name.strip()}"
                    if not isinstance(routes, list):
                        continue
                    for route in routes:
                        if not isinstance(route, str) or not route.strip():
                            continue
                        route_value = route.strip()
                        route_id = ensure_route_node(route_value)
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            self._acl_node_id("ipset", ipset_name),
                            route_id,
                            "TailscaleIPSetIncludesRoute",
                            f"{ipset_name} -> {route_value}",
                        )

            def _parse_route_targets(route_targets: List[str]) -> tuple[bool, list]:
                if not route_targets:
                    return False, []

                if "*" in route_targets:
                    return True, []
                if "autogroup:internet" in route_targets:
                    return True, []

                parsed_targets = []
                for target in route_targets:
                    if not isinstance(target, str):
                        continue
                    target = target.strip()
                    if not target:
                        continue
                    if target.startswith("ipset:"):
                        for ipset_route in resolve_ipset_routes(target):
                            parsed_targets.append(ipset_route)
                        continue
                    parsed_targets.append(target)

                target_nets = []
                for target in parsed_targets:
                    if not isinstance(target, str):
                        continue
                    target = target.strip()
                    if not target:
                        continue
                    if target == "*":
                        return True, []
                    if target == "autogroup:internet":
                        return True, []
                    if "/" in target:
                        try:
                            target_nets.append(ipaddress.ip_network(target, strict=False))
                        except ValueError:
                            continue
                        continue
                    try:
                        ip_val = ipaddress.ip_address(target)
                        target_nets.append(
                            ipaddress.ip_network(
                                f"{ip_val}/32" if ip_val.version == 4 else f"{ip_val}/128",
                                strict=False,
                            )
                        )
                    except ValueError:
                        continue

                return False, target_nets

            def add_rule_route_edges(
                rule_node_id: str,
                route_targets: List[str],
                edge_kind: str,
                props: Optional[OpenGraphProperties],
            ) -> None:
                if not rule_node_id or not route_targets:
                    return
                wildcard, target_nets = _parse_route_targets(route_targets)
                if not wildcard and not target_nets:
                    return

                if wildcard:
                    for route_value in sorted(all_enabled_routes):
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            rule_node_id,
                            ensure_route_node(route_value),
                            edge_kind,
                            f"{rule_node_id} -> {route_value}",
                            props,
                        )
                    return

                for route_value in all_enabled_routes:
                    try:
                        route_net = ipaddress.ip_network(route_value, strict=False)
                    except ValueError:
                        continue
                    if any(route_net.overlaps(net) for net in target_nets):
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            rule_node_id,
                            ensure_route_node(route_value),
                            edge_kind,
                            f"{rule_node_id} -> {route_value}",
                            props,
                        )

            def add_rule_exit_node_edges(
                rule_node_id: str,
                route_targets: List[str],
                edge_kind: str,
                prop_key: Optional[str],
                prop_value: Optional[str],
            ) -> None:
                if not rule_node_id or not route_targets:
                    return
                wildcard, target_nets = _parse_route_targets(route_targets)
                if not wildcard and not target_nets:
                    return

                routes_by_device: dict[str, set[str]] = {}
                device_labels: dict[str, str] = {}
                default_routes = {"0.0.0.0/0", "::/0"}

                def register_route(node: Node, route_value: str) -> None:
                    device_id = self._device_node_id(node)
                    routes_by_device.setdefault(device_id, set()).add(route_value)
                    if device_id not in device_labels:
                        device_labels[device_id] = node.hostname or node.dns_name or device_id

                for node in tailnet_nodes:
                    if not node:
                        continue
                    for route_value in self._node_route_values(node):
                        if not isinstance(route_value, str) or not route_value.strip():
                            continue
                        route_value = route_value.strip()
                        if wildcard:
                            register_route(node, route_value)
                            continue
                        try:
                            route_net = ipaddress.ip_network(route_value, strict=False)
                        except ValueError:
                            continue
                        if any(route_net.overlaps(net) for net in target_nets):
                            register_route(node, route_value)

                for device_id, routes in routes_by_device.items():
                    if not routes:
                        continue
                    if not any(route in default_routes for route in routes):
                        continue
                    props_dict = {
                        "Reference": "https://tailscale.com/kb/1103/exit-nodes",
                        "Routes": sorted(routes),
                    }
                    if prop_key and prop_value:
                        props_dict[prop_key] = prop_value
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        rule_node_id,
                        device_id,
                        edge_kind,
                        f"{rule_node_id} -> {device_labels.get(device_id, device_id)}",
                        OpenGraphProperties(**props_dict),
                    )

            # Host alias -> device edges (resolve IP/CIDR targets)
            if isinstance(hosts, dict):
                for alias, target in hosts.items():
                    if not isinstance(alias, str) or not alias.strip():
                        continue
                    alias = alias.strip()
                    host_node_id = self._acl_node_id("hostalias", alias)
                    targets = []
                    if isinstance(target, list):
                        targets = [t for t in target if isinstance(t, str)]
                    elif isinstance(target, str):
                        targets = [target]
                    for target_value in targets:
                        # Host aliases should resolve to the concrete device/IP target,
                        # not to devices that merely advertise a route covering it.
                        for node in resolve_devices_from_ref(
                            target_value, None, include_route_matches=False
                        ):
                            self._add_edge(
                                opengraph,
                                seen_edges,
                                host_node_id,
                                self._device_node_id(node),
                                "TailscaleHasHostAllias",
                                f"{alias} -> {node.hostname}",
                            )

            # ACL test deny edges
            if isinstance(tests, list):
                for idx, test in enumerate(tests, start=1):
                    if not isinstance(test, dict):
                        continue
                    test_node_id = self._acl_rule_node_id("test", idx)
                    src_user = None
                    if isinstance(test.get("src"), str):
                        src_ref = test.get("src").strip()
                        if src_ref:
                            candidate_user = self.network.get_user_by_id(src_ref)
                            if self._is_graph_user(candidate_user):
                                src_user = candidate_user
                            add_autogroup_membership_edges(src_ref)
                            src_id = self._resolve_acl_ref(src_ref)
                            if src_id:
                                self._add_edge(
                                    opengraph,
                                    seen_edges,
                                    src_id,
                                    test_node_id,
                                    "TailscaleACLTestSource",
                                    f"{src_ref} -> test_{idx}",
                                )
                    deny_values = test.get("deny") or []
                    if not isinstance(deny_values, list) or not deny_values:
                        continue
                    for deny in deny_values:
                        if not isinstance(deny, str):
                            continue
                        host, ports = split_acl_dst(deny)
                        if host:
                            dst_id = self._resolve_acl_ref(host)
                            if dst_id:
                                self._add_edge(
                                    opengraph,
                                    seen_edges,
                                    test_node_id,
                                    dst_id,
                                    "TailscaleACLTestDenies",
                                    f"test_{idx} -> {host}",
                                )
                            for node in resolve_devices_from_ref(
                                host, src_user, include_route_matches=False
                            ):
                                self._add_edge(
                                    opengraph,
                                    seen_edges,
                                    test_node_id,
                                    self._device_node_id(node),
                                    "TailscaleACLTestDeniesDevice",
                                    f"test_{idx} -> {node.hostname}",
                                )
                        for port in ports:
                            if not port:
                                continue
                            port_id = self._acl_node_id("port", port)
                            self._add_edge(
                                opengraph,
                                seen_edges,
                                test_node_id,
                                port_id,
                                "TailscaleACLTestDeniesPort",
                                f"test_{idx} -> {port}",
                            )

            # SSH test deny edges
            if isinstance(ssh_tests, list):
                for idx, test in enumerate(ssh_tests, start=1):
                    if not isinstance(test, dict):
                        continue
                    deny_users = test.get("deny") or []
                    if not isinstance(deny_users, list) or not deny_users:
                        continue
                    test_node_id = self._acl_rule_node_id("sshtest", idx)
                    for deny_user in deny_users:
                        if not isinstance(deny_user, str):
                            continue
                        ssh_user_id = self._resolve_acl_ssh_user(deny_user)
                        if not ssh_user_id:
                            continue
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            test_node_id,
                            ssh_user_id,
                            "TailscaleSSHTestDeniesUser",
                            f"ssh_test_{idx} -> {deny_user}",
                        )

        # Grant allow edges
        for idx, grant in enumerate(grants, start=1):
            if not isinstance(grant, dict):
                continue
            src_refs = grant.get("src") or []
            dst_refs = grant.get("dst") or []
            if not isinstance(src_refs, list) or not isinstance(dst_refs, list):
                continue
            via_refs = grant.get("via") or []
            if isinstance(via_refs, list):
                for via_ref in via_refs:
                    if not isinstance(via_ref, str):
                        continue
                    via_id = self._resolve_acl_ref(via_ref)
                    if not via_id:
                        continue
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._acl_rule_node_id("grant", idx),
                        via_id,
                        "TailscaleGrantVia",
                        f"grant_{idx} -> {via_ref}",
                    )
            grant_ports = set()
            for ip_val in grant.get("ip") or []:
                if not isinstance(ip_val, str):
                    continue
                ip_val = ip_val.strip()
                if not ip_val:
                    continue
                # Treat bare "*" as all ports so device/port access queries can
                # surface wildcard grants as "any port" access on matched devices.
                if ip_val == "*":
                    grant_ports.add(ip_val)
                elif ":" in ip_val and "/" not in ip_val:
                    grant_ports.add(ip_val)
            for port_spec in sorted(grant_ports):
                self._add_edge(
                    opengraph,
                    seen_edges,
                    self._acl_rule_node_id("grant", idx),
                    self._acl_node_id("port", port_spec),
                    "TailscaleGrantUsesPort",
                    f"grant_{idx} -> {port_spec}",
                )
            grant_route_targets = []
            for dst in dst_refs:
                if not isinstance(dst, str):
                    continue
                if dst.strip() == "*":
                    grant_route_targets.append("*")
                elif dst.startswith("ipset:"):
                    grant_route_targets.append(dst)
                elif "/" in dst:
                    grant_route_targets.append(dst)
            for src in src_refs:
                if not isinstance(src, str):
                    continue
                src_id = self._resolve_acl_ref(src)
                if not src_id:
                    continue
                add_autogroup_membership_edges(src)
                self._add_edge(
                    opengraph,
                    seen_edges,
                    src_id,
                    self._acl_rule_node_id("grant", idx),
                    "TailscaleGrantSource",
                    f"{src} -> grant_{idx}",
                )

        # Grant target edges
        if grants:
            for idx, grant in enumerate(grants, start=1):
                if not isinstance(grant, dict):
                    continue
                src_refs = grant.get("src") or []
                dst_refs = grant.get("dst") or []
                if not src_refs or not dst_refs:
                    continue
                grant_route_targets = []
                for dst in dst_refs:
                    if not isinstance(dst, str):
                        continue
                    dst_value = dst.strip()
                    if not dst_value:
                        continue
                    if dst_value == "*":
                        grant_route_targets.append("*")
                        continue
                    if dst_value == "autogroup:internet":
                        grant_route_targets.append("autogroup:internet")
                        continue
                    if dst_value.startswith("ipset:"):
                        grant_route_targets.append(dst_value)
                        continue
                    if "/" in dst_value:
                        grant_route_targets.append(dst_value)
                        continue
                    try:
                        ipaddress.ip_address(dst_value)
                        grant_route_targets.append(dst_value)
                    except ValueError:
                        continue
                if grant_route_targets:
                    add_rule_route_edges(
                        self._acl_rule_node_id("grant", idx),
                        grant_route_targets,
                        "TailscaleGrantTargetsRoute",
                        OpenGraphProperties(Grant=f"grant_{idx}"),
                    )
                    add_rule_exit_node_edges(
                        self._acl_rule_node_id("grant", idx),
                        grant_route_targets,
                        "TailscaleGrantTargetsExitNode",
                        "Grant",
                        f"grant_{idx}",
                    )
                for dst in dst_refs:
                    if not isinstance(dst, str):
                        continue
                    for app in resolve_app_connectors_from_target(dst.strip()):
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            self._acl_rule_node_id("grant", idx),
                            app["node_id"],
                            "TailscaleGrantTargetsAppConnector",
                            f"grant_{idx} -> {app['name']}",
                            OpenGraphProperties(Grant=f"grant_{idx}"),
                        )
                # Grant source -> device edges (src ref -> device)
                for src in src_refs:
                    if not isinstance(src, str):
                        continue
                    src_id = self._resolve_acl_ref(src)
                    if not src_id:
                        continue
                    src_users = resolve_users_from_ref(src)
                    device_targets = {}
                    if src_users:
                        for user in src_users:
                            for dst in dst_refs:
                                for node in resolve_devices_from_ref(dst, user):
                                    device_targets[self._device_node_id(node)] = node
                    else:
                        for dst in dst_refs:
                            for node in resolve_devices_from_ref(dst, None):
                                device_targets[self._device_node_id(node)] = node
                    for node_id, node in device_targets.items():
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            self._acl_rule_node_id("grant", idx),
                            node_id,
                            "TailscaleGrantTargetsDevice",
                            f"grant_{idx} -> {node.hostname}",
                        )

        # ACL allow edges
        for idx, rule in enumerate(acls, start=1):
            if not isinstance(rule, dict):
                continue
            action = (rule.get("action") or "accept").strip().lower()
            if action not in ("accept", "allow"):
                continue
            src_refs: List[str] = []
            for key in ("src", "users"):
                values = rule.get(key)
                if isinstance(values, list):
                    src_refs.extend([v for v in values if isinstance(v, str)])
            dst_refs: List[str] = []
            for key in ("dst", "ports"):
                values = rule.get(key)
                if isinstance(values, list):
                    dst_refs.extend([v for v in values if isinstance(v, str)])
            if not src_refs or not dst_refs:
                continue

            # ACL source -> rule edges
            for src in src_refs:
                src_id = self._resolve_acl_ref(src)
                if not src_id:
                    continue
                add_autogroup_membership_edges(src)
                self._add_edge(
                    opengraph,
                    seen_edges,
                    src_id,
                    self._acl_rule_node_id("acl", idx),
                    "TailscaleAclSource",
                    f"{src} -> acl_{idx}",
                )

            port_specs = set()
            for dst in dst_refs:
                host, ports = split_acl_dst(dst)
                for port in ports:
                    port_specs.add(port)
            for dst in (rule.get("ports") or []):
                host, ports = split_acl_dst(dst)
                for port in ports:
                    port_specs.add(port)
            for port_spec in sorted(port_specs):
                self._add_edge(
                    opengraph,
                    seen_edges,
                    self._acl_rule_node_id("acl", idx),
                    self._acl_node_id("port", port_spec),
                    "TailscaleAclUsesPort",
                    f"acl_{idx} -> {port_spec}",
                )

            acl_route_targets = []
            for dst in dst_refs:
                host, _ports = split_acl_dst(dst)
                if not host:
                    continue
                if (
                    host == "*"
                    or host == "autogroup:internet"
                    or host.startswith("ipset:")
                    or "/" in host
                ):
                    acl_route_targets.append(host)
                    continue
                try:
                    ipaddress.ip_address(host)
                    acl_route_targets.append(host)
                except ValueError:
                    continue
            if acl_route_targets:
                add_rule_route_edges(
                    self._acl_rule_node_id("acl", idx),
                    acl_route_targets,
                    "TailscaleAclTargetsRoute",
                    OpenGraphProperties(Acl=f"acl_{idx}"),
                )
                add_rule_exit_node_edges(
                    self._acl_rule_node_id("acl", idx),
                    acl_route_targets,
                    "TailscaleAclTargetsExitNode",
                    "Acl",
                    f"acl_{idx}",
                )
            for dst in dst_refs:
                host, _ports = split_acl_dst(dst)
                if not host:
                    continue
                for app in resolve_app_connectors_from_target(host):
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._acl_rule_node_id("acl", idx),
                        app["node_id"],
                        "TailscaleAclTargetsAppConnector",
                        f"acl_{idx} -> {app['name']}",
                        OpenGraphProperties(Acl=f"acl_{idx}"),
                    )

        # ACL target device edges
        if acls:
            for idx, rule in enumerate(acls, start=1):
                if not isinstance(rule, dict):
                    continue
                action = (rule.get("action") or "accept").strip().lower()
                if action not in ("accept", "allow"):
                    continue
                src_refs: List[str] = []
                for key in ("src", "users"):
                    values = rule.get(key)
                    if isinstance(values, list):
                        src_refs.extend([v for v in values if isinstance(v, str)])
                dst_refs: List[str] = []
                for key in ("dst", "ports"):
                    values = rule.get(key)
                    if isinstance(values, list):
                        dst_refs.extend([v for v in values if isinstance(v, str)])
                if not src_refs or not dst_refs:
                    continue

                acl_props = OpenGraphProperties(Acl=f"acl_{idx}")
                for src in src_refs:
                    if not isinstance(src, str):
                        continue
                    src_users = resolve_users_from_ref(src)
                    device_targets = {}
                    if src_users:
                        for src_user in src_users:
                            for dst in dst_refs:
                                host, _ports = split_acl_dst(dst)
                                if not host:
                                    continue
                                for node in resolve_devices_from_ref(host, src_user):
                                    device_targets[self._device_node_id(node)] = node
                    else:
                        for dst in dst_refs:
                            host, _ports = split_acl_dst(dst)
                            if not host:
                                continue
                            for node in resolve_devices_from_ref(host, None):
                                device_targets[self._device_node_id(node)] = node
                    for node_id, node in device_targets.items():
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            self._acl_rule_node_id("acl", idx),
                            node_id,
                            "TailscaleAclTargetsDevice",
                            f"acl_{idx} -> {node.hostname}",
                            acl_props,
                        )

        # SSH rules (nodes only)
        for idx, rule in enumerate(ssh_rules, start=1):
            if not isinstance(rule, dict):
                continue
            self._acl_rule_node_id("ssh", idx)

        # Node attribute rules (nodes only)
        for idx, rule in enumerate(node_attrs, start=1):
            if not isinstance(rule, dict):
                continue
            self._acl_rule_node_id("nodeattr", idx)

        # Node attribute effects (funnel)
        if node_attrs:
            for idx, rule in enumerate(node_attrs, start=1):
                if not isinstance(rule, dict):
                    continue
                targets = rule.get("target") or []
                attrs = rule.get("attr") or []
                if not isinstance(targets, list) or not isinstance(attrs, list):
                    continue
                has_funnel = any(
                    isinstance(attr, str) and attr.strip().lower() == "funnel"
                    for attr in attrs
                )
                if not has_funnel:
                    continue
                for target in targets:
                    if not isinstance(target, str):
                        continue
                    target_value = target.strip()
                    edge_kind = "TailscaleHasFunnelCapabilities"
                    if target_value:
                        try:
                            if "/" in target_value:
                                ipaddress.ip_network(target_value, strict=False)
                                edge_kind = "TailscaleHasFunnelEnabled"
                            else:
                                ipaddress.ip_address(target_value)
                                edge_kind = "TailscaleHasFunnelEnabled"
                        except ValueError:
                            edge_kind = "TailscaleHasFunnelCapabilities"
                    for node in resolve_devices_from_ref(target_value, None):
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            self._device_node_id(node),
                            self._tailnet_node_id(),
                            edge_kind,
                            f"{node.hostname} -> tailnet",
                            OpenGraphProperties(
                                Reference="https://tailscale.com/kb/1223/funnel"
                            ),
                        )

        # App connector device edges
        for app_connector in app_connectors:
            connectors = app_connector.get("connectors")
            if not isinstance(connectors, list):
                continue
            for connector in connectors:
                if not isinstance(connector, str):
                    continue
                for node in resolve_devices_from_ref(connector, None):
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        app_connector["node_id"],
                        self._device_node_id(node),
                        "TailscaleAppConnectorRunsOn",
                        f"{app_connector['name']} -> {node.hostname}",
                        OpenGraphProperties(AppConnector=app_connector["name"]),
                    )

        # SSH access edges based on ACL policy
        ## TO DO - BY IP OR CIDR
        if ssh_rules:
            for idx, rule in enumerate(ssh_rules, start=1):
                if not isinstance(rule, dict):
                    continue
                src_refs = rule.get("src") or []
                dst_refs = rule.get("dst") or []
                ssh_user_refs = rule.get("users") or []
                if not src_refs or not dst_refs:
                    continue
                ssh_props_dict = {"SshRule": f"ssh_{idx}"}
                action = rule.get("action")
                if action:
                    ssh_props_dict["SshAction"] = action
                ssh_props = OpenGraphProperties(**ssh_props_dict)
                self_target_id = self._resolve_acl_ref("autogroup:self")
                has_self_target = any(
                    isinstance(dst, str) and dst.strip() == "autogroup:self"
                    for dst in dst_refs
                )
                for src in src_refs:
                    if not isinstance(src, str):
                        continue
                    src_id = self._resolve_acl_ref(src)
                    if not src_id:
                        continue
                    add_autogroup_membership_edges(src)
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        src_id,
                        self._acl_rule_node_id("ssh", idx),
                        "TailscaleSSHRuleSource",
                        f"{src} -> ssh_{idx}",
                    )
                if has_self_target and self_target_id:
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._acl_rule_node_id("ssh", idx),
                        self_target_id,
                        "TailscaleSSHRuleTargetsSelf",
                        f"ssh_{idx} -> autogroup:self",
                        ssh_props,
                    )
                for src in src_refs:
                    if not isinstance(src, str):
                        continue
                    src_users = resolve_users_from_ref(src)
                    device_targets = {}
                    if src_users:
                        for src_user in src_users:
                            for dst in dst_refs:
                                if isinstance(dst, str) and dst.strip() == "autogroup:self":
                                    continue
                                for node in resolve_devices_from_ref(dst, src_user):
                                    device_targets[self._device_node_id(node)] = node
                    else:
                        for dst in dst_refs:
                            if isinstance(dst, str) and dst.strip() == "autogroup:self":
                                continue
                            for node in resolve_devices_from_ref(dst, None):
                                device_targets[self._device_node_id(node)] = node
                    for node_id, node in device_targets.items():
                        self._add_edge(
                            opengraph,
                            seen_edges,
                            self._acl_rule_node_id("ssh", idx),
                            node_id,
                            "TailscaleSSHRuleTargetsDevice",
                            f"ssh_{idx} -> {node.hostname}",
                            ssh_props,
                        )

                for ssh_user in ssh_user_refs:
                    ssh_user_id = self._resolve_acl_ssh_user(ssh_user)
                    if not ssh_user_id:
                        continue
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._acl_rule_node_id("ssh", idx),
                        ssh_user_id,
                        "TailscaleSSHRuleAllowsUser",
                        f"ssh_{idx} -> {ssh_user}",
                        ssh_props,
                    )
    
    def save_opengraph(self, filepath: str, source_kind: Optional[str] = BASE_KIND) -> bool:
        """
        Export OpenGraph JSON file
        
        Args:
            filepath: Path to save the JSON file
            source_kind: Optional source kind for metadata
            
        Returns:
            True if successful, False otherwise
        """
        opengraph = self.export_to_opengraph(source_kind)
        
        if not opengraph:
            return False
        
        try:
            with open(filepath, 'w') as f:
                json.dump(opengraph, f, indent=2)
            
            self.logger.info(f"Saved OpenGraph to: {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving OpenGraph file: {e}")
            return False
        
    def build_edges(self, opengraph: OpenGraph):
        """Create relationships between all discovered nodes"""
        if not self.network:
            self.logger.error("No network data available. Run parse() first.")
            return

        self.logger.info("Building edges between nodes")

        seen_edges = set()

        nodes = self._all_nodes()

        # Tailnet -> IDP edge (admin tailnet settings)
        provider = None
        if isinstance(self.network.tailnet_settings, dict):
            provider = self.network.tailnet_settings.get("provider")
        if isinstance(provider, str) and provider.strip():
            provider = provider.strip()
            self._add_edge(
                opengraph,
                seen_edges,
                self._tailnet_node_id(),
                self._idp_node_id(provider),
                "TailscaleIdentityProvider",
                f"tailnet -> {provider}",
            )

        # External tailnet nodes (from external device FQDNs) and externally
        # scoped tags. External tags are intentionally separate from TS_Tag so
        # tailnet-local ACL policy cannot inherit tags from another tailnet.
        external_tailnets = set()
        external_tags = set()
        for node in nodes:
            if not node or not node.is_external:
                continue
            tailnet = self._external_tailnet_for_node(node)
            if not tailnet:
                continue
            ext_id = self._external_tailnet_node_id(tailnet)
            if ext_id not in external_tailnets:
                opengraph.add_node(
                    OpenGraphNode(
                        id=ext_id,
                        kinds=["TailscaleExternalTailnet"],
                        properties=OpenGraphProperties(
                            name=tailnet,
                            TailnetName=tailnet,
                        ),
                    )
                )
                external_tailnets.add(ext_id)
            self._add_edge(
                opengraph,
                seen_edges,
                self._device_node_id(node),
                ext_id,
                "TailscaleInExternalTailnet",
                f"{node.hostname} -> {tailnet}",
            )
            for tag in node.tags or []:
                if not isinstance(tag, str) or not tag.strip():
                    continue
                tag_value = tag.strip()
                tag_id = self._external_tag_node_id(tailnet, tag_value)
                if tag_id not in external_tags:
                    opengraph.add_node(
                        OpenGraphNode(
                            id=tag_id,
                            kinds=["TailscaleExternalTag"],
                            properties=OpenGraphProperties(
                                name=f"{tag_value} @ {tailnet}",
                                TagName=tag_value,
                                ExternalTailnet=tailnet,
                            ),
                        )
                    )
                    external_tags.add(tag_id)
                self._add_edge(
                    opengraph,
                    seen_edges,
                    self._device_node_id(node),
                    tag_id,
                    "TailscaleHasExternalTag",
                    f"{node.hostname} -> {tag_value} @ {tailnet}",
                )
                self._add_edge(
                    opengraph,
                    seen_edges,
                    tag_id,
                    ext_id,
                    "TailscaleInExternalTailnet",
                    f"{tag_value} -> {tailnet}",
                )

        # Link devices to the user who registered the node. For untagged nodes,
        # Tailscale treats this registering user as the device owner.
        for node in nodes:
            if not node:
                continue
            user = self.network.get_user_by_id(node.user_id)
            if not self._is_graph_user(user):
                continue
            self._add_edge(opengraph, seen_edges, 
                self._user_node_id(user),
                self._device_node_id(node),
                "TailscaleRegisteredDevice",
                f"{user.display_name} -> {node.hostname}"
            )

        # in self create edges for capabilities
        ## if "is-admin" then create isAdminOf edge to tailnet
        self_node = self.network.self_node
        if self_node:
            self_user = self.network.get_user_by_id(self_node.user_id)
            if self._is_graph_user(self_user) and self_node.capabilities:
                caps = [cap.lower() for cap in self_node.capabilities]
                if any("cap/is-admin" in cap for cap in caps):
                    self._add_edge(opengraph, seen_edges, 
                        self._user_node_id(self_user),
                        self._tailnet_node_id(),
                        "TailscaleIsAdminOf",
                        f"{self_user.display_name} -> tailnet",
                        OpenGraphProperties(
                            Reference="https://tailscale.com/kb/1138/user-roles?q=admin+role#admin"
                        )
                    )
                ## if "is-owner" then create isOwnerOf edge to tailnet 
                if any("cap/is-owner" in cap for cap in caps):
                    self._add_edge(opengraph, seen_edges, 
                        self._user_node_id(self_user),
                        self._tailnet_node_id(),
                        "TailscaleIsOwnerOf",
                        f"{self_user.display_name} -> tailnet",
                        OpenGraphProperties(
                            Reference="https://tailscale.com/kb/1138/user-roles?q=admin+role#owner"
                        )
                    )
                if any("funnel" in cap for cap in caps):
                    self._add_edge(opengraph, seen_edges, 
                        self._user_node_id(self_user),
                        self._device_node_id(self_node),
                        "TailscaleHasFunnelCapabilities",
                        f"{self_user.display_name} -> {self_node.hostname}",
                        OpenGraphProperties(
                            Reference="https://tailscale.com/kb/1223/funnel"
                        )
                    )
        # User role edges to tailnet
        role_to_edge = {
            "owner": "TailscaleIsOwnerOf",
            "admin": "TailscaleIsAdminOf",
            "network-admin": "TailscaleIsNetworkAdminOf",
            "it-admin": "TailscaleIsITAdminOf",
            "billing-admin": "TailscaleIsBillingAdminOf",
            "auditor": "TailscaleIsAuditorOf",
            "member": "TailscaleIsMemberOf",
        }
        role_reference = "https://tailscale.com/docs/reference/user-roles#permissions-managed-by-user-roles"
        for user in self.network.users:
            if not self._is_graph_user(user) or not isinstance(user.role, str):
                continue
            role = user.role.strip().lower().replace("_", "-")
            edge_kind = role_to_edge.get(role)
            if not edge_kind:
                continue
            self._add_edge(opengraph, seen_edges, 
                self._user_node_id(user),
                self._tailnet_node_id(),
                edge_kind,
                f"{user.display_name} -> tailnet",
                OpenGraphProperties(Description=role_reference)
            )
        # Device -> Tag edges
        for node in nodes:
            if not node or not node.tags:
                continue
            if node.is_external:
                continue
            for tag in node.tags:
                if not isinstance(tag, str) or not tag.strip():
                    continue
                self._add_edge(
                    opengraph,
                    seen_edges,
                    self._device_node_id(node),
                    self._acl_node_id("tag", tag.strip()),
                    "TailscaleHasTag",
                    f"{node.hostname} -> {tag.strip()}",
                )

        # App connector device edges exposed through ACL policy or local CapMap.
        app_connector_policy = getattr(self.network, "acl_policy", None)
        if not isinstance(app_connector_policy, dict):
            app_connector_policy = {}
        for app_connector in self._combined_app_connectors(app_connector_policy):
            connectors = app_connector.get("connectors")
            if not isinstance(connectors, list):
                continue
            for connector in connectors:
                if not isinstance(connector, str) or not connector.strip():
                    continue
                connector = connector.strip()
                if connector == "*":
                    target_nodes = [node for node in nodes if node and not node.is_external]
                elif connector.startswith("tag:"):
                    target_nodes = [
                        node
                        for node in nodes
                        if node and not node.is_external and connector in (node.tags or [])
                    ]
                else:
                    target_nodes = []
                for node in target_nodes:
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        app_connector["node_id"],
                        self._device_node_id(node),
                        "TailscaleAppConnectorRunsOn",
                        f"{app_connector['name']} -> {node.hostname}",
                        OpenGraphProperties(AppConnector=app_connector["name"]),
                    )

        # Tailnet key -> Tag edges (auth keys with tags, OAuth clients, etc.)
        if getattr(self.network, "keys", None):
            for key in self.network.keys:
                for tag in key.tags or []:
                    if not isinstance(tag, str) or not tag.strip():
                        continue
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._key_node_id(key),
                        self._acl_node_id("tag", tag.strip()),
                        "TailscaleKeyHasTag",
                        f"{key.id} -> {tag.strip()}",
                    )
        # If a peer advertises/permits default routes, create isExitNode edge from user to device.
        for peer in self.network.peers:
            if self._node_advertises_exit_node(peer):
                user = self.network.get_user_by_id(peer.user_id)
                if not self._is_graph_user(user):
                    continue
                self._add_edge(opengraph, seen_edges, 
                    self._user_node_id(user),
                    self._device_node_id(peer),
                    "TailscaleIsExitNode",
                    f"{user.display_name} -> {peer.hostname}",
                    OpenGraphProperties(
                        Reference="https://tailscale.com/kb/1103/exit-nodes"
                    )
                )

        # If funnel is enabled on a device, create device -> tailnet edge
        for node in nodes:
            if not node or not node.funnel_enabled:
                continue
            if node.is_external:
                continue
            self._add_edge(
                opengraph,
                seen_edges,
                self._device_node_id(node),
                self._tailnet_node_id(),
                "TailscaleHasFunnelEnabled",
                f"{node.hostname} -> tailnet",
                OpenGraphProperties(
                    Reference="https://tailscale.com/kb/1223/funnel"
                ),
            )

        # Enabled route nodes + edges
        route_node_ids = set()
        for node in nodes:
            if not node:
                continue
            for route in self._node_route_values(node):
                if not isinstance(route, str) or not route.strip():
                    continue
                route_value = route.strip()
                route_id = self._route_node_id(route_value)
                if route_id not in route_node_ids:
                    route_node = OpenGraphNode(
                        id=route_id,
                        kinds=["TailscaleRoute"],
                        properties=OpenGraphProperties(
                            name=route_value,
                            Route=route_value,
                        ),
                    )
                    opengraph.add_node(route_node)
                    route_node_ids.add(route_id)
                self._add_edge(
                    opengraph,
                    seen_edges,
                    self._device_node_id(node),
                    route_id,
                    "TailscaleEnabledRoute",
                    f"{node.hostname} -> {route_value}",
                )

        # Link tailnet keys to their creator if available
        if getattr(self.network, "keys", None):
            for key in self.network.keys:
                creator_ref = key.user_id or key.creator
                if not creator_ref:
                    continue
                user = self.network.get_user_by_id(creator_ref)
                if not self._is_graph_user(user):
                    continue
                self._add_edge(opengraph, seen_edges, 
                    self._key_node_id(key),
                    self._user_node_id(user),
                    "TailscaleCreatedBy",
                    f"{key.id} -> {user.display_name}"
                )
                # Tailscale api keys do not associate with a user in the API response, so we can't link them. 
                # If that changes in the future we can add this back in:
                # if isinstance(key.key_type, str) and key.key_type.lower() == "api":
                #     self._add_edge(
                #         opengraph,
                #         seen_edges,
                #         self._key_node_id(key),
                #         self._user_node_id(user),
                #         "TailscaleKeyIdentity",
                #         f"{key.id} -> {user.display_name} (api key)",
                #     )

        # Link webhooks to tailnet and creator (if present)
        if getattr(self.network, "webhooks", None):
            for webhook in self.network.webhooks:
                # Tailnet -> webhook
                self._add_edge(opengraph, seen_edges, 
                    self._tailnet_node_id(),
                    self._webhook_node_id(webhook),
                    "TailscaleHasWebhook",
                    f"tailnet -> {webhook.endpoint_id}"
                )

                # Creator -> webhook
                if webhook.creator_login_name:
                    user = self.network.get_user_by_id(webhook.creator_login_name)
                    if self._is_graph_user(user):
                        self._add_edge(opengraph, seen_edges, 
                            self._user_node_id(user),
                            self._webhook_node_id(webhook),
                            "TailscaleCreatedWebhook",
                            f"{user.display_name} -> {webhook.endpoint_id}"
                        )

        # Link services to tailnet
        if getattr(self.network, "services", None):
            for service in self.network.services:
                self._add_edge(opengraph, seen_edges, 
                    self._tailnet_node_id(),
                    self._service_node_id(service),
                    "TailscaleHasService",
                    f"tailnet -> {service.name}"
                )
                # Service -> Tag edges
                for tag in service.tags or []:
                    if not isinstance(tag, str) or not tag.strip():
                        continue
                    tag_value = tag.strip()
                    self._add_edge(
                        opengraph,
                        seen_edges,
                        self._service_node_id(service),
                        self._acl_node_id("tag", tag_value),
                        "TailscaleServiceHasTag",
                        f"{service.name} -> {tag_value}",
                    )
                # Service -> Device edges (match device tags)
                if service.tags:
                    service_tags = {t.strip() for t in service.tags if isinstance(t, str) and t.strip()}
                    if service_tags:
                        for node in nodes:
                            if not node or not node.tags:
                                continue
                            if any(tag in service_tags for tag in node.tags):
                                self._add_edge(
                                    opengraph,
                                    seen_edges,
                                    self._service_node_id(service),
                                    self._device_node_id(node),
                                    "TailscaleServiceRunsOn",
                                    f"{service.name} -> {node.hostname}",
                                )

        # Link user invites to tailnet and inviter/email
        if getattr(self.network, "user_invites", None):
            for invite in self.network.user_invites:
                self._add_edge(opengraph, seen_edges, 
                    self._tailnet_node_id(),
                    self._user_invite_node_id(invite),
                    "TailscaleHasUserInvite",
                    f"tailnet -> user_invite {invite.id}"
                )

                if invite.inviter_id:
                    inviter = self.network.get_user_by_id(invite.inviter_id)
                    if self._is_graph_user(inviter):
                        self._add_edge(opengraph, seen_edges, 
                            self._user_node_id(inviter),
                            self._user_invite_node_id(invite),
                            "TailscaleCreatedInvite",
                            f"{inviter.display_name} -> user_invite {invite.id}"
                        )

        # Link device invites to tailnet, sharer, device, and acceptedBy
        if getattr(self.network, "device_invites", None):
            device_by_id = {}
            for node in [self.network.self_node] + self.network.peers:
                if not node:
                    continue
                device_by_id[str(node.id)] = node
                if node.device_id:
                    device_by_id[str(node.device_id)] = node

            for invite in self.network.device_invites:
                self._add_edge(opengraph, seen_edges, 
                    self._tailnet_node_id(),
                    self._device_invite_node_id(invite),
                    "TailscaleHasDeviceInvite",
                    f"tailnet -> device_invite {invite.id}"
                )

                if invite.sharer_id:
                    sharer = self.network.get_user_by_id(invite.sharer_id)
                    if self._is_graph_user(sharer):
                        self._add_edge(opengraph, seen_edges, 
                            self._user_node_id(sharer),
                            self._device_invite_node_id(invite),
                            "TailscaleUserSentDeviceInvite",
                            f"{sharer.display_name} -> device_invite {invite.id}"
                        )

                if invite.device_id:
                    node = device_by_id.get(str(invite.device_id))
                    if node:
                        self._add_edge(opengraph, seen_edges, 
                            self._device_invite_node_id(invite),
                            self._device_node_id(node),
                            "TailscaleInvitesToDevice",
                            f"device_invite {invite.id} -> {node.hostname}"
                        )

                if invite.accepted_by and isinstance(invite.accepted_by, dict):
                    accepted_login = invite.accepted_by.get("loginName")
                    accepted_id = invite.accepted_by.get("id")
                    accepted_user = None
                    if accepted_id:
                        accepted_user = self.network.get_user_by_id(accepted_id)
                    if not accepted_user and accepted_login:
                        accepted_user = self.network.get_user_by_id(accepted_login)
                    if self._is_graph_user(accepted_user):
                        self._add_edge(opengraph, seen_edges, 
                            self._device_invite_node_id(invite),
                            self._user_node_id(accepted_user),
                            "TailscaleAcceptedBy",
                            f"device_invite {invite.id} -> {accepted_user.display_name}"
                        )

        # ACL edges (group membership, tag ownership, grants, ssh, node attrs)
        self._add_acl_edges(opengraph, seen_edges)
            
