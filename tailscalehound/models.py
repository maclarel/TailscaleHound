"""
Shared data models for TailscaleHound.
Represents users, peers, and network nodes from Tailscale status.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Union


@dataclass
class User:
    """Represents a Tailscale user"""
    id: Union[int, str]
    login_name: str
    display_name: str
    user_id: Optional[Union[int, str]] = None
    stable_id: Optional[str] = None
    profile_pic_url: Optional[str] = None
    role: Optional[str] = None
    is_admin: Optional[bool] = None
    is_owner: Optional[bool] = None
    status: Optional[str] = None
    tailnet_id: Optional[str] = None
    org_tailnet_id: Optional[str] = None
    created: Optional[str] = None
    last_seen: Optional[str] = None
    currently_connected: Optional[bool] = None
    device_count: Optional[int] = None
    user_type: Optional[str] = None
    domain_name: Optional[str] = None
    shared_domain: Optional[bool] = None
    can_edit_billing: Optional[bool] = None
    needs_onboarding: Optional[bool] = None
    use_business_pricing: Optional[bool] = None
    no_longer_provisioned: Optional[bool] = None
    is_external: Optional[bool] = None
    is_system: Optional[bool] = None
    
    def __repr__(self):
        return f"User(id={self.id}, login_name='{self.login_name}', display_name='{self.display_name}')"
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'login_name': self.login_name,
            'display_name': self.display_name,
            'user_id': self.user_id,
            'stable_id': self.stable_id,
            'profile_pic_url': self.profile_pic_url,
            'role': self.role,
            'is_admin': self.is_admin,
            'is_owner': self.is_owner,
            'status': self.status,
            'tailnet_id': self.tailnet_id,
            'org_tailnet_id': self.org_tailnet_id,
            'created': self.created,
            'last_seen': self.last_seen,
            'currently_connected': self.currently_connected,
            'device_count': self.device_count,
            'user_type': self.user_type,
            'domain_name': self.domain_name,
            'shared_domain': self.shared_domain,
            'can_edit_billing': self.can_edit_billing,
            'needs_onboarding': self.needs_onboarding,
            'use_business_pricing': self.use_business_pricing,
            'no_longer_provisioned': self.no_longer_provisioned,
            'is_external': self.is_external,
            'is_system': self.is_system,
        }


@dataclass
class Node:
    """Represents a Tailscale node/peer"""
    id: str
    public_key: str
    hostname: str
    dns_name: str
    os: str
    user_id: Union[int, str]
    tailscale_ips: List[str] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)
    primary_routes: List[str] = field(default_factory=list)
    advertised_routes: List[str] = field(default_factory=list)
    enabled_routes: List[str] = field(default_factory=list)
    online: bool = False
    exit_node: bool = False
    exit_node_option: bool = False
    tags: List[str] = field(default_factory=list)
    created: Optional[str] = None
    last_seen: Optional[str] = None
    last_write: Optional[str] = None
    last_handshake: Optional[str] = None
    key_expiry: Optional[str] = None
    router: Optional[bool] = None
    device_id: Optional[str] = None
    key_expiry_disabled: Optional[bool] = None
    authorized: Optional[bool] = None
    is_external: Optional[bool] = None
    blocks_incoming_connections: Optional[bool] = None
    multiple_connections: Optional[bool] = None
    machine_key: Optional[str] = None
    tailnet_lock_error: Optional[str] = None
    tailnet_lock_key: Optional[str] = None
    ssh_enabled: Optional[bool] = None
    is_ephemeral: Optional[bool] = None
    client_version: Optional[str] = None
    update_available: Optional[bool] = None
    connected_to_control: Optional[bool] = None
    distro_name: Optional[str] = None
    distro_version: Optional[str] = None
    distro_code_name: Optional[str] = None
    client_connectivity_latency: Optional[dict] = None
    client_connectivity_supports: Optional[dict] = None
    posture_attributes: Optional[dict] = None
    posture_expiries: Optional[dict] = None

    # Admin machines (login.tailscale.com/admin/machines) fields
    stable_id: Optional[str] = None
    fqdn: Optional[str] = None
    machine_name: Optional[str] = None
    os_version: Optional[str] = None
    parsed_os_version: Optional[str] = None
    ipn_version: Optional[str] = None
    creator: Optional[str] = None
    domain: Optional[str] = None
    available_update_version: Optional[str] = None
    automatic_name_mode: Optional[bool] = None
    auto_updates_enabled: Optional[bool] = None
    can_nat: Optional[bool] = None
    endpoints: Optional[List[str]] = None
    extra_ips: Optional[List[str]] = None
    allowed_tags: Optional[List[str]] = None
    invalid_tags: Optional[List[str]] = None
    advertised_ips: Optional[List[str]] = None
    accepted_share_count: Optional[int] = None
    share_id: Optional[str] = None
    has_exit_node: Optional[bool] = None
    advertised_exit_node: Optional[bool] = None
    allowed_exit_node: Optional[bool] = None
    has_subnets: Optional[bool] = None
    ssh_usernames: Optional[List[str]] = None
    other_ssh_usernames_allowed: Optional[bool] = None
    funnel_enabled: Optional[bool] = None
    never_expires: Optional[bool] = None
    
    # Optional fields
    addrs: List[str] = field(default_factory=list)
    relay: Optional[str] = None
    peer_relay: Optional[str] = None
    cur_addr: Optional[str] = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    active: bool = False
    ssh_host_keys: List[str] = field(default_factory=list)
    peer_api_url: List[str] = field(default_factory=list)
    taildrop_target: int = 0
    no_file_sharing_reason: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    cap_map: dict = field(default_factory=dict)
    in_network_map: bool = False
    in_magic_sock: bool = False
    in_engine: bool = False
    
    def __repr__(self):
        status = "online" if self.online else "offline"
        return f"Node(hostname='{self.hostname}', os='{self.os}', {status})"
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'device_id': self.device_id,
            'public_key': self.public_key,
            'hostname': self.hostname,
            'dns_name': self.dns_name,
            'os': self.os,
            'user_id': self.user_id,
            'tailscale_ips': self.tailscale_ips,
            'allowed_ips': self.allowed_ips,
            'primary_routes': self.primary_routes,
            'advertised_routes': self.advertised_routes,
            'enabled_routes': self.enabled_routes,
            'online': self.online,
            'exit_node': self.exit_node,
            'exit_node_option': self.exit_node_option,
            'tags': self.tags,
            'created': self.created,
            'last_seen': self.last_seen,
            'last_write': self.last_write,
            'last_handshake': self.last_handshake,
            'key_expiry': self.key_expiry,
            'router': self.router,
            'key_expiry_disabled': self.key_expiry_disabled,
            'authorized': self.authorized,
            'is_external': self.is_external,
            'blocks_incoming_connections': self.blocks_incoming_connections,
            'multiple_connections': self.multiple_connections,
            'machine_key': self.machine_key,
            'tailnet_lock_error': self.tailnet_lock_error,
            'tailnet_lock_key': self.tailnet_lock_key,
            'ssh_enabled': self.ssh_enabled,
            'is_ephemeral': self.is_ephemeral,
            'client_version': self.client_version,
            'update_available': self.update_available,
            'connected_to_control': self.connected_to_control,
            'distro_name': self.distro_name,
            'distro_version': self.distro_version,
            'distro_code_name': self.distro_code_name,
            'client_connectivity_latency': self.client_connectivity_latency,
            'client_connectivity_supports': self.client_connectivity_supports,
            'posture_attributes': self.posture_attributes,
            'posture_expiries': self.posture_expiries,
            'stable_id': self.stable_id,
            'fqdn': self.fqdn,
            'machine_name': self.machine_name,
            'os_version': self.os_version,
            'parsed_os_version': self.parsed_os_version,
            'ipn_version': self.ipn_version,
            'creator': self.creator,
            'domain': self.domain,
            'available_update_version': self.available_update_version,
            'automatic_name_mode': self.automatic_name_mode,
            'auto_updates_enabled': self.auto_updates_enabled,
            'can_nat': self.can_nat,
            'endpoints': self.endpoints,
            'extra_ips': self.extra_ips,
            'allowed_tags': self.allowed_tags,
            'invalid_tags': self.invalid_tags,
            'advertised_ips': self.advertised_ips,
            'accepted_share_count': self.accepted_share_count,
            'share_id': self.share_id,
            'has_exit_node': self.has_exit_node,
            'advertised_exit_node': self.advertised_exit_node,
            'allowed_exit_node': self.allowed_exit_node,
            'has_subnets': self.has_subnets,
            'ssh_usernames': self.ssh_usernames,
            'other_ssh_usernames_allowed': self.other_ssh_usernames_allowed,
            'funnel_enabled': self.funnel_enabled,
            'never_expires': self.never_expires,
            'addrs': self.addrs,
            'relay': self.relay,
            'peer_relay': self.peer_relay,
            'cur_addr': self.cur_addr,
            'rx_bytes': self.rx_bytes,
            'tx_bytes': self.tx_bytes,
            'active': self.active,
            'ssh_host_keys': self.ssh_host_keys,
            'peer_api_url': self.peer_api_url,
            'taildrop_target': self.taildrop_target,
            'no_file_sharing_reason': self.no_file_sharing_reason,
            'capabilities': self.capabilities,
            'cap_map': self.cap_map,
            'in_network_map': self.in_network_map,
            'in_magic_sock': self.in_magic_sock,
            'in_engine': self.in_engine
        }
    
    @property
    def primary_ip(self) -> Optional[str]:
        """Returns the primary IPv4 address if available"""
        for ip in self.tailscale_ips:
            if ':' not in ip:  # IPv4 check (simple)
                return ip
        return self.tailscale_ips[0] if self.tailscale_ips else None


@dataclass
class TailscaleNetwork:
    """Represents the entire Tailscale network status"""
    version: str
    backend_state: str
    self_node: Optional[Node] = None
    users: List[User] = field(default_factory=list)
    peers: List[Node] = field(default_factory=list)
    keys: List["TailnetKey"] = field(default_factory=list)
    magic_dns_suffix: Optional[str] = None
    tailnet_name: Optional[str] = None
    tailnet_id: Optional[str] = None
    tailnet_magic_dns_suffix: Optional[str] = None
    tailnet_magic_dns_enabled: Optional[bool] = None
    tailnet_settings: Optional[dict] = None
    dns_nameservers: List[str] = field(default_factory=list)
    dns_search_paths: List[str] = field(default_factory=list)
    dns_magic_dns: Optional[bool] = None
    dns_split_dns: Optional[dict] = None
    dns_configuration: Optional[dict] = None
    webhooks: List["TailnetWebhook"] = field(default_factory=list)
    logging_configuration: Optional[dict] = None
    logging_network: Optional[dict] = None
    logstream_configuration: Optional[dict] = None
    logstream_status: Optional[dict] = None
    services: List["TailnetService"] = field(default_factory=list)
    contacts: Optional[dict] = None
    user_invites: List["TailnetUserInvite"] = field(default_factory=list)
    device_invites: List["TailnetDeviceInvite"] = field(default_factory=list)
    acl_policy: Optional[dict] = None
    
    def __repr__(self):
        return (f"TailscaleNetwork(version='{self.version}', "
                f"users={len(self.users)}, peers={len(self.peers)})")
    
    def get_user_by_id(self, user_id: Union[int, str]) -> Optional[User]:
        """Find a user by their ID"""
        for user in self.users:
            if user.id == user_id:
                return user
            if str(user.id) == str(user_id):
                return user
            if user.user_id is not None and str(user.user_id) == str(user_id):
                return user
            if user.login_name and str(user.login_name) == str(user_id):
                return user
        return None
    
    def get_online_peers(self) -> List[Node]:
        """Get all online peers"""
        return [peer for peer in self.peers if peer.online]
    
    def get_offline_peers(self) -> List[Node]:
        """Get all offline peers"""
        return [peer for peer in self.peers if not peer.online]
    
    def get_exit_nodes(self) -> List[Node]:
        """Get all exit nodes"""
        return [peer for peer in self.peers if peer.exit_node]
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'version': self.version,
            'backend_state': self.backend_state,
            'self_node': self.self_node.to_dict() if self.self_node else None,
            'users': [user.to_dict() for user in self.users],
            'peers': [peer.to_dict() for peer in self.peers],
            'keys': [key.to_dict() for key in self.keys],
            'magic_dns_suffix': self.magic_dns_suffix,
            'tailnet_name': self.tailnet_name,
            'tailnet_id': self.tailnet_id,
            'tailnet_magic_dns_suffix': self.tailnet_magic_dns_suffix,
            'tailnet_magic_dns_enabled': self.tailnet_magic_dns_enabled,
            'tailnet_settings': self.tailnet_settings,
            'dns_nameservers': self.dns_nameservers,
            'dns_search_paths': self.dns_search_paths,
            'dns_magic_dns': self.dns_magic_dns,
            'dns_split_dns': self.dns_split_dns,
            'dns_configuration': self.dns_configuration,
            'webhooks': [webhook.to_dict() for webhook in self.webhooks],
            'logging_configuration': self.logging_configuration,
            'logging_network': self.logging_network,
            'logstream_configuration': self.logstream_configuration,
            'logstream_status': self.logstream_status,
            'services': [service.to_dict() for service in self.services],
            'contacts': self.contacts,
            'user_invites': [invite.to_dict() for invite in self.user_invites],
            'device_invites': [invite.to_dict() for invite in self.device_invites],
            'acl_policy': self.acl_policy,
        }


@dataclass
class TailnetKey:
    """Represents a Tailscale tailnet key (auth, client, api, federated)."""
    id: str
    key: Optional[str] = None
    key_type: Optional[str] = None
    description: Optional[str] = None
    user_id: Optional[str] = None
    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None
    revoked: Optional[str] = None
    expiry_seconds: Optional[int] = None
    scopes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    invalid: Optional[bool] = None
    capabilities: Optional[dict] = None
    creator: Optional[str] = None
    authkey: Optional[dict] = None
    apikey: Optional[dict] = None
    oauthclient: Optional[dict] = None
    audience: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    custom_claim_rules: Optional[dict] = None

    def to_dict(self):
        return {
            "id": self.id,
            "key": self.key,
            "key_type": self.key_type,
            "description": self.description,
            "user_id": self.user_id,
            "created": self.created,
            "updated": self.updated,
            "expires": self.expires,
            "revoked": self.revoked,
            "expiry_seconds": self.expiry_seconds,
            "scopes": self.scopes,
            "tags": self.tags,
            "invalid": self.invalid,
            "capabilities": self.capabilities,
            "creator": self.creator,
            "authkey": self.authkey,
            "apikey": self.apikey,
            "oauthclient": self.oauthclient,
            "audience": self.audience,
            "issuer": self.issuer,
            "subject": self.subject,
            "custom_claim_rules": self.custom_claim_rules,
        }


@dataclass
class TailnetWebhook:
    """Represents a Tailscale webhook endpoint configuration."""
    endpoint_id: str
    endpoint_url: Optional[str] = None
    provider_type: Optional[str] = None
    creator_login_name: Optional[str] = None
    created: Optional[str] = None
    last_modified: Optional[str] = None
    subscriptions: List[str] = field(default_factory=list)
    secret: Optional[str] = None

    def to_dict(self):
        return {
            "endpoint_id": self.endpoint_id,
            "endpoint_url": self.endpoint_url,
            "provider_type": self.provider_type,
            "creator_login_name": self.creator_login_name,
            "created": self.created,
            "last_modified": self.last_modified,
            "subscriptions": self.subscriptions,
            "secret": self.secret,
        }


@dataclass
class TailnetService:
    """Represents a Tailscale VIP service."""
    name: str
    addrs: List[str] = field(default_factory=list)
    comment: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "name": self.name,
            "addrs": self.addrs,
            "comment": self.comment,
            "ports": self.ports,
            "tags": self.tags,
        }


@dataclass
class TailnetUserInvite:
    """Represents a tailnet user invite."""
    id: str
    role: Optional[str] = None
    tailnet_id: Optional[str] = None
    inviter_id: Optional[str] = None
    email: Optional[str] = None
    last_email_sent_at: Optional[str] = None
    invite_url: Optional[str] = None

    def to_dict(self):
        return {
            "id": self.id,
            "role": self.role,
            "tailnet_id": self.tailnet_id,
            "inviter_id": self.inviter_id,
            "email": self.email,
            "last_email_sent_at": self.last_email_sent_at,
            "invite_url": self.invite_url,
        }


@dataclass
class TailnetDeviceInvite:
    """Represents a device share invite."""
    id: str
    created: Optional[str] = None
    tailnet_id: Optional[str] = None
    device_id: Optional[str] = None
    sharer_id: Optional[str] = None
    multi_use: Optional[bool] = None
    allow_exit_node: Optional[bool] = None
    email: Optional[str] = None
    last_email_sent_at: Optional[str] = None
    invite_url: Optional[str] = None
    accepted: Optional[bool] = None
    accepted_by: Optional[dict] = None

    def to_dict(self):
        return {
            "id": self.id,
            "created": self.created,
            "tailnet_id": self.tailnet_id,
            "device_id": self.device_id,
            "sharer_id": self.sharer_id,
            "multi_use": self.multi_use,
            "allow_exit_node": self.allow_exit_node,
            "email": self.email,
            "last_email_sent_at": self.last_email_sent_at,
            "invite_url": self.invite_url,
            "accepted": self.accepted,
            "accepted_by": self.accepted_by,
        }
