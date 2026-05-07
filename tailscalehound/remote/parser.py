import json
import logging
from collections import Counter
from typing import Optional, List

import requests

from ..models import (
    TailscaleNetwork,
    User,
    Node,
    TailnetKey,
    TailnetWebhook,
    TailnetService,
    TailnetUserInvite,
    TailnetDeviceInvite,
)

ADMIN_MACHINES_URL = "https://login.tailscale.com/admin/api/machines"
ADMIN_USERS_URL = "https://login.tailscale.com/admin/api/users"
ADMIN_TAILNET_SETTINGS_URL = "https://login.tailscale.com/admin/api/tailnet-settings"
ADMIN_STRIPE_SUBSCRIPTION_URL = "https://login.tailscale.com/admin/api/stripe/subscription"
ADMIN_DOMAINKEYS_URL = "https://login.tailscale.com/admin/api/domainkeys"
ADMIN_KEYS_URL = "https://login.tailscale.com/admin/api/keys"


def fetch_oauth_access_token(
    client_id: str,
    client_secret: str,
    api_base_url: str = "https://api.tailscale.com/api/v2",
    timeout: int = 30,
    verify: bool = True,
    logger: Optional[logging.Logger] = None,
) -> Optional[str]:
    url = f"{api_base_url.rstrip('/')}/oauth/token"
    headers = {"Accept": "application/json"}
    data = {"client_id": client_id, "client_secret": client_secret}
    try:
        if logger:
            logger.debug(f"POST {url}")
        resp = requests.post(url, data=data, headers=headers, timeout=timeout, verify=verify)
        if logger:
            logger.debug(f"Status: {resp.status_code}")
            logger.debug(f"Body: {resp.text}")
        if not (200 <= resp.status_code < 300):
            if logger:
                logger.error(f"OAuth token request failed with status {resp.status_code}.")
                if resp.text:
                    logger.debug(f"Body: {resp.text}")
            return None
        try:
            payload = resp.json()
        except json.JSONDecodeError as e:
            if logger:
                logger.error(f"Error parsing OAuth token response JSON: {e}")
            return None
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            if logger:
                logger.error("OAuth token response missing access_token.")
            return None
        return token
    except requests.exceptions.RequestException as e:
        if logger:
            logger.error(f"OAuth token request error: {e}")
        return None


class RemoteParser:
    """
    Parser for Tailscale API responses.

    Intended to mirror the local Parser interface, but pull data
    from the Tailscale APIs instead of a local JSON file.
    """

    def __init__(
        self,
        api_key: str,
        tailnet: Optional[str] = None,
        api_base_url: str = "https://api.tailscale.com/api/v2",
        timeout: int = 30,
        verify: bool = True,
        include_network_logs: bool = False,
        tailcontrol: Optional[str] = None,
    ):
        self.api_base_url = api_base_url.rstrip("/")
        self.api_key = api_key
        self.tailnet = tailnet
        self.timeout = timeout
        self.verify = verify
        self.include_network_logs = include_network_logs
        self.tailcontrol = tailcontrol
        self.logger = logging.getLogger(__name__)
        self.network: Optional[TailscaleNetwork] = None
        self._acl_policy_cache: Optional[dict] = None
        self._user_detail_cache: dict[str, dict] = {}
        self._admin_machines_cache: Optional[List[dict]] = None
        self._admin_users_cache: Optional[List[dict]] = None
        self._admin_tailnet_settings_cache: Optional[dict] = None
        self._admin_stripe_subscription_cache: Optional[dict] = None
        self._admin_domainkeys_cache: Optional[dict] = None
        self._admin_keys_cache: Optional[dict] = None

    def list_admin_machines(self) -> Optional[List[dict]]:
        if not self.tailcontrol:
            return None
        if self._admin_machines_cache is not None:
            return self._admin_machines_cache
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/144.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
        }
        try:
            self.logger.debug(f"GET {ADMIN_MACHINES_URL}")
            resp = requests.get(
                ADMIN_MACHINES_URL,
                headers=headers,
                cookies={"tailcontrol": self.tailcontrol},
                timeout=self.timeout,
                verify=self.verify,
            )
            self.logger.debug(f"Status: {resp.status_code}")
            if resp.text:
                self.logger.debug(f"Body: {resp.text[:200]}...")
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Admin machines request error: {e}")
            self._admin_machines_cache = []
            return self._admin_machines_cache
        if not (200 <= resp.status_code < 300):
            self.logger.warning(f"Admin machines request failed with status {resp.status_code}")
            self._admin_machines_cache = []
            return self._admin_machines_cache

        payload = None
        try:
            payload = resp.json()
        except json.JSONDecodeError as e:
            self.logger.warning(f"Admin machines JSON parse error: {e}")
            payload = None

        machines: List[dict] = []
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict) and isinstance(data.get("machines"), list):
                machines = data.get("machines") or []
            elif isinstance(payload.get("machines"), list):
                machines = payload.get("machines") or []

        if not machines:
            self.logger.warning("Admin machines response missing machines list.")

        self._admin_machines_cache = [m for m in machines if isinstance(m, dict)]
        return self._admin_machines_cache

    def list_admin_users(self) -> Optional[List[dict]]:
        if not self.tailcontrol:
            return None
        if self._admin_users_cache is not None:
            return self._admin_users_cache
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/144.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
        }
        try:
            self.logger.debug(f"GET {ADMIN_USERS_URL}")
            resp = requests.get(
                ADMIN_USERS_URL,
                headers=headers,
                cookies={"tailcontrol": self.tailcontrol},
                timeout=self.timeout,
                verify=self.verify,
            )
            self.logger.debug(f"Status: {resp.status_code}")
            if resp.text:
                self.logger.debug(f"Body: {resp.text[:200]}...")
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Admin users request error: {e}")
            self._admin_users_cache = []
            return self._admin_users_cache
        if not (200 <= resp.status_code < 300):
            self.logger.warning(f"Admin users request failed with status {resp.status_code}")
            self._admin_users_cache = []
            return self._admin_users_cache

        payload = None
        try:
            payload = resp.json()
        except json.JSONDecodeError as e:
            self.logger.warning(f"Admin users JSON parse error: {e}")
            payload = None

        users: List[dict] = []
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict) and isinstance(data.get("users"), list):
                users = data.get("users") or []
            elif isinstance(payload.get("users"), list):
                users = payload.get("users") or []

        if not users:
            self.logger.warning("Admin users response missing users list.")

        self._admin_users_cache = [u for u in users if isinstance(u, dict)]
        return self._admin_users_cache

    def get_admin_tailnet_settings(self) -> Optional[dict]:
        if not self.tailcontrol:
            return None
        if self._admin_tailnet_settings_cache is not None:
            return self._admin_tailnet_settings_cache
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/144.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
        }
        try:
            self.logger.debug(f"GET {ADMIN_TAILNET_SETTINGS_URL}")
            resp = requests.get(
                ADMIN_TAILNET_SETTINGS_URL,
                headers=headers,
                cookies={"tailcontrol": self.tailcontrol},
                timeout=self.timeout,
                verify=self.verify,
            )
            self.logger.debug(f"Status: {resp.status_code}")
            if resp.text:
                self.logger.debug(f"Body: {resp.text[:200]}...")
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Admin tailnet settings request error: {e}")
            self._admin_tailnet_settings_cache = {}
            return self._admin_tailnet_settings_cache
        if not (200 <= resp.status_code < 300):
            self.logger.warning(
                f"Admin tailnet settings request failed with status {resp.status_code}"
            )
            self._admin_tailnet_settings_cache = {}
            return self._admin_tailnet_settings_cache

        payload = None
        try:
            payload = resp.json()
        except json.JSONDecodeError as e:
            self.logger.warning(f"Admin tailnet settings JSON parse error: {e}")
            payload = None

        settings = {}
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict):
                settings = data
            elif isinstance(payload.get("settings"), dict):
                settings = payload.get("settings") or {}

        if not settings:
            self.logger.warning("Admin tailnet settings response missing data.")

        self._admin_tailnet_settings_cache = settings
        return self._admin_tailnet_settings_cache

    def get_admin_stripe_subscription(self) -> Optional[dict]:
        if not self.tailcontrol:
            return None
        if self._admin_stripe_subscription_cache is not None:
            return self._admin_stripe_subscription_cache
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/144.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
        }
        try:
            self.logger.debug(f"GET {ADMIN_STRIPE_SUBSCRIPTION_URL}")
            resp = requests.get(
                ADMIN_STRIPE_SUBSCRIPTION_URL,
                headers=headers,
                cookies={"tailcontrol": self.tailcontrol},
                timeout=self.timeout,
                verify=self.verify,
            )
            self.logger.debug(f"Status: {resp.status_code}")
            if resp.text:
                self.logger.debug(f"Body: {resp.text[:200]}...")
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Admin stripe subscription request error: {e}")
            self._admin_stripe_subscription_cache = {}
            return self._admin_stripe_subscription_cache
        if not (200 <= resp.status_code < 300):
            self.logger.warning(
                f"Admin stripe subscription request failed with status {resp.status_code}"
            )
            self._admin_stripe_subscription_cache = {}
            return self._admin_stripe_subscription_cache

        payload = None
        try:
            payload = resp.json()
        except json.JSONDecodeError as e:
            self.logger.warning(f"Admin stripe subscription JSON parse error: {e}")
            payload = None

        data = {}
        if isinstance(payload, dict):
            data = payload.get("data") or {}

        if not data:
            self.logger.warning("Admin stripe subscription response missing data.")

        self._admin_stripe_subscription_cache = data
        return self._admin_stripe_subscription_cache

    def get_admin_domainkeys(self) -> Optional[dict]:
        if not self.tailcontrol:
            return None
        if self._admin_domainkeys_cache is not None:
            return self._admin_domainkeys_cache
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/144.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
        }
        try:
            self.logger.debug(f"GET {ADMIN_DOMAINKEYS_URL}")
            resp = requests.get(
                ADMIN_DOMAINKEYS_URL,
                headers=headers,
                cookies={"tailcontrol": self.tailcontrol},
                timeout=self.timeout,
                verify=self.verify,
            )
            self.logger.debug(f"Status: {resp.status_code}")
            if resp.text:
                self.logger.debug(f"Body: {resp.text[:200]}...")
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Admin domainkeys request error: {e}")
            self._admin_domainkeys_cache = {}
            return self._admin_domainkeys_cache
        if not (200 <= resp.status_code < 300):
            self.logger.warning(
                f"Admin domainkeys request failed with status {resp.status_code}"
            )
            self._admin_domainkeys_cache = {}
            return self._admin_domainkeys_cache

        payload = None
        try:
            payload = resp.json()
        except json.JSONDecodeError as e:
            self.logger.warning(f"Admin domainkeys JSON parse error: {e}")
            payload = None

        data = {}
        if isinstance(payload, dict):
            data = payload.get("data") or {}

        if not data:
            self.logger.warning("Admin domainkeys response missing data.")

        self._admin_domainkeys_cache = data
        return self._admin_domainkeys_cache

    def get_admin_keys(self) -> Optional[dict]:
        if not self.tailcontrol:
            return None
        if self._admin_keys_cache is not None:
            return self._admin_keys_cache
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/144.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
        }
        try:
            self.logger.debug(f"GET {ADMIN_KEYS_URL}")
            resp = requests.get(
                ADMIN_KEYS_URL,
                headers=headers,
                cookies={"tailcontrol": self.tailcontrol},
                timeout=self.timeout,
                verify=self.verify,
            )
            self.logger.debug(f"Status: {resp.status_code}")
            if resp.text:
                self.logger.debug(f"Body: {resp.text[:200]}...")
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Admin keys request error: {e}")
            self._admin_keys_cache = {}
            return self._admin_keys_cache
        if not (200 <= resp.status_code < 300):
            self.logger.warning(
                f"Admin keys request failed with status {resp.status_code}"
            )
            self._admin_keys_cache = {}
            return self._admin_keys_cache

        payload = None
        try:
            payload = resp.json()
        except json.JSONDecodeError as e:
            self.logger.warning(f"Admin keys JSON parse error: {e}")
            payload = None

        data = {}
        if isinstance(payload, dict):
            data = payload.get("data") or {}

        if not data:
            self.logger.warning("Admin keys response missing data.")

        self._admin_keys_cache = data
        return self._admin_keys_cache

    def _tailnet_id(self) -> str:
        # Use '-' shorthand when tailnet is not provided and the token is scoped to one tailnet.
        return self.tailnet or "-"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: Optional[dict] = None) -> Optional[dict]:
        url = f"{self.api_base_url}/{path.lstrip('/')}"
        try:
            self.logger.debug(f"GET {url}")
            resp = requests.get(
                url,
                headers=self._headers(),
                params=params,
                timeout=self.timeout,
                verify=self.verify,
            )
            self.logger.debug(f"Status: {resp.status_code}")
            if resp.text:
                self.logger.debug(f"Body: {resp.text}")
            if not (200 <= resp.status_code < 300):
                return None
            return resp.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error: {e}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing response JSON: {e}")
            return None

    def list_users_raw(self) -> Optional[List[dict]]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/users")
        if payload is None:
            return None

        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("users", "data", "items"):
                if key in payload and isinstance(payload[key], list):
                    return payload[key]
        self.logger.error("Unexpected users response shape.")
        return None

    def list_users(self) -> Optional[List[User]]:
        raw_users = self.list_users_raw()
        if raw_users is None:
            return None

        users: List[User] = []
        for item in raw_users:
            if not isinstance(item, dict):
                continue
            user_id = item.get("id")
            login_name = item.get("loginName") or item.get("login_name") or ""
            display_name = item.get("displayName") or item.get("display_name") or login_name
            profile_pic_url = item.get("profilePicUrl") or item.get("profilePicURL")
            role = item.get("role")
            status = item.get("status")
            tailnet_id = item.get("tailnetId") or item.get("tailnet_id")
            created = item.get("created")
            last_seen = item.get("lastSeen") or item.get("last_seen")
            currently_connected = item.get("currentlyConnected")
            device_count = item.get("deviceCount")
            user_type = item.get("type")

            users.append(
                User(
                    id=user_id,
                    login_name=login_name,
                    display_name=display_name,
                    user_id=None,
                    profile_pic_url=profile_pic_url,
                    role=role,
                    status=status,
                    tailnet_id=tailnet_id,
                    created=created,
                    last_seen=last_seen,
                    currently_connected=currently_connected,
                    device_count=device_count,
                    user_type=user_type,
                )
            )

        admin_users = self.list_admin_users() if self.tailcontrol else None
        if admin_users:
            users_by_login = {
                (u.login_name or "").lower(): u for u in users if u.login_name
            }

            def update_user_from_admin(user: User, admin: dict) -> None:
                admin_id = admin.get("id")
                if user.user_id is None and admin_id is not None:
                    user.user_id = str(admin_id)
                if not user.stable_id:
                    user.stable_id = admin.get("stableId")
                if not user.display_name:
                    user.display_name = admin.get("displayName") or user.display_name
                if not user.profile_pic_url:
                    user.profile_pic_url = admin.get("profilePicURL") or admin.get("profilePicUrl")
                if not user.role:
                    user.role = admin.get("role") or user.role
                if user.is_admin is None and admin.get("isAdmin") is not None:
                    user.is_admin = admin.get("isAdmin")
                if user.is_owner is None and admin.get("isOwner") is not None:
                    user.is_owner = admin.get("isOwner")
                if not user.status and admin.get("status"):
                    user.status = admin.get("status")
                if not user.org_tailnet_id:
                    user.org_tailnet_id = admin.get("orgTailnetId")
                if not user.domain_name:
                    user.domain_name = admin.get("domainName")
                if user.shared_domain is None and admin.get("sharedDomain") is not None:
                    user.shared_domain = admin.get("sharedDomain")
                if not user.created and admin.get("created"):
                    user.created = admin.get("created")
                if not user.last_seen and admin.get("lastSeen"):
                    user.last_seen = admin.get("lastSeen")
                if user.currently_connected is None and admin.get("currentlyConnected") is not None:
                    user.currently_connected = admin.get("currentlyConnected")
                if user.device_count is None and admin.get("deviceCount") is not None:
                    user.device_count = admin.get("deviceCount")
                if user.can_edit_billing is None and admin.get("canEditBilling") is not None:
                    user.can_edit_billing = admin.get("canEditBilling")
                if user.needs_onboarding is None and admin.get("needsOnboarding") is not None:
                    user.needs_onboarding = admin.get("needsOnboarding")
                if user.use_business_pricing is None and admin.get("useBusinessPricing") is not None:
                    user.use_business_pricing = admin.get("useBusinessPricing")
                if user.no_longer_provisioned is None and admin.get("noLongerProvisioned") is not None:
                    user.no_longer_provisioned = admin.get("noLongerProvisioned")

            for admin in admin_users:
                if not isinstance(admin, dict):
                    continue
                login = admin.get("loginName") or admin.get("login_name")
                if not login:
                    continue
                key = str(login).lower()
                existing = users_by_login.get(key)
                if existing:
                    update_user_from_admin(existing, admin)
                    continue
                new_user = User(
                    id=str(admin.get("id") or login),
                    login_name=login,
                    display_name=admin.get("displayName", login),
                )
                update_user_from_admin(new_user, admin)
                users.append(new_user)
                users_by_login[key] = new_user

        return users

    def get_user(self, user_id: str) -> Optional[dict]:
        if not user_id:
            return None
        cached = self._user_detail_cache.get(str(user_id))
        if cached is not None:
            return cached
        payload = self._get(f"users/{user_id}")
        if payload is None:
            self.logger.warning(f"Failed to fetch user details for user: {user_id}")
            return None
        if isinstance(payload, dict):
            self._user_detail_cache[str(user_id)] = payload
            return payload
        self.logger.warning(f"Unexpected user response shape for user: {user_id}")
        return None

    def list_devices_raw(self) -> Optional[List[dict]]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/devices")
        if payload is None:
            return None

        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("devices", "data", "items"):
                if key in payload and isinstance(payload[key], list):
                    return payload[key]
        self.logger.error("Unexpected devices response shape.")
        return None

    def list_devices(self, users: Optional[List[User]] = None) -> Optional[List[Node]]:
        raw_devices = self.list_devices_raw()
        if raw_devices is None:
            return None

        users = users or []
        user_by_login = {u.login_name: u for u in users if u.login_name}
        admin_machines = self.list_admin_machines() if self.tailcontrol else None
        admin_index: dict[str, dict] = {}
        matched_admin = set()
        if admin_machines:
            def index_machine(value: Optional[str], machine: dict) -> None:
                if value is None:
                    return
                key = str(value).strip()
                if not key:
                    return
                admin_index.setdefault(key, machine)

            for machine in admin_machines:
                if not isinstance(machine, dict):
                    continue
                index_machine(machine.get("stableId"), machine)
                index_machine(machine.get("id"), machine)
                index_machine(machine.get("nodeKey"), machine)
                index_machine(machine.get("machineKey"), machine)
                index_machine(machine.get("name"), machine)
                index_machine(machine.get("hostname"), machine)
                index_machine(machine.get("fqdn"), machine)

        devices: List[Node] = []
        for item in raw_devices:
            if not isinstance(item, dict):
                continue

            legacy_id = item.get("id") or ""
            node_id = item.get("nodeId") or legacy_id or ""
            admin_machine = None
            if admin_index:
                for candidate in (
                    item.get("stableId"),
                    item.get("nodeId"),
                    legacy_id,
                    item.get("nodeKey"),
                    item.get("machineKey"),
                    item.get("name"),
                    item.get("hostname"),
                    item.get("fqdn"),
                ):
                    if candidate is None:
                        continue
                    admin_machine = admin_index.get(str(candidate))
                    if admin_machine:
                        matched_admin.add(id(admin_machine))
                        break

            hostname = item.get("hostname") or (admin_machine.get("hostname") if admin_machine else "") or ""
            dns_name = item.get("name") or (admin_machine.get("name") if admin_machine else "") or ""
            os_name = item.get("os") or (admin_machine.get("os") if admin_machine else "") or ""
            addresses = item.get("addresses") or (admin_machine.get("addresses") if admin_machine else []) or []
            tags = item.get("tags") or []
            created = item.get("created") or (admin_machine.get("created") if admin_machine else None)
            last_seen = item.get("lastSeen") or item.get("last_seen") or (admin_machine.get("lastSeen") if admin_machine else None)
            connected_to_control = item.get("connectedToControl")
            if connected_to_control is None and admin_machine is not None:
                connected_to_control = admin_machine.get("connectedToControl")
            online = bool(connected_to_control) if connected_to_control is not None else False

            advertised_routes = item.get("advertisedRoutes") or []
            enabled_routes = item.get("enabledRoutes") or []

            routes = None
            if legacy_id or node_id:
                routes = self.get_device_routes(legacy_id or node_id)
            if isinstance(routes, dict):
                advertised_routes = routes.get("advertisedRoutes") or advertised_routes
                enabled_routes = routes.get("enabledRoutes") or enabled_routes
            if admin_machine and not advertised_routes:
                advertised_routes = admin_machine.get("advertisedIPs") or advertised_routes

            user_login = item.get("user") or (admin_machine.get("user") if admin_machine else None)
            user = user_by_login.get(user_login) if user_login else None
            user_id = user.id if user else (user_login or "")

            default_routes = {"0.0.0.0/0", "::/0"}
            exit_node = any(r in default_routes for r in advertised_routes)
            exit_node_option = any(r in default_routes for r in enabled_routes)
            router = any(
                r and r not in default_routes for r in (advertised_routes + enabled_routes)
            )

            client_connectivity = item.get("clientConnectivity")
            latency = None
            client_supports = None
            endpoints = []
            if isinstance(client_connectivity, dict):
                endpoints = client_connectivity.get("endpoints") or []
                latency = client_connectivity.get("latency")
                client_supports = client_connectivity.get("clientSupports")

            posture_attributes = None
            posture_expiries = None
            if node_id:
                attrs = self.get_device_attributes(node_id)
                if attrs:
                    posture_attributes = attrs.get("attributes")
                    posture_expiries = attrs.get("expiries")

            distro = item.get("distro") or {}
            if not isinstance(distro, dict):
                distro = {}

            allowed_ips = item.get("allowedIPs") or []
            if admin_machine and not allowed_ips:
                allowed_ips = admin_machine.get("allowedIPs") or []

            devices.append(
                Node(
                    id=node_id,
                    device_id=legacy_id or None,
                    public_key=item.get("nodeKey") or (admin_machine.get("nodeKey") if admin_machine else "") or "",
                    hostname=hostname,
                    dns_name=dns_name,
                    os=os_name,
                    user_id=user_id,
                    tailscale_ips=addresses,
                    allowed_ips=allowed_ips,
                    primary_routes=[],
                    advertised_routes=advertised_routes,
                    enabled_routes=enabled_routes,
                    online=online,
                    connected_to_control=connected_to_control,
                    exit_node=exit_node,
                    exit_node_option=exit_node_option,
                    router=router,
                    tags=tags,
                    created=created,
                    last_seen=last_seen,
                    key_expiry=item.get("expires"),
                    key_expiry_disabled=item.get("keyExpiryDisabled"),
                    authorized=item.get("authorized"),
                    is_external=item.get("isExternal"),
                    blocks_incoming_connections=item.get("blocksIncomingConnections"),
                    multiple_connections=item.get("multipleConnections"),
                    machine_key=item.get("machineKey") or (admin_machine.get("machineKey") if admin_machine else None),
                    tailnet_lock_error=item.get("tailnetLockError"),
                    tailnet_lock_key=item.get("tailnetLockKey"),
                    ssh_enabled=item.get("sshEnabled"),
                    is_ephemeral=item.get("isEphemeral"),
                    client_version=item.get("clientVersion"),
                    update_available=item.get("updateAvailable"),
                    distro_name=distro.get("name"),
                    distro_version=distro.get("version"),
                    distro_code_name=distro.get("codeName"),
                    client_connectivity_latency=latency,
                    client_connectivity_supports=client_supports,
                    posture_attributes=posture_attributes,
                    posture_expiries=posture_expiries,
                    addrs=endpoints,
                    active=online,
                    stable_id=admin_machine.get("stableId") if admin_machine else item.get("stableId"),
                    fqdn=admin_machine.get("fqdn") if admin_machine else item.get("fqdn"),
                    machine_name=admin_machine.get("name") if admin_machine else None,
                    os_version=admin_machine.get("osVersion") if admin_machine else None,
                    parsed_os_version=admin_machine.get("parsedOSVersion") if admin_machine else None,
                    ipn_version=admin_machine.get("ipnVersion") if admin_machine else None,
                    creator=admin_machine.get("creator") if admin_machine else None,
                    domain=admin_machine.get("domain") if admin_machine else None,
                    available_update_version=admin_machine.get("availableUpdateVersion") if admin_machine else None,
                    automatic_name_mode=admin_machine.get("automaticNameMode") if admin_machine else None,
                    auto_updates_enabled=admin_machine.get("autoUpdatesEnabled") if admin_machine else None,
                    can_nat=admin_machine.get("canNat") if admin_machine else None,
                    endpoints=admin_machine.get("endpoints") if admin_machine else None,
                    extra_ips=admin_machine.get("extraIPs") if admin_machine else None,
                    allowed_tags=admin_machine.get("allowedTags") if admin_machine else None,
                    invalid_tags=admin_machine.get("invalidTags") if admin_machine else None,
                    advertised_ips=admin_machine.get("advertisedIPs") if admin_machine else None,
                    accepted_share_count=admin_machine.get("acceptedShareCount") if admin_machine else None,
                    share_id=admin_machine.get("shareID") if admin_machine else None,
                    has_exit_node=admin_machine.get("hasExitNode") if admin_machine else None,
                    advertised_exit_node=admin_machine.get("advertisedExitNode") if admin_machine else None,
                    allowed_exit_node=admin_machine.get("allowedExitNode") if admin_machine else None,
                    has_subnets=admin_machine.get("hasSubnets") if admin_machine else None,
                    ssh_usernames=admin_machine.get("sshUsernames") if admin_machine else None,
                    other_ssh_usernames_allowed=admin_machine.get("otherSSHUsernamesAllowed") if admin_machine else None,
                    funnel_enabled=admin_machine.get("funnelEnabled") if admin_machine else None,
                    never_expires=admin_machine.get("neverExpires") if admin_machine else None,
                )
            )
        # Add admin-only machines that were not present in the devices API response.
        if admin_machines:
            default_routes = {"0.0.0.0/0", "::/0"}
            admin_only_count = 0
            for machine in admin_machines:
                if not isinstance(machine, dict):
                    continue
                if id(machine) in matched_admin:
                    continue
                device_id = machine.get("id") or ""
                node_id = (
                    machine.get("stableId")
                    or device_id
                    or machine.get("nodeKey")
                    or machine.get("machineKey")
                    or machine.get("name")
                    or machine.get("hostname")
                    or machine.get("fqdn")
                    or ""
                )
                if not node_id:
                    continue

                addresses = machine.get("addresses") or []
                advertised_routes = machine.get("advertisedIPs") or []
                enabled_routes = machine.get("allowedIPs") or []
                exit_node = any(r in default_routes for r in advertised_routes)
                exit_node_option = any(r in default_routes for r in enabled_routes)
                router = any(
                    r and r not in default_routes for r in (advertised_routes + enabled_routes)
                )

                connected_to_control = machine.get("connectedToControl")
                online = bool(connected_to_control) if connected_to_control is not None else False

                hostname = machine.get("hostname") or machine.get("name") or ""
                dns_name = machine.get("name") or machine.get("hostname") or ""
                os_name = machine.get("os") or ""

                user_login = machine.get("user")
                user = user_by_login.get(user_login) if user_login else None
                user_id = user.id if user else (user_login or "")

                tags = machine.get("allowedTags") or []
                devices.append(
                    Node(
                        id=node_id,
                        device_id=device_id or None,
                        public_key=machine.get("nodeKey") or "",
                        hostname=hostname,
                        dns_name=dns_name,
                        os=os_name,
                        user_id=user_id,
                        tailscale_ips=addresses,
                        allowed_ips=machine.get("allowedIPs") or [],
                        primary_routes=[],
                        advertised_routes=advertised_routes,
                        enabled_routes=enabled_routes,
                        online=online,
                        connected_to_control=connected_to_control,
                        exit_node=exit_node,
                        exit_node_option=exit_node_option,
                        router=router,
                        tags=tags,
                        created=machine.get("created"),
                        last_seen=machine.get("lastSeen"),
                        key_expiry=machine.get("expires"),
                        authorized=machine.get("authorized"),
                        is_external=machine.get("isExternal"),
                        machine_key=machine.get("machineKey"),
                        stable_id=machine.get("stableId"),
                        fqdn=machine.get("fqdn"),
                        machine_name=machine.get("name"),
                        os_version=machine.get("osVersion"),
                        parsed_os_version=machine.get("parsedOSVersion"),
                        ipn_version=machine.get("ipnVersion"),
                        creator=machine.get("creator"),
                        domain=machine.get("domain"),
                        available_update_version=machine.get("availableUpdateVersion"),
                        automatic_name_mode=machine.get("automaticNameMode"),
                        auto_updates_enabled=machine.get("autoUpdatesEnabled"),
                        can_nat=machine.get("canNat"),
                        endpoints=machine.get("endpoints"),
                        extra_ips=machine.get("extraIPs"),
                        allowed_tags=machine.get("allowedTags"),
                        invalid_tags=machine.get("invalidTags"),
                        advertised_ips=machine.get("advertisedIPs"),
                        accepted_share_count=machine.get("acceptedShareCount"),
                        share_id=machine.get("shareID"),
                        has_exit_node=machine.get("hasExitNode"),
                        advertised_exit_node=machine.get("advertisedExitNode"),
                        allowed_exit_node=machine.get("allowedExitNode"),
                        has_subnets=machine.get("hasSubnets"),
                        ssh_usernames=machine.get("sshUsernames"),
                        other_ssh_usernames_allowed=machine.get("otherSSHUsernamesAllowed"),
                        funnel_enabled=machine.get("funnelEnabled"),
                        never_expires=machine.get("neverExpires"),
                    )
                )
                admin_only_count += 1
            if admin_only_count:
                self.logger.info(
                    f"Added {admin_only_count} admin-only machines not present in devices API."
                )
        return devices

    def get_device_routes(self, device_id: str) -> Optional[dict]:
        payload = self._get(f"device/{device_id}/routes")
        if payload is None:
            self.logger.warning(f"Failed to fetch routes for device: {device_id}")
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.warning(f"Unexpected routes response shape for device: {device_id}")
        return None

    def list_user_invites_raw(self) -> Optional[List[dict]]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/user-invites")
        if payload is None:
            return None
        if isinstance(payload, list):
            return payload
        self.logger.error("Unexpected user invites response shape.")
        return None

    def list_user_invites(self) -> Optional[List[TailnetUserInvite]]:
        raw_invites = self.list_user_invites_raw()
        if raw_invites is None:
            return None

        invites: List[TailnetUserInvite] = []
        for item in raw_invites:
            if not isinstance(item, dict):
                continue
            invites.append(
                TailnetUserInvite(
                    id=item.get("id") or "",
                    role=item.get("role"),
                    tailnet_id=item.get("tailnetId"),
                    inviter_id=item.get("inviterId"),
                    email=item.get("email"),
                    last_email_sent_at=item.get("lastEmailSentAt"),
                    invite_url=item.get("inviteUrl"),
                )
            )
        return invites

    def list_device_invites_for_device(self, device_id: str) -> Optional[List[dict]]:
        payload = self._get(f"device/{device_id}/device-invites")
        if payload is None:
            return None
        if isinstance(payload, list):
            return payload
        self.logger.error(f"Unexpected device invites response for device {device_id}.")
        return None

    def list_device_invites(
        self,
        devices: Optional[List[Node]] = None,
        users: Optional[List[User]] = None,
    ) -> Optional[List[TailnetDeviceInvite]]:
        devices = devices or []
        users = users or []
        invites: List[TailnetDeviceInvite] = []
        user_by_login = {u.login_name: u for u in users if u.login_name}
        for device in devices:
            device_id = device.device_id or device.id
            if not device_id:
                continue
            raw_invites = self.list_device_invites_for_device(device_id)
            if raw_invites is None:
                continue
            for item in raw_invites:
                if not isinstance(item, dict):
                    continue
                sharer_id = item.get("sharerId")
                if sharer_id is not None:
                    sharer_detail = self.get_user(str(sharer_id))
                    if isinstance(sharer_detail, dict):
                        login = sharer_detail.get("loginName") or sharer_detail.get("login_name")
                        if login and login in user_by_login:
                            user_by_login[login].user_id = str(sharer_id)
                accepted_by = item.get("acceptedBy")
                if isinstance(accepted_by, dict):
                    accepted_login = accepted_by.get("loginName")
                    accepted_id = accepted_by.get("id")
                    if accepted_login and accepted_login in user_by_login:
                        if accepted_id is not None:
                            user_by_login[accepted_login].user_id = str(accepted_id)
                    elif accepted_id is not None:
                        accepted_detail = self.get_user(str(accepted_id))
                        if isinstance(accepted_detail, dict):
                            login = accepted_detail.get("loginName") or accepted_detail.get("login_name")
                            if login and login in user_by_login:
                                user_by_login[login].user_id = str(accepted_id)
                invites.append(
                    TailnetDeviceInvite(
                        id=item.get("id") or "",
                        created=item.get("created"),
                        tailnet_id=item.get("tailnetId"),
                        device_id=item.get("deviceId") or device_id,
                        sharer_id=sharer_id,
                        multi_use=item.get("multiUse"),
                        allow_exit_node=item.get("allowExitNode"),
                        email=item.get("email"),
                        last_email_sent_at=item.get("lastEmailSentAt"),
                        invite_url=item.get("inviteUrl"),
                        accepted=item.get("accepted"),
                        accepted_by=accepted_by,
                    )
                )
        return invites

    def get_device_attributes(self, device_id: str) -> Optional[dict]:
        payload = self._get(f"device/{device_id}/attributes")
        if payload is None:
            self.logger.warning(f"Failed to fetch attributes for device: {device_id}")
            return None
        if isinstance(payload, dict) and "attributes" in payload:
            return payload
        self.logger.warning(f"Unexpected attributes response shape for device: {device_id}")
        return None

    def list_keys_raw(self) -> Optional[List[dict]]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/keys")
        if payload is None:
            return None

        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("keys", "data", "items"):
                if key in payload and isinstance(payload[key], list):
                    return payload[key]
        self.logger.error("Unexpected keys response shape.")
        return None

    def get_key(self, key_id: str) -> Optional[dict]:
        if not key_id:
            return None
        payload = self._get(f"tailnet/{self._tailnet_id()}/keys/{key_id}")
        if payload is None:
            self.logger.warning(f"Failed to fetch key details for key: {key_id}")
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.warning(f"Unexpected key response shape for key: {key_id}")
        return None

    def list_keys(self) -> Optional[List[TailnetKey]]:
        raw_keys = self.list_keys_raw()
        if raw_keys is None:
            return None

        keys: List[TailnetKey] = []
        for item in raw_keys:
            if not isinstance(item, dict):
                continue
            key_id = item.get("id") or ""
            detail = self.get_key(key_id) if key_id else None
            if isinstance(detail, dict):
                item = {**item, **detail}
            keys.append(
                TailnetKey(
                    id=item.get("id") or "",
                    key=item.get("key"),
                    key_type=item.get("keyType"),
                    description=item.get("description"),
                    user_id=item.get("userId"),
                    created=item.get("created"),
                    updated=item.get("updated"),
                    expires=item.get("expires"),
                    revoked=item.get("revoked"),
                    expiry_seconds=item.get("expirySeconds"),
                    scopes=item.get("scopes") or [],
                    tags=item.get("tags") or [],
                    invalid=item.get("invalid"),
                    capabilities=item.get("capabilities"),
                    audience=item.get("audience"),
                    issuer=item.get("issuer"),
                    subject=item.get("subject"),
                    custom_claim_rules=item.get("customClaimRules"),
                )
            )

        if self.tailcontrol:
            admin_payloads = [
                self.get_admin_domainkeys() or {},
                self.get_admin_keys() or {},
            ]

            def iter_admin_keys(payload: dict) -> List[dict]:
                entries: List[dict] = []
                if not isinstance(payload, dict):
                    return entries
                groups = [
                    ("authKeys", False),
                    ("invalidAuthKeys", True),
                    ("apiKeys", False),
                    ("invalidApiKeys", True),
                    ("oauthClients", False),
                    ("invalidOauthClients", True),
                ]
                for key, invalid in groups:
                    items = payload.get(key)
                    if not isinstance(items, list):
                        continue
                    for entry in items:
                        if not isinstance(entry, dict):
                            continue
                        entry = dict(entry)
                        entry["_invalid"] = invalid
                        entries.append(entry)
                return entries

            keys_by_id = {k.id: k for k in keys if k.id}
            for payload in admin_payloads:
                for admin_key in iter_admin_keys(payload):
                    key_id = admin_key.get("id")
                    if not key_id:
                        continue
                    key_obj = keys_by_id.get(key_id)
                    if not key_obj:
                        key_obj = TailnetKey(id=key_id)
                        keys.append(key_obj)
                        keys_by_id[key_id] = key_obj

                    if not key_obj.key_type and admin_key.get("type"):
                        key_obj.key_type = admin_key.get("type")
                    if not key_obj.description and admin_key.get("description"):
                        key_obj.description = admin_key.get("description")
                    if not key_obj.created and admin_key.get("created"):
                        key_obj.created = admin_key.get("created")
                    if not key_obj.updated and admin_key.get("updated"):
                        key_obj.updated = admin_key.get("updated")
                    if not key_obj.revoked and admin_key.get("revoked"):
                        key_obj.revoked = admin_key.get("revoked")
                    if not key_obj.expires and admin_key.get("expiry"):
                        key_obj.expires = admin_key.get("expiry")
                    if admin_key.get("creator"):
                        key_obj.creator = admin_key.get("creator")
                    if admin_key.get("_invalid"):
                        key_obj.invalid = True

                    authkey = admin_key.get("authkey")
                    if isinstance(authkey, dict) and authkey:
                        key_obj.authkey = authkey
                    apikey = admin_key.get("apikey")
                    if isinstance(apikey, dict) and apikey:
                        key_obj.apikey = apikey
                    oauthclient = admin_key.get("oauthclient")
                    if isinstance(oauthclient, dict) and oauthclient:
                        key_obj.oauthclient = oauthclient
                        if not key_obj.scopes and isinstance(oauthclient.get("scopes"), list):
                            key_obj.scopes = oauthclient.get("scopes")
        return keys

    def list_webhooks_raw(self) -> Optional[List[dict]]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/webhooks")
        if payload is None:
            return None

        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("webhooks", "data", "items"):
                if key in payload and isinstance(payload[key], list):
                    return payload[key]
        self.logger.error("Unexpected webhooks response shape.")
        return None

    def list_webhooks(self) -> Optional[List[TailnetWebhook]]:
        raw_webhooks = self.list_webhooks_raw()
        if raw_webhooks is None:
            return None

        webhooks: List[TailnetWebhook] = []
        for item in raw_webhooks:
            if not isinstance(item, dict):
                continue
            webhooks.append(
                TailnetWebhook(
                    endpoint_id=item.get("endpointId") or "",
                    endpoint_url=item.get("endpointUrl"),
                    provider_type=item.get("providerType"),
                    creator_login_name=item.get("creatorLoginName"),
                    created=item.get("created"),
                    last_modified=item.get("lastModified"),
                    subscriptions=item.get("subscriptions") or [],
                    secret=item.get("secret"),
                )
            )
        return webhooks

    def list_dns_nameservers(self) -> Optional[List[str]]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/dns/nameservers")
        if payload is None:
            return None
        if isinstance(payload, dict) and isinstance(payload.get("dns"), list):
            return payload.get("dns")
        self.logger.error("Unexpected DNS nameservers response shape.")
        return None

    def list_dns_preferences(self) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/dns/preferences")
        if payload is None:
            return None
        if isinstance(payload, dict) and "magicDNS" in payload:
            return payload
        self.logger.error("Unexpected DNS preferences response shape.")
        return None

    def list_dns_search_paths(self) -> Optional[List[str]]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/dns/searchpaths")
        if payload is None:
            return None
        if isinstance(payload, dict) and isinstance(payload.get("searchPaths"), list):
            return payload.get("searchPaths")
        self.logger.error("Unexpected DNS search paths response shape.")
        return None

    def list_dns_split(self) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/dns/split-dns")
        if payload is None:
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.error("Unexpected split DNS response shape.")
        return None

    def list_dns_configuration(self) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/dns/configuration")
        if payload is None:
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.error("Unexpected DNS configuration response shape.")
        return None

    def get_logging_configuration(self) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/logging/configuration")
        if payload is None:
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.error("Unexpected logging configuration response shape.")
        return None

    def get_logging_network(self) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/logging/network")
        if payload is None:
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.error("Unexpected logging network response shape.")
        return None

    def get_logstream_configuration(self, log_type: str) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/logging/{log_type}/stream")
        if payload is None:
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.error(f"Unexpected logstream configuration response for {log_type}.")
        return None

    def get_logstream_status(self, log_type: str) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/logging/{log_type}/stream/status")
        if payload is None:
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.error(f"Unexpected logstream status response for {log_type}.")
        return None

    def get_acl_policy(self) -> Optional[dict]:
        if self._acl_policy_cache is not None:
            return self._acl_policy_cache
        url = f"{self.api_base_url}/tailnet/{self._tailnet_id()}/acl"
        try:
            self.logger.debug(f"GET {url}")
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout, verify=self.verify)
            self.logger.debug(f"Status: {resp.status_code}")
            if resp.text:
                self.logger.debug(f"Body: {resp.text}")
            if not (200 <= resp.status_code < 300):
                return None
            try:
                self._acl_policy_cache = resp.json()
            except json.JSONDecodeError:
                self._acl_policy_cache = {"raw": resp.text}
            return self._acl_policy_cache
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error: {e}")
            return None

    def save_acl_policy(self, filepath: str) -> bool:
        policy = self.get_acl_policy()
        if policy is None:
            self.logger.error("Failed to fetch ACL policy from Tailscale API.")
            return False
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(policy, f, indent=2)
            self.logger.info(f"Saved ACL policy to: {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving ACL policy: {e}")
            return False

    def list_services_raw(self) -> Optional[List[dict]]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/services")
        if payload is None:
            return None
        if isinstance(payload, dict) and isinstance(payload.get("vipServices"), list):
            return payload.get("vipServices")
        if isinstance(payload, list):
            return payload
        self.logger.error("Unexpected services response shape.")
        return None

    def list_services(self) -> Optional[List[TailnetService]]:
        raw_services = self.list_services_raw()
        if raw_services is None:
            return None

        services: List[TailnetService] = []
        for item in raw_services:
            if not isinstance(item, dict):
                continue
            services.append(
                TailnetService(
                    name=item.get("name") or "",
                    addrs=item.get("addrs") or [],
                    comment=item.get("comment"),
                    ports=item.get("ports") or [],
                    tags=item.get("tags") or [],
                )
            )
        return services

    def get_contacts(self) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/contacts")
        if payload is None:
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.error("Unexpected contacts response shape.")
        return None

    def get_tailnet_settings(self) -> Optional[dict]:
        payload = self._get(f"tailnet/{self._tailnet_id()}/settings")
        if payload is None:
            return None
        if isinstance(payload, dict):
            return payload
        self.logger.error("Unexpected tailnet settings response shape.")
        return None

    def parse(self) -> Optional[TailscaleNetwork]:
        """
        Fetch data from the Tailscale API and return a TailscaleNetwork object.
        Populates users and devices (peers).
        """
        users = self.list_users()
        if users is None:
            self.logger.error("Failed to fetch users from Tailscale API.")
            return None
        devices = self.list_devices(users=users)
        if devices is None:
            self.logger.error("Failed to fetch devices from Tailscale API.")
            return None
        keys = self.list_keys()
        if keys is None:
            self.logger.warning("Failed to fetch tailnet keys from Tailscale API.")
            keys = []
        webhooks = self.list_webhooks()
        if webhooks is None:
            self.logger.warning("Failed to fetch webhooks from Tailscale API.")
            webhooks = []
        dns_nameservers = self.list_dns_nameservers()
        if dns_nameservers is None:
            self.logger.warning("Failed to fetch DNS nameservers from Tailscale API.")
            dns_nameservers = []
        dns_preferences = self.list_dns_preferences()
        if dns_preferences is None:
            self.logger.warning("Failed to fetch DNS preferences from Tailscale API.")
            dns_preferences = {}
        dns_search_paths = self.list_dns_search_paths()
        if dns_search_paths is None:
            self.logger.warning("Failed to fetch DNS search paths from Tailscale API.")
            dns_search_paths = []
        dns_split = self.list_dns_split()
        if dns_split is None:
            self.logger.warning("Failed to fetch split DNS from Tailscale API.")
            dns_split = {}
        dns_configuration = self.list_dns_configuration()
        if dns_configuration is None:
            self.logger.warning("Failed to fetch DNS configuration from Tailscale API.")
            dns_configuration = {}
        tailnet_settings = self.get_tailnet_settings()
        if tailnet_settings is None:
            self.logger.warning("Failed to fetch tailnet settings from Tailscale API.")
            tailnet_settings = {}
        admin_tailnet_settings = self.get_admin_tailnet_settings() if self.tailcontrol else None
        if admin_tailnet_settings:
            for key, value in admin_tailnet_settings.items():
                if value is not None:
                    tailnet_settings[key] = value
        admin_stripe = self.get_admin_stripe_subscription() if self.tailcontrol else None
        if admin_stripe:
            subscription = admin_stripe.get("subscription") if isinstance(admin_stripe, dict) else None
            billing_usage = admin_stripe.get("billingUsage") if isinstance(admin_stripe, dict) else None
            if subscription is not None:
                tailnet_settings["StripeSubscription"] = subscription
            if billing_usage is not None:
                tailnet_settings["StripeBillingUsage"] = billing_usage
        logging_configuration = self.get_logging_configuration()
        if logging_configuration is None:
            self.logger.warning("Failed to fetch logging configuration from Tailscale API.")
            logging_configuration = {}
        logging_network = {}
        if self.include_network_logs:
            logging_network = self.get_logging_network()
            if logging_network is None:
                self.logger.warning("Failed to fetch logging network logs from Tailscale API.")
                logging_network = {}
        logstream_configuration = {
            "configuration": self.get_logstream_configuration("configuration") or {},
            "network": self.get_logstream_configuration("network") or {},
        }
        logstream_status = {
            "configuration": self.get_logstream_status("configuration") or {},
            "network": self.get_logstream_status("network") or {},
        }
        services = self.list_services()
        if services is None:
            self.logger.warning("Failed to fetch services from Tailscale API.")
            services = []
        user_invites = self.list_user_invites()
        if user_invites is None:
            self.logger.warning("Failed to fetch user invites from Tailscale API.")
            user_invites = []
        device_invites = self.list_device_invites(devices=devices, users=users)
        if device_invites is None:
            self.logger.warning("Failed to fetch device invites from Tailscale API.")
            device_invites = []
        contacts = self.get_contacts()
        if contacts is None:
            self.logger.warning("Failed to fetch contacts from Tailscale API.")
            contacts = {}
        acl_policy = self.get_acl_policy()
        if acl_policy is None:
            self.logger.warning("Failed to fetch ACL policy from Tailscale API.")
            acl_policy = {}

        tailnet_id = None
        if users:
            candidates = [u.tailnet_id for u in users if getattr(u, "tailnet_id", None)]
            if candidates:
                tailnet_id = Counter(candidates).most_common(1)[0][0]

        network = TailscaleNetwork(
            version="api",
            backend_state="api",
        )
        if self.tailnet and self.tailnet != "-":
            network.tailnet_name = self.tailnet
        if tailnet_id:
            network.tailnet_id = tailnet_id
        network.users = users
        network.peers = devices
        network.keys = keys
        network.webhooks = webhooks
        network.dns_nameservers = dns_nameservers
        network.dns_search_paths = dns_search_paths
        network.dns_magic_dns = dns_preferences.get("magicDNS") if isinstance(dns_preferences, dict) else None
        network.dns_split_dns = dns_split
        network.dns_configuration = dns_configuration
        network.tailnet_settings = tailnet_settings
        network.logging_configuration = logging_configuration
        network.logging_network = logging_network
        network.logstream_configuration = logstream_configuration
        network.logstream_status = logstream_status
        network.services = services
        network.user_invites = user_invites
        network.device_invites = device_invites
        network.contacts = contacts
        network.acl_policy = acl_policy
        self.network = network
        return network
