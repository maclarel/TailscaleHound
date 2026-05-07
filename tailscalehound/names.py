"""BloodHound kind naming helpers for the TailscaleHound extension."""

NAMESPACE = "TS"
BASE_KIND = f"{NAMESPACE}_Base"

TAILSCALE_KIND_PREFIXES = ("Tailscale", "Tailnet")
TAILSCALE_RELATIONSHIP_KINDS = {
    "AZUserSyncedToTailscaleUser",
    "AZUserSyncedToUser",
}

TRAVERSABLE_EDGE_KINDS = frozenset(
    {
        "TS_AZUserSyncedToUser",
        "TS_AclSource",
        "TS_AclTargetsAppConnector",
        "TS_AclTargetsDevice",
        "TS_AclTargetsExitNode",
        "TS_AclTargetsRoute",
        "TS_GrantSource",
        "TS_GrantTargetsAppConnector",
        "TS_GrantTargetsDevice",
        "TS_GrantTargetsExitNode",
        "TS_GrantTargetsRoute",
        "TS_HasFunnelCapabilities",
        "TS_HasFunnelEnabled",
        "TS_HasTag",
        "TS_IsAdminOf",
        "TS_IsITAdminOf",
        "TS_IsMemberOf",
        "TS_IsNetworkAdminOf",
        "TS_IsOwnerOf",
        "TS_RegisteredDevice",
        "TS_SSHRuleSource",
        "TS_SSHRuleTargetsDevice",
        "TS_SSHRuleTargetsSelf",
    }
)


def _compact_kind(kind: str) -> str:
    if kind == "TailscaleBase" or kind == "Base":
        return "Base"
    if kind in TAILSCALE_RELATIONSHIP_KINDS:
        return kind.replace("Tailscale", "")
    for prefix in TAILSCALE_KIND_PREFIXES:
        if kind.startswith(prefix):
            return kind[len(prefix):]
    return kind


def bloodhound_kind(kind: str) -> str:
    """Return the BloodHound extension-prefixed form for TailscaleHound kinds."""
    if not isinstance(kind, str) or not kind:
        return kind
    has_namespace = kind.startswith(f"{NAMESPACE}_")
    local_kind = kind[len(f"{NAMESPACE}_"):] if has_namespace else kind
    compact_kind = _compact_kind(local_kind)
    if has_namespace or compact_kind != local_kind or local_kind in TAILSCALE_RELATIONSHIP_KINDS:
        return f"{NAMESPACE}_{compact_kind}"
    return kind


def is_traversable_edge(kind: str) -> bool:
    """Return whether a TailscaleHound edge kind is schema-traversable."""
    return bloodhound_kind(kind) in TRAVERSABLE_EDGE_KINDS


def apply_bloodhound_names(opengraph: dict) -> dict:
    """Prefix TailscaleHound node and relationship kinds in an OpenGraph export."""
    graph = opengraph.get("graph") if isinstance(opengraph.get("graph"), dict) else opengraph

    metadata = opengraph.get("metadata")
    if isinstance(metadata, dict) and metadata.get("source_kind"):
        metadata["source_kind"] = bloodhound_kind(metadata["source_kind"])

    for node in graph.get("nodes", []) or []:
        if not isinstance(node, dict):
            continue
        kinds = node.get("kinds")
        if isinstance(kinds, list):
            node["kinds"] = [bloodhound_kind(kind) for kind in kinds]

    for edge in graph.get("edges", []) or []:
        if isinstance(edge, dict) and edge.get("kind"):
            edge["kind"] = bloodhound_kind(edge["kind"])

    return opengraph
