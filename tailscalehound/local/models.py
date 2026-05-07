"""
Deprecated: use tailscalehound.models for shared data models.
This module re-exports the shared models for backward compatibility.
"""

from ..models import (
    Node,
    TailscaleNetwork,
    User,
    TailnetKey,
    TailnetWebhook,
    TailnetService,
    TailnetUserInvite,
    TailnetDeviceInvite,
)

__all__ = [
    "User",
    "Node",
    "TailscaleNetwork",
    "TailnetKey",
    "TailnetWebhook",
    "TailnetService",
    "TailnetUserInvite",
    "TailnetDeviceInvite",
]
