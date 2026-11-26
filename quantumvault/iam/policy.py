"""Policy Decision Point (PDP) and Policy Enforcement Point (PEP) for QuantumVault."""
from __future__ import annotations
from typing import Tuple

ROLE_HIERARCHY = {
    "viewer": 1,
    "analyst": 2,
    "auditor": 3,
    "admin": 4
}


class PolicyEngine:
    """Enforces ownership, role permissions, and revocation rules."""

    @staticmethod
    def evaluate_access(actor: str, asset: str, asset_owner: str | None, is_disabled: bool,
                        role: str = "viewer", device_id: str | None = None,
                        is_device_revoked: bool = False,
                        required_role: str | None = None) -> Tuple[str, str]:
        """Evaluate authorization for an actor/device requesting an asset or action.
        
        Returns:
            (decision: 'allow' | 'deny', rule: str)
        """
        # Rule 1: Check identity revocation / disabled status first
        if is_disabled:
            return "deny", "identity_disabled"

        # Rule 2: Check device-level revocation if device context is provided
        if device_id is not None and is_device_revoked:
            return "deny", "device_revoked"

        # Rule 3: Check role privilege requirement if specified
        if required_role is not None:
            user_level = ROLE_HIERARCHY.get(role, 0)
            req_level = ROLE_HIERARCHY.get(required_role, 0)
            if user_level < req_level:
                return "deny", "insufficient_privilege"

        # Rule 4: Check resource existence and ownership
        if asset_owner is None:
            return "deny", "owner_required"

        if asset_owner != actor:
            return "deny", "owner_required"

        # Rule 5: Authorized owner
        return "allow", "owner_allowed"
