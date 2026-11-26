"""Request dispatcher routing JSON requests to QuantumVaultService."""
from typing import Any

from quantumvault.core.errors import InvalidRequestError
from quantumvault.core.service import QuantumVaultService


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    """Route a single Adapter Contract v1 request to the core service."""
    if not isinstance(request, dict):
        raise InvalidRequestError("Request payload must be a JSON object")

    op = request.get("op")
    if not op or not isinstance(op, str):
        raise InvalidRequestError("Request must contain a valid string 'op' field")

    service = QuantumVaultService()
    try:
        if op == "setup":
            return service.setup(
                owners=request.get("owners", {}),
                contents=request.get("contents", {}),
                disabled=request.get("disabled", []),
                key_material=request.get("key_material", "")
            )
        elif op == "read":
            actor = request.get("actor")
            asset = request.get("asset")
            request_id = request.get("request_id")
            if not actor or not asset or not request_id:
                return {"decision": "deny"}
            return service.read(actor=str(actor), asset=str(asset), request_id=str(request_id))
        elif op == "revoke":
            actor = request.get("actor")
            if not actor:
                return {}
            return service.revoke(actor=str(actor))
        elif op == "audit":
            request_id = request.get("request_id")
            if not request_id:
                return {"error": "unknown_request"}
            return service.audit(request_id=str(request_id))
        elif op == "protected_read":
            actor = request.get("actor")
            asset = request.get("asset")
            challenge = request.get("challenge")
            public_key = request.get("public_key")
            if not actor or not asset or not challenge or not public_key:
                return {"decision": "deny"}
            return service.protected_read(
                actor=str(actor),
                asset=str(asset),
                challenge=str(challenge),
                public_key=str(public_key)
            )
        else:
            return {"error": "unsupported_operation"}
    finally:
        service.close()
