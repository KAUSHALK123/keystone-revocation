"""Request dispatcher routing JSON requests to QuantumVaultService."""
from typing import Any

from quantumvault.core.errors import InvalidRequestError
from quantumvault.core.service import QuantumVaultService


def _is_nonempty_str(val: Any) -> bool:
    return isinstance(val, str) and len(val) > 0


def _validate_str_mapping(val: Any, field_name: str) -> dict[str, str]:
    if val is None:
        return {}
    if not isinstance(val, dict):
        raise InvalidRequestError(f"Field '{field_name}' must be an object mapping strings to strings")
    for k, v in val.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise InvalidRequestError(f"Field '{field_name}' keys and values must be strings")
    return val


def _validate_str_list(val: Any, field_name: str) -> list[str]:
    if val is None:
        return []
    if not isinstance(val, list):
        raise InvalidRequestError(f"Field '{field_name}' must be a list of strings")
    for item in val:
        if not isinstance(item, str):
            raise InvalidRequestError(f"Field '{field_name}' items must be strings")
    return val


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    """Route a single Adapter Contract v1 request to the core service."""
    if not isinstance(request, dict):
        raise InvalidRequestError("Request payload must be a JSON object")

    op = request.get("op")
    if not _is_nonempty_str(op):
        raise InvalidRequestError("Request must contain a valid string 'op' field")

    service = QuantumVaultService()
    try:
        if op == "setup":
            owners = _validate_str_mapping(request.get("owners"), "owners")
            contents = _validate_str_mapping(request.get("contents"), "contents")
            disabled = _validate_str_list(request.get("disabled", []), "disabled")
            key_material = request.get("key_material")
            if not isinstance(key_material, str) or not key_material:
                raise InvalidRequestError("Setup 'key_material' must be a non-empty string")
            return service.setup(
                owners=owners,
                contents=contents,
                disabled=disabled,
                key_material=key_material,
            )
        elif op == "read":
            actor = request.get("actor")
            asset = request.get("asset")
            request_id = request.get("request_id")
            if not (_is_nonempty_str(actor) and _is_nonempty_str(asset) and _is_nonempty_str(request_id)):
                return {"decision": "deny"}
            return service.read(actor=actor, asset=asset, request_id=request_id)
        elif op == "revoke":
            actor = request.get("actor")
            if actor is not None and not isinstance(actor, str):
                raise InvalidRequestError("Revoke 'actor' must be a string")
            if not actor:
                return {}
            return service.revoke(actor=actor)
        elif op == "audit":
            request_id = request.get("request_id")
            if request_id is not None and not isinstance(request_id, str):
                return {"error": "unknown_request"}
            if not request_id:
                return {"error": "unknown_request"}
            return service.audit(request_id=request_id)
        elif op == "protected_read":
            actor = request.get("actor")
            asset = request.get("asset")
            challenge = request.get("challenge")
            public_key = request.get("public_key")
            if not (
                _is_nonempty_str(actor)
                and _is_nonempty_str(asset)
                and _is_nonempty_str(challenge)
                and _is_nonempty_str(public_key)
            ):
                return {"decision": "deny"}
            return service.protected_read(
                actor=actor,
                asset=asset,
                challenge=challenge,
                public_key=public_key,
            )
        else:
            return {"error": "unsupported_operation"}
    finally:
        service.close()
