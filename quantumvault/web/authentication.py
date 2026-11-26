"""Security and Operator Authentication for QuantumVault Web API."""
import hmac
import secrets
from fastapi import Cookie, Header, HTTPException, Request, status

# Per-server-process runtime operator token generated via CSPRNG
_OPERATOR_TOKEN = secrets.token_hex(24)
OPERATOR_COOKIE_NAME = "qv_operator_token"
SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}


def get_operator_token() -> str:
    """Return active runtime operator token."""
    return _OPERATOR_TOKEN


def rotate_operator_token() -> str:
    """Rotate active operator token via CSPRNG, immediately invalidating prior tokens."""
    global _OPERATOR_TOKEN
    _OPERATOR_TOKEN = secrets.token_hex(24)
    return _OPERATOR_TOKEN


def verify_operator_auth(
    request: Request,
    x_operator_token: str | None = Header(default=None),
    qv_operator_token: str | None = Cookie(default=None),
) -> dict[str, str | bool]:
    """Verify operator credentials via constant-time token comparison and CSRF defense.

    - State-changing requests (POST/PUT/PATCH/DELETE) MUST provide `X-Operator-Token` header
      to defend against cookie-based CSRF attacks.
    - Safe requests (GET/HEAD) accept `X-Operator-Token` or `qv_operator_token` cookie.
    """
    is_mutation = request.method.upper() not in SAFE_HTTP_METHODS
    if is_mutation:
        supplied = x_operator_token
        if not supplied:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Operator-Token header for state-changing request",
                headers={"WWW-Authenticate": "Bearer"},
            )
    else:
        supplied = x_operator_token or qv_operator_token
        if not supplied:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing operator authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if not isinstance(supplied, str) or not hmac.compare_digest(supplied.strip(), _OPERATOR_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid operator authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "identity": "sec-admin",
        "role": "SOC Administrator",
        "authorized": True,
    }
