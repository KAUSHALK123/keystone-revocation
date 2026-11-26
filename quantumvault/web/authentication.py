"""Security and Operator Authentication for QuantumVault Web API."""
import hmac
import secrets
from fastapi import Cookie, Header, HTTPException, status

# Per-server-process runtime operator token generated via CSPRNG
_OPERATOR_TOKEN = secrets.token_hex(24)
OPERATOR_COOKIE_NAME = "qv_operator_token"


def get_operator_token() -> str:
    """Return active runtime operator token."""
    return _OPERATOR_TOKEN


def rotate_operator_token() -> str:
    """Generate and activate a fresh runtime operator token."""
    global _OPERATOR_TOKEN
    _OPERATOR_TOKEN = secrets.token_hex(24)
    return _OPERATOR_TOKEN


def verify_operator_auth(
    x_operator_token: str | None = Header(default=None),
    qv_operator_token: str | None = Cookie(default=None),
) -> dict[str, str | bool]:
    """Verify operator credentials via constant-time token comparison.

    Accepts either:
    - `X-Operator-Token` header (API clients, dashboard fetch, tests)
    - `qv_operator_token` HttpOnly SameSite=Strict cookie (served with dashboard HTML)

    Rejects missing or invalid credentials with 401 Unauthorized.
    """
    supplied = x_operator_token or qv_operator_token
    if not supplied or not isinstance(supplied, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing operator authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not hmac.compare_digest(supplied.strip(), _OPERATOR_TOKEN):
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
