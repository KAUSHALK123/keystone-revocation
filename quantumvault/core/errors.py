"""Standard exceptions for QuantumVault."""


class QuantumVaultError(Exception):
    """Base exception for all QuantumVault errors."""
    pass


class AuthorizationError(QuantumVaultError):
    """Raised when access is denied by policy or ownership verification."""
    def __init__(self, message: str = "Access denied", rule: str = "unknown"):
        super().__init__(message)
        self.rule = rule


class ResourceNotFoundError(QuantumVaultError):
    """Raised when a requested asset is not found."""
    pass


class StateError(QuantumVaultError):
    """Raised when persistent state is invalid or inaccessible."""
    pass


class CryptoError(QuantumVaultError):
    """Raised when cryptographic operations fail."""
    pass


class InvalidRequestError(QuantumVaultError):
    """Raised when an incoming request fails structural or schema validation."""
    pass


class AuthenticationError(QuantumVaultError):
    """Raised when authentication or proof-of-possession fails."""
    pass


class IdentityError(QuantumVaultError):
    """Raised when an identity or device operation fails."""
    pass


class SecurityPolicyError(QuantumVaultError):
    """Raised when a security policy invariant or forward secrecy constraint is violated."""
    pass
