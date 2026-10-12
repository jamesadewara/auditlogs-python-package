"""Errors raised by auditlogs-verify. A TAMPERED chain is a result, not an error."""


class VerifierError(Exception):
    """Base class for every error raised by this package."""


class ConfigurationError(VerifierError, ValueError):
    """The trusted keys or arguments are unusable (empty key set, bad base64, wrong key length)."""


class BundleError(VerifierError, ValueError):
    """The audit bundle file is missing, unreadable or does not match the documented format."""
