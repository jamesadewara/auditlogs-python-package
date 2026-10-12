"""
Independent checkpoint timestamps (RFC 3161).

Each checkpoint may carry a timestamp from an independent timestamp authority
(TSA) over SHA-256 of its signed message. It proves the checkpoint existed at
the TSA's time, so an operator who holds the signing key still cannot re-sign
a rewritten history later without the timestamps giving it away.

A timestamp is valid when it is signed by a TSA chaining to a root you trust,
covers exactly this checkpoint's message, and its time lies within the
allowed delay of the checkpoint's signed_at (in either direction).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta, timezone
from pathlib import Path

import rfc3161_client
from cryptography import x509

from .errors import ConfigurationError
from .models import Checkpoint


@dataclass(frozen=True)
class AnchorPolicy:
    """Trusted TSA roots and the largest allowed gap between signed_at and the TSA time."""

    roots: Sequence[x509.Certificate]
    max_delay: timedelta

    def __post_init__(self) -> None:
        if not self.roots:
            raise ConfigurationError("at least one trusted TSA root certificate is required")
        if self.max_delay <= timedelta(0):
            raise ConfigurationError("the maximum timestamp delay must be positive")


def load_tsa_roots(path: str | Path) -> list[x509.Certificate]:
    """Read one or more PEM certificates (for example FreeTSA's cacert.pem)."""
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise ConfigurationError(f"cannot read the TSA roots file {path}: {e}") from e
    try:
        roots = x509.load_pem_x509_certificates(data)
    except ValueError as e:
        raise ConfigurationError(f"the TSA roots file {path} holds no valid PEM certificate: {e}") from e
    if not roots:
        raise ConfigurationError(f"the TSA roots file {path} holds no certificate")
    return roots


def anchor_problem(cp: Checkpoint, message: bytes, policy: AnchorPolicy) -> str | None:
    """Why the checkpoint's timestamp is not valid, or None when it verifies."""
    if cp.timestamp is None:
        return None
    try:
        der = base64.b64decode(cp.timestamp.tsa_response, validate=True)
    except (binascii.Error, ValueError):
        return "the stored TSA response is not valid base64"
    try:
        response = rfc3161_client.decode_timestamp_response(der)
    except ValueError as e:
        return f"the TSA response cannot be parsed: {e}"
    digest = hashlib.sha256(message).digest()
    builder = rfc3161_client.VerifierBuilder()
    for root in policy.roots:
        builder = builder.add_root_certificate(root)
    try:
        builder.build().verify(response, digest)
    except rfc3161_client.VerificationError as e:
        return f"the timestamp does not verify: {e}"
    gen_time = response.tst_info.gen_time.astimezone(timezone.utc)
    stored = cp.timestamp.gen_time.astimezone(timezone.utc)
    if gen_time != stored:
        return f"the stored time {stored.isoformat()} differs from the signed TSA time {gen_time.isoformat()}"
    gap = gen_time - cp.signed_at.astimezone(timezone.utc)
    if abs(gap) > policy.max_delay:
        return (
            f"the TSA time {gen_time.isoformat()} is {abs(gap)} away from signed_at "
            f"{cp.signed_at.astimezone(timezone.utc).isoformat()} (allowed {policy.max_delay})"
        )
    return None
