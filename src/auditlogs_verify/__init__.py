"""
auditlogs-verify: check an AuditLogs audit yourself, without trusting the service.

It recomputes the hash chain from the stored payloads and checks the Ed25519
checkpoint signatures against public keys you pinned. Everything else in
AuditLogs is plain HTTP and needs no library. The format is specified in
docs/SPEC.md.

    from auditlogs_verify import load_bundle, load_trusted_keys, read_key_file, verify_bundle

    report = verify_bundle(load_bundle("audit.json"), load_trusted_keys(read_key_file("keys.json")),
                           anchor_policy=AnchorPolicy(load_tsa_roots("tsa-root.pem"), timedelta(days=1)))
    if not report.intact:
        print(report.failure.kind, report.failure.seq, report.failure.message)
"""

from ._version import __version__
from .anchors import AnchorPolicy, anchor_problem, load_tsa_roots
from .bundle import load_bundle, parse_bundle, read_key_file
from .chain import (
    ChainVerifier,
    checkpoint_message,
    event_hash,
    genesis_hash,
    load_trusted_keys,
    verify_bundle,
    verify_chain,
)
from .errors import BundleError, ConfigurationError, VerifierError
from .models import (
    Bundle,
    Checkpoint,
    StoredEvent,
    VerificationAnchor,
    VerificationFailure,
    VerificationReport,
)

__all__ = [
    "__version__",
    "load_bundle",
    "parse_bundle",
    "read_key_file",
    "load_trusted_keys",
    "AnchorPolicy",
    "load_tsa_roots",
    "anchor_problem",
    "verify_bundle",
    "verify_chain",
    "ChainVerifier",
    "genesis_hash",
    "event_hash",
    "checkpoint_message",
    "Bundle",
    "StoredEvent",
    "Checkpoint",
    "VerificationReport",
    "VerificationFailure",
    "VerificationAnchor",
    "VerifierError",
    "ConfigurationError",
    "BundleError",
]
