"""
Checkpoint timestamps, checked against a real FreeTSA reply.

fixtures/anchor-checkpoint.tsr is FreeTSA's answer for SHA-256 of the message
of the checkpoint in fixtures/anchor-checkpoint.json (signed one second
before the TSA time); fixtures/freetsa-root.pem is FreeTSA's published root.
The same fixture is checked by the Go service's tests.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from auditlogs_verify import AnchorPolicy, ConfigurationError, load_tsa_roots
from auditlogs_verify.anchors import anchor_problem
from auditlogs_verify.chain import checkpoint_message
from auditlogs_verify.models import Checkpoint

FIX = Path(__file__).parent / "fixtures"
TSA_TIME = datetime(2026, 10, 12, 11, 35, 2, tzinfo=timezone.utc)


def fixture_checkpoint(**changes: object) -> Checkpoint:
    data = json.loads((FIX / "anchor-checkpoint.json").read_text())["checkpoint"]
    data["timestamp"] = {
        "tsa_url": "https://freetsa.org/tsr",
        "gen_time": TSA_TIME.isoformat(),
        "tsa_response": base64.b64encode((FIX / "anchor-checkpoint.tsr").read_bytes()).decode(),
    }
    data.update(changes)
    return Checkpoint.model_validate(data)


def policy(max_delay: timedelta = timedelta(hours=1)) -> AnchorPolicy:
    return AnchorPolicy(load_tsa_roots(FIX / "freetsa-root.pem"), max_delay)


def check(cp: Checkpoint, p: AnchorPolicy | None = None) -> str | None:
    return anchor_problem(cp, checkpoint_message(cp), p or policy())


def test_a_real_freetsa_timestamp_verifies() -> None:
    assert check(fixture_checkpoint()) is None


def test_a_timestamp_of_another_checkpoint_is_rejected() -> None:
    problem = check(fixture_checkpoint(last_seq=6))
    assert problem is not None and problem.startswith("the timestamp does not verify")


def test_a_timestamp_long_after_signing_is_rejected() -> None:
    problem = check(fixture_checkpoint(), policy(timedelta(milliseconds=500)))
    assert problem is not None and "away from signed_at" in problem


def test_an_edited_stored_time_is_rejected() -> None:
    cp = fixture_checkpoint()
    assert cp.timestamp is not None
    edited = cp.timestamp.model_copy(update={"gen_time": TSA_TIME - timedelta(minutes=1)})
    cp = cp.model_copy(update={"timestamp": edited})
    problem = check(cp)
    assert problem is not None and "differs from the signed TSA time" in problem


def test_an_untrusted_tsa_is_rejected() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some Other Root")])
    other = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2020, 1, 1))
        .not_valid_after(datetime(2040, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    problem = check(fixture_checkpoint(), AnchorPolicy([other], timedelta(hours=1)))
    assert problem is not None and problem.startswith("the timestamp does not verify")


def test_policy_needs_roots_and_a_positive_delay() -> None:
    with pytest.raises(ConfigurationError, match="at least one trusted TSA root"):
        AnchorPolicy([], timedelta(hours=1))
    with pytest.raises(ConfigurationError, match="must be positive"):
        AnchorPolicy(load_tsa_roots(FIX / "freetsa-root.pem"), timedelta(0))
