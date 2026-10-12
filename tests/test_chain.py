"""
Local verification must agree with the Go service's verifier: same hashes,
same signed message bytes, and the same failure kind at the same seq.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from auditlogs_verify import ConfigurationError, verify_chain
from auditlogs_verify.chain import checkpoint_message, event_hash, genesis_hash, load_trusted_keys
from auditlogs_verify.models import Checkpoint

from .conftest import Signer, build_chain, make_event, payload

# Golden values pinned by the Go service's tests
# (internal/core/hashchain/chain_test.go and checkpoint_test.go).
GOLDEN_AUDIT = UUID("11111111-1111-1111-1111-111111111111")
GOLDEN_GENESIS = "8ca77dd1315d327e91d6b15196511eedde02397f45160ffa71a066552382f072"
GOLDEN_HASH = "5b77a6063c22ba83c213f05cc90c654a7a4e4263d2655dcb0f09da5da6f7facb"
GOLDEN_PAYLOAD = (
    r'{"audit_id":"11111111-1111-1111-1111-111111111111","schema_version":1,"seq":2,'
    r'"prev_hash":"8ca77dd1315d327e91d6b15196511eedde02397f45160ffa71a066552382f072","hash":"",'
    r'"recorded_at":"2026-10-12T09:00:00.123456Z","occurred_at":"2026-10-12T08:59:59Z",'
    r'"actor":{"id":"u-1","ip":"10.0.0.1","type":"user"},"action":"order.created","outcome":"success",'
    r'"summary":"Order \u003c42\u003e \u0026 co","resource":{"id":"42","type":"order"},'
    r'"changes":{"after":{"a":["x",null,true],"z":1.5}},"metadata":{"big":12345678901234567000,"k":"v"},'
    r'"idempotency_key":"idem-1"}'
)


# ── Parity with the Go implementation ────────────────────────────────────────


def test_genesis_matches_go() -> None:
    assert genesis_hash(GOLDEN_AUDIT) == GOLDEN_GENESIS


def test_event_hash_matches_go() -> None:
    assert event_hash(GOLDEN_GENESIS, GOLDEN_PAYLOAD) == GOLDEN_HASH


def test_event_hash_rejects_malformed_previous_hash() -> None:
    with pytest.raises(ValueError, match="64-character lowercase hex"):
        event_hash(GOLDEN_GENESIS.upper(), GOLDEN_PAYLOAD)


def test_checkpoint_message_matches_go() -> None:
    cp = Checkpoint(
        id=uuid4(),
        audit_id=GOLDEN_AUDIT,
        kind="retention",
        last_seq=9,
        last_hash=GOLDEN_HASH,
        first_retained_seq=10,
        signature="AA==",
        key_id="ckpt-2026",
        signed_at=datetime(2026, 10, 12, 9, 0, 0, 123456, tzinfo=timezone.utc),
    )
    assert (
        checkpoint_message(cp)
        == (
            "auditlogs-checkpoint-v1\nkind=retention\naudit_id=11111111-1111-1111-1111-111111111111\n"
            f"last_seq=9\nlast_hash={GOLDEN_HASH}\nfirst_retained_seq=10\n"
            "signed_at=2026-10-12T09:00:00.123456Z\nkey_id=ckpt-2026\n"
        ).encode()
    )


# ── Intact chains ────────────────────────────────────────────────────────────


def run(audit_id: UUID, events, checkpoints, signer: Signer):  # type: ignore[no-untyped-def]
    return verify_chain(
        audit_id=audit_id,
        slug="orders",
        events=events,
        checkpoints=checkpoints,
        trusted_keys=load_trusted_keys(signer.trusted()),
        anchor_policy=None,  # these tests are about the chain; timestamps have their own tests
    )


def test_intact_chain_with_checkpoint(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 5)
    cps = [signer.checkpoint(audit_id, "periodic", 3, events[2].hash)]
    report = run(audit_id, events, cps, signer)
    assert report.intact
    assert (report.events_checked, report.first_sequence, report.last_sequence) == (5, 1, 5)
    assert report.last_hash == events[-1].hash
    assert report.checkpoints_checked == 1
    assert report.failure is None


def test_empty_audit_is_intact_at_genesis(audit_id: UUID, signer: Signer) -> None:
    report = run(audit_id, [], [], signer)
    assert report.intact
    assert report.last_sequence == 0
    assert report.last_hash == genesis_hash(audit_id)


def test_retention_anchor_explains_removed_prefix(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 6)
    anchor = signer.checkpoint(audit_id, "retention", 3, events[2].hash)
    report = run(audit_id, events[3:], [anchor], signer)
    assert report.intact
    assert report.first_sequence == 4
    assert report.anchor is not None and report.anchor.first_retained_seq == 4


# ── Tamper detection (exact kind and seq) ────────────────────────────────────


def test_edited_field_is_modified_at_its_seq(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 5)
    edited = events[2].canonical_payload.replace("order.created", "order.deleted")
    events[2] = events[2].model_copy(update={"canonical_payload": edited})
    report = run(audit_id, events, [], signer)
    assert report.status == "TAMPERED"
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("MODIFIED", 3)
    assert report.failure.message == "payload at seq 3 does not hash to the stored hash"


def test_deleted_middle_event_is_a_gap(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 5)
    del events[2]
    report = run(audit_id, events, [], signer)
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("GAP", 3)
    assert report.failure.message == "expected seq 3 but the next stored event is seq 4"


def test_deleted_tail_is_truncated_against_checkpoint(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 5)
    cps = [signer.checkpoint(audit_id, "periodic", 5, events[4].hash)]
    report = run(audit_id, events[:3], cps, signer)
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("TRUNCATED", 4)
    assert report.failure.message == "signed checkpoint covers seq 5 but stored events end at seq 3"


def test_reordered_pair_is_detected_at_first_swap(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 5)
    events[1], events[2] = events[2], events[1]
    report = run(audit_id, events, [], signer)
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("GAP", 2)


def test_recomputed_chain_without_key_mismatches_checkpoint(audit_id: UUID, signer: Signer) -> None:
    original = build_chain(audit_id, 5)
    cps = [signer.checkpoint(audit_id, "periodic", 4, original[3].hash)]
    # An attacker rewrites seq 2 and recomputes every later hash, but cannot re-sign.
    forged = original[:1]
    prev = original[0].hash
    for seq in range(2, 6):
        extra = {"note": "forged"} if seq == 2 else {}
        e = make_event(audit_id, seq, prev, payload(audit_id, seq, prev, **extra))
        forged.append(e)
        prev = e.hash
    report = run(audit_id, forged, cps, signer)
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("CHECKPOINT_MISMATCH", 4)
    assert report.failure.expected_hash == original[3].hash
    assert report.failure.found_hash == forged[3].hash


def test_broken_link_reports_expected_and_found(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 3)
    events[2] = events[2].model_copy(update={"prev_hash": "0" * 64})
    report = run(audit_id, events, [], signer)
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("BROKEN_LINK", 3)
    assert report.failure.expected_hash == events[1].hash
    assert report.failure.found_hash == "0" * 64


def test_prefix_deleted_without_anchor_is_gap_at_1(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 5)
    report = run(audit_id, events[2:], [], signer)
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("GAP", 1)
    assert "records from seq 1 to 2 are missing" in report.failure.message


def test_payload_moved_from_another_audit_is_modified(audit_id: UUID, signer: Signer) -> None:
    other = uuid4()
    prev = genesis_hash(audit_id)
    foreign = make_event(audit_id, 1, prev, payload(other, 1, prev))
    report = run(audit_id, [foreign], [], signer)
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("MODIFIED", 1)
    assert report.failure.message == "payload at seq 1 names a different audit"


def test_forged_signature_is_bad_checkpoint(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 3)
    attacker = Signer(signer.key_id)  # same key id, different key
    cps = [attacker.checkpoint(audit_id, "periodic", 2, events[1].hash)]
    report = run(audit_id, events, cps, signer)
    assert report.failure is not None
    assert (report.failure.kind, report.failure.seq) == ("BAD_CHECKPOINT", 2)
    assert report.failure.message.endswith("signature does not verify")
    assert report.checkpoints_checked == 0


def test_unknown_key_id_is_bad_checkpoint(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 2)
    cps = [Signer("ckpt-other").checkpoint(audit_id, "periodic", 2, events[1].hash)]
    report = run(audit_id, events, cps, signer)
    assert report.failure is not None
    assert report.failure.kind == "BAD_CHECKPOINT"
    assert "unknown key id 'ckpt-other'" in report.failure.message


def test_checkpoint_for_another_audit_is_bad_checkpoint(audit_id: UUID, signer: Signer) -> None:
    events = build_chain(audit_id, 2)
    cps = [signer.checkpoint(uuid4(), "periodic", 2, events[1].hash)]
    report = run(audit_id, events, cps, signer)
    assert report.failure is not None
    assert report.failure.kind == "BAD_CHECKPOINT"
    assert "belongs to audit" in report.failure.message


# ── Trusted keys ─────────────────────────────────────────────────────────────


def test_trusted_keys_must_not_be_empty() -> None:
    with pytest.raises(ConfigurationError, match="at least one trusted"):
        load_trusted_keys({})


def test_trusted_key_must_be_32_bytes() -> None:
    with pytest.raises(ConfigurationError, match="must decode to 32 bytes, got 3"):
        load_trusted_keys({"k1": base64.b64encode(b"abc").decode()})


def test_trusted_key_must_be_base64() -> None:
    with pytest.raises(ConfigurationError, match="not valid base64"):
        load_trusted_keys({"k1": "not base64!!"})
