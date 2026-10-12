"""
Shared test helpers: a real hash chain built with the documented formula and
real Ed25519 checkpoint signatures from a key generated per test run. No test
reads a developer's keys or .env.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from auditlogs_verify.chain import checkpoint_message, event_hash, genesis_hash
from auditlogs_verify.models import Checkpoint, StoredEvent

T0 = datetime(2026, 10, 12, 9, 0, 0, 123456, tzinfo=timezone.utc)


@dataclass
class Signer:
    key_id: str
    private: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    @property
    def public_b64(self) -> str:
        raw = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def trusted(self) -> dict[str, str]:
        return {self.key_id: self.public_b64}

    def checkpoint(
        self, audit_id: UUID, kind: Literal["periodic", "retention"], last_seq: int, last_hash: str
    ) -> Checkpoint:
        unsigned = Checkpoint(
            id=uuid4(),
            audit_id=audit_id,
            kind=kind,
            last_seq=last_seq,
            last_hash=last_hash,
            first_retained_seq=last_seq + 1 if kind == "retention" else None,
            signature="AA==",
            key_id=self.key_id,
            signed_at=T0 + timedelta(seconds=last_seq),
        )
        sig = base64.b64encode(self.private.sign(checkpoint_message(unsigned))).decode()
        return unsigned.model_copy(update={"signature": sig})


def payload(audit_id: UUID, seq: int, prev: str, **extra: Any) -> str:
    """A canonical-looking payload; verification hashes whatever text is stored."""
    body = {"audit_id": str(audit_id), "seq": seq, "prev_hash": prev, "hash": "", "action": "order.created"}
    body.update(extra)
    return json.dumps(body, separators=(",", ":"), sort_keys=False)


def make_event(audit_id: UUID, seq: int, prev: str, text: str) -> StoredEvent:
    return StoredEvent(
        seq=seq,
        prev_hash=None if seq == 1 else prev,
        hash=event_hash(prev, text),
        canonical_payload=text,
    )


def build_chain(
    audit_id: UUID, n: int, start_seq: int = 1, start_prev: str | None = None
) -> list[StoredEvent]:
    prev = start_prev if start_prev is not None else genesis_hash(audit_id)
    events = []
    for seq in range(start_seq, start_seq + n):
        e = make_event(audit_id, seq, prev, payload(audit_id, seq, prev))
        events.append(e)
        prev = e.hash
    return events


def event_json(e: StoredEvent) -> dict[str, Any]:
    return e.model_dump(mode="json")


def checkpoint_json(c: Checkpoint) -> dict[str, Any]:
    return c.model_dump(mode="json", exclude_none=True)


@pytest.fixture
def audit_id() -> UUID:
    return uuid4()


@pytest.fixture
def signer() -> Signer:
    return Signer("ckpt-test")
