"""
Data the verifier reads and the report it produces.

Input models accept the objects exactly as the AuditLogs API returns them
(events from GET /v1/audits/{slug}/events, checkpoints from
GET /v1/audits/{slug}/checkpoints) and ignore fields the verifier does not
need. A missing or mistyped field the verifier does need is an error, never
defaulted.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

HASH_PATTERN = r"^[0-9a-f]{64}$"
BUNDLE_FORMAT = "auditlogs-bundle-v1"


class _Input(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class StoredEvent(_Input):
    """
    One stored chain record. ``canonical_payload`` is the exact text that was
    hashed: ``hash == sha256(prev_hash + canonical_payload)``, with the
    genesis hash in place of ``prev_hash`` for seq 1 (stored as null).
    """

    seq: int = Field(ge=1)
    prev_hash: str | None = Field(default=None, pattern=HASH_PATTERN)
    hash: str = Field(pattern=HASH_PATTERN)
    canonical_payload: str = Field(min_length=2)


class CheckpointTimestamp(_Input):
    """An RFC 3161 timestamp of a checkpoint from an independent timestamp authority."""

    tsa_url: str = Field(min_length=1)
    gen_time: datetime
    tsa_response: str = Field(min_length=1, description="Standard base64 of the DER TimeStampResp")


class Checkpoint(_Input):
    """A signed statement of the chain's hash at ``last_seq``."""

    id: UUID
    audit_id: UUID
    kind: Literal["periodic", "retention"]
    last_seq: int = Field(ge=1)
    last_hash: str = Field(pattern=HASH_PATTERN)
    first_retained_seq: int | None = None
    signature: str = Field(min_length=1, description="Standard base64 Ed25519 signature")
    key_id: str = Field(min_length=1)
    signed_at: datetime
    timestamp: CheckpointTimestamp | None = None

    @model_validator(mode="after")
    def _retention_fields(self) -> Checkpoint:
        if self.kind == "retention" and self.first_retained_seq != self.last_seq + 1:
            raise ValueError("a retention checkpoint needs first_retained_seq = last_seq + 1")
        if self.kind == "periodic" and self.first_retained_seq is not None:
            raise ValueError("a periodic checkpoint has no first_retained_seq")
        return self


class Bundle(_Input):
    """
    Everything needed to verify one audit offline. See docs/SPEC.md.

    Events may be in any order; they are verified in seq order. A seq that
    appears twice must be identical both times (paging can repeat a record).
    """

    format: Literal["auditlogs-bundle-v1"]
    audit_id: UUID
    slug: str = Field(min_length=1)
    events: list[StoredEvent]
    checkpoints: list[Checkpoint]


FailureKind = Literal[
    "GAP", "BROKEN_LINK", "MODIFIED", "BAD_CHECKPOINT", "CHECKPOINT_MISMATCH", "TRUNCATED", "BAD_ANCHOR"
]


class VerificationFailure(BaseModel):
    """The first break found. ``seq`` is where the chain stops being trustworthy."""

    model_config = ConfigDict(frozen=True)

    kind: FailureKind
    seq: int
    expected_hash: str | None = None
    found_hash: str | None = None
    message: str


class VerificationAnchor(BaseModel):
    """The signed retention checkpoint the walk started from."""

    model_config = ConfigDict(frozen=True)

    last_seq: int
    last_hash: str
    first_retained_seq: int


class VerificationReport(BaseModel):
    """Same shape as the service's GET /v1/audits/{slug}/verify response."""

    model_config = ConfigDict(frozen=True)

    status: Literal["INTACT", "TAMPERED"]
    slug: str
    audit_id: UUID
    events_checked: int = Field(ge=0)
    first_sequence: int = Field(ge=0)
    last_sequence: int = Field(ge=0)
    last_hash: str
    checkpoints_checked: int = Field(ge=0)
    # Independent timestamps: how many verified, and how many checkpoints have none.
    # timestamps_checked is False when the caller chose not to check them.
    anchors_checked: int = Field(ge=0)
    checkpoints_unanchored: int = Field(ge=0)
    timestamps_checked: bool
    anchor: VerificationAnchor | None = None
    failure: VerificationFailure | None = None

    @model_validator(mode="after")
    def _consistent(self) -> VerificationReport:
        if (self.status == "TAMPERED") != (self.failure is not None):
            raise ValueError("a TAMPERED report must carry a failure and an INTACT one must not")
        return self

    @property
    def intact(self) -> bool:
        return self.status == "INTACT"
