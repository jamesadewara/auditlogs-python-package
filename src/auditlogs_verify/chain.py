"""
Independent verification of an audit's hash chain and signed checkpoints.

This mirrors the service's verifier (``internal/core/hashchain`` in the Go
service) so a customer can check their audit without trusting the service's
own ``/verify`` answer:

    genesis      = sha256("GENESIS" + audit_id)              (hex)
    hash(seq n)  = sha256(hash(seq n-1) + canonical_payload)  (hex)

``canonical_payload`` is the exact text the service hashed and returns with
each event, so nothing is re-serialised here. Checkpoints are Ed25519
signatures over the "auditlogs-checkpoint-v1" message below, checked against
public keys you trust. Pass keys you obtained out of band (pinned in your
configuration); keys fetched from the same service you are checking only prove
consistency with that service.

The first break is reported with its kind and exact sequence number:
GAP, BROKEN_LINK, MODIFIED, BAD_CHECKPOINT, CHECKPOINT_MISMATCH or TRUNCATED.

Limitation: when decoding a payload to confirm its audit_id, seq and
prev_hash, field names are matched exactly. The Go service matches them
case-insensitively, so for a hand-crafted payload with oddly cased keys this
check is stricter than the service's.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timezone
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .anchors import AnchorPolicy, anchor_problem
from .errors import ConfigurationError
from .models import (
    Bundle,
    Checkpoint,
    FailureKind,
    StoredEvent,
    VerificationAnchor,
    VerificationFailure,
    VerificationReport,
)

MESSAGE_VERSION = "auditlogs-checkpoint-v1"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ED25519_PUBLIC_KEY_LEN = 32
_ED25519_SIGNATURE_LEN = 64


# ── Primitives ───────────────────────────────────────────────────────────────


def genesis_hash(audit_id: UUID) -> str:
    """The hash that seq 1 links to."""
    return hashlib.sha256(b"GENESIS" + str(audit_id).encode("ascii")).hexdigest()


def event_hash(prev_hash: str, canonical_payload: str) -> str:
    """sha256(prev_hash + canonical_payload). prev_hash must be a 64-character lowercase hex digest."""
    if not _HASH.match(prev_hash):
        raise ValueError(f"previous hash {prev_hash!r} is not a 64-character lowercase hex digest")
    return hashlib.sha256(prev_hash.encode("ascii") + canonical_payload.encode("utf-8")).hexdigest()


class InvalidCheckpointError(ValueError):
    """A checkpoint's fields cannot form a valid signed message."""


def checkpoint_message(cp: Checkpoint) -> bytes:
    """The exact bytes the service signed for this checkpoint."""
    if not _HASH.match(cp.last_hash):
        raise InvalidCheckpointError("last_hash is not a 64-character lowercase hex digest")
    if cp.last_seq < 1:
        raise InvalidCheckpointError(f"last_seq must be at least 1, got {cp.last_seq}")
    if not _KEY_ID.match(cp.key_id):
        raise InvalidCheckpointError(f"key_id {cp.key_id!r} has an invalid format")
    if cp.signed_at.tzinfo is None:
        raise InvalidCheckpointError("signed_at has no timezone")
    if cp.kind == "periodic":
        if cp.first_retained_seq is not None:
            raise InvalidCheckpointError("a periodic checkpoint has no first_retained_seq")
        first_retained = "none"
    else:
        if cp.first_retained_seq != cp.last_seq + 1:
            raise InvalidCheckpointError("a retention checkpoint needs first_retained_seq = last_seq + 1")
        first_retained = str(cp.first_retained_seq)
    signed_at = cp.signed_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return (
        f"{MESSAGE_VERSION}\nkind={cp.kind}\naudit_id={cp.audit_id}\nlast_seq={cp.last_seq}\n"
        f"last_hash={cp.last_hash}\nfirst_retained_seq={first_retained}\n"
        f"signed_at={signed_at}\nkey_id={cp.key_id}\n"
    ).encode()


# ── Trusted keys ─────────────────────────────────────────────────────────────

TrustedKeys = Mapping[str, Ed25519PublicKey]


def load_trusted_keys(keys: Mapping[str, str]) -> dict[str, Ed25519PublicKey]:
    """
    Build the key ring from ``{key_id: base64 public key}``.
    An empty or malformed key set is an error, never an empty ring.
    """
    pairs = dict(keys)
    if not pairs:
        raise ConfigurationError("at least one trusted checkpoint public key is required")
    ring: dict[str, Ed25519PublicKey] = {}
    for key_id, encoded in pairs.items():
        if not isinstance(key_id, str) or not _KEY_ID.match(key_id):
            raise ConfigurationError(f"checkpoint key id {key_id!r} has an invalid format")
        if not isinstance(encoded, str):
            raise ConfigurationError(f"checkpoint key {key_id!r} must be a base64 string")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as e:
            raise ConfigurationError(f"checkpoint key {key_id!r} is not valid base64: {e}") from e
        if len(raw) != _ED25519_PUBLIC_KEY_LEN:
            raise ConfigurationError(
                f"checkpoint key {key_id!r} must decode to {_ED25519_PUBLIC_KEY_LEN} bytes, got {len(raw)}"
            )
        ring[key_id] = Ed25519PublicKey.from_public_bytes(raw)
    return ring


def checkpoint_problem(cp: Checkpoint, audit_id: UUID, ring: TrustedKeys) -> str | None:
    """Why this checkpoint cannot be trusted, or None when its signature verifies."""
    if cp.audit_id != audit_id:
        return f"checkpoint at seq {cp.last_seq} belongs to audit {cp.audit_id}"
    try:
        message = checkpoint_message(cp)
    except InvalidCheckpointError as e:
        return f"checkpoint at seq {cp.last_seq} is not trustworthy: invalid checkpoint: {e}"
    key = ring.get(cp.key_id)
    if key is None:
        return (
            f"checkpoint at seq {cp.last_seq} is not trustworthy: signed with an unknown key id {cp.key_id!r}"
        )
    try:
        signature = base64.b64decode(cp.signature, validate=True)
    except (binascii.Error, ValueError):
        signature = b""
    try:
        if len(signature) != _ED25519_SIGNATURE_LEN:
            raise InvalidSignature()
        key.verify(signature, message)
    except InvalidSignature:
        return f"checkpoint at seq {cp.last_seq} is not trustworthy: signature does not verify"
    return None


# ── Verifier ─────────────────────────────────────────────────────────────────


class _Number(str):
    """A JSON integer kept as its literal text, so seq is compared exactly as written."""


@dataclass
class _Start:
    prev_hash: str
    anchor: Checkpoint | None


class ChainVerifier:
    """
    Streaming verifier: call ``feed`` with events in ascending seq order, then
    ``finish``. It never needs the whole chain in memory. Single use.
    """

    def __init__(
        self,
        *,
        audit_id: UUID,
        slug: str,
        checkpoints: Sequence[Checkpoint],
        trusted_keys: TrustedKeys,
        anchor_policy: AnchorPolicy | None,
    ) -> None:
        if not trusted_keys:
            raise ConfigurationError("at least one trusted checkpoint public key is required")
        self._audit_id = audit_id
        self._slug = slug
        self._genesis = genesis_hash(audit_id)
        self._failure: VerificationFailure | None = None
        self._checkpoints: list[Checkpoint] = sorted(checkpoints, key=lambda c: c.last_seq)
        self._checkpoints_checked = 0
        self._by_seq: dict[int, list[Checkpoint]] = {}
        self._starts: dict[int, _Start] = {1: _Start(self._genesis, None)}
        self._base_seq = 0
        self._base_hash = self._genesis
        self._started = False
        self._expected = 0
        self._prev = ""
        self._events_checked = 0
        self._first_seq = 0
        self._last_seq = 0
        self._last_hash = ""
        self._anchor: Checkpoint | None = None
        self._finished = False
        # None means the caller chose not to check timestamps; the report says so.
        self._anchor_policy = anchor_policy
        self._anchors_checked = 0
        self._unanchored = 0

        for cp in self._checkpoints:
            problem = checkpoint_problem(cp, audit_id, trusted_keys)
            if problem is not None:
                self._fail("BAD_CHECKPOINT", cp.last_seq, problem)
                return
        self._checkpoints_checked = len(self._checkpoints)
        for cp in self._checkpoints:
            if cp.kind == "retention":
                self._starts[cp.last_seq + 1] = _Start(cp.last_hash, cp)
                if cp.last_seq > self._base_seq:
                    self._base_seq, self._base_hash = cp.last_seq, cp.last_hash
            self._by_seq.setdefault(cp.last_seq, []).append(cp)

    @property
    def failed(self) -> bool:
        return self._failure is not None

    def _fail(
        self,
        kind: FailureKind,
        seq: int,
        message: str,
        expected: str | None = None,
        found: str | None = None,
    ) -> None:
        self._failure = VerificationFailure(
            kind=kind,
            seq=seq,
            expected_hash=expected or None,
            found_hash=found or None,
            message=message,
        )

    def feed(self, event: StoredEvent) -> bool:
        """Check one event. Returns False once the chain is broken; stop feeding then."""
        if self._finished:
            raise RuntimeError("this verifier has already finished")
        if self.failed:
            return False
        if not self._started:
            self._started = True
            if not self._begin(event.seq):
                return False

        if event.seq != self._expected:
            self._fail(
                "GAP",
                self._expected,
                f"expected seq {self._expected} but the next stored event is seq {event.seq}",
            )
            return False

        stored_prev = ""
        if event.prev_hash is not None:
            stored_prev = event.prev_hash
        elif event.seq == 1 and self._prev == self._genesis:
            stored_prev = self._genesis  # the writer stores NULL for the first event
        if stored_prev != self._prev:
            self._fail(
                "BROKEN_LINK",
                event.seq,
                f"prev_hash at seq {event.seq} does not match the hash of the previous record",
                self._prev,
                stored_prev,
            )
            return False

        try:
            computed = event_hash(self._prev, event.canonical_payload)
        except ValueError as e:
            self._fail("BROKEN_LINK", event.seq, f"cannot hash seq {event.seq}: {e}", self._prev)
            return False
        if computed != event.hash:
            self._fail(
                "MODIFIED",
                event.seq,
                f"payload at seq {event.seq} does not hash to the stored hash",
                computed,
                event.hash,
            )
            return False
        mismatch = self._payload_mismatch(event)
        if mismatch is not None:
            self._fail("MODIFIED", event.seq, mismatch)
            return False

        for cp in self._by_seq.get(event.seq, []):
            if cp.last_hash != event.hash:
                self._fail(
                    "CHECKPOINT_MISMATCH",
                    event.seq,
                    f"signed {cp.kind} checkpoint at seq {event.seq} records a different hash",
                    cp.last_hash,
                    event.hash,
                )
                return False

        if self._events_checked == 0:
            self._first_seq = event.seq
        self._events_checked += 1
        self._last_seq, self._last_hash = event.seq, event.hash
        self._prev = event.hash
        self._expected = event.seq + 1
        return True

    def _begin(self, first_seq: int) -> bool:
        start = self._starts.get(first_seq)
        if start is not None:
            self._expected, self._prev = first_seq, start.prev_hash
            self._anchor = start.anchor
            return True
        # No legitimate start explains this first event: earlier records were
        # deleted without a retention anchor. Report the first missing seq.
        at_or_before = [s for s in self._starts if s <= first_seq]
        missing = max(at_or_before) if at_or_before else min(self._starts)
        self._fail(
            "GAP",
            missing,
            f"records from seq {missing} to {first_seq - 1} are missing "
            "and no retention checkpoint covers them",
        )
        return False

    def _payload_mismatch(self, event: StoredEvent) -> str | None:
        """The hashed payload must agree with the row about its audit, position and predecessor."""
        try:
            body, _ = json.JSONDecoder(parse_int=_Number).raw_decode(event.canonical_payload)
        except ValueError as e:
            return f"payload at seq {event.seq} is not valid JSON: {e}"
        if not isinstance(body, dict):
            return f"payload at seq {event.seq} is not valid JSON: not an object"
        audit_id = body.get("audit_id")
        if not isinstance(audit_id, str) or audit_id != str(self._audit_id):
            return f"payload at seq {event.seq} names a different audit"
        seq = body.get("seq")
        if not isinstance(seq, _Number) or str(seq) != str(event.seq):
            return f"payload at seq {event.seq} records a different seq"
        prev = body.get("prev_hash")
        if not isinstance(prev, str) or prev != self._prev:
            return f"payload at seq {event.seq} records a different prev_hash"
        return None

    def finish(self) -> VerificationReport:
        """
        Complete the run. A signed checkpoint beyond the last stored event
        means the newest records were removed (TRUNCATED).
        """
        if self._finished:
            raise RuntimeError("this verifier has already finished")
        self._finished = True
        if not self.failed:
            if self._events_checked == 0:
                self._last_seq, self._last_hash = self._base_seq, self._base_hash
            for cp in self._checkpoints:
                if cp.last_seq > self._last_seq:
                    self._fail(
                        "TRUNCATED",
                        self._last_seq + 1,
                        f"signed checkpoint covers seq {cp.last_seq} "
                        f"but stored events end at seq {self._last_seq}",
                        cp.last_hash,
                    )
                    break
        if not self.failed:
            self._check_timestamps()
        anchor = None
        if self._anchor is not None:
            anchor = VerificationAnchor(
                last_seq=self._anchor.last_seq,
                last_hash=self._anchor.last_hash,
                first_retained_seq=self._anchor.last_seq + 1,
            )
        return VerificationReport(
            status="TAMPERED" if self.failed else "INTACT",
            slug=self._slug,
            audit_id=self._audit_id,
            events_checked=self._events_checked,
            first_sequence=self._first_seq,
            last_sequence=self._last_seq,
            last_hash=self._last_hash,
            checkpoints_checked=self._checkpoints_checked,
            anchors_checked=self._anchors_checked,
            checkpoints_unanchored=self._unanchored,
            timestamps_checked=self._anchor_policy is not None,
            anchor=anchor,
            failure=self._failure,
        )

    def _check_timestamps(self) -> None:
        """Check every checkpoint's independent timestamp (same rules as the service)."""
        for cp in self._checkpoints:
            if cp.timestamp is None:
                self._unanchored += 1
                continue
            if self._anchor_policy is None:
                continue
            problem = anchor_problem(cp, checkpoint_message(cp), self._anchor_policy)
            if problem is not None:
                self._fail(
                    "BAD_ANCHOR",
                    cp.last_seq,
                    f"timestamp of the {cp.kind} checkpoint at seq {cp.last_seq}: {problem}",
                )
                return
            self._anchors_checked += 1


def verify_chain(
    *,
    audit_id: UUID,
    slug: str,
    events: Iterable[StoredEvent],
    checkpoints: Sequence[Checkpoint],
    trusted_keys: TrustedKeys,
    anchor_policy: AnchorPolicy | None,
) -> VerificationReport:
    """
    Verify events (ascending seq order) and checkpoints you already hold.
    anchor_policy checks the checkpoints' independent timestamps; pass None
    only to skip that check on purpose (the report then says so).
    """
    verifier = ChainVerifier(
        audit_id=audit_id,
        slug=slug,
        checkpoints=checkpoints,
        trusted_keys=trusted_keys,
        anchor_policy=anchor_policy,
    )
    for event in events:
        if not verifier.feed(event):
            break
    return verifier.finish()


def verify_bundle(
    bundle: Bundle, trusted_keys: TrustedKeys, *, anchor_policy: AnchorPolicy | None
) -> VerificationReport:
    """Verify a loaded audit bundle (see ``load_bundle``)."""
    return verify_chain(
        audit_id=bundle.audit_id,
        slug=bundle.slug,
        events=bundle.events,
        checkpoints=bundle.checkpoints,
        trusted_keys=trusted_keys,
        anchor_policy=anchor_policy,
    )
