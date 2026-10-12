"""Loading audit bundles and trusted key files from disk, with strict validation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .errors import BundleError, ConfigurationError
from .models import Bundle, StoredEvent


def _read_json(path: Path, what: str) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise BundleError(f"cannot read the {what} file {path}: {e}") from e
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise BundleError(f"the {what} file {path} is not valid JSON: {e}") from e


def parse_bundle(data: Any) -> Bundle:
    """Validate a bundle that is already parsed JSON."""
    try:
        bundle = Bundle.model_validate(data)
    except ValidationError as e:
        raise BundleError(f"the bundle does not match the auditlogs-bundle-v1 format: {e}") from e
    seen: dict[int, StoredEvent] = {}
    for event in bundle.events:
        earlier = seen.get(event.seq)
        if earlier is not None and earlier != event:
            raise BundleError(f"seq {event.seq} appears twice with different content")
        seen[event.seq] = event
    return bundle.model_copy(update={"events": [seen[s] for s in sorted(seen)]})


def load_bundle(path: str | Path) -> Bundle:
    """Read and validate a bundle file. Events come back once each, in seq order."""
    return parse_bundle(_read_json(Path(path), "bundle"))


def read_key_file(path: str | Path) -> Mapping[str, str]:
    """
    Read trusted checkpoint keys. Accepts either ``{"key_id": "base64 public key"}``
    or the service's GET /v1/checkpoint-keys response ``{"keys": [{"key_id", "public_key", ...}]}``.
    """
    data = _read_json(Path(path), "keys")
    if isinstance(data, dict) and isinstance(data.get("keys"), list):
        pairs: dict[str, str] = {}
        for item in data["keys"]:
            if not (
                isinstance(item, dict)
                and isinstance(item.get("key_id"), str)
                and isinstance(item.get("public_key"), str)
            ):
                raise ConfigurationError("each entry in 'keys' needs string key_id and public_key")
            if item.get("algorithm") != "Ed25519":
                raise ConfigurationError(f"key {item['key_id']!r} is not an Ed25519 key")
            pairs[item["key_id"]] = item["public_key"]
        return pairs
    if isinstance(data, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        return data
    raise ConfigurationError(
        'the keys file must be {"key_id": "base64 key"} or a /v1/checkpoint-keys response'
    )
