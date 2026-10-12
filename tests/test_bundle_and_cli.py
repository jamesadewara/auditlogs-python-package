"""Bundle loading, key files and the command line, including every exit status."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from auditlogs_verify import BundleError, ConfigurationError, load_bundle, read_key_file
from auditlogs_verify.cli import EXIT_INTACT, EXIT_TAMPERED, EXIT_UNCHECKED, main

from .conftest import Signer, build_chain, checkpoint_json, event_json


def bundle_dict(audit_id: UUID, events: list[Any], checkpoints: list[Any]) -> dict[str, Any]:
    return {
        "format": "auditlogs-bundle-v1",
        "audit_id": str(audit_id),
        "slug": "orders",
        "events": [event_json(e) for e in events],
        "checkpoints": [checkpoint_json(c) for c in checkpoints],
    }


def write(path: Path, data: Any) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


# ── Bundle loading ───────────────────────────────────────────────────────────


def test_events_are_sorted_and_repeats_collapsed(tmp_path: Path, audit_id: UUID) -> None:
    events = build_chain(audit_id, 5)
    shuffled = events + [events[2]]  # a page boundary repeated one record
    random.Random(7).shuffle(shuffled)
    bundle = load_bundle(write(tmp_path / "b.json", bundle_dict(audit_id, shuffled, [])))
    assert [e.seq for e in bundle.events] == [1, 2, 3, 4, 5]


def test_conflicting_duplicate_is_rejected(tmp_path: Path, audit_id: UUID) -> None:
    events = build_chain(audit_id, 3)
    other = events[1].model_copy(update={"canonical_payload": events[1].canonical_payload + " "})
    with pytest.raises(BundleError, match="seq 2 appears twice with different content"):
        load_bundle(write(tmp_path / "b.json", bundle_dict(audit_id, [*events, other], [])))


def test_wrong_format_is_rejected(tmp_path: Path, audit_id: UUID) -> None:
    data = bundle_dict(audit_id, build_chain(audit_id, 1), [])
    data["format"] = "something-else"
    with pytest.raises(BundleError, match="does not match the auditlogs-bundle-v1 format"):
        load_bundle(write(tmp_path / "b.json", data))


def test_missing_and_invalid_files_are_reported(tmp_path: Path) -> None:
    with pytest.raises(BundleError, match="cannot read the bundle file"):
        load_bundle(tmp_path / "nope.json")
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(BundleError, match="is not valid JSON"):
        load_bundle(tmp_path / "bad.json")


def test_api_event_objects_load_as_returned(tmp_path: Path, audit_id: UUID) -> None:
    # Extra fields from GET /events (actor, action, ...) are ignored, not rejected.
    e = event_json(build_chain(audit_id, 1)[0])
    e.update({"actor": {"type": "user", "id": "u"}, "action": "a", "metadata": {}})
    data = bundle_dict(audit_id, [], [])
    data["events"] = [e]
    assert load_bundle(write(tmp_path / "b.json", data)).events[0].seq == 1


# ── Key files ────────────────────────────────────────────────────────────────


def test_key_file_accepts_both_shapes(tmp_path: Path, signer: Signer) -> None:
    plain = read_key_file(write(tmp_path / "k1.json", signer.trusted()))
    api = read_key_file(
        write(
            tmp_path / "k2.json",
            {"keys": [{"key_id": signer.key_id, "algorithm": "Ed25519", "public_key": signer.public_b64}]},
        )
    )
    assert plain == api == signer.trusted()


def test_key_file_rejects_other_algorithms(tmp_path: Path) -> None:
    path = write(tmp_path / "k.json", {"keys": [{"key_id": "k", "algorithm": "RSA", "public_key": "AA=="}]})
    with pytest.raises(ConfigurationError, match="is not an Ed25519 key"):
        read_key_file(path)


# ── Command line ─────────────────────────────────────────────────────────────


def test_cli_intact(
    tmp_path: Path, audit_id: UUID, signer: Signer, capsys: pytest.CaptureFixture[str]
) -> None:
    events = build_chain(audit_id, 4)
    cps = [signer.checkpoint(audit_id, "periodic", 4, events[3].hash)]
    bundle = write(tmp_path / "b.json", bundle_dict(audit_id, events, cps))
    keys = write(tmp_path / "k.json", signer.trusted())
    assert main([bundle, "--keys", keys]) == EXIT_INTACT
    out = capsys.readouterr().out
    assert "status     INTACT" in out and "4 checked, seq 1 to 4" in out


def test_cli_tampered_names_kind_and_seq(
    tmp_path: Path, audit_id: UUID, signer: Signer, capsys: pytest.CaptureFixture[str]
) -> None:
    events = build_chain(audit_id, 4)
    del events[1]
    bundle = write(tmp_path / "b.json", bundle_dict(audit_id, events, []))
    keys = write(tmp_path / "k.json", signer.trusted())
    assert main([bundle, "--keys", keys, "--json"]) == EXIT_TAMPERED
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "TAMPERED"
    assert (report["failure"]["kind"], report["failure"]["seq"]) == ("GAP", 2)


def test_cli_unusable_input_is_not_a_verdict(
    tmp_path: Path, audit_id: UUID, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = write(tmp_path / "b.json", bundle_dict(audit_id, build_chain(audit_id, 1), []))
    empty_keys = write(tmp_path / "k.json", {})
    assert main([bundle, "--keys", empty_keys]) == EXIT_UNCHECKED
    assert "not checked: at least one trusted checkpoint public key is required" in capsys.readouterr().err


def test_cli_demands_a_choice_about_timestamps(
    tmp_path: Path, audit_id: UUID, signer: Signer, capsys: pytest.CaptureFixture[str]
) -> None:
    events = build_chain(audit_id, 2)
    cp = checkpoint_json(signer.checkpoint(audit_id, "periodic", 2, events[1].hash))
    cp["timestamp"] = {
        "tsa_url": "https://freetsa.org/tsr",
        "gen_time": "2026-10-12T11:35:02Z",
        "tsa_response": "AAAA",
    }
    bundle = write(tmp_path / "b.json", bundle_dict(audit_id, events, []) | {"checkpoints": [cp]})
    keys = write(tmp_path / "k.json", signer.trusted())

    assert main([bundle, "--keys", keys]) == EXIT_UNCHECKED
    assert "pass --tsa-roots and --max-anchor-delay, or --skip-timestamps" in capsys.readouterr().err

    assert main([bundle, "--keys", keys, "--skip-timestamps", "--max-anchor-delay", "60"]) == EXIT_UNCHECKED
    assert "cannot be combined" in capsys.readouterr().err

    assert main([bundle, "--keys", keys, "--skip-timestamps"]) == EXIT_INTACT
    assert "timestamps NOT CHECKED" in capsys.readouterr().out

    roots = str(Path(__file__).parent / "fixtures" / "freetsa-root.pem")
    assert (
        main([bundle, "--keys", keys, "--tsa-roots", roots, "--max-anchor-delay", "86400", "--json"])
        == EXIT_TAMPERED
    )
    report = json.loads(capsys.readouterr().out)
    assert report["failure"]["kind"] == "BAD_ANCHOR" and report["failure"]["seq"] == 2
