# auditlogs-verify

An independent checker for AuditLogs audits. It recomputes the hash chain from the stored payloads
and checks the Ed25519 checkpoint signatures against public keys **you** pinned, so an auditor does
not have to take the service's word that nothing changed.

Everything else in AuditLogs is plain HTTPS. Sending, reading and provisioning need no library;
the dashboard shows ready-to-run examples.

## Install

```bash
pip install auditlogs-verify
```

Requires Python 3.10 or newer. Depends on `pydantic` (v2), `cryptography` and `rfc3161-client`.

## Command line

```bash
auditlogs-verify audit-bundle.json --keys trusted-keys.json \
    --tsa-roots freetsa-root.pem --max-anchor-delay 86400
auditlogs-verify audit-bundle.json --keys trusted-keys.json --skip-timestamps --json
```

Get the bundle with `GET /v1/audits/{slug}/export/bundle` (read key). When it contains checkpoint
timestamps you must either pass `--tsa-roots` and `--max-anchor-delay`, or say `--skip-timestamps`;
the report then states that timestamps were not checked.

| Exit status | Meaning |
|---|---|
| 0 | INTACT |
| 1 | TAMPERED: prints the kind and exact sequence number of the first break |
| 2 | Not checked: the bundle or key file is missing or malformed. This is never a verdict. |

- **`trusted-keys.json`** is either `{"key_id": "base64 public key"}` or a saved copy of
  `GET /v1/checkpoint-keys`.
- **`audit-bundle.json`** holds the audit's events and checkpoints, as described in
  [docs/SPEC.md](docs/SPEC.md). The lab notebook `04_integrity.ipynb` shows how to build one with
  plain HTTP.

## Library

```python
from auditlogs_verify import load_bundle, load_trusted_keys, read_key_file, verify_bundle

report = verify_bundle(load_bundle("audit-bundle.json"),
                       load_trusted_keys(read_key_file("trusted-keys.json")))
if not report.intact:
    print(report.failure.kind, report.failure.seq, report.failure.message)
```

Also available:
- `verify_chain`, for events and checkpoints you already hold in memory;
- `ChainVerifier`, which checks events one at a time for very large audits;
- `genesis_hash`, `event_hash` and `checkpoint_message`.

## What it guarantees, and what it does not

It detects:
- edited, deleted, reordered or moved records;
- a chain recomputed without the signing key;
- newest records deleted after a checkpoint;
- forged or unknown checkpoints.

It does not protect against an operator who holds the signing key and rewrites history before you
pinned any checkpoint. See "Known limits" in the spec.

## Development

```bash
pip install -e ".[dev]"
pytest && ruff check src tests && mypy
```
