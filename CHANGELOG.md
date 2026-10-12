# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

First release of **auditlogs-verify**: check an AuditLogs audit yourself, without trusting the
service. Sending, reading and provisioning audits are plain HTTP and need no library.

- `auditlogs-verify` command, also runnable as `python -m auditlogs_verify`. Exit status 0 means
  INTACT, 1 means TAMPERED, and 2 means the input could not be checked.
- Library functions: `load_bundle`, `parse_bundle`, `read_key_file`, `load_trusted_keys`,
  `verify_bundle`, `verify_chain` and the streaming `ChainVerifier`.
- The `auditlogs-bundle-v1` input format, and the hash and signature rules with shared test values,
  in `docs/SPEC.md`.
- Checks independent RFC 3161 checkpoint timestamps (`AnchorPolicy`, `load_tsa_roots`, the
  `BAD_ANCHOR` failure kind, and the `--tsa-roots`, `--max-anchor-delay` and `--skip-timestamps`
  flags). The report says when timestamps were not checked.
