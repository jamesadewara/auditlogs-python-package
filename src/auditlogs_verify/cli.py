"""
Command line: verify an audit bundle offline against keys you trust.

    auditlogs-verify BUNDLE.json --keys KEYS.json [--json]

Exit status: 0 INTACT, 1 TAMPERED, 2 the input could not be checked
(missing or malformed file, unusable keys). Exit 2 is never a verdict.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import timedelta

from ._version import __version__
from .anchors import AnchorPolicy, load_tsa_roots
from .bundle import load_bundle, read_key_file
from .chain import load_trusted_keys, verify_bundle
from .errors import ConfigurationError, VerifierError
from .models import VerificationReport

EXIT_INTACT = 0
EXIT_TAMPERED = 1
EXIT_UNCHECKED = 2


def _describe(report: VerificationReport) -> str:
    lines = [
        f"audit      {report.slug} ({report.audit_id})",
        f"status     {report.status}",
        f"events     {report.events_checked} checked, seq {report.first_sequence} to {report.last_sequence}",
        f"checkpoints {report.checkpoints_checked} signature(s) verified",
        (
            f"timestamps {report.anchors_checked} verified, "
            f"{report.checkpoints_unanchored} checkpoint(s) without one"
            if report.timestamps_checked
            else "timestamps NOT CHECKED (--skip-timestamps or none present)"
        ),
        f"head hash  {report.last_hash}",
    ]
    if report.anchor is not None:
        lines.append(f"anchor     retention checkpoint at seq {report.anchor.last_seq}")
    if report.failure is not None:
        f = report.failure
        lines.append(f"failure    {f.kind} at seq {f.seq}: {f.message}")
        if f.expected_hash:
            lines.append(f"expected   {f.expected_hash}")
        if f.found_hash:
            lines.append(f"found      {f.found_hash}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditlogs-verify",
        description="Verify an AuditLogs audit bundle offline: hash chain and Ed25519 checkpoint signatures.",
    )
    parser.add_argument("bundle", help="audit bundle JSON file (format auditlogs-bundle-v1)")
    parser.add_argument(
        "--keys",
        required=True,
        help='trusted keys JSON: {"key_id": "base64"} or a /v1/checkpoint-keys response',
    )
    parser.add_argument(
        "--tsa-roots", help="PEM file of trusted timestamp authority roots (for example FreeTSA's cacert.pem)"
    )
    parser.add_argument(
        "--max-anchor-delay",
        type=int,
        metavar="SECONDS",
        help="largest allowed gap between a checkpoint's signed_at and its timestamp",
    )
    parser.add_argument(
        "--skip-timestamps",
        action="store_true",
        help="do not check checkpoint timestamps (the report says they were not checked)",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        ring = load_trusted_keys(read_key_file(args.keys))
        bundle = load_bundle(args.bundle)
        policy = None
        if args.skip_timestamps:
            if args.tsa_roots or args.max_anchor_delay is not None:
                raise ConfigurationError(
                    "--skip-timestamps cannot be combined with --tsa-roots or --max-anchor-delay"
                )
        elif any(cp.timestamp is not None for cp in bundle.checkpoints):
            if not args.tsa_roots or args.max_anchor_delay is None:
                raise ConfigurationError(
                    "the bundle has checkpoint timestamps: pass --tsa-roots and --max-anchor-delay, "
                    "or --skip-timestamps to leave them unchecked"
                )
            policy = AnchorPolicy(load_tsa_roots(args.tsa_roots), timedelta(seconds=args.max_anchor_delay))
        report = verify_bundle(bundle, ring, anchor_policy=policy)
    except VerifierError as e:
        print(f"auditlogs-verify: not checked: {e}", file=sys.stderr)
        return EXIT_UNCHECKED

    print(report.model_dump_json(indent=2) if args.json else _describe(report))
    return EXIT_INTACT if report.intact else EXIT_TAMPERED


if __name__ == "__main__":
    sys.exit(main())
