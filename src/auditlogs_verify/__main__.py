"""``python -m auditlogs_verify`` runs the command line."""

import sys

from .cli import main

sys.exit(main())
