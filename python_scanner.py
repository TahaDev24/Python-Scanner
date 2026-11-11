#!/usr/bin/env python3
"""Backward-compatible entry point and public API re-export.

New code should import from core.engine or interface.app directly.
"""

from core.engine import *
from interface.app import *

if __name__ == "__main__":
    raise SystemExit(main())
