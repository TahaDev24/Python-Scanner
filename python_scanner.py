#!/usr/bin/env python3
"""Compatibility launcher; use main.py for the canonical entry point."""

from interface.app import main


if __name__ == "__main__":
    raise SystemExit(main())
