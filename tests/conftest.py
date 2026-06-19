"""Shared pytest configuration and fixtures."""

import sys
from pathlib import Path

# Ensure project root is on sys.path so ``src.*`` imports resolve without
# requiring an editable install.
sys.path.insert(0, str(Path(__file__).parent.parent))
