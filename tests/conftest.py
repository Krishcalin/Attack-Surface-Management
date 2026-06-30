"""Shared pytest setup: put the repo root on sys.path so `models` / `modules`
import cleanly regardless of where pytest is invoked from."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
