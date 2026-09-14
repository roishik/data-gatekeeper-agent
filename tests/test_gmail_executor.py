"""Layer 4 tests: the pure query-building helper (the real GoogleGmailClient
needs live credentials and is exercised through the fake in
tests/test_pipeline_injection.py instead)."""
from __future__ import annotations

from app.gmail_executor import build_search_query


def test_build_search_query_without_newer_than_days():
    assert build_search_query("invoice", None) == "invoice"


def test_build_search_query_with_newer_than_days():
    assert build_search_query("invoice", 7) == "invoice newer_than:7d"
