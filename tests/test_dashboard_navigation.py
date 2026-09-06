from __future__ import annotations

from pathlib import Path

from dashboard.core import (
    page_registry,
)


def test_dashboard_directory_exists():
    assert (
        page_registry.DASHBOARD_DIRECTORY
    ).exists()


def test_pages_directory_exists():
    assert (
        page_registry.PAGES_DIRECTORY
    ).exists()


def test_find_unified_email_page():
    page = page_registry.find_page(
        [
            "*Unified_Email_Security_Pipeline.py",
            "*Unified*Email*Pipeline*.py",
        ]
    )

    assert page is not None
    assert page.is_file()


def test_find_attachment_page():
    page = page_registry.find_page(
        [
            "*Attachment_QR_Inspection.py",
            "*Attachment*QR*.py",
        ]
    )

    assert page is not None
    assert page.is_file()


def test_relative_page_path():
    page = (
        page_registry.PAGES_DIRECTORY
        / "example.py"
    )

    assert (
        page_registry.relative_page_path(
            page
        )
        == "dashboard/pages/example.py"
    )
