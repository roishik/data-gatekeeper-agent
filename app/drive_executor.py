"""
drive_executor.py — Layer 4: the only module that touches Drive for
drive.create_file.

Writes a single plain-text file into ONE fixed, app-owned folder
(GOOGLE_DRIVE_FOLDER_ID, created on first use if unset -- same
create-then-log-loudly convention as SheetsAuditLog/SheetsStateStore in
app/audit_log.py / app/state_store.py). There is no `folder` field
anywhere upstream (see app/policy.py's DriveCreateFileParams) for a
request to redirect a write elsewhere in Drive.

Scope: drive.file only -- the same scope already granted for the
Sheets-backed audit log and state store (research/07 section 4), so this
verb needs no new OAuth consent beyond what's already requested. Per
Google's own scope semantics, drive.file only ever grants access to
files/folders this app itself creates, never the owner's existing Drive
content -- this executor can create files, but structurally cannot read
or touch anything it didn't create itself.

NOT exercised against a live Drive API call -- the files.create request
shape below comes from Google's published REST reference. See the final
build report's "could not verify" section.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from app.config import GOOGLE_DRIVE_FOLDER_ID
from app.google_auth_helper import build_google_service

DRIVE_FILE_SCOPE = "https://www.googleapis.com/auth/drive.file"

logger = logging.getLogger("gatekeeper.drive_executor")


@dataclass(frozen=True)
class DriveFileResult:
    file_id: str
    name: str


class DriveClient(Protocol):
    def create_file(self, name: str, content: str) -> DriveFileResult: ...


class GoogleDriveClient:
    """Real implementation, gated behind having Google OAuth credentials
    configured (checked in google_auth_helper.build_google_credentials)."""

    def __init__(self, folder_id: str | None = None):
        self._folder_id = folder_id or GOOGLE_DRIVE_FOLDER_ID

    def _service(self):
        return build_google_service("drive", "v3", scopes=[DRIVE_FILE_SCOPE])

    def _resolve_folder_id(self, service) -> str:
        if self._folder_id:
            return self._folder_id
        folder = (
            service.files()
            .create(body={"name": "data-gatekeeper-files", "mimeType": "application/vnd.google-apps.folder"}, fields="id")
            .execute()
        )
        folder_id = folder["id"]
        logger.warning(
            "created a new Drive folder for drive.create_file (id=%s) -- set GOOGLE_DRIVE_FOLDER_ID "
            "to this value so future runs write into it instead of creating another one",
            folder_id,
        )
        self._folder_id = folder_id
        return folder_id

    def create_file(self, name: str, content: str) -> DriveFileResult:
        from googleapiclient.http import MediaInMemoryUpload  # lazy: keep this module importable without the package

        service = self._service()
        folder_id = self._resolve_folder_id(service)
        media = MediaInMemoryUpload(content.encode("utf-8"), mimetype="text/plain")
        created = (
            service.files()
            .create(body={"name": name, "parents": [folder_id]}, media_body=media, fields="id, name")
            .execute()
        )
        return DriveFileResult(file_id=created.get("id", ""), name=created.get("name", name))
