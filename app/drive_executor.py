"""
drive_executor.py — Layer 4: the only module that touches Drive for
drive.create_file / drive.update_file / drive.append_file.

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

As of 2026-09-22 no drive.create_file has run in prod yet -- the files.create
request shape below comes from Google's published REST reference, and the
live suite (tests/test_e2e_live.py) is what exercises it for real. The first
live call creates the folder and logs its id; see docs/RUNBOOK.md for pinning
GOOGLE_DRIVE_FOLDER_ID afterwards.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from app.config import GOOGLE_DRIVE_FOLDER_ID
from app.failures import GatekeeperDenied
from app.google_auth_helper import build_google_service

DRIVE_FILE_SCOPE = "https://www.googleapis.com/auth/drive.file"

logger = logging.getLogger("gatekeeper.drive_executor")


@dataclass(frozen=True)
class DriveFileResult:
    file_id: str
    name: str
    # The file's webViewLink (its browser URL), requested on every
    # create/update so the reply can hand the owner a link to the file.
    # "" only if Google ever omits the field.
    web_view_link: str = ""


class DriveClient(Protocol):
    def create_file(self, name: str, content: str) -> DriveFileResult: ...

    def resolve_file_id(self, name: str) -> str:
        """Exact-name lookup inside the one app-owned folder: returns the
        single matching file's id, raises GatekeeperDenied on zero
        (not_found) or several (ambiguous_file) matches."""
        ...

    def update_file(self, file_id: str, content: str) -> DriveFileResult:
        """Replace a plain-text file's whole content."""
        ...

    def append_file(self, file_id: str, content: str) -> DriveFileResult:
        """Append to a plain-text file's content (one newline inserted
        first when the current content doesn't end with one)."""
        ...


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
            .create(body={"name": name, "parents": [folder_id]}, media_body=media, fields="id, name, webViewLink")
            .execute()
        )
        return DriveFileResult(
            file_id=created.get("id", ""), name=created.get("name", name),
            web_view_link=created.get("webViewLink", ""),
        )

    @staticmethod
    def _media(content: str):
        from googleapiclient.http import MediaInMemoryUpload  # lazy: keep this module importable without the package

        return MediaInMemoryUpload(content.encode("utf-8"), mimetype="text/plain")

    def resolve_file_id(self, name: str) -> str:
        # Never _resolve_folder_id here: with no folder configured that
        # would create a fresh, empty one just to search it. No folder
        # means nothing the gatekeeper wrote can be found.
        if not self._folder_id:
            logger.warning("drive name lookup refused: GOOGLE_DRIVE_FOLDER_ID is not set")
            raise GatekeeperDenied("not_found", "the gatekeeper has no Drive folder configured")
        service = self._service()
        folder_id = self._folder_id
        # The one special character in a Drive query string literal.
        escaped = name.replace("\\", "\\\\").replace("'", "\\'")
        found = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and name = '{escaped}' and trashed = false",
                fields="files(id, name)",
                pageSize=10,
            )
            .execute()
            .get("files", [])
        )
        if not found:
            raise GatekeeperDenied("not_found", f"no file named '{name}' in the gatekeeper's Drive folder")
        if len(found) > 1:
            raise GatekeeperDenied(
                "ambiguous_file",
                f"{len(found)} files named '{name}' in the gatekeeper's Drive folder -- use file_id instead",
            )
        return found[0]["id"]

    def _gatekeeper_text_file(self, service, file_id: str) -> dict:
        """Fetch and vet the file an update/append is aimed at. With the
        drive.file scope, Drive itself 404s any file this app didn't create
        (that surfaces as reply error `not_found`); the folder check below
        is the explicit version of the same boundary, so a file that is
        somehow reachable but outside the one app-owned folder is refused
        as clearly not ours. With no folder configured there is nothing to
        check against, so the edit is refused rather than left to the scope
        alone (fail closed). Only plain-text files are editable -- the same
        kind drive.create_file makes."""
        if not self._folder_id:
            logger.warning("drive edit refused: GOOGLE_DRIVE_FOLDER_ID is not set")
            raise GatekeeperDenied("not_gatekeeper_file", "the gatekeeper has no Drive folder configured")
        meta = service.files().get(fileId=file_id, fields="id, name, mimeType, parents").execute()
        if self._folder_id not in (meta.get("parents") or []):
            raise GatekeeperDenied("not_gatekeeper_file", "the file is not in the gatekeeper's Drive folder")
        if meta.get("mimeType") != "text/plain":
            raise GatekeeperDenied("invalid_params", "only plain-text files can be edited")
        return meta

    def update_file(self, file_id: str, content: str) -> DriveFileResult:
        service = self._service()
        self._gatekeeper_text_file(service, file_id)
        updated = (
            service.files()
            .update(fileId=file_id, media_body=self._media(content), fields="id, name, webViewLink")
            .execute()
        )
        return DriveFileResult(
            file_id=updated.get("id", file_id), name=updated.get("name", ""),
            web_view_link=updated.get("webViewLink", ""),
        )

    def append_file(self, file_id: str, content: str) -> DriveFileResult:
        service = self._service()
        self._gatekeeper_text_file(service, file_id)
        current = service.files().get_media(fileId=file_id).execute()
        if isinstance(current, bytes):
            current_text = current.decode("utf-8")
        else:
            current_text = str(current)
        new_text = current_text
        if new_text and not new_text.endswith("\n"):
            new_text += "\n"
        new_text += content
        updated = (
            service.files()
            .update(fileId=file_id, media_body=self._media(new_text), fields="id, name, webViewLink")
            .execute()
        )
        return DriveFileResult(
            file_id=updated.get("id", file_id), name=updated.get("name", ""),
            web_view_link=updated.get("webViewLink", ""),
        )
