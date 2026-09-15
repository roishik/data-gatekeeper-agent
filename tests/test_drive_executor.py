"""Layer 4 tests: GoogleDriveClient.create_file against a fake
googleapiclient Drive service -- always writes into one fixed folder,
creating it on first use (and caching the id) exactly like
SheetsAuditLog/SheetsStateStore create their spreadsheet on first use."""
from __future__ import annotations

from app.drive_executor import GoogleDriveClient


class _Call:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result


class _Files:
    def __init__(self):
        self.create_calls: list[dict] = []
        self._next_folder_id = 1

    def create(self, body, fields=None, media_body=None):
        self.create_calls.append({"body": body, "media_body": media_body})
        if body.get("mimeType") == "application/vnd.google-apps.folder":
            folder_id = f"folder_{self._next_folder_id}"
            self._next_folder_id += 1
            return _Call({"id": folder_id})
        return _Call({"id": "file_1", "name": body["name"]})


class _Service:
    def __init__(self):
        self._files = _Files()

    def files(self):
        return self._files


def _client(service, folder_id=None):
    client = GoogleDriveClient(folder_id=folder_id)
    client._service = lambda: service  # type: ignore[method-assign]
    return client


def test_create_file_with_pinned_folder_id_never_creates_a_folder():
    service = _Service()
    client = _client(service, folder_id="folder_pinned")

    result = client.create_file(name="notes.txt", content="hello")

    assert result.file_id == "file_1"
    assert result.name == "notes.txt"
    folder_creates = [c for c in service._files.create_calls if c["body"].get("mimeType") == "application/vnd.google-apps.folder"]
    assert folder_creates == []
    file_create = [c for c in service._files.create_calls if "parents" in c["body"]][0]
    assert file_create["body"]["parents"] == ["folder_pinned"]


def test_create_file_without_folder_id_creates_folder_once_and_caches_it():
    service = _Service()
    client = _client(service, folder_id=None)

    client.create_file(name="a.txt", content="a")
    client.create_file(name="b.txt", content="b")

    folder_creates = [c for c in service._files.create_calls if c["body"].get("mimeType") == "application/vnd.google-apps.folder"]
    assert len(folder_creates) == 1  # only created once, then cached on the client instance

    file_creates = [c for c in service._files.create_calls if "parents" in c["body"]]
    assert file_creates[0]["body"]["parents"] == ["folder_1"]
    assert file_creates[1]["body"]["parents"] == ["folder_1"]


def test_create_file_writes_no_folder_field_from_params():
    """Structural guarantee mirroring app/policy.py's DriveCreateFileParams:
    there is no `folder` argument on create_file at all -- a request
    cannot redirect the write anywhere but the one fixed, pinned folder."""
    import inspect

    from app.drive_executor import DriveClient

    sig = inspect.signature(DriveClient.create_file)
    assert set(sig.parameters) == {"self", "name", "content"}
