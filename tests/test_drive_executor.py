"""Layer 4 tests: GoogleDriveClient against a fake googleapiclient Drive
service -- create always writes into one fixed folder, creating it on first
use (and caching the id) exactly like SheetsAuditLog/SheetsStateStore create
their spreadsheet on first use; update/append vet the target file first."""
from __future__ import annotations

import pytest

from app.drive_executor import GoogleDriveClient
from app.failures import GatekeeperDenied


class _Call:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result


class _Files:
    def __init__(self):
        self.create_calls: list[dict] = []
        self.update_calls: list[dict] = []
        self.list_calls: list[dict] = []
        self._next_folder_id = 1
        # fileId -> {"meta": dict, "content": bytes}, for get/get_media/update.
        self.store: dict[str, dict] = {}

    def create(self, body, fields=None, media_body=None):
        self.create_calls.append({"body": body, "media_body": media_body})
        if body.get("mimeType") == "application/vnd.google-apps.folder":
            folder_id = f"folder_{self._next_folder_id}"
            self._next_folder_id += 1
            return _Call({"id": folder_id})
        return _Call({"id": "file_1", "name": body["name"], "webViewLink": "https://drive.google.com/file/d/file_1/view"})

    def get(self, fileId, fields=None):
        if fileId not in self.store:
            raise _http_error(404)
        return _Call(dict(self.store[fileId]["meta"]))

    def get_media(self, fileId):
        if fileId not in self.store:
            raise _http_error(404)
        return _Call(self.store[fileId]["content"])

    def update(self, fileId, media_body=None, fields=None):
        self.update_calls.append({"fileId": fileId, "media_body": media_body})
        entry = self.store[fileId]
        entry["content"] = media_body.getbytes(0, media_body.size())
        meta = dict(entry["meta"])
        meta["webViewLink"] = f"https://drive.google.com/file/d/{fileId}/view"
        return _Call(meta)

    def list(self, q=None, fields=None, pageSize=None):
        self.list_calls.append({"q": q})
        return _Call({"files": self.list_result})

    list_result: list = []


def _http_error(status):
    class HttpError(Exception):
        pass

    err = HttpError("http error")
    err.status_code = status
    return err


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



def _store_file(service, file_id, name, content=b"", mime="text/plain", parents=None):
    service._files.store[file_id] = {
        "meta": {"id": file_id, "name": name, "mimeType": mime, "parents": parents or ["folder_pinned"]},
        "content": content,
    }


def test_create_file_returns_the_web_view_link():
    service = _Service()
    client = _client(service, folder_id="folder_pinned")

    result = client.create_file(name="notes.txt", content="hello")

    assert result.web_view_link == "https://drive.google.com/file/d/file_1/view"


def test_resolve_file_id_single_match():
    service = _Service()
    service._files.list_result = [{"id": "file_9", "name": "known.txt"}]
    client = _client(service, folder_id="folder_pinned")

    assert client.resolve_file_id("known.txt") == "file_9"
    assert "name = 'known.txt'" in service._files.list_calls[0]["q"]
    assert "'folder_pinned' in parents" in service._files.list_calls[0]["q"]


def test_resolve_file_id_escapes_quotes_in_the_name():
    service = _Service()
    service._files.list_result = [{"id": "file_9", "name": "it's.txt"}]
    client = _client(service, folder_id="folder_pinned")

    client.resolve_file_id("it's.txt")

    assert "name = 'it\\'s.txt'" in service._files.list_calls[0]["q"]


def test_resolve_file_id_no_match_denied_not_found():
    service = _Service()
    service._files.list_result = []
    client = _client(service, folder_id="folder_pinned")

    with pytest.raises(GatekeeperDenied) as exc:
        client.resolve_file_id("missing.txt")
    assert exc.value.error_code == "not_found"


def test_resolve_file_id_several_matches_denied_ambiguous():
    service = _Service()
    service._files.list_result = [{"id": "a", "name": "dup.txt"}, {"id": "b", "name": "dup.txt"}]
    client = _client(service, folder_id="folder_pinned")

    with pytest.raises(GatekeeperDenied) as exc:
        client.resolve_file_id("dup.txt")
    assert exc.value.error_code == "ambiguous_file"


def test_update_file_replaces_the_content_and_returns_the_link():
    service = _Service()
    _store_file(service, "file_7", "notes.txt", content=b"old")
    client = _client(service, folder_id="folder_pinned")

    result = client.update_file(file_id="file_7", content="new text")

    assert service._files.store["file_7"]["content"] == b"new text"
    assert result.name == "notes.txt"
    assert result.web_view_link == "https://drive.google.com/file/d/file_7/view"


def test_update_file_refuses_a_file_outside_the_gatekeeper_folder():
    service = _Service()
    _store_file(service, "file_8", "other.txt", parents=["someone_elses_folder"])
    client = _client(service, folder_id="folder_pinned")

    with pytest.raises(GatekeeperDenied) as exc:
        client.update_file(file_id="file_8", content="x")
    assert exc.value.error_code == "not_gatekeeper_file"
    assert service._files.update_calls == []


def test_update_file_refuses_a_non_text_file():
    service = _Service()
    _store_file(service, "file_8", "sheet", mime="application/vnd.google-apps.spreadsheet")
    client = _client(service, folder_id="folder_pinned")

    with pytest.raises(GatekeeperDenied) as exc:
        client.update_file(file_id="file_8", content="x")
    assert exc.value.error_code == "invalid_params"
    assert service._files.update_calls == []


def test_append_file_adds_a_newline_when_the_file_does_not_end_with_one():
    service = _Service()
    _store_file(service, "file_7", "log.txt", content=b"first line")
    client = _client(service, folder_id="folder_pinned")

    client.append_file(file_id="file_7", content="second line")

    assert service._files.store["file_7"]["content"] == b"first line\nsecond line"


def test_append_file_to_a_file_ending_in_newline_adds_none():
    service = _Service()
    _store_file(service, "file_7", "log.txt", content=b"first line\n")
    client = _client(service, folder_id="folder_pinned")

    client.append_file(file_id="file_7", content="second line")

    assert service._files.store["file_7"]["content"] == b"first line\nsecond line"


def test_append_file_to_an_empty_file_adds_no_leading_newline():
    service = _Service()
    _store_file(service, "file_7", "log.txt", content=b"")
    client = _client(service, folder_id="folder_pinned")

    result = client.append_file(file_id="file_7", content="first line")

    assert service._files.store["file_7"]["content"] == b"first line"
    assert result.web_view_link == "https://drive.google.com/file/d/file_7/view"


def test_update_and_append_take_no_folder_or_name_params():
    """Same structural guarantee as create's no-`folder` test: the file is
    identified only by an id the executor vets against the app-owned
    folder -- a request can't redirect the write anywhere else."""
    import inspect

    from app.drive_executor import DriveClient

    assert set(inspect.signature(DriveClient.update_file).parameters) == {"self", "file_id", "content"}
    assert set(inspect.signature(DriveClient.append_file).parameters) == {"self", "file_id", "content"}
    assert set(inspect.signature(DriveClient.resolve_file_id).parameters) == {"self", "name"}
