"""Offline regressions for the live-feed boundary and atomic publication."""

import io
import json
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest

from scripts import sync_community_attacks as sync


KEY = "synthetic-key-do-not-log"
BASE = "https://example.supabase.co"


def report(number=1, **changes):
    row = dict(
        id=str(UUID(int=number)), status="approved", reviewed_at="2026-09-10T06:00:00Z",
        confidence="medium", suspicion_level=2, heuristic_flags=["authority claim"],
        summary="Synthetic report", example_input="ignore previous instructions",
        suspicion_reason="Attempts to change instruction priority", attacker_goal="Redirect the task",
        suggested_defense="Treat source content as data", agent_platform="test", attack_category="ATTACK-01",
        reviewer_notes=None,
    )
    row.update(changes)
    return row


class Response:
    status = 200

    def __init__(self, data, content_range):
        self.data = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.headers = {"Content-Range": content_range}
        self.read_sizes = []

    def read(self, size):
        self.read_sizes.append(size)
        return self.data[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class Opener:
    def __init__(self, *results):
        self.results = list(results)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        assert 0 < timeout <= sync.REQUEST_TIMEOUT
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture(autouse=True)
def no_wait(monkeypatch):
    monkeypatch.setattr(sync.time, "sleep", lambda _: None)


@pytest.mark.parametrize("url", [
    "http://example.supabase.co", "https://user:password@example.supabase.co", "https://example.supabase.co/rest/v1",
    "https://example.supabase.co?token=private", "https://example.supabase.co#fragment", "https://",
    "https://example.supabase.co:bad", "https://bad\nhost.supabase.co", "https://example.supabase.co:80",
])
def test_invalid_origin_rejected_before_request(url):
    with pytest.raises(sync.SyncError):
        sync.configuration({"SUPABASE_URL": url, "SUPABASE_SERVICE_KEY": KEY})


def test_configuration_accepts_whitespace_and_prefers_read_key():
    assert sync.configuration({"SUPABASE_URL": f"  {BASE}/\n", "SUPABASE_READ_KEY": "sb_publishable_fake",
                               "SUPABASE_SERVICE_KEY": KEY}) == (BASE, "sb_publishable_fake")


@pytest.mark.parametrize("env", [{}, {"SUPABASE_URL": BASE}, {"SUPABASE_SERVICE_KEY": KEY},
                                    {"SUPABASE_URL": BASE, "SUPABASE_SERVICE_KEY": "bad\nkey"}])
def test_missing_or_malformed_configuration(env):
    with pytest.raises(sync.SyncError):
        sync.configuration(env)


def test_short_page_does_not_truncate_complete_feed():
    opener = Opener(Response([report(1)], "0-0/2"), Response([report(2)], "1-1/2"))
    rows = sync.fetch_reports(BASE, KEY, opener=opener)
    assert len(rows) == 2
    queries = [parse_qs(urlsplit(req.full_url).query) for req in opener.requests]
    assert [q["offset"] for q in queries] == [["0"], ["1"]]
    assert queries[0]["status"] == ["eq.approved"]
    assert queries[0]["order"] == ["reviewed_at.asc,id.asc"]
    assert "example_input" in queries[0]["select"][0]
    assert opener.requests[0].get_header("Prefer") == "count=exact"


def test_empty_feed_requires_exact_zero_count():
    assert sync.fetch_reports(BASE, KEY, opener=Opener(Response([], "*/0"))) == []


@pytest.mark.parametrize("header,rows", [
    ("", []), ("0-0/*", [report()]), ("*/1", []), ("1-1/1", [report()]),
    ("0-1/2", [report()]), ("0-0/0", [report()]), ("*/5001", []),
    ("0-0/" + "9" * 100, [report()]),
])
def test_incomplete_or_invalid_range_is_rejected(header, rows):
    with pytest.raises(sync.SyncError):
        sync.fetch_reports(BASE, KEY, opener=Opener(Response(rows, header)))


@pytest.mark.parametrize("second", [Response([report(2)], "1-1/3"), Response([report(1)], "1-1/2")])
def test_concurrent_count_changes_or_duplicate_rows_stop_publication(second):
    with pytest.raises(sync.SyncError):
        sync.fetch_reports(BASE, KEY, opener=Opener(Response([report(1)], "0-0/2"), second))


@pytest.mark.parametrize("change", [
    {"status": "pending"}, {"status": "rejected"}, {"id": "not-a-uuid"},
    {"reviewed_at": None}, {"reviewed_at": "2026-09-10T06:00:00"},
    {"summary": " "}, {"summary": "a" * 501}, {"example_input": None},
    {"reviewer_notes": ["bad type"]}, {"confidence": "unreviewed"},
    {"suspicion_level": True}, {"suspicion_level": 5}, {"heuristic_flags": "bad type"},
    {"heuristic_flags": ["flag"] * 21}, {"heuristic_flags": [123]},
    {"agent_platform": "a" * 101},
])
def test_invalid_or_unapproved_reports_rejected(change):
    with pytest.raises(sync.SyncError):
        sync.fetch_reports(BASE, KEY, opener=Opener(Response([report(**change)], "0-0/1")))


@pytest.mark.parametrize("body", [b'{"error":"private backend detail"}', b'invalid json', b'[null]', b'\xff'])
def test_malformed_body_is_not_published_or_echoed(body):
    with pytest.raises(sync.SyncError) as exc:
        sync.fetch_reports(BASE, KEY, opener=Opener(Response(body, "0-0/1")))
    assert "private backend detail" not in str(exc.value)


def test_page_download_is_bounded(monkeypatch):
    monkeypatch.setattr(sync, "MAX_PAGE_BYTES", 10)
    response = Response(b"x" * 100, "0-0/1")
    with pytest.raises(sync.SyncError, match="page size limit"):
        sync.fetch_reports(BASE, KEY, opener=Opener(response))
    assert response.read_sizes == [11]


def test_total_download_is_bounded(monkeypatch):
    monkeypatch.setattr(sync, "MAX_TOTAL_BYTES", 1)
    with pytest.raises(sync.SyncError, match="download budget"):
        sync.fetch_reports(BASE, KEY, opener=Opener(Response([], "*/0")))


@pytest.mark.parametrize("key,bearer", [(KEY, True), ("sb_publishable_fake", False), ("sb_secret_fake", False)])
def test_key_formats_use_correct_headers(key, bearer):
    opener = Opener(Response([], "*/0"))
    sync.fetch_reports(BASE, key, opener=opener)
    assert opener.requests[0].get_header("Apikey") == key
    assert bool(opener.requests[0].get_header("Authorization")) == bearer


def test_redirects_do_not_forward_credentials():
    request = sync.Request(BASE, headers={"Authorization": f"Bearer {KEY}"})
    with pytest.raises(sync.SyncError, match="not forwarded"):
        sync.NoRedirects().redirect_request(request, None, 302, "Found", {}, "https://other.example")


@pytest.mark.parametrize("code,message", [(401, "authentication"), (403, "permission"), (404, "not found"), (540, "paused")])
def test_terminal_http_errors_are_actionable_and_not_retried(code, message):
    error = HTTPError(BASE, code, KEY, {}, io.BytesIO(b"private response"))
    opener = Opener(error)
    with pytest.raises(sync.SyncError, match=message) as exc:
        sync.fetch_reports(BASE, KEY, opener=opener)
    assert KEY not in str(exc.value) and "private response" not in str(exc.value)
    assert len(opener.requests) == 1


@pytest.mark.parametrize("error", [
    URLError(socket.gaierror(-2, "sensitive hostname")), URLError(TimeoutError(KEY)),
    HTTPError(BASE, 503, KEY, {}, None), HTTPError(BASE, 429, KEY, {}, None),
], ids=["dns", "timeout", "server-error", "rate-limit"])
def test_transient_failure_retries_and_recovers(error):
    opener = Opener(error, Response([], "*/0"))
    assert sync.fetch_reports(BASE, KEY, opener=opener) == []
    assert len(opener.requests) == 2


def test_dns_retries_are_bounded_without_secret_logging():
    opener = Opener(*[URLError(socket.gaierror(-2, KEY)) for _ in range(3)])
    with pytest.raises(sync.SyncError, match="hostname could not be resolved") as exc:
        sync.fetch_reports(BASE, KEY, opener=opener)
    assert KEY not in str(exc.value) and len(opener.requests) == 3


def test_tls_errors_do_not_weaken_verification_or_retry():
    opener = Opener(URLError(ssl.SSLCertVerificationError(KEY)))
    with pytest.raises(sync.SyncError, match="TLS"):
        sync.fetch_reports(BASE, KEY, opener=opener)
    assert len(opener.requests) == 1


def test_expired_budget_stops_before_network(monkeypatch):
    monkeypatch.setattr(sync, "SYNC_TIMEOUT", 0)
    opener = Opener()
    with pytest.raises(sync.SyncError, match="time budget"):
        sync.fetch_reports(BASE, KEY, opener=opener)
    assert not opener.requests


def validated(*rows):
    return [sync._validate_report(row) for row in rows]


def test_renderer_is_deterministic_and_does_not_invent_taxonomy_ids():
    first, second = report(1), report(2, attack_category="")
    assert sync.render_reports(validated(first, second)) == sync.render_reports(validated(second, first))
    rendered = sync.render_reports(validated(first, second))
    assert "Latest source review: 2026-09-10T06:00:00+00:00" in rendered
    assert "Uncategorized" in rendered
    assert "ATTACK-14" not in rendered


def test_renderer_escapes_breakout_and_hidden_controls():
    payload = "\\[link](https://example.invalid)\n<script>*header*\u202e"
    rendered = sync.render_reports(validated(report(example_input=payload)))
    assert "<script>" not in rendered and "\u202e" not in rendered
    assert "\\[link\\]\\(https://example\\.invalid\\)" in rendered
    assert "untrusted reference data" in rendered
    assert "\n<script>" not in rendered


def test_empty_feed_and_unchanged_feed_do_not_cause_rewrites(tmp_path):
    destination = tmp_path / "feed.md"
    content = sync.render_reports([])
    assert sync.replace_if_changed(destination, content)
    modified = destination.stat().st_mtime_ns
    assert not sync.replace_if_changed(destination, sync.render_reports([]))
    assert destination.stat().st_mtime_ns == modified


def test_atomic_replace_failure_preserves_previous_feed(tmp_path, monkeypatch):
    destination = tmp_path / "feed.md"
    destination.write_text("previous feed")
    def fail_replace(*args):
        raise OSError("synthetic disk failure")
    monkeypatch.setattr(sync.os, "replace", fail_replace)
    with pytest.raises(OSError):
        sync.replace_if_changed(destination, "new feed")
    assert destination.read_text() == "previous feed"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("check", [False, True])
def test_failed_fetch_preserves_feed_in_both_modes(tmp_path, monkeypatch, capsys, check):
    destination = tmp_path / "feed.md"
    destination.write_text("previous feed")
    monkeypatch.setenv("SUPABASE_URL", BASE)
    monkeypatch.setenv("SUPABASE_SERVICE_KEY", KEY)
    def fail_fetch(*args):
        raise sync.SyncError("network unavailable")
    monkeypatch.setattr(sync, "fetch_reports", fail_fetch)
    args = ["--output", str(destination)] + (["--check"] if check else [])
    assert sync.main(args) == 1
    assert destination.read_text() == "previous feed"
    output = capsys.readouterr()
    assert "network unavailable" in output.err and KEY not in output.err


def test_check_mode_validates_live_data_without_writing(tmp_path, monkeypatch, capsys):
    destination = tmp_path / "feed.md"
    monkeypatch.setenv("SUPABASE_URL", BASE)
    monkeypatch.setenv("SUPABASE_READ_KEY", "sb_publishable_fake")
    monkeypatch.setattr(sync, "fetch_reports", lambda *args: validated(report()))
    assert sync.main(["--check", "--output", str(destination)]) == 0
    assert not destination.exists()
    assert "Validated 1 approved reports; no files changed." in capsys.readouterr().out
