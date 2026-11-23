import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch, tmp_path):
    """No test reaches a registry or OSV: every fetch fails as if offline,
    and the cache is a fresh directory. Tests that want registry data
    replace lockly.enrich.fetch with a fake."""
    monkeypatch.setenv("LOCKLY_CACHE_DIR", str(tmp_path / "lockly-cache"))

    def refuse(url, body=None):
        from lockly.enrich import LookupError_

        raise LookupError_(f"network disabled in tests: {url}")

    monkeypatch.setattr("lockly.enrich.fetch", refuse)
    monkeypatch.setattr("lockly.enrich._get_text", lambda url, cache: refuse(url))
