"""
Tests for modem session and status caching.

Measured on the real device, this modem takes ~18s to render its status page,
so avoiding redundant fetches matters more here than anywhere else in the app.
These tests never touch the network.
"""

import time
from importlib import reload

import pytest

import config
from core.modem_scraper import ModemScraper, ModemStatus


def make_status(error=None):
    from datetime import datetime
    return ModemStatus(
        modem_info=None,
        wifi_info_24ghz=None,
        wifi_info_5ghz=None,
        connected_devices=[],
        lan_ports=[],
        last_updated=datetime.now(),
        error=error,
    )


@pytest.fixture
def scraper():
    return ModemScraper(modem_ip="192.0.2.1", username="u", password="p")


class TestSessionCache:
    def test_new_scraper_has_no_session(self, scraper):
        assert scraper._session_is_fresh() is False

    def test_fresh_after_login(self, scraper):
        scraper._is_logged_in = True
        scraper._login_time = time.monotonic()
        assert scraper._session_is_fresh() is True

    def test_expires_after_ttl(self, scraper):
        scraper._is_logged_in = True
        scraper._login_time = time.monotonic() - (scraper.SESSION_TTL_SECONDS + 1)
        assert scraper._session_is_fresh() is False

    def test_invalidate_clears_it(self, scraper):
        scraper._is_logged_in = True
        scraper._login_time = time.monotonic()
        scraper.invalidate_session()
        assert scraper._session_is_fresh() is False

    def test_login_short_circuits_when_fresh(self, scraper):
        """
        _login must return early on a cached session.

        The flag existed before this change but was never read, so every poll
        paid a full handshake.
        """
        scraper._is_logged_in = True
        scraper._login_time = time.monotonic()

        def explode(*args, **kwargs):
            raise AssertionError("_login hit the network despite a fresh session")

        scraper._session.get = explode
        assert scraper._login() is True

    def test_login_without_address_skips_request(self, monkeypatch):
        scraper = ModemScraper(modem_ip="")

        def unexpected_request(*args, **kwargs):
            pytest.fail("A modem address must be set before making a request")

        monkeypatch.setattr(scraper._session, "get", unexpected_request)
        assert scraper._login() is False

    def test_login_without_password_uses_read_only_access(self, scraper, monkeypatch):
        scraper.password = ""

        def unexpected_login(*args, **kwargs):
            pytest.fail("Missing credentials must skip the login form")

        monkeypatch.setattr(scraper._session, "get", unexpected_login)
        monkeypatch.setattr(scraper, "_try_without_login", lambda: True)
        assert scraper._login() is True


class TestStatusCache:
    def test_second_call_reuses_the_result(self, scraper, monkeypatch):
        calls = []
        monkeypatch.setattr(
            scraper, "_fetch_status",
            lambda: (calls.append(1), make_status())[1]
        )

        first = scraper.get_status()
        second = scraper.get_status()

        assert len(calls) == 1, "the ~18s fetch ran twice"
        assert second is first

    def test_max_age_zero_forces_a_fetch(self, scraper, monkeypatch):
        calls = []
        monkeypatch.setattr(
            scraper, "_fetch_status",
            lambda: (calls.append(1), make_status())[1]
        )

        scraper.get_status()
        scraper.get_status(max_age=0)

        assert len(calls) == 2

    def test_expired_cache_refetches(self, scraper, monkeypatch):
        calls = []
        monkeypatch.setattr(
            scraper, "_fetch_status",
            lambda: (calls.append(1), make_status())[1]
        )

        scraper.get_status()
        scraper._cached_status_time = time.monotonic() - (
            scraper.STATUS_CACHE_SECONDS + 1
        )
        scraper.get_status()

        assert len(calls) == 2

    def test_failures_are_not_cached(self, scraper, monkeypatch):
        """A failed fetch must not poison the cache for a minute."""
        calls = []
        monkeypatch.setattr(
            scraper, "_fetch_status",
            lambda: (calls.append(1), make_status(error="boom"))[1]
        )

        scraper.get_status()
        scraper.get_status()

        assert len(calls) == 2

    def test_invalidate_clears_the_cache(self, scraper, monkeypatch):
        calls = []
        monkeypatch.setattr(
            scraper, "_fetch_status",
            lambda: (calls.append(1), make_status())[1]
        )

        scraper.get_status()
        scraper.invalidate_status_cache()
        scraper.get_status()

        assert len(calls) == 2

    def test_concurrent_callers_share_one_fetch(self, scraper, monkeypatch):
        """
        Device Discovery and the Modem tab can both ask at once.

        Only one of them should pay for it.
        """
        import threading

        calls = []

        def slow_fetch():
            calls.append(1)
            time.sleep(0.3)
            return make_status()

        monkeypatch.setattr(scraper, "_fetch_status", slow_fetch)

        threads = [threading.Thread(target=scraper.get_status) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(calls) == 1, f"{len(calls)} concurrent fetches; the lock is not holding"


class TestConfigDefaults:
    def test_defaults_come_from_config(self):
        s = ModemScraper()
        assert s.modem_ip == config.MODEM_DEFAULT_IP
        assert s.username == config.MODEM_DEFAULT_USERNAME
        assert s.password == config.MODEM_DEFAULT_PASSWORD

    @pytest.mark.parametrize(
        ("variable", "setting", "example"),
        [
            ("NETGUARDIAN_MODEM_IP", "MODEM_DEFAULT_IP", "192.0.2.5"),
            ("NETGUARDIAN_MODEM_USER", "MODEM_DEFAULT_USERNAME", "test-user"),
            ("NETGUARDIAN_MODEM_PASSWORD", "MODEM_DEFAULT_PASSWORD", "test-password"),
        ],
    )
    def test_modem_setting_default_and_override(self, monkeypatch, variable, setting, example):
        try:
            with monkeypatch.context() as env:
                env.delenv(variable, raising=False)
                assert getattr(reload(config), setting) == ""

                env.setenv(variable, example)
                assert getattr(reload(config), setting) == example
        finally:
            reload(config)
