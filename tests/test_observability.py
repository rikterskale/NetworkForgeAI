"""Tests for central logging configuration."""

import logging

import networkforgeai.observability as obs


def _reset():
    obs._CONFIGURED = False


def test_configure_logging_honors_explicit_level():
    _reset()
    obs.configure_logging("DEBUG", force=True)
    assert logging.getLogger().level == logging.DEBUG


def test_configure_logging_reads_env(monkeypatch):
    _reset()
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    obs.configure_logging(force=True)
    assert logging.getLogger().level == logging.WARNING


def test_unknown_level_falls_back_to_info(monkeypatch):
    _reset()
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    obs.configure_logging("NONSENSE", force=True)
    assert logging.getLogger().level == logging.INFO


def test_idempotent_without_force():
    _reset()
    obs.configure_logging("ERROR", force=True)
    # Second call without force should not change the level.
    obs.configure_logging("DEBUG")
    assert logging.getLogger().level == logging.ERROR


def test_get_logger_returns_named_logger():
    assert obs.get_logger("x.y").name == "x.y"
