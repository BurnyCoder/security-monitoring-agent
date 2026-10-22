"""Global: configuration round-trip regression. Local: use temporary dotenv files without credentials."""

from security_monitoring_agent.config import load_settings, save_settings


def test_settings_roundtrip_preserves_literal_numbers(tmp_path):
    """Global: saved UI preferences must restart. Local: numeric Literals need explicit dotenv conversion."""
    settings = load_settings(tmp_path)
    settings.auto_scan = False
    settings.news_days = 30
    save_settings(tmp_path, settings)
    assert load_settings(tmp_path) == settings
