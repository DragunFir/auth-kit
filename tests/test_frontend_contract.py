from __future__ import annotations

from pathlib import Path


def test_avatar_url_is_not_rendered_as_text_input() -> None:
    app_source = Path("web/src/App.tsx").read_text()

    assert 'label="Avatar URL"' not in app_source
    assert "value={profile.avatar_url" not in app_source
    assert "value={adminForm.profile.avatar_url" not in app_source
    assert "src={profile.avatar_url || undefined}" in app_source
