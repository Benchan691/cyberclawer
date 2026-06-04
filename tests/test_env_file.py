from __future__ import annotations

import os
from pathlib import Path

from vuln_scraper.env_file import load_project_dotenv, read_dotenv


def test_read_dotenv_parses_export_syntax(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text('export CISCO_OPENVULN_TOKEN="from-file"\n', encoding="utf-8")

    assert read_dotenv(env_path) == {"CISCO_OPENVULN_TOKEN": "from-file"}


def test_load_project_dotenv_sets_cisco_token(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CISCO_OPENVULN_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("CISCO_OPENVULN_TOKEN=file-token\n", encoding="utf-8")

    loaded = load_project_dotenv()

    assert loaded == tmp_path / ".env"
    assert os.getenv("CISCO_OPENVULN_TOKEN") == "file-token"
