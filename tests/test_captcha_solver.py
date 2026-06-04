import json
from pathlib import Path

from vuln_scraper.captcha_solver import CaptchaMap, hash_captcha_data_url, resolve_captcha_map_path


def test_hash_captcha_data_url_matches_map_keys() -> None:
    path = Path("captcha_map.json")
    if not path.is_file():
        return

    raw = json.loads(path.read_text(encoding="utf-8"))
    for key, entry in raw.items():
        src = entry["src_url"]
        assert hash_captcha_data_url(src) == key


def test_captcha_map_loads_answers() -> None:
    path = resolve_captcha_map_path()
    if path is None:
        return

    captcha_map = CaptchaMap.load(path)
    assert len(captcha_map) >= 1
    first_hash = next(iter(json.loads(path.read_text(encoding="utf-8"))))
    assert captcha_map.lookup(first_hash) is not None


def test_captcha_map_indexes_src_url_hash(tmp_path) -> None:
    src_url = "data:image/png;base64,Y2FwdGNoYS1ieXRlcw=="
    image_hash = hash_captcha_data_url(src_url)
    path = tmp_path / "captcha_map.json"
    path.write_text(
        json.dumps(
            {
                "browser-label-id": {
                    "answer": "abc123",
                    "src_url": src_url,
                }
            }
        ),
        encoding="utf-8",
    )

    captcha_map = CaptchaMap.load(path)

    assert image_hash is not None
    assert captcha_map.lookup(image_hash) == "abc123"
