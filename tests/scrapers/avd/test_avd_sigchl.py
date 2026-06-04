import pytest

from vuln_scraper.scrapers.avd.h import AVDSigchlError, solve_redirect_url

pytest.importorskip("quickjs")


CHALLENGE_HTML = """
<html>
  <head>
    <script>
      location.href = 'https://avd.aliyun.com/high-risk/list?page=1&timestamp__1384=testtoken';
    </script>
  </head>
</html>
"""


def test_solve_redirect_url_from_inline_script() -> None:
    url = "https://avd.aliyun.com/high-risk/list?page=1"
    redirect = solve_redirect_url(url, CHALLENGE_HTML, user_agent="test-agent")

    assert "timestamp__" in redirect
    assert redirect.startswith("https://avd.aliyun.com/high-risk/list")
    assert "page=1" in redirect


def test_solve_redirect_url_raises_when_no_script() -> None:
    with pytest.raises(AVDSigchlError):
        solve_redirect_url(
            "https://avd.aliyun.com/high-risk/list?page=1",
            "<html><body>no scripts</body></html>",
            user_agent="test-agent",
        )
