from vuln_scraper.scrapers.zimbra.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.zimbra.parsers.list import parse_release_list


LIST_HTML = """
<div id="mw-content-text"><div class="mw-parser-output">
<table><tr><th>Release</th><th>Codename</th><th>Patch Level</th><th>Third-Party Patch Level</th><th>General Availability</th></tr>
<tr><td>10.1.0 GA Release</td><td>Daffodil</td><td><a href="/wiki/Zimbra_Releases/10.1.20"><b>Patch 10.1.20</b></a></td><td>No released patches</td><td>07/16/2024</td></tr>
<tr><td>8.8.15 GA Release</td><td>Joule</td><td><a href="/wiki/Zimbra_Releases/8.8.15/P47"><b>Patch 47</b></a></td><td>No released patches</td><td>07/22/2019</td></tr>
</table></div></div>
"""


DETAIL_HTML = """
<div id="mw-content-text"><div class="mw-parser-output">
<h1>Zimbra Daffodil (v10.1.20) Patch Release</h1>
<div><p>Release Date: <b>July 20, 2026</b></p></div>
<h1>Security Fixes</h1>
<table><tr><th>Summary</th></tr><tr><td>Fixed command injection.</td></tr><tr><td>Fixed stored XSS.</td></tr></table>
<h1>Fixed Issues</h1><h2>Licensing</h2><ul><li>Fixed COS reset.</li></ul>
<h1>Packages</h1><pre>zimbra-patch -&gt; 10.1.20.1783418035-2
zimbra-mta-patch -&gt; 10.1.20.1783342495-1</pre>
<h1>Patch Installation</h1><p><a href="/wiki/Zimbra_Releases/10.1.0/patch_installation">Patch Installation</a></p>
<h1>Quick note: Open Source repo</h1><p><a href="https://github.com/Zimbra/zm-build">Github</a></p>
</div></div>
"""


def test_parse_release_list_finds_new_style_and_legacy_patch_links() -> None:
    page = parse_release_list(LIST_HTML, page=1)

    assert [entry.key for entry in page.entries] == ["zimbra:10.1.20", "zimbra:8.8.15/P47"]
    assert page.entries[0].embedded_detail["codename"] == "Daffodil"
    assert page.entries[1].embedded_detail["reference_links"] == [
        "https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P47"
    ]


def test_parse_detail_extracts_release_contents() -> None:
    detail = parse_detail_page(DETAIL_HTML).to_dict()

    assert detail["version"] == "10.1.20"
    assert detail["release_date"] == "2026-07-20"
    assert detail["security_fixes"] == ["Fixed command injection.", "Fixed stored XSS."]
    assert detail["fixed_issues"] == {"Licensing": ["Fixed COS reset."]}
    assert detail["packages"] == {
        "zimbra-patch": "10.1.20.1783418035-2",
        "zimbra-mta-patch": "10.1.20.1783342495-1",
    }
    assert detail["patch_installation_url"].endswith("patch_installation")
    assert detail["open_source_repo_url"] == "https://github.com/Zimbra/zm-build"
