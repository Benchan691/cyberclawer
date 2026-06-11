from vuln_scraper.table_extractor import extract_raw_tables


def test_extract_raw_tables_preserves_headers_empty_cells_and_multiple_tables() -> None:
    html = """
    <table>
      <tr><th> Name </th><th>Notes</th></tr>
      <tr><td>Product   One</td><td></td></tr>
      <tr><td>Product Two</td></tr>
    </table>
    <table><tr><td>Second</td></tr></table>
    """

    assert extract_raw_tables(html) == [
        [["Name", "Notes"], ["Product One", ""], ["Product Two", ""]],
        [["Second"]],
    ]


def test_extract_raw_tables_expands_rowspan_and_colspan_to_rectangular_grid() -> None:
    html = """
    <table>
      <tr><th rowspan="2">Product</th><th colspan="2">Versions</th></tr>
      <tr><th>Affected</th><th>Fixed</th></tr>
      <tr><td>Widget</td><td colspan="2">1.2.3</td></tr>
    </table>
    """

    assert extract_raw_tables(html) == [
        [
            ["Product", "Versions", "Versions"],
            ["Product", "Affected", "Fixed"],
            ["Widget", "1.2.3", "1.2.3"],
        ]
    ]


def test_extract_raw_tables_finds_html_nested_in_json_payloads() -> None:
    payload = {
        "data": {
            "content": "<p>Detail</p><table><tr><td>Nested</td><td>HTML</td></tr></table>",
            "title": "No table here",
        }
    }

    assert extract_raw_tables(payload) == [[["Nested", "HTML"]]]


def test_extract_raw_tables_returns_empty_when_detail_has_no_table() -> None:
    assert extract_raw_tables({"data": {"content": "<p>Plain detail</p>"}}) == []
