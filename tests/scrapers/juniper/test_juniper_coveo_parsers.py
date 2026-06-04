from vuln_scraper.scrapers.juniper.parsers.coveo import parse_coveo_detail, parse_coveo_list


def test_parse_coveo_list_builds_entries() -> None:
    payload = {
        "totalCount": 2,
        "results": [
            {
                "title": "JSA93456 : Junos OS advisory",
                "clickUri": "https://supportportal.juniper.net/s/article/JSA93456",
                "raw": {
                    "sfcec_documentid__c": "JSA93456",
                    "sftitle": "JSA93456 : Junos OS advisory",
                    "sfrecordtypename": "Security Advisories",
                    "sflastpublisheddate": "2026-05-29",
                    "sfcustomer_url__c": "https://supportportal.juniper.net/s/article/JSA93456",
                    "sfurlname": "JSA93456",
                },
            },
            {
                "title": "JSA93455 : Older advisory",
                "raw": {
                    "sfcec_documentid__c": "JSA93455",
                    "sftitle": "JSA93455 : Older advisory",
                    "sfrecordtypename": "Security Advisories",
                    "sflastpublisheddate": "2026-05-22",
                    "sfcustomer_url__c": "https://supportportal.juniper.net/s/article/JSA93455",
                },
            },
        ],
    }

    page = parse_coveo_list(payload, page=1)

    assert page.total_records == 2
    assert len(page.entries) == 2
    assert page.entries[0].identity.code == "JSA93456"
    assert page.entries[0].disclosure_date == "2026-05-29"
    assert page.entries[0].embedded_detail["slug"] == "JSA93456"


def test_parse_coveo_detail_maps_sections() -> None:
    payload = {
        "results": [
            {
                "title": "JSA93456 : Junos OS advisory",
                "excerpt": "Summary text",
                "raw": {
                    "sfcec_documentid__c": "JSA93456",
                    "sftitle": "JSA93456 : Junos OS advisory",
                    "sfrecordtypename": "Security Advisories",
                    "sflastpublisheddate": "2026-05-29",
                    "sflastmodifieddate": "2026-05-30",
                    "sfcustomer_url__c": "https://supportportal.juniper.net/s/article/JSA93456",
                    "sfcec_problem__c": "Problem includes CVE-2026-55555.",
                    "sfcec_product_affected__c": "Junos OS 24.2",
                    "sfcec_solution__c": "Upgrade to fixed release.",
                    "sfcec_workaround__c": "Disable J-Web.",
                },
            }
        ]
    }

    detail = parse_coveo_detail(payload).to_dict()

    assert detail["article_id"] == "JSA93456"
    assert detail["published_date"] == "2026-05-29"
    assert detail["updated_date"] == "2026-05-30"
    assert detail["cve_ids"] == ["CVE-2026-55555"]
    assert detail["products"] == ["Junos OS 24.2"]
    assert "fixed release" in detail["solution"]


def test_parse_coveo_detail_strips_html_tags() -> None:
    payload = {
        "results": [
            {
                "title": "JSA93456 : Junos OS advisory",
                "raw": {
                    "sfcec_documentid__c": "JSA93456",
                    "sftitle": "JSA93456 : Junos OS advisory",
                    "sfrecordtypename": "Security Advisories",
                    "sflastpublisheddate": "2026-05-29",
                    "sfcustomer_url__c": "https://supportportal.juniper.net/s/article/JSA93456",
                    "sfcec_problem__c": "<p>Problem includes <strong>CVE-2026-55555</strong>.</p>",
                    "sfcec_product_affected__c": "<ul><li>Junos OS</li><li>Junos EVO</li></ul>",
                    "sfcec_solution__c": "<p>Upgrade to <em>fixed</em> release.</p>",
                },
            }
        ]
    }

    detail = parse_coveo_detail(payload).to_dict()

    assert "<p>" not in (detail["description"] or "")
    assert "<li>" not in str(detail["products"])
    assert detail["products"] == ["Junos OS", "Junos EVO"]
    assert detail["description"] == "Problem includes CVE-2026-55555."
    assert detail["solution"] == "Upgrade to fixed release."
    assert "<p>" not in detail["raw_sections"]["problem"]
