import asyncio

from scripts.remake_qianxin_mongodb import remake_qianxin_documents
from vuln_scraper.config import ScraperSettings


SKIPPED_CHAPTER_CONTENT = """<div id="poc-preview"><div>
<h1>第一章 安全通告</h1><p>Advisory text.</p>
<h1>第二章 漏洞信息</h1><p>Summary.</p>
<h1>第三章 威胁评估</h1><p>Assessment.</p>
<h1>第四章 处置建议</h1><p>修复解决方案 patch info.</p><p>临时缓解方案.</p>
<h1>第五章 参考资料</h1><p>1.[相关链接] https://example.test/ref</p>
<p>奇安信 CERT</p>
</div></div>"""


class FakeJSONResult:
    def __init__(self, data: dict, url: str) -> None:
        self.data = data
        self.status_code = 200
        self.url = url


class FakeJSONClient:
    async def get_json(self, url: str, *, headers=None):
        return FakeJSONResult(
            {
                "status": 10000,
                "data": {
                    "id": 1861,
                    "title": "Linux Kernel advisory",
                    "author": "QAX CERT",
                    "category": "风险通告",
                    "digest": "Advisory digest.",
                    "publish_time": "2026-05-29 10:31:26",
                    "update_time": "2026-05-29 10:32:47",
                    "content": SKIPPED_CHAPTER_CONTENT,
                },
            },
            url,
        )


class FakeCollection:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = {document["_id"]: dict(document) for document in documents}
        self.writes: list[dict] = []

    def find(self, query=None):
        return [dict(document) for document in self.documents.values()]

    def replace_one(self, query: dict, document: dict, *, upsert: bool = False) -> None:
        self.writes.append(document)
        self.documents[query["_id"]] = dict(document)


def _legacy_document() -> dict:
    return {
        "_id": "qianxin:1861",
        "type": "qianxin",
        "code": "1861",
        "cve_code": None,
        "title": "Linux Kernel advisory",
        "vuln_type": "风险通告",
        "disclosure_date": "2026-05-29",
        "status": "High",
        "details": {
            "qianxin": {
                "article_id": "1861",
                "title": "Linux Kernel advisory",
                "description": {
                    "security_advisory": "Advisory text.",
                    "vulnerability_information": {"summary": "Summary."},
                    "threat_assessment": {"context": "Assessment."},
                    "affected_assets": "修复解决方案 patch info.\n临时缓解方案.",
                    "recommendations": ["1.[相关链接] https://example.test/ref"],
                    "references": [],
                },
                "reference_links": [
                    "https://ti.qianxin.com/vulnerability/notice-detail/1861?type=risk",
                    "https://example.test/ref",
                ],
            }
        },
        "source": {
            "provider": "qianxin",
            "url": "https://ti.qianxin.com/vulnerability/notice-list",
            "detail_url": "https://ti.qianxin.com/vulnerability/notice-detail/1861?type=risk",
        },
        "scraped_at": "2026-06-05T09:55:30.050134+00:00",
    }


def test_remake_qianxin_documents_dry_run_detects_misaligned_chapters() -> None:
    collection = FakeCollection([_legacy_document()])
    settings = ScraperSettings(request_delay=0, retries=0).for_provider("qianxin").normalized()

    class FakeClientContext:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def __aenter__(self):
            return FakeJSONClient()

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

    result = asyncio.run(
        remake_qianxin_documents(
            collection,
            settings=settings,
            apply=False,
            client_factory=FakeClientContext,
        )
    )

    assert result.scanned == 1
    assert result.refreshed == 1
    assert result.skipped == 0
    assert collection.writes == []


def test_remake_qianxin_documents_apply_rewrites_chapter_fields() -> None:
    collection = FakeCollection([_legacy_document()])
    settings = ScraperSettings(request_delay=0, retries=0).for_provider("qianxin").normalized()

    class FakeClientContext:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def __aenter__(self):
            return FakeJSONClient()

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

    result = asyncio.run(
        remake_qianxin_documents(
            collection,
            settings=settings,
            apply=True,
            client_factory=FakeClientContext,
        )
    )

    assert result.scanned == 1
    assert result.refreshed == 1
    assert len(collection.writes) == 1

    description = collection.documents["qianxin:1861"]["details"]["qianxin"]["description"]
    assert description["affected_assets"] == ""
    assert description["recommendations"] == ["修复解决方案 patch info.", "临时缓解方案."]
    assert description["references"] == ["1.[相关链接] https://example.test/ref"]
