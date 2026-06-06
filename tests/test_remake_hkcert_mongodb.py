import asyncio

from scripts.remake_hkcert_mongodb import remake_hkcert_documents
from vuln_scraper.config import ScraperSettings
from vuln_scraper.scrapers.hkcert.parsers.detail import normalize_hkcert_detail


class FakeHTMLClient:
    async def get_html(self, url: str):
        raise AssertionError(f"unexpected fetch: {url}")


class FakeCollection:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = {document["_id"]: dict(document) for document in documents}
        self.writes: list[dict] = []

    def find(self, query=None):
        return [dict(document) for document in self.documents.values()]

    def replace_one(self, query: dict, document: dict, *, upsert: bool = False) -> None:
        self.writes.append(document)
        self.documents[query["_id"]] = dict(document)


def test_remake_hkcert_documents_normalize_only_updates_legacy_shape() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "hkcert:adobe-products-multiple-vulnerabilities_20260604",
                "type": "hkcert",
                "code": "adobe-products-multiple-vulnerabilities_20260604",
                "details": {
                    "hkcert": {
                        "intro": "Adobe Premiere Pro Medium Risk Remote Code Execution APSB26-46",
                        "intro_tables": [
                            {
                                "headers": ["vulnerable_product", "details"],
                                "rows": [
                                    {
                                        "vulnerable_product": "Adobe Premiere Pro",
                                        "details": "APSB26-46",
                                    }
                                ],
                            }
                        ],
                    }
                },
            }
        ]
    )
    settings = ScraperSettings(request_delay=0, retries=0).for_provider("hkcert").normalized()

    class FakeClientContext:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def __aenter__(self):
            return FakeHTMLClient()

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

    result = asyncio.run(
        remake_hkcert_documents(
            collection,
            settings=settings,
            apply=True,
            refetch=False,
            client_factory=FakeClientContext,
        )
    )

    assert result.scanned == 1
    assert result.normalized_only == 1
    document = collection.documents["hkcert:adobe-products-multiple-vulnerabilities_20260604"]
    hkcert_detail = normalize_hkcert_detail(document["details"]["hkcert"])
    assert "intro_tables" not in hkcert_detail
    assert hkcert_detail["table"][0]["name"] == "Adobe Premiere Pro"
