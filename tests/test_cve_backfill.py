import asyncio
import copy

from vuln_scraper.config import ScraperSettings
from vuln_scraper.cve_backfill import backfill_missing_cves


def test_backfill_missing_cves_fetches_and_syncs_missing_master_record() -> None:
    client = FakeMongoClient({"cve": FakeCollection()})
    settings = ScraperSettings(
        mongo_enabled=True,
        mongo_database="avd",
        mongo_config_file=None,
        limit=3,
        request_delay=0,
        retries=0,
    ).normalized()

    result = asyncio.run(
        backfill_missing_cves(
            [{"type": "avd", "code": "2024-3094", "cve_code": "2024-3094"}],
            settings,
            client,
            scraped_at="2026-06-02T00:00:00+00:00",
            client_factory=FakeNVDClient,
        )
    )

    assert result.inserted == 1
    document = client.collections["cve"].documents["cve:2024-3094"]
    assert document["type"] == "cve"
    assert document["code"] == "2024-3094"
    assert document["cve_code"] is None
    assert document["details"]["cve"]["cve_id"] == "CVE-2024-3094"
    assert FakeNVDClient.instances[0].delay == 6.0


class FakeNVDClient:
    instances = []

    def __init__(self, *, delay: float, retries: int, timeout: float) -> None:
        self.delay = delay
        self.retries = retries
        self.timeout = timeout
        self.urls: list[str] = []
        self.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get_json(self, url: str, *, headers=None):
        self.urls.append(url)
        return FakeJSONResult(
            {
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-3094",
                            "published": "2024-03-29T17:15:21.150",
                            "lastModified": "2025-08-19T01:15:57.407",
                            "vulnStatus": "Modified",
                            "descriptions": [{"lang": "en", "value": "xz backdoor"}],
                            "metrics": {},
                            "weaknesses": [],
                            "references": [],
                            "configurations": [],
                        }
                    }
                ],
            }
        )


class FakeJSONResult:
    def __init__(self, data: dict) -> None:
        self.data = data
        self.status_code = 200
        self.url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094"


class FakeMongoClient:
    def __init__(self, collections: dict[str, "FakeCollection"]) -> None:
        self.collections = collections

    def __getitem__(self, name: str):
        return FakeDatabase(self.collections)


class FakeDatabase:
    def __init__(self, collections: dict[str, "FakeCollection"]) -> None:
        self.collections = collections

    def __getitem__(self, name: str) -> "FakeCollection":
        return self.collections.setdefault(name, FakeCollection())


class FakeCollection:
    def __init__(self) -> None:
        self.documents: dict[str, dict] = {}
        self.indexes = []

    def create_index(self, field, unique: bool = False) -> None:
        self.indexes.append((field, unique))

    def find(self, query: dict | None = None, projection: dict | None = None):
        query = query or {}
        if "_id" in query and isinstance(query["_id"], dict) and "$in" in query["_id"]:
            ids = set(query["_id"]["$in"])
            return [copy.deepcopy(document) for key, document in self.documents.items() if key in ids]
        return [copy.deepcopy(document) for document in self.documents.values()]

    def find_one(self, query: dict) -> dict | None:
        document = self.documents.get(query["_id"])
        return copy.deepcopy(document) if document is not None else None

    def insert_one(self, document: dict) -> None:
        self.documents[document["_id"]] = copy.deepcopy(document)

    def replace_one(self, query: dict, document: dict, *, upsert: bool = False) -> None:
        self.documents[query["_id"]] = copy.deepcopy(document)
