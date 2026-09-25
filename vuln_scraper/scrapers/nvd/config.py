BASE_URL = "https://services.nvd.nist.gov"
LIST_URL = f"{BASE_URL}/rest/json/cves/2.0"
SOURCE_URL = "https://nvd.nist.gov/vuln/detail"
DETAIL_URL = "https://nvd.nist.gov/vuln/detail"
DEFAULT_COLLECTION = "nvd"
# NVD API 2.0 allows resultsPerPage up to 2000.
DEFAULT_PAGE_SIZE = 200
# lastModStartDate/lastModEndDate windows are capped at 120 days by the API.
DEFAULT_WINDOW_DAYS = 7
