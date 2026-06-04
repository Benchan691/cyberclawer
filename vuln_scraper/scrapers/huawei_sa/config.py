BASE_URL = "https://securitybulletin.huawei.com"
SOURCE_URL = f"{BASE_URL}/enterprise/en/security-advisory"
API_URL = f"{BASE_URL}/vdmsapi/services/vdmsapi/rest/v1/enterprise/advisories"
DETAIL_URL = f"{BASE_URL}/enterprise/en/sa/detail"
DEFAULT_COLLECTION = "huawei_sa"
PAGE_SIZE = 20

PAYLOAD = {
    "keyword": "",
    "publishDateFrom": "",
    "publishDateTo": "",
    "products": [],
    "sort": 1,
    "sortField": "publish_date",
    "vulId": "",
    "cveId": "",
    "cvssFrom": None,
    "cvssTo": None,
    "severity": [],
    "productVersionsMsg": [],
    "cvssV4From": None,
    "cvssV4To": None,
    "productLine": "",
    "range": 1,
}
