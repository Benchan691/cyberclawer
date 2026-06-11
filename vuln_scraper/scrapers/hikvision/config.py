import re

BASE_URL = "https://www.hikvision.com"
LIST_URL = f"{BASE_URL}/hk/support/cybersecurity/security-advisory/"
CONTENT_ADVISORY_URL = (
    f"{BASE_URL}/content/hikvision/hk/support/cybersecurity/security-advisory/"
)
HK_ADVISORY_PATH = "/hk/support/cybersecurity/security-advisory"
CONTENT_ADVISORY_PATH = "/content/hikvision/hk/support/cybersecurity/security-advisory"
HSRC_CODE_RE = re.compile(r"^hsrc-\d{4,6}-\d+$", re.IGNORECASE)
SOURCE_URL = LIST_URL
DEFAULT_COLLECTION = "hikvision"
