BASE_URL = "https://supportportal.juniper.net"
SOURCE_URL = (
    f"{BASE_URL}/s/global-search/%40uri"
    "#f-sf_primarysourcename=Knowledge&f-sf_articletype=Security%20Advisories"
)
SEARCH_URL = f"{BASE_URL}/s/global-search/%40uri"
ARTICLE_URL = f"{BASE_URL}/s/article"
DEFAULT_COLLECTION = "juniper"
PAGE_SIZE = 10
# Facet filters alone still return KB/Mist docs; this query restricts list results to advisories.
COVEO_LIST_QUERY = '@sfrecordtypename=="Security Advisories"'
