BASE_URL = "https://wiki.zimbra.com"
LIST_URL = (
    f"{BASE_URL}/api.php?action=feedrecentchanges&feedformat=rss"
    "&namespace=0&target=Zimbra_Releases&days=30&limit=50"
)
SOURCE_URL = f"{BASE_URL}/wiki/Zimbra_Releases"
DEFAULT_COLLECTION = "zimbra"
