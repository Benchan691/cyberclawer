CATEGORICAL_FIELDS = (
    "type",
    "status",
    "vuln_type",
    "disclosure_date",
    "details.cnnvd.published_date",
    "details.cnnvd.created_by",
    "details.cnnvd.cve_ids",
)

TEXT_FIELDS = (
    "code",
    "cve_code",
    "title",
    "details.cnnvd.warn_id",
    "details.cnnvd.summary",
    "details.cnnvd.description",
    "details.cnnvd.reference_links",
    "details.cnnvd.raw_sections",
)

DYNAMIC_ATTACK_METRICS_PATH = None
