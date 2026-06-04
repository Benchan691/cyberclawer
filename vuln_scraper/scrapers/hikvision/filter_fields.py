CATEGORICAL_FIELDS = (
    "type",
    "status",
    "vuln_type",
    "disclosure_date",
    "details.hikvision.severity",
    "details.hikvision.published_date",
    "details.hikvision.updated_date",
    "details.hikvision.cve_ids",
    "details.hikvision.affected_products",
)

TEXT_FIELDS = (
    "code",
    "cve_code",
    "title",
    "details.hikvision.advisory_id",
    "details.hikvision.summary",
    "details.hikvision.description",
    "details.hikvision.solution",
    "details.hikvision.reference_links",
)

DYNAMIC_ATTACK_METRICS_PATH = None
