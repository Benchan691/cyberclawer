CATEGORICAL_FIELDS = (
    "type",
    "status",
    "severity",
    "vuln_type",
    "disclosure_date",
    "details.cnvd.severity",
    "details.cnvd.published_date",
    "details.cnvd.updated_date",
    "details.cnvd.affected_products",
    "details.cnvd.cve_ids",
)

TEXT_FIELDS = (
    "code",
    "cve_code",
    "title",
    "details.cnvd.cnvd_id",
    "details.cnvd.description",
    "details.cnvd.solution",
    "details.cnvd.reference_links",
    "details.cnvd.raw_fields",
)

DYNAMIC_ATTACK_METRICS_PATH = None
