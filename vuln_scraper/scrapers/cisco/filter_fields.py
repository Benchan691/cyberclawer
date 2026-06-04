CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "vuln_type",
    "disclosure_date",
    "details.cisco.sir",
    "details.cisco.status",
    "details.cisco.first_published",
    "details.cisco.cve_ids",
    "details.cisco.cwe",
    "details.cisco.product_names",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
    "details.cisco.advisory_id",
    "details.cisco.advisory_title",
    "details.cisco.summary",
    "details.cisco.cve_ids",
    "details.cisco.bug_ids",
    "details.cisco.cwe",
    "details.cisco.product_names",
    "details.cisco.publication_url",
)

DYNAMIC_ATTACK_METRICS_PATH = None
