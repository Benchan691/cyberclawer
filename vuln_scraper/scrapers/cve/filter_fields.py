CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "severity",
    "disclosure_date",
    "details.cve.vuln_status",
    "details.cve.metrics.cvss_v40.cvssData.baseSeverity",
    "details.cve.metrics.cvss_v31.cvssData.baseSeverity",
    "details.cve.metrics.cvss_v30.cvssData.baseSeverity",
    "details.cve.metrics.cvss_v2.baseSeverity",
    "details.cve.weaknesses.descriptions.cweId",
    "details.cve.weaknesses.descriptions.description",
    "details.cve.references.tags",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "title",
    "details.cve.cve_id",
    "details.cve.source_identifier",
    "details.cve.published",
    "details.cve.last_modified",
    "details.cve.descriptions.value",
    "details.cve.affected_products",
    "details.cve.references.url",
    "details.cve.configurations",
)

DYNAMIC_ATTACK_METRICS_PATH = None
