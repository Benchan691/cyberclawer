CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "severity",
    "vuln_type",
    "disclosure_date",
    "cve_code",
    "details.msrc.document_id",
    "details.msrc.current_release_date",
    "details.msrc.cwe.id",
    "details.msrc.product_statuses.type",
    "details.msrc.product_statuses.product_names",
    "details.msrc.threats.type",
    "details.msrc.threats.description",
    "details.msrc.threats.product_names",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
    "vuln_type",
    "details.msrc.cve_id",
    "details.msrc.title",
    "details.msrc.description",
    "details.msrc.document_title",
    "details.msrc.notes.value",
    "details.msrc.cwe.value",
    "details.msrc.product_statuses.product_names",
    "details.msrc.threats.description",
    "details.msrc.remediations.description",
    "details.msrc.acknowledgments.names",
    "details.msrc.cvrf_url",
)

DYNAMIC_ATTACK_METRICS_PATH = None
