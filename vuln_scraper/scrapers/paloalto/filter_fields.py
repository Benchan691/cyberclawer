CATEGORICAL_FIELDS = (
    "type",
    "status",
    "severity",
    "vuln_type",
    "details.paloalto.severity",
    "details.paloalto.urgency",
    "details.paloalto.products",
    "details.paloalto.cve_ids",
    "details.paloalto.weakness.cwe_id",
)

TEXT_FIELDS = (
    "code",
    "cve_code",
    "title",
    "details.paloalto.advisory_id",
    "details.paloalto.description",
    "details.paloalto.solution",
    "details.paloalto.workarounds",
    "details.paloalto.exploitation_status",
    "details.paloalto.reference_links",
)

DYNAMIC_ATTACK_METRICS_PATH = None
