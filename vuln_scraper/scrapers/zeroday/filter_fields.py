CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "vuln_type",
    "disclosure_date",
    "details.zeroday.vulnerable_component",
    "details.zeroday.patch_status",
    "details.zeroday.disclosed_date",
    "details.zeroday.patched_date",
    "details.zeroday.cwe.id",
    "details.zeroday.cwe.name",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
    "details.zeroday.cve_id",
    "details.zeroday.advisory.title",
    "details.zeroday.advisory.url",
    "details.zeroday.cvss_v3_vector",
    "details.zeroday.description",
    "details.zeroday.reference_links",
)

DYNAMIC_ATTACK_METRICS_PATH = None
