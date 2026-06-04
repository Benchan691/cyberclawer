CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "vuln_type",
    "disclosure_date",
    "details.avd.danger_level",
    "details.avd.exploitability",
    "details.avd.patch_status",
    "details.avd.cwe.id",
    "details.avd.cwe.name",
    "details.avd.affected_software.vendor",
    "details.avd.affected_software.product",
    "details.avd.affected_software.version",
    "details.avd.affected_software.impact",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
    "details.avd.description",
    "details.avd.solution",
    "details.avd.impact_range",
    "details.avd.security_versions",
    "details.avd.reference_links",
)

DYNAMIC_ATTACK_METRICS_PATH = "details.avd.attack_metrics"
