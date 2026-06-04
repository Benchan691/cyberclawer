CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "vuln_type",
    "disclosure_date",
    "details.govcert.alert_code",
    "details.govcert.alert_type",
    "details.govcert.published_date",
    "details.govcert.tags",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
    "details.govcert.description",
    "details.govcert.affected_systems",
    "details.govcert.impact",
    "details.govcert.recommendation",
    "details.govcert.more_information_links",
    "details.govcert.cve_ids",
    "details.govcert.raw_sections",
)

DYNAMIC_ATTACK_METRICS_PATH = None
