CATEGORICAL_FIELDS = (
    "type",
    "status",
    "severity",
    "vuln_type",
    "details.infosec.alert_type",
    "details.infosec.alert_code",
    "details.infosec.tags",
    "details.infosec.affected_systems",
    "details.infosec.cve_ids",
)

TEXT_FIELDS = (
    "code",
    "cve_code",
    "title",
    "details.infosec.summary",
    "details.infosec.description",
    "details.infosec.impact",
    "details.infosec.recommendation",
    "details.infosec.more_information_links",
    "details.infosec.govcert_detail_url",
)

DYNAMIC_ATTACK_METRICS_PATH = None
