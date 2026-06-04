CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "disclosure_date",
    "details.hkcert.risk_level",
    "details.hkcert.bulletin_source",
    "details.hkcert.release_date",
    "details.hkcert.last_update_date",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
    "details.hkcert.intro",
    "details.hkcert.note",
    "details.hkcert.impact",
    "details.hkcert.systems_affected",
    "details.hkcert.solutions",
    "details.hkcert.solution_links",
    "details.hkcert.related_links",
)

DYNAMIC_ATTACK_METRICS_PATH = None
