"""Default MongoDB filter fields when a provider has no filter_fields module."""

CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "severity",
    "vuln_type",
    "disclosure_date",
    "published_time",
    "updated_time",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
)

DYNAMIC_ATTACK_METRICS_PATH: str | None = None
