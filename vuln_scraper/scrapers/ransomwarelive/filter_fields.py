CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "severity",
    "vuln_type",
    "disclosure_date",
    "details.ransomwarelive.group",
    "details.ransomwarelive.country",
    "details.ransomwarelive.activity",
    "details.ransomwarelive.attackdate",
    "details.ransomwarelive.discovered",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "title",
    "details.ransomwarelive.victim",
    "details.ransomwarelive.group",
    "details.ransomwarelive.country",
    "details.ransomwarelive.activity",
    "details.ransomwarelive.website",
    "details.ransomwarelive.infostealer",
    "details.ransomwarelive.press",
    "details.ransomwarelive.permalink",
)

DYNAMIC_ATTACK_METRICS_PATH = None
