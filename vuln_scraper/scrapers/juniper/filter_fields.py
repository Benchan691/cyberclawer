CATEGORICAL_FIELDS = (
    "type",
    "status",
    "vuln_type",
    "disclosure_date",
    "details.juniper.article_type",
    "details.juniper.source_name",
    "details.juniper.published_date",
    "details.juniper.updated_date",
    "details.juniper.cve_ids",
    "details.juniper.products",
)

TEXT_FIELDS = (
    "code",
    "cve_code",
    "title",
    "details.juniper.article_id",
    "details.juniper.summary",
    "details.juniper.description",
    "details.juniper.solution",
    "details.juniper.workaround",
    "details.juniper.reference_links",
)

DYNAMIC_ATTACK_METRICS_PATH = None
