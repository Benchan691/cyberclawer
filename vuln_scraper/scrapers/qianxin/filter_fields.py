CATEGORICAL_FIELDS = (
    "type",
    "status",
    "cve_code",
    "details.qianxin.category",
    "details.qianxin.level",
    "details.qianxin.threat_status",
    "details.qianxin.published_date",
    "details.qianxin.updated_date",
    "details.qianxin.vuln_ids",
    "details.qianxin.cve_ids",
)

TEXT_FIELDS = (
    "title",
    "vuln_type",
    "details.qianxin.article_id",
    "details.qianxin.title",
    "details.qianxin.author",
    "details.qianxin.digest",
    "details.qianxin.description",
    "details.qianxin.reference_links",
    "details.qianxin.raw_sections",
)

DYNAMIC_ATTACK_METRICS_PATH = None
