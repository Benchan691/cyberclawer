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
    "details.qianxin.description.vulnerability_information.vendor",
    "details.qianxin.description.vulnerability_information.product",
    "details.qianxin.description.vulnerability_information.risk.qianxin_cert_rating",
    "details.qianxin.description.vulnerability_information.risk.risk_level",
    "details.qianxin.description.threat_assessment.cvss_3_1_rating",
)

TEXT_FIELDS = (
    "title",
    "vuln_type",
    "details.qianxin.article_id",
    "details.qianxin.title",
    "details.qianxin.author",
    "details.qianxin.digest",
    "details.qianxin.description.security_advisory",
    "details.qianxin.description.vulnerability_information.summary",
    "details.qianxin.description.vulnerability_information.vulnerability_name",
    "details.qianxin.description.vulnerability_information.vulnerability_description",
    "details.qianxin.description.vulnerability_information.affected_versions",
    "details.qianxin.description.threat_assessment.impact_description",
    "details.qianxin.description.affected_assets",
    "details.qianxin.description.recommendations",
    "details.qianxin.description.references",
    "details.qianxin.reference_links",
)

DYNAMIC_ATTACK_METRICS_PATH = None
