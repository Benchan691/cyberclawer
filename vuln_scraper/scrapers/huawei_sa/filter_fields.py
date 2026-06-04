CATEGORICAL_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "vuln_type",
    "disclosure_date",
    "details.huawei_sa.severity",
    "details.huawei_sa.lang",
    "details.huawei_sa.permission",
    "details.huawei_sa.sasnVersion",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
    "details.huawei_sa.summary",
    "details.huawei_sa.sasnNo",
    "details.huawei_sa.vul.hwPsirtId",
    "details.huawei_sa.vul.cveId",
    "details.huawei_sa.cve_ids",
)

DYNAMIC_ATTACK_METRICS_PATH = None
