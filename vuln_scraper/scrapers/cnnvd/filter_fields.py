CATEGORICAL_FIELDS = (
    "type",
    "status",
    "severity",
    "vuln_type",
    "disclosure_date",
    "details.cnnvd.publishTime",
    "details.cnnvd.updateTime",
    "details.cnnvd.hazardLevel",
    "details.cnnvd.vulType",
    "details.cnnvd.vulTypeName",
    "details.cnnvd.vendor",
    "details.cnnvd.affectedVendor",
    "details.cnnvd.cveCode",
)

TEXT_FIELDS = (
    "code",
    "cve_code",
    "title",
    "details.cnnvd.id",
    "details.cnnvd.cnnvdCode",
    "details.cnnvd.vulName",
    "details.cnnvd.vulDesc",
    "details.cnnvd.affectedProduct",
    "details.cnnvd.affectedSystem",
    "details.cnnvd.productDesc",
    "details.cnnvd.patch",
    "details.cnnvd.referUrl",
)

DYNAMIC_ATTACK_METRICS_PATH = None
