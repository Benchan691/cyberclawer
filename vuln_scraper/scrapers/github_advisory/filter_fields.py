CATEGORICAL_FIELDS = (
    "type",
    "status",
    "severity",
    "cve_code",
    "details.github_advisory.advisory_type",
    "details.github_advisory.severity",
    "details.github_advisory.cve_ids",
    "details.github_advisory.vulnerabilities.package.ecosystem",
    "details.github_advisory.vulnerabilities.package.name",
    "details.github_advisory.cwes.cwe_id",
    "details.github_advisory.withdrawn_at",
)

TEXT_FIELDS = (
    "title",
    "vuln_type",
    "details.github_advisory.ghsa_id",
    "details.github_advisory.cve_id",
    "details.github_advisory.cve_ids",
    "details.github_advisory.summary",
    "details.github_advisory.description",
    "details.github_advisory.html_url",
    "details.github_advisory.source_code_location",
    "details.github_advisory.references",
    "details.github_advisory.vulnerabilities.package.name",
)

DYNAMIC_ATTACK_METRICS_PATH = None
