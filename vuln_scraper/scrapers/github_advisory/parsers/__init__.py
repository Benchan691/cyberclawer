from vuln_scraper.scrapers.github_advisory.parsers.detail import (
    GitHubAdvisoryDetailRecord,
    parse_advisory_response,
)
from vuln_scraper.scrapers.github_advisory.parsers.list import parse_advisory_list

__all__ = ["GitHubAdvisoryDetailRecord", "parse_advisory_list", "parse_advisory_response"]
