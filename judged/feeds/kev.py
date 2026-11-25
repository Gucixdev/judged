"""CISA Known Exploited Vulnerabilities: CVEs that attackers are using now. A package with one of these is a failure whatever its CVSS score says."""
import json

NAME = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DOC = "CISA list of vulnerabilities known to be exploited"


def parse(raw: bytes) -> dict:
    """{CVE id: [date added, fix due date, used in ransomware: Known | Unknown]}"""
    return {v["cveID"]: [v.get("dateAdded", ""), v.get("dueDate", ""), v.get("knownRansomwareCampaignUse", "Unknown")]
            for v in json.loads(raw)["vulnerabilities"]}
