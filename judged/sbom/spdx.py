"""SPDX 2.3 JSON."""
import hashlib
import json
import re

from . import serial

NAME, EXT = "spdx", ".spdx.json"


def _id(c, i: int) -> str:
    """SPDX ids allow only letters, digits, '.' and '-'; the index keeps equal names apart."""
    return f"SPDXRef-{i}-" + re.sub(r"[^A-Za-z0-9.-]+", "-", c.name).strip("-")[:60]


def render(doc: dict) -> str:
    comps = doc["components"]
    ids = [_id(c, i) for i, c in enumerate(comps, 1)]
    out = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": doc["name"],
        "documentNamespace": f"https://spdx.invalid/judged/{re.sub(r'[^A-Za-z0-9.-]+', '-', doc['name'])}/{serial(doc['name'], comps)}",
        "creationInfo": {"created": doc["created"], "creators": ["Tool: judged"], "comment": " | ".join(doc["notes"])},
        "packages": [{"SPDXID": i, "name": c.name, "versionInfo": c.version, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                      "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
                      "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c.purl}]}
                     for i, c in zip(ids, comps)],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": i} for i in ids],
    }
    return json.dumps(out, indent=1, ensure_ascii=False) + "\n"
