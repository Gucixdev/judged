"""CycloneDX 1.5 JSON."""
import json

from . import serial

NAME, EXT = "cyclonedx", ".cdx.json"


def render(doc: dict) -> str:
    comps = doc["components"]
    out = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{serial(doc['name'], comps)}", "version": 1,
        "metadata": {"timestamp": doc["created"], "tools": {"components": [{"type": "application", "name": "judged"}]},
                     "component": {"type": "application", "name": doc["name"], "bom-ref": f"project:{doc['name']}"},
                     "properties": [{"name": "judged:note", "value": n} for n in doc["notes"]]},
        "components": [{"type": "library", "bom-ref": c.purl, "name": c.name, "version": c.version, "purl": c.purl} for c in comps],
    }
    return json.dumps(out, indent=1, ensure_ascii=False) + "\n"
