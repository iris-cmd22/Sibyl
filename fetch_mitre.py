"""One-shot enrichment of cwe_wiki.json with official MITRE CWE data.

Fetches each CWE already present in the wiki from the public MITRE CWE REST API
(no credentials needed) and adds official fields WITHOUT touching the curated
detection / sink / source / constant names:

    mitre_name, mitre_description, mitre_mitigations, references

Usage:
    python fetch_mitre.py                              # all wiki CWEs, via REST API
    python fetch_mitre.py CWE-89 CWE-327               # only these, via REST API
    python fetch_mitre.py --xml C:\\path\\cwec_latest.xml        # all, OFFLINE from XML
    python fetch_mitre.py CWE-89 --xml C:\\path\\cwec_latest.xml # one, OFFLINE from XML

Two sources for the official layer:
  - REST API (default): https://cwe-api.mitre.org  (needs network)
  - Local XML (--xml):  the full MITRE catalog cwec_latest.xml  (offline)
Either way, only the mitre_* fields are written; curated names are untouched.
The wiki keeps the official text cached locally afterwards.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

# Bundled knowledge data lives inside the server package.
CWE_WIKI_PATH = Path(__file__).resolve().parent / "server" / "knowledge" / "data" / "cwe_wiki.json"

API = "https://cwe-api.mitre.org/api/v1/cwe/weakness/"


XML_NS = {"c": "http://cwe.mitre.org/cwe-7"}


def _fetch(ids: list[str]) -> dict:
    nums = ",".join(i.split("-")[-1] for i in ids)
    url = API + nums
    with urllib.request.urlopen(url, timeout=30) as r:
        data = json.loads(r.read().decode("utf-8"))
    out = {}
    for w in data.get("Weaknesses", []):
        out[f"CWE-{w.get('ID')}"] = w
    return out


def _fetch_xml(ids: list[str], xml_path: str) -> dict:
    """Offline source: read the official MITRE CWE XML catalog (cwec_latest.xml).
    Returns the same shape as _fetch so main() can stay source-agnostic."""
    import xml.etree.ElementTree as ET

    want = {i.split("-")[-1] for i in ids}
    root = ET.parse(xml_path).getroot()
    out = {}
    for w in root.findall("c:Weaknesses/c:Weakness", XML_NS):
        if w.get("ID") not in want:
            continue
        desc = w.find("c:Description", XML_NS)
        ext = w.find("c:Extended_Description", XML_NS)
        mits = []
        for m in w.findall("c:Potential_Mitigations/c:Mitigation", XML_NS):
            d = m.find("c:Description", XML_NS)
            if d is not None:
                mits.append({"Description": " ".join(d.itertext()).strip()})
        # Richer fields: common consequences and observed examples (CVEs).
        cons = []
        for c in w.findall("c:Common_Consequences/c:Consequence", XML_NS):
            scopes = [s.text for s in c.findall("c:Scope", XML_NS) if s.text]
            impacts = [im.text for im in c.findall("c:Impact", XML_NS) if im.text]
            if scopes or impacts:
                cons.append(f"{', '.join(scopes)}: {', '.join(impacts)}")
        obs = []
        for o in w.findall("c:Observed_Examples/c:Observed_Example", XML_NS):
            ref = o.find("c:Reference", XML_NS)
            d = o.find("c:Description", XML_NS)
            if ref is not None and ref.text:
                obs.append(f"{ref.text}: {(d.text or '').strip() if d is not None else ''}".strip())
        out[f"CWE-{w.get('ID')}"] = {
            "ID": w.get("ID"),
            "Name": w.get("Name", ""),
            "Description": (desc.text or "").strip() if desc is not None else "",
            "ExtendedDescription": " ".join(ext.itertext()).strip() if ext is not None else "",
            "PotentialMitigations": mits,
            "_consequences": cons,
            "_observed": obs,
        }
    return out


def _mitigations(w: dict, limit: int = 3) -> list[str]:
    res = []
    for m in w.get("PotentialMitigations", []) or []:
        text = (m.get("Description") or "").strip()
        if text:
            res.append(text)
        if len(res) >= limit:
            break
    return res


def main(argv: list[str]) -> int:
    args = argv[1:]
    xml_path = None
    if "--xml" in args:
        i = args.index("--xml")
        xml_path = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        if not xml_path:
            print("ERROR: --xml requires a path to cwec_latest.xml", file=sys.stderr)
            return 1

    wiki = json.loads(CWE_WIKI_PATH.read_text(encoding="utf-8"))
    targets = args or list(wiki.keys())
    targets = [t if t.upper().startswith("CWE-") else f"CWE-{t}" for t in targets]

    try:
        fetched = _fetch_xml(targets, xml_path) if xml_path else _fetch(targets)
        src = f"XML ({xml_path})" if xml_path else "MITRE API"
        print(f"Source: {src}", file=sys.stderr)
    except Exception as e:
        print(f"ERROR reading CWE data: {e}", file=sys.stderr)
        return 1

    updated = 0
    for cid in targets:
        w = fetched.get(cid)
        if not w:
            print(f"  - {cid}: not found in source", file=sys.stderr)
            continue
        entry = wiki.setdefault(cid, {})
        entry["mitre_name"] = w.get("Name", "")
        entry["mitre_description"] = (w.get("Description") or "").strip()
        ext = (w.get("ExtendedDescription") or "").strip()
        if ext:
            entry["mitre_extended_description"] = ext
        mit = _mitigations(w)
        if mit:
            entry["mitre_mitigations"] = mit
        if w.get("_consequences"):
            entry["mitre_consequences"] = w["_consequences"]
        if w.get("_observed"):
            entry["mitre_observed_examples"] = w["_observed"][:3]
        ref = f"https://cwe.mitre.org/data/definitions/{cid.split('-')[-1]}.html"
        refs = entry.setdefault("references", [])
        if ref not in refs:
            refs.append(ref)
        updated += 1
        print(f"  + {cid}: {w.get('Name','')}")

    CWE_WIKI_PATH.write_text(
        json.dumps(wiki, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Enriched {updated}/{len(targets)} CWEs into {CWE_WIKI_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
