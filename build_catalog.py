"""Build the FULL CWE catalog (official layer) from the MITRE XML.

This is the read-only "what it is" knowledge for ANY CWE (~969 entries), used as
a lookup fallback by cwe_knowledge when a CWE is not in the curated detection
wiki (cwe_wiki.json). It does NOT contain detection/sink/source names — those
stay curated in cwe_wiki.json for the CWEs the templates can actually verify.

Usage:
    python build_catalog.py --xml C:\\path\\cwec_latest.xml
    python build_catalog.py --xml ... --out knowledge/cwe_catalog.json
"""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET

import config

NS = {"c": "http://cwe.mitre.org/cwe-7"}


def _text(el):
    return " ".join(el.itertext()).strip() if el is not None else ""


def build(xml_path: str) -> dict:
    root = ET.parse(xml_path).getroot()
    catalog = {}
    for w in root.findall("c:Weaknesses/c:Weakness", NS):
        cid = f"CWE-{w.get('ID')}"
        desc = w.find("c:Description", NS)
        ext = w.find("c:Extended_Description", NS)
        mits = []
        for m in w.findall("c:Potential_Mitigations/c:Mitigation", NS):
            t = _text(m.find("c:Description", NS))
            if t:
                mits.append(t)
            if len(mits) >= 2:          # keep the catalog lean
                break
        cons = []
        for c in w.findall("c:Common_Consequences/c:Consequence", NS):
            scopes = [s.text for s in c.findall("c:Scope", NS) if s.text]
            impacts = [im.text for im in c.findall("c:Impact", NS) if im.text]
            if scopes or impacts:
                cons.append(f"{', '.join(scopes)}: {', '.join(impacts)}")
        catalog[cid] = {
            "name": w.get("Name", ""),
            "abstraction": w.get("Abstraction", ""),
            "status": w.get("Status", ""),
            "description": (desc.text or "").strip() if desc is not None else "",
            "extended_description": _text(ext),
            "mitigations": mits,
            "consequences": cons,
            "reference": f"https://cwe.mitre.org/data/definitions/{w.get('ID')}.html",
        }
    return catalog


def main(argv: list[str]) -> int:
    args = argv[1:]
    if "--xml" not in args:
        print("ERROR: --xml <path to cwec_latest.xml> is required", file=sys.stderr)
        return 1
    xml_path = args[args.index("--xml") + 1]
    out = config.CWE_CATALOG_PATH
    if "--out" in args:
        out = args[args.index("--out") + 1]

    catalog = build(xml_path)
    from pathlib import Path
    Path(out).write_text(json.dumps(catalog, ensure_ascii=False), encoding="utf-8")
    size_mb = round(Path(out).stat().st_size / 1024 / 1024, 1)
    print(f"Wrote {len(catalog)} CWEs to {out} ({size_mb} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
