#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Vince Bono
"""Build a one-page digest and RSS feed of the newest CISA ICS advisories from CISA's CSAF files."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path

BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"
ADVISORY_ID = re.compile(r"ics(m?)a-(\d\d)-(\d{3})-(\d+)", re.I)
CISA_PAGES = "https://www.cisa.gov/news-events/"  # only link here; anything else in the file is not trusted as a URL
TIMEOUT = 30

# CVSS v3/v4 metric values in plain words. UI: v3 uses N/R, v4 uses N/P/A.
ACCESS = {"N": "over the network", "A": "from the same network segment", "L": "with local access", "P": "with physical access"}
LOGIN = {"N": "no login needed", "L": "needs a normal user account", "H": "needs an admin account"}


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ics-advisory-digest"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read()


def newest(index: str, limit: int) -> list[str]:
    """Paths of the `limit` newest advisories. IDs encode year and day of year: icsa-YY-DDD-NN."""
    keyed = []
    for path in index.split():
        if m := ADVISORY_ID.search(path):
            keyed.append((int(m[2]), int(m[3]), int(m[4]), not m[1], path))
    return [k[-1] for k in sorted(keyed, reverse=True)[:limit]]


def plain_words(vector: str) -> str:
    """'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/...' -> 'over the network, no login needed, no user action'."""
    metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    words = [ACCESS.get(metrics.get("AV", "")), LOGIN.get(metrics.get("PR", ""))]
    if "UI" in metrics:
        words.append("no user action" if metrics["UI"] == "N" else "someone must be tricked into acting")
    return ", ".join(w for w in words if w)


def severity(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "none"


def summarize(csaf: dict) -> dict:
    """The fields the digest shows, from one CSAF document. Raises KeyError if it is not an advisory."""
    doc = csaf["document"]
    notes = doc.get("notes", [])
    worst = {"baseScore": 0.0, "vectorString": ""}
    cves, cwes = [], {}
    for vuln in csaf.get("vulnerabilities", []):
        if vuln.get("cve"):
            cves.append(vuln["cve"])
        if cwe := vuln.get("cwe"):
            cwes[cwe["id"]] = cwe.get("name", "")
        for entry in vuln.get("scores", []):
            for key in ("cvss_v4", "cvss_v3"):
                if key in entry and entry[key].get("baseScore", 0) > worst["baseScore"]:
                    worst = entry[key]
    link = next((r["url"] for r in doc.get("references", []) if r.get("url", "").startswith(CISA_PAGES)), "")
    return {
        "id": doc["tracking"]["id"],
        "title": doc["title"],
        "published": doc["tracking"]["initial_release_date"][:10],
        "updated": doc["tracking"]["current_release_date"][:10],
        "vendors": [b["name"] for b in csaf.get("product_tree", {}).get("branches", []) if b.get("category") == "vendor"],
        "sectors": next((n["text"] for n in notes if n.get("title") == "Critical infrastructure sectors"), ""),
        "score": worst["baseScore"],
        "severity": severity(worst["baseScore"]),
        "exposure": plain_words(worst["vectorString"]),
        "cves": cves,
        "cwes": [f"{k} {v}".strip() for k, v in cwes.items()],
        "link": link or f"{CISA_PAGES}ics-advisories/{doc['tracking']['id'].lower()}",
    }


def render_html(items: list[dict], built: datetime) -> str:
    e = html.escape
    rows = "\n".join(
        f'<tr class="{e(i["severity"])}"><td>{e(i["published"])}</td>'
        f'<td><a href="{e(i["link"])}">{e(i["id"])}</a><br>{e(i["title"])}</td>'
        f'<td>{i["score"] or ""} {e(i["severity"])}</td><td>{e(i["exposure"])}</td>'
        f'<td>{len(i["cves"])}</td><td>{e("; ".join(i["cwes"]))}</td><td>{e(i["sectors"])}</td></tr>'
        for i in items
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ICS advisory digest</title>
<link rel="alternate" type="application/rss+xml" title="ICS advisory digest" href="feed.xml">
<style>
body{{font:15px/1.45 system-ui,sans-serif;margin:1rem;color:#1a1e24;background:#fff}}
table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #ccd;vertical-align:top}}
.critical td:nth-child(3){{font-weight:700;color:#b00020}}.high td:nth-child(3){{font-weight:700;color:#a04a00}}
.wrap{{overflow-x:auto}}
@media (prefers-color-scheme:dark){{body{{color:#e6e6e6;background:#0d1117}}a{{color:#58a6ff}}th,td{{border-color:#30363d}}
.critical td:nth-child(3){{color:#ff7b72}}.high td:nth-child(3){{color:#ffa657}}}}
</style></head><body>
<h1>ICS advisory digest</h1>
<p>The {len(items)} newest <a href="https://www.cisa.gov/news-events/cybersecurity-advisories">CISA ICS advisories</a>,
worst CVSS score first within each day. Built {built:%Y-%m-%d %H:%M} UTC from CISA's
<a href="https://github.com/cisagov/CSAF">CSAF files</a>. <a href="feed.xml">RSS</a> · <a href="advisories.json">JSON</a></p>
<p>"How it is reached" restates the worst vulnerability's CVSS vector. It is not a statement about your plant;
read the advisory before acting.</p>
<div class="wrap"><table>
<thead><tr><th>Published</th><th>Advisory</th><th>Worst CVSS</th><th>How it is reached</th><th>CVEs</th><th>Weakness</th><th>Sectors</th></tr></thead>
<tbody>
{rows}
</tbody></table></div>
</body></html>
"""


def render_rss(items: list[dict], built: datetime) -> str:
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = "ICS advisory digest"
    ET.SubElement(channel, "link").text = "https://www.cisa.gov/news-events/cybersecurity-advisories"
    ET.SubElement(channel, "description").text = "Newest CISA ICS advisories with the worst CVSS score in plain words"
    ET.SubElement(channel, "lastBuildDate").text = format_datetime(built)
    for i in items:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = f"[{i['severity']} {i['score']}] {i['title']}"
        ET.SubElement(item, "link").text = i["link"]
        ET.SubElement(item, "guid", isPermaLink="false").text = i["id"]
        published = datetime.fromisoformat(i["published"]).replace(tzinfo=timezone.utc)
        ET.SubElement(item, "pubDate").text = format_datetime(published)
        ET.SubElement(item, "description").text = f"{i['exposure']}. {len(i['cves'])} CVE(s). {'; '.join(i['cwes'])}"
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(rss, encoding="unicode")


def build(limit: int, out: Path, fetch=fetch) -> int:
    """Write the site. Returns the number of advisories. Raises if nothing could be read, so an empty page is never published."""
    items = []
    for path in newest(fetch(BASE + "index.txt").decode("utf-8"), limit):
        try:
            items.append(summarize(json.loads(fetch(BASE + path))))
        except (OSError, ValueError, KeyError, TypeError) as e:
            print(f"warning: skipped {path}: {e!r}", file=sys.stderr)
    if not items:
        raise RuntimeError("no advisory could be read")
    items.sort(key=lambda i: (i["published"], i["score"]), reverse=True)
    built = datetime.now(timezone.utc)
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(render_html(items, built), encoding="utf-8")
    (out / "feed.xml").write_text(render_rss(items, built), encoding="utf-8")
    (out / "advisories.json").write_text(json.dumps(items, indent=2), encoding="utf-8")
    return len(items)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=30, help="how many advisories to show (default 30)")
    ap.add_argument("--out", type=Path, default=Path("site"), help="output folder (default site)")
    args = ap.parse_args(argv)
    try:
        count = build(args.limit, args.out)
    except (OSError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"wrote {count} advisories to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
