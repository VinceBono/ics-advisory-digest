# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Vince Bono
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import digest  # noqa: E402


def advisory(advisory_id: str, title: str, score: float, vector: str, published: str = "2026-11-10") -> dict:
    """A made-up CSAF document with only the fields the digest reads."""
    return {
        "document": {
            "title": title,
            "tracking": {"id": advisory_id, "initial_release_date": f"{published}T00:00:00Z", "current_release_date": f"{published}T00:00:00Z"},
            "notes": [{"category": "other", "title": "Critical infrastructure sectors", "text": "Energy"}],
            "references": [{"url": f"https://www.cisa.gov/news-events/ics-advisories/{advisory_id.lower()}"}],
        },
        "product_tree": {"branches": [{"category": "vendor", "name": "Example Controls"}]},
        "vulnerabilities": [
            {"cve": "CVE-2026-0001", "cwe": {"id": "CWE-787", "name": "Out-of-bounds Write"}, "scores": [{"cvss_v3": {"baseScore": 5.3, "vectorString": "CVSS:3.1/AV:L/PR:L/UI:R"}}]},
            {"cve": "CVE-2026-0002", "cwe": {"id": "CWE-306", "name": "Missing Authentication"}, "scores": [{"cvss_v3": {"baseScore": score, "vectorString": vector}}]},
        ],
    }


class DigestTest(unittest.TestCase):
    def test_newest_orders_by_year_then_day_and_ignores_other_lines(self):
        index = "2025/icsa-25-350-01.json\n2026/icsma-26-295-01.json\n2026/icsa-26-316-02.json\n2026/icsa-26-316-01.json\nREADME.md\n"
        self.assertEqual(digest.newest(index, 3), ["2026/icsa-26-316-02.json", "2026/icsa-26-316-01.json", "2026/icsma-26-295-01.json"])

    def test_plain_words_for_v3_and_v4_vectors(self):
        self.assertEqual(digest.plain_words("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "over the network, no login needed, no user action")
        self.assertEqual(digest.plain_words("CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:H"), "from the same network segment, needs an admin account, someone must be tricked into acting")
        self.assertEqual(digest.plain_words(""), "")

    def test_summarize_takes_the_worst_score_and_its_vector(self):
        got = digest.summarize(advisory("ICSA-26-316-01", "Example PLC", 9.8, "CVSS:3.1/AV:N/PR:N/UI:N"))
        self.assertEqual((got["score"], got["severity"], got["exposure"]), (9.8, "critical", "over the network, no login needed, no user action"))
        self.assertEqual(got["cves"], ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertEqual(got["vendors"], ["Example Controls"])
        self.assertEqual(got["published"], "2026-11-10")

    def test_only_cisa_https_pages_are_used_as_the_link(self):
        doc = advisory("ICSA-26-316-01", "Example PLC", 9.8, "CVSS:3.1/AV:N/PR:N/UI:N")
        doc["document"]["references"] = [{"url": "javascript:alert(1)//cisa.gov/news-events/x"}]
        self.assertEqual(digest.summarize(doc)["link"], "https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-01")

    def test_build_writes_escaped_html_valid_rss_and_skips_a_broken_file(self):
        files = {
            "index.txt": b"2026/icsa-26-316-01.json\n2026/icsa-26-316-02.json\n2026/icsa-26-316-03.json\n",
            "2026/icsa-26-316-01.json": json.dumps(advisory("ICSA-26-316-01", "<script>alert(1)</script> HMI", 7.5, "CVSS:3.1/AV:N/PR:L/UI:N")).encode(),
            "2026/icsa-26-316-02.json": json.dumps(advisory("ICSA-26-316-02", "Example PLC", 9.8, "CVSS:3.1/AV:N/PR:N/UI:N")).encode(),
            "2026/icsa-26-316-03.json": b"{not json",
        }
        with tempfile.TemporaryDirectory() as d:
            count = digest.build(10, Path(d), fetch=lambda url: files[url.removeprefix(digest.BASE)])
            page = Path(d, "index.html").read_text(encoding="utf-8")
            feed = ET.parse(Path(d, "feed.xml")).getroot()
            data = json.loads(Path(d, "advisories.json").read_text(encoding="utf-8"))
        self.assertEqual(count, 2)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertEqual([i["id"] for i in data], ["ICSA-26-316-02", "ICSA-26-316-01"])  # worst first within a day
        self.assertEqual(len(feed.findall("./channel/item")), 2)

    def test_build_refuses_to_publish_an_empty_page(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(RuntimeError):
            digest.build(10, Path(d), fetch=lambda url: b"")


if __name__ == "__main__":
    unittest.main()
