# ics-advisory-digest

One page and one RSS feed of the newest CISA advisories for industrial control systems, with the worst
vulnerability in each restated in plain words: how an attacker reaches it, whether they need a login, and
whether someone has to be tricked.

CISA publishes several advisories a week. Each is long and written for the vendor's product specialists.
This is the triage view for the person who has to decide which ones to open.

| Published | Advisory | Worst CVSS | How it is reached |
|---|---|---|---|
| 2026-11-03 | ICSA-26-307-01 Subnet Solutions PowerSYSTEM Center | 9.0 critical | from the same network segment, needs a normal user account, no user action |
| 2026-10-27 | ICSA-26-302-03 Hitachi Energy CoreTec Product | 8.8 high | with local access, needs a normal user account, no user action |

## Run it

Python 3.10+, no dependencies.

```bash
python digest.py            # writes site/index.html, site/feed.xml, site/advisories.json
python digest.py --limit 50 --out public
```

It reads CISA's machine-readable advisory files from [cisagov/CSAF](https://github.com/cisagov/CSAF) and
writes three static files. Nothing is stored between runs.

## Publish it daily

`.github/workflows/publish.yml` rebuilds the page every day and deploys it to GitHub Pages. To turn it on in
a fork: Settings → Pages → Source: **GitHub Actions**.

If CISA's files cannot be read, the run fails and the last published page stays up. An advisory file that
cannot be parsed is skipped with a warning in the log.

## Limits

- **"How it is reached" is the CVSS vector in words, nothing more.** It describes the worst-scored
  vulnerability in the advisory as the vendor scored it. It says nothing about whether you own the product
  or how it is deployed in your plant.
- **Newest means newest advisory number.** An update to an older advisory does not move it back up the page.
- **No MITRE ATT&CK for ICS mapping yet.** CISA's files do not carry one, and a guessed mapping would be
  worse than none.
- **Not affiliated with CISA.** Advisory content is CISA's and the vendors'; follow the link to the
  advisory before acting on anything here.

## Development

```bash
python -m unittest discover -s tests -v
python scripts/commitguard.py --all
```

The tests use made-up advisories and never touch the network.

## License

MIT. See [LICENSE](LICENSE).
