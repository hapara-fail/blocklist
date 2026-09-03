# Contributing to the hapara.fail blocklist

Thank you for helping keep the list accurate. Contributions should be narrow, evidence-based, and mindful that blocking shared infrastructure can disrupt unrelated services.

## Report an issue

- [Request a service or domain addition](https://github.com/hapara-fail/blocklist/issues/new?template=addition.yml)
- [Report a false positive or removal](https://github.com/hapara-fail/blocklist/issues/new?template=removal.yml)
- [Report patched/failsafe behavior](https://github.com/hapara-fail/blocklist/issues/new?template=patched.yml)

Include exact domains, product and version information, observed behavior, and non-sensitive evidence when available. Do not publish private student data, credentials, or confidential network details.

## Submit a blocklist change

Edit only [`data/blocklist.csv`](data/blocklist.csv). The generated `dist/` files and legacy `blocklist.txt` are updated automatically after a change reaches `main`.

1. Fork the repository and create a focused branch.
2. Add or update one CSV row per hostname.
3. Keep the canonical rows grouped by category/service when practical; generated files are always domain-sorted.
4. Run validation and tests.
5. Commit the canonical change and open a pull request with the reason and evidence.

The exact header is:

```csv
action,domain,service,category,description,source,added
```

Required values:

- `action`: `block` or, for an intentional Adblock-only exception, `allow`.
- `domain`: hostname only. Do not add `https://`, paths, ports, wildcards, leading dots, trailing root dots, or Adblock syntax.
- `service`: recognizable vendor or product name.
- `category`: `monitoring`, `filtering`, `device-management`, `parental-control`, or `other`.

Optional values:

- `description`: concise context or purpose. Quote the CSV field if it contains a comma.
- `source`: an absolute HTTP(S) evidence/provenance URL.
- `added`: the known addition date as `YYYY-MM-DD`.

Example:

```csv
block,telemetry.example,Example Classroom,monitoring,Telemetry endpoint,https://example.org/evidence,2026-09-03
```

The generator normalizes case and internationalized names, but duplicate domains after normalization are errors. A canonical domain means “block the apex and all subdomains” in formats that can express that behavior. Plain-domain and hosts consumers generally match only the exact hostname, so add specific subdomains when those users must receive them.

## Validate locally

Python 3.13 is used in CI:

```sh
python -m pip install -r requirements.txt
python scripts/generate_blocklist.py --validate-only
python -m unittest discover -s scripts -p "test_*.py" -v
```

Maintainers can generate all published formats with `python scripts/generate_blocklist.py`. CI additionally checks the RPZ with `named-checkzone`, dnsmasq with `dnsmasq --test`, and Unbound with `unbound-checkconf`.

## Code of conduct and license

Follow the [Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree that your contribution is licensed under the repository's [GPL-3.0-only license](LICENSE).
