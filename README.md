# hapara.fail Blocklist

[![jsDelivr](https://data.jsdelivr.com/v1/package/gh/hapara-fail/blocklist/badge)](https://www.jsdelivr.com/package/gh/hapara-fail/blocklist)

A community-maintained blocklist for school-mandated surveillance, filtering, device-management, and parental-control services. Review the [risk warning](#scope-and-safety) before deployment: blocking management infrastructure can disable browsing or other required device functions.

`data/blocklist.csv` is the only source of truth. Everything in `dist/`, plus the legacy root `blocklist.txt`, is generated from it.

## Available formats

| Format | File | Compatible software | Apex and subdomains | Direct jsDelivr link |
| --- | --- | --- | --- | --- |
| Adblock | [`dist/adblock.txt`](dist/adblock.txt) | uBlock Origin, Adblock Plus, AdGuard, AdGuard Home | Yes; browser products can differ for top-level document blocking | [Download](https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/dist/adblock.txt) |
| Domains | [`dist/domains.txt`](dist/domains.txt) | Pi-hole Gravity, Technitium block-list URLs, scripts and domain-list consumers | Exact entries; any expansion is consumer-specific | [Download](https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/dist/domains.txt) |
| Hosts | [`dist/hosts.txt`](dist/hosts.txt) | OS hosts files, AdAway, and hosts-file consumers | Exact hostnames only | [Download](https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/dist/hosts.txt) |
| dnsmasq | [`dist/dnsmasq.conf`](dist/dnsmasq.conf) | dnsmasq and systems that include dnsmasq configuration fragments | Yes; returns NXDOMAIN | [Download](https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/dist/dnsmasq.conf) |
| Unbound | [`dist/unbound.conf`](dist/unbound.conf) | Unbound and systems that accept Unbound include files | Yes; returns NXDOMAIN | [Download](https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/dist/unbound.conf) |
| RPZ | [`dist/blocklist.rpz`](dist/blocklist.rpz) | BIND 9, PowerDNS Recursor, and other RPZ-capable resolvers | Yes; explicit apex and wildcard triggers return NXDOMAIN | [Download](https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/dist/blocklist.rpz) |
| JSON | [`dist/blocklist.json`](dist/blocklist.json) | APIs, scripts, integrations, and hapara.fail | N/A; semantics are explicit in `action` | [Download](https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/dist/blocklist.json) |
| CSV | [`dist/blocklist.csv`](dist/blocklist.csv) | Spreadsheets, scripts, and data pipelines | N/A; semantics are explicit in `action` | [Download](https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/dist/blocklist.csv) |

The historical URL remains supported and is an exact copy of the Adblock export:

```text
https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/blocklist.txt
```

### Format semantics

- Adblock `||example.com^` matches requests to the domain and its subdomains. The generated list retains `@@` allow rules. AdGuard browser products do not apply a plain domain rule to a top-level document in every context; DNS products interpret it at the hostname level.
- A plain line or hosts entry represents only the hostname written. It cannot express the same subtree rule portably. Add an explicit subdomain row when exact-host consumers must block it.
- Hosts uses `0.0.0.0`, the unspecified address. It avoids sending blocked traffic to a service on the local loopback address (`127.0.0.1`) and is widely used by maintained hosts lists. Some clients may require a different sink address.
- dnsmasq uses `address=/example.com/` with an empty address. Current dnsmasq documents this as NXDOMAIN for the named domain and all subdomains.
- Unbound uses `always_nxdomain` local zones. This returns NXDOMAIN for every name and record type within each listed zone, ignoring local data.
- RPZ emits both `example.com CNAME .` and `*.example.com CNAME .`. RPZ wildcards do not include the apex, so both records are required. The SOA serial is the UTC build time as Unix epoch seconds.
- DNS/hosts exports contain only `block` entries. They omit canonical `allow` entries because those formats have no portable exception mechanism.

No separate Pi-hole, AdGuard Home, Technitium, PowerDNS, OPNsense, or pfSense file is generated when one of the standard exports is already accepted. Use the format supported by the specific version and integration you run; appliance import screens may impose additional requirements.

## Usage

For uBlock Origin, Adblock Plus, AdGuard, or AdGuard Home, add the Adblock URL as a custom filter/blocklist. AdGuard Home documents the generated `||domain^` syntax directly, including subdomain and exception behavior.

For Pi-hole, add the Domains URL to **Adlists** and rebuild Gravity:

```sh
pihole -g
```

For a local hosts file, download `hosts.txt` and merge its entries into the platform's hosts file. Do not blindly replace an existing hosts file because it may contain required local mappings.

For dnsmasq, download `dnsmasq.conf`, include it from the main configuration, test it, and reload dnsmasq:

```text
conf-file=/path/to/hapara-fail-dnsmasq.conf
```

For Unbound, include the complete generated fragment at top level, then validate before reloading:

```text
include: "/path/to/hapara-fail-unbound.conf"
```

```sh
unbound-checkconf
```

For BIND 9 RPZ, save the zone file locally and configure it as a primary policy zone. Adjust paths and access control for your environment:

```text
zone "rpz.hapara.fail" {
    type primary;
    file "/path/to/blocklist.rpz";
    allow-query { none; };
};

options {
    response-policy { zone "rpz.hapara.fail"; };
};
```

Validate it with `named-checkzone rpz.hapara.fail blocklist.rpz` before reloading BIND.

## jsDelivr versioning

The table uses `@main`, which follows accepted updates and is convenient for automatically refreshed blocklist subscriptions. jsDelivr caches branch URLs and this repository purges each published file after generated distributions change.

For reproducible deployments, replace `@main` with a release tag (for example, `@v1.0.0`) or a full commit hash. Tags provide readable, immutable releases; commit hashes pin the exact content. A moving branch is the easiest to maintain but can change without local review. jsDelivr documents long-lived caching for static versions and shorter caching for branches in its [official usage documentation](https://github.com/jsdelivr/jsdelivr#github).

## Contributing

Contributors edit only [`data/blocklist.csv`](data/blocklist.csv). Do not manually edit `dist/` or `blocklist.txt`; the main-branch workflow regenerates and commits them after validation succeeds.

Each row has these columns:

| Column | Required | Meaning |
| --- | --- | --- |
| `action` | Yes | `block` or `allow`; use `allow` only for an intentional Adblock exception |
| `domain` | Yes | A hostname without scheme, path, port, wildcard, leading dot, or trailing root dot |
| `service` | Yes | Human-readable product or vendor name |
| `category` | Yes | `monitoring`, `filtering`, `device-management`, `parental-control`, or `other` |
| `description` | No | Short reason/context, especially for unusual or risky entries |
| `source` | No | Absolute HTTP(S) evidence or provenance URL |
| `added` | No | Known addition date in `YYYY-MM-DD` form |

Example:

```csv
block,telemetry.example,Example Classroom,monitoring,Telemetry endpoint,https://example.org/evidence,2026-09-03
```

The generator applies UTS #46 compatibility processing and IDNA 2008 validation, emits lowercase ASCII/Punycode network names, rejects invalid metadata and normalized duplicates, and sorts every output deterministically. Lines whose first field starts with `#` and blank lines are ignored as canonical comments.

To validate and test locally:

```sh
python -m pip install -r requirements.txt
python scripts/generate_blocklist.py --validate-only
python -m unittest discover -s scripts -p "test_*.py" -v
```

Maintainers can regenerate the committed files with:

```sh
python scripts/generate_blocklist.py
```

Set `SOURCE_DATE_EPOCH` or pass an ISO 8601 `--timestamp` for reproducible metadata. The generated JSON contract is versioned as `1.0.0` and formally defined in [`schemas/blocklist.schema.json`](schemas/blocklist.schema.json). A schema-version change is required for breaking field or semantic changes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the pull-request workflow and evidence guidelines.

## Authoritative format references

- [Adblock Plus filter syntax and special comments](https://help.adblockplus.org/adblock-plus-help-center/how-to-write-filters)
- [AdGuard filtering-rule syntax](https://adguard.com/kb/general/ad-filtering/create-own-filters/)
- [AdGuard Home DNS blocklist syntax](https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists)
- [uBlock Origin static filter syntax](https://github.com/gorhill/uBlock/wiki/Static-filter-syntax)
- [Linux `hosts(5)` format](https://man7.org/linux/man-pages/man5/hosts.5.html)
- [dnsmasq current manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
- [Unbound `local-zone` configuration](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [BIND 9 RPZ reference and examples](https://bind9.readthedocs.io/en/stable/reference.html#response-policy-zone-rpz-rewriting)
- [PowerDNS Recursor RPZ support](https://docs.powerdns.com/recursor/lua-config/rpz.html)
- [Pi-hole Gravity behavior](https://docs.pi-hole.net/main/pihole-command/#gravity)
- [Technitium DNS block-list URLs](https://technitium.com/dns/)
- [IDNA 2008 and UTS #46 implementation](https://pypi.org/project/idna/)

## Scope and safety

Several targeted products can fail closed: if their infrastructure is unreachable, they may intentionally disable all browsing. GoGuardian, Lightspeed Systems, and Securly have been reported with such behavior, but it can vary by product version and deployment. Test in a controlled environment, expect false positives or shared-infrastructure impact, and comply with applicable policies and law. This list does not guarantee that a product will be bypassed or disabled.

Report additions, false positives, or patched/failsafe behavior with the repository's issue templates. Community discussion is also available through the [hapara.fail Discord](https://www.hapara.fail/discord).

## License

This project is licensed under [GPL-3.0-only](LICENSE).
