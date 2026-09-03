# Blocklist pull request

## Change

- [ ] Add domains
- [ ] Remove or correct domains
- [ ] Generator, tests, CI, or documentation

Related issue:

Summary and evidence:

## Verification

- [ ] I edited `data/blocklist.csv` for entry changes.
- [ ] I did not manually edit `dist/` or `blocklist.txt`.
- [ ] Each changed row has a valid action, hostname, service, and category.
- [ ] I checked for shared-infrastructure or false-positive risk.
- [ ] I ran `python scripts/generate_blocklist.py --validate-only`.
- [ ] I ran `python -m unittest discover -s scripts -p "test_*.py" -v`.
- [ ] For removals, I confirmed that removing the entry restores the affected service.

By submitting this pull request, I agree to the [contribution guidelines](../CONTRIBUTING.md), [Code of Conduct](../CODE_OF_CONDUCT.md), and repository license.
