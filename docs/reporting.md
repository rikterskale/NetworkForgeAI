# Reporting

Each completed scan writes:

- `findings.json` for structured integration.
- `findings.csv` for spreadsheet workflows.
- `findings.sarif` for CI/security tooling.
- `report.md` for human review.

Findings are sanitized before output to reduce accidental credential disclosure.
Reports are evidence containers, not proof that a vulnerability is exploitable; every
finding must retain its approval and validation context.

