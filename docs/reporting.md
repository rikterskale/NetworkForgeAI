# Reporting

Each completed scan writes:

- `findings.json` for structured integration.
- `findings.csv` for spreadsheet workflows.
- `findings.sarif` for CI/security tooling.
- `report.md` for human review.

Findings are sanitized before output to reduce accidental credential disclosure.
Reports are evidence containers, not proof that a vulnerability is exploitable; every
finding must retain its approval and validation context.

## Canonical finding model

Reports normalize dictionary findings into a validated `Finding` record with:

- stable identity derived from finding type, target, and title;
- normalized severity and lifecycle status;
- typed evidence records with sensitive content redacted by default;
- CVSS, CWE, OWASP, references, source, and metadata fields;
- baseline remediation guidance when a scanner does not provide remediation.

Duplicate findings collapse to one record, retaining the highest severity. Legacy
scanner fields such as PoCs, reproduction steps, timestamps, and agent identifiers
are preserved in metadata during normalization.
