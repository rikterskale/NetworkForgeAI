# Security Policy

## Scope

Report vulnerabilities in the NetworkForgeAI codebase, build process, CI workflow,
or safety controls. Do not submit real target data, credentials, exploit output, or
customer information in an issue or pull request.

## Reporting

Use the repository's private GitHub security advisory workflow when available. If it
is unavailable, contact the project maintainers privately with:

- affected commit or version;
- reproducible steps in a local test environment;
- impact assessment;
- suggested mitigation.

Do not publicly disclose an issue until maintainers have had a reasonable opportunity
to triage and release a fix.

## Safe testing

All security testing must use owned or explicitly authorized targets. The CI workflow
does not scan external systems and should remain limited to unit, integration, build,
documentation, and safety-policy verification.

