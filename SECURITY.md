# Security policy

minicrun is an educational container-runtime prototype. It is not
production-ready and must not be treated as a security boundary for untrusted
workloads.

## Supported versions

Security fixes are made on the latest commit of the `main` branch. There are no
supported stable release branches yet.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub Private
Vulnerability Reporting in the repository's **Security** tab. Include:

- the affected commit or version;
- a minimal reproduction;
- the expected and observed security boundary;
- host kernel, cgroup, network, and privilege details; and
- any known cleanup or host-impact implications.

Do not include secrets or sensitive host data. Please do not open a public issue
until the report has been reviewed and coordinated disclosure has been agreed.
