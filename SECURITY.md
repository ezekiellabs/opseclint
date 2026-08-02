# Security Policy

## Supported versions

opseclint follows [Semantic Versioning](https://semver.org/). Security fixes land
on `main` and in the next release on the current major.

| Version | Supported |
|---|---|
| 1.x | ✅ |
| 0.x | ❌ |

Older majors are not backported — upgrade to the latest `1.x` release.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting: on this repository, open the
**Security** tab → **Report a vulnerability**. That creates a private advisory
visible only to the maintainer.

Please include:

- the affected version or commit,
- a description of the issue,
- steps to reproduce, and
- the impact you foresee.

You can expect an initial response within a few days.

## Scope note

opseclint performs **static analysis** and never executes the commands, scripts,
or playbooks it analyzes. Its knowledge base and Sigma references are
informational and should be validated against your own detection stack before
you rely on them.
