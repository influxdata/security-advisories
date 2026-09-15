# InfluxData security advisories

This repository is the central, public home for security advisories published
by InfluxData. It gives customers and users one place to find out which
releases fix security issues, and one place to subscribe for notifications
when new advisories are published. Advisories for all InfluxData products are
published here rather than in individual product repositories.

**[View current advisories](https://github.com/influxdata/security-advisories/security/advisories)**

Advisories are published using GitHub's repository security advisory feature,
so they appear under the [Security tab](https://github.com/influxdata/security-advisories/security)
of this repository rather than as files in the repository itself.

> [!NOTE]
> Telegraf is the pilot product for this program. Other InfluxData products
> will be added over time. Until then, they continue to communicate security
> fixes through their release notes.

## What an advisory contains

Advisories contain the security fixes included in a specific release, the
affected and patched versions, and the recommended action, which in most
cases is to upgrade. Each release with security content gets one advisory,
which can include:

- Vulnerabilities in code that InfluxData writes and maintains.
- Toolchain and standard library CVEs confirmed to affect the product.
- Third-party dependency issues confirmed to affect the product and assessed
  as high or critical severity.

The **Affected products** section of an advisory identifies the product by name
(for example, `telegraf`) along with its affected and patched version ranges.
When an advisory covers multiple issues, the description lists a CVSS score for
each issue and the advisory's severity reflects the highest of those scores.

### What is not covered

To keep advisories high-signal and actionable, the following are not
published as advisories:

- Routine dependency updates that have not been confirmed to affect the
  product, or that are assessed below high severity. Release notes continue
  to note when dependencies are refreshed.
- Findings in container images. Images are refreshed periodically,
  independently of advisories.
- Historical releases. Advisories begin with the release line that was
  current when a product joined the program and are not backfilled further.

## When advisories are published

InfluxData follows responsible disclosure. Advisories are drafted privately
and published when the release that fixes the issue ships. There is no
advisory for an issue until a fix is available, with one exception: a high or
critical issue that cannot be fixed promptly may receive an advisory with
mitigations so you can protect yourself. That advisory is updated when a fix
becomes available.

## Reporting a vulnerability

Do not report security vulnerabilities by opening an issue or pull request in
this repository.

InfluxData takes security and our users' trust seriously. If you believe you
have found a security issue in an InfluxData product, please responsibly
disclose it by contacting `security@influxdata.com`. For more information,
see [How to report security vulnerabilities](https://www.influxdata.com/how-to-report-security-vulnerabilities/).
