# Advisory authoring guide

This guide is for people who draft, review, and publish InfluxData security
advisories in this repository. It covers what an advisory must include, how
to fill in each field of the GitHub advisory form, how to identify the
affected product, and how to write in a consistent voice.

For what advisories cover and when they are published, see the
[README](../README.md). This guide assumes that policy and describes how to
apply it.

## Before you start

You need the following before drafting an advisory:

- **Assessment data** from Security and Engineering for each issue the
  release fixes: a short description of the issue and its impact, the
  affected versions, the CVSS score for each issue in InfluxData's own code,
  and any mitigations for users who cannot upgrade immediately.
- **The fixing release** version number and its expected ship date.
- **Permission** to create draft advisories in this repository. Ask the
  repository administrators if you do not have it.

Keep these rules in mind throughout:

- **One advisory per release.** A single advisory covers all security content
  in a release: issues in InfluxData's own code, toolchain CVEs confirmed
  to affect the product, and urgent dependency issues. Do not create one
  advisory per issue.
- **Draft privately, publish at release.** A draft advisory is visible only to
  repository administrators and the collaborators you add. Publish it when
  the fixing release is available, not before.
- **Publishing is permanent.** A published advisory cannot be unpublished, and
  every edit after publication is public. Advisories must be reviewed before
  being published.

## Workflow

| Step              | Owner teams                    | What happens                                                                                                  |
| :---------------- | :----------------------------- | :------------------------------------------------------------------------------------------------------------ |
| 1. Identification | Security, Engineering          | Issues that need advisory coverage are identified during triage and fix work.                                 |
| 2. Assessment     | Security, Engineering, Product | Impact, affected versions, severity, and mitigations are established. Security supplies fix and impact prose. |
| 3. Authoring      | Product                        | The author creates the draft advisory in this repository using the assessment data and this guide.            |
| 4. Review         | Security, Engineering, Product | Reviewers check the draft for accuracy, clarity, and completeness.                                            |
| 5. Publishing     | Product                        | The advisory is published as part of the fixing release's process.                                            |

## Create the draft

1. Open the repository's [Security tab](https://github.com/influxdata/security-advisories/security)
   and click **Advisories** in the sidebar.
2. Click **New draft security advisory**.
3. Fill in the form using the [field conventions](#field-conventions) below.
4. Click **Create draft security advisory**.
5. Add reviewers who do not already have access as collaborators on the
   draft so they can read and comment on it.

For GitHub's own instructions, see
[Creating a repository security advisory](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/creating-a-repository-security-advisory).

## Field conventions

The GitHub form has more fields than most advisories need. Use this table to
decide what goes in each one.

| Field                  | Use it? | What to enter                                                                                                                            |
| :--------------------- | :------ | :--------------------------------------------------------------------------------------------------------------------------------------- |
| Title                  | Always  | `<Product> <version> security release`. For example, `Telegraf 1.39.2 security release`.                                                 |
| CVE identifier         | Depends | See [CVE identifier](#cve-identifier).                                                                                                   |
| Description            | Always  | The advisory body. Use the [description template](#description-template).                                                                |
| Affected products      | Always  | One entry per product and release line. See [Affected products](#affected-products).                                                     |
| Severity               | Always  | See [Severity](#severity).                                                                                                               |
| Weaknesses (CWE)       | Depends | Add the CWE for each issue in InfluxData's own code. Leave empty if the advisory contains only toolchain or dependency issues.           |
| Credits                | Depends | Credit external reporters and finders who have agreed to be named. Ask before adding someone; GitHub notifies them and they can decline. |
| Vulnerable functions   | Never   | Leave empty.                                                                                                                             |
| Temporary private fork | Never   | Not used. This repository contains no product code.                                                                                      |

### CVE identifier

The CVE field applies only to issues in InfluxData's own code. Toolchain and
dependency CVEs are listed in the description, not here.

- If an issue in InfluxData's own code warrants a CVE and none has been
  assigned, select **Request CVE ID later**, then request the CVE from GitHub
  before publishing. GitHub usually responds within 72 hours, so request it
  as soon as the draft is stable. Requesting a CVE does not make the advisory
  public.
- If a CVE was already assigned by another CVE Numbering Authority, select
  **I have an existing CVE identifier** and enter it.
- If no issue warrants a CVE, leave the field at its default. The GHSA ID
  assigned to the advisory is sufficient on its own.

> [!NOTE]
> The form accepts one CVE per advisory. If a single release fixes more than
> one issue in InfluxData's own code that each warrant a CVE, ask Security how
> to proceed before requesting one.

### Affected products

The **Affected products** section is how readers and InfluxData's tooling
identify which product an advisory applies to. Fill it in exactly as follows:

| Form field        | Value                                                                                                     |
| ----------------- | --------------------------------------------------------------------------------------------------------- |
| Ecosystem         | `Other`                                                                                                   |
| Package name      | The package name from the [product table](#product-package-names). Copy it exactly.                       |
| Affected versions | The vulnerable range in GitHub's operator syntax. For example, `< 1.39.2` or `>= 1.38.0, < 1.39.2`.       |
| Patched versions  | The fixing version. For example, `1.39.2`.                                                                |

Version syntax rules, from GitHub's
[best practices for repository security advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/best-practices-for-writing-repository-security-advisories):

- Put a space between the operator and the version: `< 1.39.2`, not `<1.39.2`.
- Separate a lower and upper bound with a comma and a space: `>= 1.38.0, < 1.39.2`.
- Use `>=` for lower bounds, never `>`.
- Do not include a `v` prefix.
- Each entry holds one range. If a fix ships on more than one release line,
  click **Add another affected product** and add one entry per line with its
  own affected and patched versions.

If the earliest affected version is not known, use only an upper bound, such
as `< 1.39.2`.

#### Product package names

Package names are lowercase, hyphen-separated identifiers. InfluxData's
tooling matches on the exact string, so use the names in this table and do
not invent variants. To add a product, add a row here and notify Engineering
so that tooling recognizes it.

| Product                    | Package name                | Notes                                                                                                       |
| :------------------------- | :-------------------------- | :---------------------------------------------------------------------------------------------------------- |
| Telegraf                   | `telegraf`                  |                                                                                                             |
| Telegraf Controller        | `telegraf-controller`       |                                                                                                             |
| InfluxDB 3 Core            | `influxdb3-core`            |                                                                                                             |
| InfluxDB 3 Enterprise      | `influxdb3-enterprise`      |                                                                                                             |
| InfluxDB 3 Explorer        | `influxdb3-explorer`        |                                                                                                             |
| InfluxDB OSS 1.x and 2.x   | `influxdb`                  | Add one Affected products entry per release line so that the 1.x and 2.x ranges stay separate.              |
| InfluxDB Enterprise 1.x    | `influxdb-enterprise`       |                                                                                                             |
| Chronograf                 | `chronograf`                |                                                                                                             |
| Kapacitor                  | `kapacitor`                 |                                                                                                             |
| Client libraries and tools | Repository name             | For example, `influxdb3-python`, `influx-cli`, or `influxctl`. Use the GitHub repository name as published. |

### Severity

The form holds one severity per advisory, but a release can fix several
issues. Handle this as follows:

- Compute a CVSS 3.1 score for each issue in InfluxData's own code and list
  it in that issue's section of the description.
- In the **Severity** field, select **Assess severity using CVSS** and enter
  the vector of the highest-scoring issue in InfluxData's own code.
- Do not compute CVSS for toolchain or dependency issues. Report the upstream
  score in the description if one exists.
- If the advisory contains no issues in InfluxData's own code, select the
  severity level that Security assigned during assessment instead of entering
  a CVSS vector.

GitHub's severity levels are **Low**, **Moderate**, **High**, and
**Critical**. CVSS calls the second level "Medium"; both refer to the same
range.

## Description template

The description is the part of the advisory most readers see first, and it
is what appears in notifications and API results. Copy this template and
delete the sections that do not apply. Every advisory has the opening
sentence; the rest depends on what the release fixes.

```markdown
<Product> <version> fixes the following security issues.

## <Issue title> (CVE-YYYY-NNNNN)

CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.2, Medium)

<What the issue is, which component it affects, and the conditions under
which it can be exploited. One or two paragraphs.>

**Mitigation:** Upgrade to <version>. If you cannot upgrade, <workaround>.

## <Language> toolchain

Updated to <language> <version> to fix <CVE list>, which were confirmed to
affect <Product>.

## Dependencies

Updated <module> to <version> to fix <CVE> (<upstream score and rating>),
which was confirmed to affect <Product>.

**Mitigation:** Upgrade to <version>. If you cannot upgrade, <workaround>.
```

Section by section:

- **Opening sentence.** Names the product and version and nothing else.
  Readers scanning a list of advisories should be able to tell from this
  line whether the advisory applies to them.
- **Issue sections.** One `##` section per issue in InfluxData's own code.
  The heading names the affected component and the kind of problem, with
  the CVE in parentheses if one exists. For example,
  `Credential exposure in inputs.http debug logs (CVE-2026-12345)`. The
  first line under the heading is the CVSS vector with its score and rating.
  Then describe the issue, and end with the mitigation.
- **Toolchain.** One section listing every toolchain CVE confirmed to affect the
  product. Do not list CVEs that were fixed in the toolchain update but do not
  affect the product. Omit the section if there are none.
- **Dependencies.** One section per urgent dependency issue, or omit the
  section. Routine dependency refreshes belong in release notes, not here.

For a complete example, see the [worked example](#worked-example).

## Style

Advisories use the same voice as InfluxData product documentation, which
follows the
[Google developer documentation style guide](https://developers.google.com/style).
The points below are the ones that matter most in an advisory.

### Voice and tone

- **Address the reader as "you."** Write in the second person, present tense,
  active voice: "Upgrade to 1.39.2," not "Users should upgrade to 1.39.2."
- **Refer to the company as InfluxData,** not "we."
- **Be factual and calm.** State what the issue is, what it affects, and what
  to do. Do not minimize ("a minor issue") or dramatize ("a serious flaw").
- **Lead with the action.** Readers want to know whether they are affected
  and what to do about it. Put the affected conditions and the mitigation
  where they are easy to find.
- **Say only what is known.** Do not speculate about exploitation in the
  wild, do not promise future fixes or dates, and do not describe the
  internal process that produced the advisory.

### Content to leave out

- Internal ticket numbers, customer names, and employee names.
- Exploit details beyond what a reader needs to judge their exposure.
- Anything about how InfluxData tooling consumes advisories.

### Formatting

- **Headings** are sentence case: "Go toolchain," not "Go Toolchain."
- **Product names** use their official form: InfluxDB 3 Core, Telegraf
  Controller, InfluxDB 3 Enterprise. Do not abbreviate.
- **Versions** are bare numbers: `1.39.2`, not `v1.39.2`. In prose, describe
  ranges in words: "Telegraf versions earlier than 1.39.2."
- **Component names** such as plugins, modules, and configuration options go
  in code font: `inputs.http`, `crypto/tls`.
- **CVE IDs** are written in full: `CVE-2026-12345`. Link each CVE to its
  entry in the relevant vulnerability database when one exists, for example
  the [Go vulnerability database](https://pkg.go.dev/vuln/) or the
  [RustSec Advisory Database](https://rustsec.org/).
- **CVSS vectors** are written as the full vector string followed by the
  numeric score and qualitative rating in parentheses.
- **Paragraphs** are written on a single line. GitHub renders line breaks in
  the description field literally, so do not wrap text or use semantic line
  feeds as you would in the documentation repository.

## Review checklist

Reviewers confirm each of the following before the advisory is published:

- [ ] The title names the correct product and version.
- [ ] Every issue from the assessment appears in the description, and
      nothing in the description is absent from the assessment.
- [ ] Affected and patched versions in the form match the description and
      the release.
- [ ] The package name matches the [product table](#product-package-names)
      exactly.
- [ ] The advisory severity is the highest CVSS score among issues in
      InfluxData's own code.
- [ ] Each mitigation is correct and complete.
- [ ] Any CVE request has been made and, if assigned, the ID matches the
      description.
- [ ] Credits have been accepted by the people named.
- [ ] Nothing internal or confidential appears in the text.
- [ ] Links resolve.

## Publish

1. Confirm the fixing release is available: the release tag exists and the
   release artifacts are published.
2. Open the draft advisory, scroll to the bottom, and click
   **Publish advisory**.
3. Link to the advisory from the release notes for the fixing release.

InfluxData's tooling picks up published advisories automatically. No further
action is needed.

For GitHub's own instructions, see
[Publishing a repository security advisory](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/publishing-a-repository-security-advisory).

## Update a published advisory

Update a published advisory only when the change provides substantial benefit
to customers, for example when an issue originally assessed as not affecting
the product is later confirmed to affect it. Do not update advisories for
later low- or medium-severity findings, wording tweaks, or additional
context.

When you do update one:

1. Make the change in place so the advisory stays accurate when read on its
   own.
2. Add an **Updates** section at the end of the description with a dated
   entry describing what changed and why.
3. Have the change reviewed the same way as the original advisory.

To withdraw a published advisory, contact Security. Withdrawing requires
GitHub support and is reserved for advisories that were published in error.

## Worked example

> [!IMPORTANT]
> This example is illustrative only and does not describe a real
> vulnerability. It shows an advisory for a release that fixes one issue in
> InfluxData's own code and two Go toolchain CVEs.

**Title:** `Telegraf 1.39.2 security release`

**CVE identifier:** Request CVE ID later

**Affected products:**

| Ecosystem | Package name | Affected versions | Patched versions |
| --------- | ------------ | ----------------- | ---------------- |
| Other     | `telegraf`   | `< 1.39.2`        | `1.39.2`         |

**Severity:** Assess severity using CVSS, `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Weaknesses:** CWE-532

**Description:**

```markdown
Telegraf 1.39.2 fixes the following security issues.

## Credential exposure in inputs.http debug logs (CVE-2026-12345)

CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.2, Medium)

When debug logging is enabled, the `inputs.http` plugin logs full request headers, including `Authorization` headers. Anyone with read access to Telegraf's logs can recover credentials used by the plugin. Telegraf versions earlier than 1.39.2 with `debug = true` and at least one `inputs.http` plugin configured are affected.

**Mitigation:** Upgrade to 1.39.2. If you cannot upgrade, disable debug logging and rotate any credentials that may have been logged.

## Go toolchain

Updated to Go 1.26.5 to fix CVE-2026-42505 (`crypto/tls`) and CVE-2026-39822 (`os`), both confirmed to affect Telegraf.
```
