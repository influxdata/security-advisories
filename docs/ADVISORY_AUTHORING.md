# Advisory authoring guide

This guide is for people who draft, review, and publish InfluxData security
advisories in this repository. It covers what an advisory must include, how
to fill in each field of the GitHub advisory form, how to identify the
affected product, how to handle toolchain CVEs, and how to write in a
consistent voice.

For what advisories cover and when they are published, see the
[README](../README.md). This guide assumes that policy and describes how to
apply it.

## Before you start

You need the following before drafting an advisory:

- **Assessment data** from Security and Engineering for each issue the
  release fixes: a short description of the issue and its impact, the
  affected versions, the CVSS score for each issue in InfluxData's own code,
  and any workarounds for users who cannot upgrade immediately.
- **The fixing release** version number and its expected ship date. For
  toolchain CVEs, confirm the fixing release yourself before drafting. The
  triage names the release it reviewed, which is not always the first
  release that contains the fix. See [Toolchain CVEs](#toolchain-cves).
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
| 2. Assessment     | Security, Engineering, Product | Impact, affected versions, severity, and workarounds are established. Security supplies fix and impact prose. |
| 3. Authoring      | Product                        | The author creates the draft advisory in this repository using the assessment data and this guide.            |
| 4. Review         | Security, Engineering, Product | Reviewers check the draft for accuracy, clarity, and completeness.                                            |
| 5. Publishing     | Product                        | The advisory is published as part of the fixing release's process.                                            |

## Create the draft

1. Open the repository's [Advisories page](https://github.com/influxdata/security-advisories/security/advisories)
   and click **New draft security advisory**.
2. Fill in the form using the [field conventions](#field-conventions) below.
   The help text under each field is written for people reporting a
   vulnerability to a maintainer. Follow this guide instead.
3. Click **Create draft security advisory**. GitHub joins the Summary,
   Details, Proof of concept, and Impact fields into one description, each
   under a level-3 heading in that order. From then on the description is a
   single field that you edit as a whole.
4. Add reviewers who do not already have access as collaborators on the
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
| Summary                | Always  | What the release fixes and who is affected, in one to three sentences. See [Summary](#summary).                                          |
| Details                | Always  | The issue sections, then Patches, Workarounds, and References. See [Details](#details).                                                  |
| Proof of concept       | Always  | The standard statement and nothing else. See [Proof of concept](#proof-of-concept).                                                      |
| Impact                 | Always  | What kind of issue it is, who can exploit it, and what they gain. See [Impact](#impact).                                                 |
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

The **Affected products** section is how readers and the advisory build
pipeline identify which product an advisory applies to. Fill it in exactly as
follows:

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
as `< 1.39.2`. For toolchain CVEs, use only an upper bound unless the Go
vulnerability database shows that an earlier release was already built with
a fixed Go version.

#### Product package names

Package names are lowercase, hyphen-separated identifiers. The advisory
build pipeline in this repository matches on the exact string to build the
per-product advisory lists, so use the names in this table and do not invent
variants. To add a product, add a row here and update the build pipeline to
recognize the new name.

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
- Do not compute CVSS for toolchain or dependency issues. For a dependency
  issue, report the upstream score in its Details line as information only,
  because it may not reflect how the product uses the affected code. For
  toolchain CVEs, do not report upstream ratings in the description. If the
  advisory's severity is below the upstream rating, one sentence at the end
  of Impact may say why.
- If the advisory contains no issues in InfluxData's own code, select the
  severity level that Security assigned during assessment instead of entering
  a CVSS vector. Expect this to be the common case, because most releases
  contain only toolchain and dependency fixes. Security's rating is for the
  product, so it can be lower than the upstream rating of the same CVE.

GitHub's severity levels map directly to the CVSS levels, with one naming
difference: GitHub's **Moderate** is CVSS **Medium**.

## Description fields

The description is the part of the advisory most readers see first, and it
is what appears in notifications and API results. The form collects it as
four fields. GitHub joins them into one description when you create the
draft, under the headings `### Summary`, `### Details`,
`### Proof of concept`, and `### Impact`, in that order. Headings inside a
field are therefore level 4. Paragraphs are written on a single line, as
described under [Formatting](#formatting).

For a complete example, see the [worked example](#worked-example).

### Summary

One to three sentences: the product and version, what the issues allow,
which components are affected, and, when it helps readers decide quickly,
the configuration that is affected. Do not state the severity; the Severity
field carries it. Readers scanning a list of advisories should be able to
tell from this field whether the advisory applies to them.

```markdown
<Product> <version> fixes <what the issues allow> in <component>. <Who is affected and under which configuration.>
```

### Details

One `####` section per issue in InfluxData's own code, then a Go toolchain
section, then a Dependencies section, then Patches, Workarounds, and
References once for the whole advisory. The comments in the template mark
which sections are optional. Delete them as you fill in the form.

```markdown
<!-- One section per issue in InfluxData's own code. Omit if there are none. -->
#### <Issue title> (CVE-YYYY-NNNNN)

CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.2, Medium)

<What the issue is, which component it affects, who is affected, and the conditions under which it can be exploited. One or two paragraphs.>

<!-- Omit if the release has no toolchain update. -->
#### Go toolchain

Updated to Go <version> to fix the following CVEs in the Go standard library, which were confirmed to affect <Product>.

- [CVE-YYYY-NNNNN](https://pkg.go.dev/vuln/GO-YYYY-NNNN): <title line from the Go release announcement, verbatim>.

<!-- Omit if the release has no urgent dependency fixes. -->
#### Dependencies

Updated <module> to <version> to fix <CVE> (<upstream score and rating>), which was confirmed to affect <Product>.

#### Patches

Fixed in <Product> <version>.

#### Workarounds

<What to do if you cannot upgrade, or "None.">

#### References

- [<Product> <version> release notes](<url>)
<!-- Add pull requests or commits only when the release notes do not identify the fix. -->
- [<Fixing pull request or commit>](<url>)
```

Section by section:

- **Issue sections.** One `####` section per issue in InfluxData's own code.
  The heading names the affected component and the kind of problem, with
  the CVE in parentheses if one exists. For example,
  `Credential exposure in inputs.http debug logs (CVE-2026-12345)`. The
  first line under the heading is the CVSS vector with its score and rating.
  Keep that line even when the advisory has a single issue; the Severity
  field holds one vector per advisory, and the line is what ties the score
  to the issue. The paragraphs that follow describe the issue, the affected
  component, who is affected, and the conditions required to exploit it.
- **Go toolchain.** One bullet per toolchain CVE confirmed to affect the
  product, sorted ascending by CVE number. Each bullet is the CVE linked to
  its Go vulnerability database record, a colon, the title line of that
  CVE's section in the Go release announcement copied without changes, and
  a period. Do not paraphrase the title and do not describe exposure in the
  bullet; exposure goes in [Impact](#impact). Do not list CVEs that were
  fixed in the toolchain update but do not affect the product. Omit the
  section if there are none. See [Toolchain CVEs](#toolchain-cves) for how
  to find the title line and verify the fixing release.
- **Dependencies.** One line per urgent dependency issue, or omit the
  section. Routine dependency refreshes belong in release notes, not here.
- **Patches.** States the version that fixes every issue in the advisory,
  with the product name. Add what changed when it helps readers, for
  example "Bearer authentication is rejected when `shared-secret` is empty."
- **Workarounds.** Tells readers who cannot upgrade what to do, once for the
  advisory. When workarounds differ by issue, write one paragraph per
  issue and name the issue. Write "None." if there is no workaround. Do not
  omit the subsection.
- **References.** Always link the release notes for the fixing release.
  Link individual pull requests or commits only when they add something the
  release notes do not, for example when the release notes do not identify
  which change fixed the issue, or when the change itself helps readers judge
  their exposure. For a toolchain update, link the pull request that updated
  Go, because product release notes do not identify which CVEs it fixed.
  Add the reporter's public issue if there is one. Keep the list short.

### Proof of concept

InfluxData does not publish reproduction steps. The form requires the field,
so enter the following statement and nothing else, adjusted for the product,
the version, singular or plural, and which section describes the
configuration that exposes the issue.

For one issue:

```markdown
InfluxData does not publish reproduction steps for this issue. The configuration that exposes it is described under Details: <conditions>. Upgrade to <Product> <version> or <workaround>.
```

For several issues:

```markdown
InfluxData does not publish reproduction steps for these issues. The configurations that expose each one are described under Impact. Upgrade to <Product> <version> or apply the workarounds under Details.
```

### Impact

What kind of issue it is, who can exploit it, and what they gain. Keep it
short, and do not repeat affected versions or configurations that Details
already states. For toolchain CVEs, Impact is where exposure is described:
one bullet per affected component that names the CVEs, the effect, the
configuration that opens the path, and who can reach it. Group CVEs that
share a path, and end with a sentence saying which deployments are not
affected.

For an issue in InfluxData's own code:

```markdown
<Kind of issue>. <Who can exploit it, from where, and what they gain.>
```

For toolchain CVEs:

```markdown
- <Effect> against <component>: <CVEs> let <who> <do what>. <Which configuration is affected and who can reach it.>

<Which deployments are not affected.>
```

## Toolchain CVEs

Security's triage of a Go security release lists, for each CVE, whether it
affects the product and the Go versions that fix it. The triage compares
those fix versions with the Go version of the release it reviewed and
reports the CVE as remediated by that release. It does not check whether the
previous release already contained the fix, so verify the fixing release
before drafting.

1. Find the Go version of the release under review and of the release
   before it. For Telegraf, read `FROM golang:<version>` in
   `scripts/ci.docker` at each tag. For Kapacitor, read the "Upgrade Go
   version" line in the changelog. For any product, `go version -m` on the
   published binary is definitive.
2. For each CVE, read the affected version ranges in its Go vulnerability
   database record at `https://pkg.go.dev/vuln/GO-YYYY-NNNN`, for example
   "before go1.26.9" and "from go1.27.0-0 before go1.27.2". A range that
   ends at a release candidate, such as "before go1.27.0-rc.3", means the
   final release contains the fix.
3. The advisory belongs to the first release whose Go version is outside
   every range for that CVE. If that is the release under review, draft as
   usual. If it is an earlier release with a published advisory, add the
   toolchain section to that advisory as an update; see
   [Update a published advisory](#update-a-published-advisory). If it is an
   earlier release with no advisory, there is nothing to publish; see the
   README on historical releases. A release whose remaining security
   content is empty gets no advisory.
4. List only the CVEs the triage confirmed as affecting the product. Leave
   out CVEs marked not affected or ignored, even though the same Go release
   fixed them.
5. Take each bullet's text from the Go release announcement on the
   golang-announce group, which every vulnerability database record links
   under its references. The title line of the CVE's section, for example
   `net/http: HTTP/2 server memory exhaustion due to Trailer headers`, is
   the bullet text.
6. Put exposure in Impact: which plugin or component reaches the affected
   code, the configuration that opens the path, and who can reach it. The
   triage notes identify these; strip file paths, line numbers, and names.
7. Set Severity from Security's product-context rating, which can be lower
   than the upstream rating.
8. Link the Go update pull request in References.

When the fixing release has not shipped, draft against the expected version
with placeholders for the Go version, the release-notes anchor, and the
pull request number. Keep the draft unpublished unless the README's
exception for high or critical issues applies.

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
  and what to do about it. Put the affected conditions and the workaround
  where they are easy to find.
- **Say only what is known.** Do not speculate about exploitation in the
  wild, do not promise future fixes or dates, and do not describe the
  internal process that produced the advisory.

### Content to leave out

- Internal ticket numbers, customer names, and employee names.
- Exploit details beyond what a reader needs to judge their exposure. The
  Proof of concept field never carries reproduction steps.
- Anything about how InfluxData tooling consumes advisories.

### Formatting

- **Headings** are sentence case: "Go toolchain," not "Go Toolchain."
  Headings inside the description fields are level 4 (`####`), because
  GitHub adds a level-3 heading for each field.
- **Product names** use their official form: InfluxDB 3 Core, Telegraf
  Controller, InfluxDB 3 Enterprise. Do not abbreviate.
- **Versions** are bare numbers: `1.39.2`, not `v1.39.2`. In prose, describe
  ranges in words: "Telegraf versions earlier than 1.39.2."
- **Component names** such as plugins, modules, and configuration options go
  in code font: `inputs.http`, `crypto/tls`. The exception is a toolchain
  bullet, which copies the Go announcement's title line as written.
- **CVE IDs** are written in full: `CVE-2026-12345`. Link each CVE to its
  entry in the relevant vulnerability database when one exists, for example
  the [Go vulnerability database](https://pkg.go.dev/vuln/) or the
  [RustSec Advisory Database](https://rustsec.org/).
- **CVSS vectors** are written as the full vector string followed by the
  numeric score and qualitative rating in parentheses.
- **Paragraphs** are written on a single line. GitHub renders line breaks in
  the description fields literally, so do not wrap text or use semantic line
  feeds as you would in the documentation repository.

## Review checklist

Reviewers confirm each of the following before the advisory is published:

- [ ] The title names the correct product and version.
- [ ] Every issue from the assessment appears in the description, and
      nothing in the description is absent from the assessment.
- [ ] For toolchain CVEs, the previous release's Go version was checked
      against the vulnerability database ranges, and the advisory is on the
      first release that contains the fix.
- [ ] Toolchain bullets use the announcement title lines without changes and
      are sorted ascending by CVE number.
- [ ] The Summary does not state the severity.
- [ ] Proof of concept contains the standard statement and nothing else.
- [ ] Affected and patched versions in the form match the description and
      the release.
- [ ] The package name matches the [product table](#product-package-names)
      exactly.
- [ ] The advisory severity is the highest CVSS score among issues in
      InfluxData's own code, or Security's rating when there are none.
- [ ] Each workaround is correct and complete, or stated as none.
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

The advisory build pipeline picks up published advisories automatically. No
further action is needed.

For GitHub's own instructions, see
[Publishing a repository security advisory](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/publishing-a-repository-security-advisory).

## Update a published advisory

Update a published advisory only when the change helps readers judge their
exposure:

- An issue originally assessed as not affecting the product is later
  confirmed to affect it.
- A toolchain CVE is confirmed after publication to affect the product and
  to have been fixed by that release's toolchain update; see
  [Toolchain CVEs](#toolchain-cves). Add or extend the Go toolchain section
  under Details, add the Go update pull request to References, and widen
  the affected range if the toolchain CVEs affect releases outside it.

Do not update advisories for wording changes or additional context.

When you do update one:

1. Make the change in place so the advisory stays accurate when read on its
   own.
2. Add an **Updates** section at the end of the description with a dated
   entry describing what changed and why.
3. Have the change reviewed the same way as the original advisory.

```markdown
### Updates

- <YYYY-MM-DD>: <What changed and why.>
```

To withdraw a published advisory, contact Security. Withdrawing requires
GitHub support and is reserved for advisories that were published in error.

## Worked example

> [!IMPORTANT]
> This example is illustrative only and does not describe a real
> vulnerability. The CVE identifiers, vulnerability database records, and
> Go announcement titles are invented. It shows an advisory for a release
> that fixes one issue in InfluxData's own code and two Go toolchain CVEs.

**Title:** `Telegraf 1.39.2 security release`

**CVE identifier:** Request CVE ID later

**Affected products:**

| Ecosystem | Package name | Affected versions | Patched versions |
| --------- | ------------ | ----------------- | ---------------- |
| Other     | `telegraf`   | `< 1.39.2`        | `1.39.2`         |

**Severity:** Assess severity using CVSS, `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Weaknesses:** CWE-532

**Summary:**

```markdown
Telegraf 1.39.2 fixes a credential exposure in the debug logs of the `inputs.http` plugin and two CVEs in the Go standard library that affect TLS connections. The credential exposure affects agents that run `inputs.http` with `debug = true`. The toolchain CVEs affect every agent that makes TLS connections.
```

**Details:**

```markdown
#### Credential exposure in inputs.http debug logs (CVE-2026-12345)

CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.2, Medium)

When debug logging is enabled, the `inputs.http` plugin logs full request headers, including `Authorization` headers. Anyone with read access to Telegraf's logs can recover credentials used by the plugin. Telegraf versions earlier than 1.39.2 with `debug = true` and at least one `inputs.http` plugin configured are affected.

#### Go toolchain

Updated to Go 1.26.5 to fix the following CVEs in the Go standard library, which were confirmed to affect Telegraf.

- [CVE-2026-00001](https://pkg.go.dev/vuln/GO-2026-0001): crypto/tls: excessive CPU consumption during client certificate verification.
- [CVE-2026-00002](https://pkg.go.dev/vuln/GO-2026-0002): crypto/x509: unbounded memory growth when parsing certificate chains.

#### Patches

Fixed in Telegraf 1.39.2.

#### Workarounds

For the credential exposure, disable debug logging and rotate any credentials that may have been logged. For the toolchain CVEs, connect only to servers you trust; there is no configuration workaround.

#### References

- [Telegraf 1.39.2 release notes](https://docs.influxdata.com/telegraf/v1/release-notes/#v1392)
- [Fixing pull request](https://github.com/influxdata/telegraf/pull/<number>)
- [Go 1.26.5 update](https://github.com/influxdata/telegraf/pull/<number>)
```

**Proof of concept:**

```markdown
InfluxData does not publish reproduction steps for these issues. The configurations that expose each one are described under Impact. Upgrade to Telegraf 1.39.2 or apply the workarounds under Details.
```

**Impact:**

```markdown
- Credential exposure: anyone with read access to the logs of an agent that runs `inputs.http` with `debug = true` can recover the credentials the plugin sends.
- Denial of service against TLS connections: CVE-2026-00001 and CVE-2026-00002 let a server that an agent connects to consume the agent's CPU or memory during the TLS handshake. Agents are affected when any plugin connects over TLS to a server that is not trusted.

Agents that do not run `inputs.http` with `debug = true` and do not make TLS connections are not affected.
```
