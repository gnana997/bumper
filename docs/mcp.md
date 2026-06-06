# The Advisor MCP

The hosted **Advisor** speaks [MCP](https://modelcontextprotocol.io) so a coding agent can
consult bumper's security knowledge **while it works** — before it pins a dependency, adds
a package, or writes Terraform for a resource. It's the same data as [the Advisor
API](api.md), exposed as agent tools.

It is **lookup-not-upload**: the agent sends a query, a package coordinate, or a small list
of named packages — never your code, plan, or state.

> **Two different MCP servers.** This page is the **hosted, remote** Advisor
> (`advisor.bumper.sh/mcp`) — knowledge only, nothing to install. bumper *also* ships an
> **offline, local** MCP (`bumper mcp`, stdio) that scans your actual Terraform plans
> (`scan_plan`, `verify`, the `guard` hook). That one is covered in
> [agents.md](agents.md). Use both: the local server enforces *your* plan; the hosted
> Advisor answers *general* best-practice and dependency questions.

- [Connect](#connect)
- [Tools](#tools)
  - [`search_rules`](#search_rules)
  - [`get_rule`](#get_rule)
  - [`search_cve`](#search_cve)
  - [`lookup_cve`](#lookup_cve)
  - [`get_vuln`](#get_vuln)
  - [`check_malware`](#check_malware)
- [Lean by default](#lean-by-default)
- [Malware vs. vulnerabilities](#malware-vs-vulnerabilities)
- [Privacy](#privacy)

## Connect

The endpoint is **streamable-http** (no install, no API key):

```
https://advisor.bumper.sh/mcp
```

**Claude Code** — add it as an HTTP server:

```sh
claude mcp add --transport http bumper-advisor https://advisor.bumper.sh/mcp
```

…or write it into `.mcp.json` directly (works for any MCP client that supports HTTP):

```json
{
  "mcpServers": {
    "bumper-advisor": {
      "type": "http",
      "url": "https://advisor.bumper.sh/mcp"
    }
  }
}
```

That's it — the agent now has the six tools below. (Prefer everything in one step, wired
into your repo alongside the offline scanner? `bumper init` — see [agents.md](agents.md).)

## Tools

| Tool | Use it to |
| --- | --- |
| [`search_rules`](#search_rules) | find IaC best-practice rules before writing Terraform |
| [`get_rule`](#get_rule) | pull one rule in full, with the AI insight |
| [`search_cve`](#search_cve) | search CVEs by description |
| [`lookup_cve`](#lookup_cve) | check an exact `package@version` for known vulnerabilities |
| [`get_vuln`](#get_vuln) | pull one CVE in full, with the AI insight |
| [`check_malware`](#check_malware) | check a package for known-**malicious** code before adding it |

### `search_rules`

Semantic + lexical search across bumper's enforced rules and the federated advisory
catalog (Trivy / Checkov / KICS / Prowler). Returns `{results, advisory}`; each hit carries
`has_ai_insight`.

- `query` *(required)* · `provider` · `severity` · `limit` (default 30)
- Best practice, offline-style knowledge — it never sees your infrastructure. Fetch the
  full insight for a hit with `get_rule`.

### `get_rule`

Full record for one rule: severity, resources, remediation, refs, cwe.

- `source` *(required)* — `bumper` \| `trivy` \| `checkov` \| `kics` \| `prowler`
- `source_id` *(required)*
- `include_insight` (default `true`) — pass `false` for a smaller response without the AI
  `ai_insight` block. `has_ai_insight` is always returned.

### `search_cve`

Semantic + lexical search over the CVE mirror (language ecosystems + Linux distros).
Returns matching vulns with severity, affected ecosystems/packages, and CWE; each carries
`has_ai_insight`.

- `query` *(required)* · `ecosystem` · `severity` · `limit` (default 20)

### `lookup_cve`

Which known CVEs affect an **exact** `package@version` — the check before pinning a
dependency. **Vulnerabilities only** (known-malicious packages are
[`check_malware`](#check_malware)'s job).

- `ecosystem` *(required)* — `npm` \| `PyPI` \| `Maven` \| `Go` \| `crates.io` \| `NuGet` \|
  `RubyGems` \| `Debian:12` \| `Alpine:v3.19` \| …
- `package` *(required)* · `version` *(required)*
- Returns `{status, vulns: [{id, severity, fixed_version, summary, cwe, has_ai_insight}],
  count}`. `status` is `ok` even at `count: 0` (clean); `ecosystem_unsupported` means the
  ecosystem isn't mirrored — **never** read that as safe. Lean by design: call `get_vuln`
  for a specific one's full insight.

### `get_vuln`

Full record for one CVE / GHSA / OSV id: summary, details, severity, CWE, references.

- `id` *(required)*
- `include_insight` (default `true`) — `false` drops the `ai_insight` block;
  `has_ai_insight` is always returned.

### `check_malware`

Is a dependency **known-malicious** (typosquat / backdoor / install-time payload; OSV
`MAL-`)? The safety check to run **before** adding a package.

- One package: `ecosystem` + `package`. Or a batch: `packages=[{ecosystem, package}, …]`.
- **Name-level** — no `version` needed; a malicious package is bad at every version.
- Returns `{status, checked, malicious_count, results: [{ecosystem, package,
  advisories: [{id, summary, refs}]}]}`. Empty `results` is **not** proof of safety:
  `status: "unavailable"` means the mirror isn't ready, and an unmirrored ecosystem is
  skipped. Lean — call `get_vuln(id)` for an advisory's full write-up.

## Lean by default

The Advisor follows MCP **progressive disclosure** so it never floods an agent's context:

- **Lists, searches, and lookups return a flag, not the payload** — each item carries a
  cheap `has_ai_insight` boolean instead of the full AI explanation.
- **Detail tools (`get_rule`, `get_vuln`) attach the full `ai_insight` by default**, and
  accept `include_insight=false` when you want the record without it.

So the loop is: search/lookup broadly (cheap) → pull the full insight only for the one or
two items you actually act on. AI insights are illustrative — the deterministic rule/CVE
data is the source of truth (each insight ships a `provenance` block saying so).

## Malware vs. vulnerabilities

These are **distinct paths**, on purpose:

- **`check_malware`** → the whole package is hostile (it shouldn't exist in your tree at
  all). Name-level; treat a hit as a hard stop.
- **`lookup_cve`** → a legitimate package has a known flaw at some versions; the answer is
  usually "upgrade to `fixed_version`."

`lookup_cve` deliberately **excludes** `MAL-` advisories so the two never get conflated.

## Privacy

Lookup-not-upload: queries, package coordinates, and named-package lists are all that leave
the machine — never code, plans, or state — and the server doesn't log them. To keep even
coordinates in-house, self-host the Advisor and point the `url` at your own instance (see
[api.md → Self-hosting](api.md#self-hosting)).
