# The Advisor API

**bumper Advisor** is a hosted, read-only knowledge API over bumper's security data:
the federated IaC rule catalog (Trivy / Checkov / KICS / Prowler + bumper's enforced
rules) and a CVE mirror built from [OSV](https://osv.dev) (language ecosystems **and**
Linux distros). It answers *"what's the best practice?"* and *"is this dependency
known-bad?"* — it is **lookup-not-upload**: you send a query, a package coordinate, or a
dependency list; it never sees your infrastructure, plan, state, or source.

The same core also speaks MCP for agents — see [the Advisor MCP](mcp.md).

- [Base URL & conventions](#base-url--conventions)
- [Endpoints](#endpoints)
  - [`GET /search` — IaC rules + advisory catalog](#get-search--iac-rules--advisory-catalog)
  - [`GET /rule` — one rule, in full](#get-rule--one-rule-in-full)
  - [`GET /cve/search` — search CVEs](#get-cvesearch--search-cves)
  - [`GET /cve/lookup` — CVEs for an exact package version](#get-cvelookup--cves-for-an-exact-package-version)
  - [`GET /vuln` — one CVE, in full](#get-vuln--one-cve-in-full)
  - [`POST /malware-check` — is a package known-malicious?](#post-malware-check--is-a-package-known-malicious)
  - [`POST /scan` — scan a dependency list](#post-scan--scan-a-dependency-list)
  - [`GET /healthz`](#get-healthz)
- [AI insights](#ai-insights)
- [Limits & status](#limits--status)
- [Privacy](#privacy)
- [Self-hosting](#self-hosting)

## Base URL & conventions

```
https://advisor.bumper.sh
```

- **No auth, no keys.** Public and read-only.
- **JSON in, JSON out.** `Content-Type: application/json` for POST bodies.
- **GET** for single lookups (cacheable); **POST** for the batch gates (`/malware-check`,
  `/scan`) whose input is a list.
- **CORS** is open (`*`) — you can call it directly from a browser.
- Every string argument is length-capped (512 chars); batch lists are capped at **5,000**
  entries per call (see [Limits](#limits--status)).

A note on **enriched vs lean**: detail endpoints (`/rule`, `/vuln`) attach an AI-generated
`ai_insight` by default; pass `include_insight=false` to omit it. List/search/scan
responses are **lean by design** — they carry a `has_ai_insight` boolean instead of the
full insight, so a result set never floods a client. See [AI insights](#ai-insights).

---

## Endpoints

### `GET /search` — IaC rules + advisory catalog

Hybrid (semantic + lexical) search across bumper's **enforced** rules and the federated
**advisory** catalog. Returns two lists: `results` (enforced, must-fix) and `advisory`
(best-practice, round-robined across sources).

| param | required | default | notes |
| --- | --- | --- | --- |
| `q` (or `query`) | yes | — | the search text |
| `provider` | no | — | e.g. `aws`, `gcp`, `azure` |
| `severity` | no | — | `critical` \| `high` \| `medium` \| `low` |
| `limit` | no | 30 | 1–100 |

```sh
curl "https://advisor.bumper.sh/search?q=s3+bucket+public&limit=1"
```

```jsonc
{
  "query": "s3 bucket public",
  "results": [
    {
      "uid": "bumper:AWS_S3_BUCKET_PUBLIC_ACL",
      "source": "bumper", "source_id": "AWS_S3_BUCKET_PUBLIC_ACL",
      "title": "S3 bucket uses a public canned ACL",
      "provider": "aws", "severity": "high", "enforced": true,
      "resources": ["aws_s3_bucket"],
      "remediation": "Use a private ACL and an aws_s3_bucket_public_access_block; …",
      "refs": ["https://docs.aws.amazon.com/…/access-control-block-public-access.html"],
      "has_ai_insight": true
    }
  ],
  "advisory": [ { "uid": "kics:1a4bc881-…", "source": "kics", "enforced": false, … } ],
  "count": { "results": 1, "advisory": 1 }
}
```

Fetch the full record (incl. the AI insight) for any hit with [`/rule`](#get-rule--one-rule-in-full),
using its `source` + `source_id`. See [rules.md](rules.md) for the enforced-vs-advisory model.

### `GET /rule` — one rule, in full

| param | required | notes |
| --- | --- | --- |
| `source` | yes | `bumper` \| `trivy` \| `checkov` \| `kics` \| `prowler` |
| `source_id` (or `id`) | yes | the rule id within that source |
| `include_insight` | no | `true` (default) \| `false` |

```sh
curl "https://advisor.bumper.sh/rule?source=bumper&source_id=AWS_S3_BUCKET_PUBLIC_ACL"
```

Returns the rule fields (`title`, `severity`, `provider`, `resources`, `remediation`,
`refs`, `cwe`, …) plus, when enriched, an `ai_insight` object and `has_ai_insight: true`.
404s if the rule isn't found.

### `GET /cve/search` — search CVEs

Hybrid search over the curated CVE corpus.

| param | required | default | notes |
| --- | --- | --- | --- |
| `q` (or `query`) | yes | — | the search text |
| `ecosystem` | no | — | `npm` \| `PyPI` \| `Go` \| `Maven` \| `RubyGems` \| `crates.io` \| `NuGet` \| `Debian:12` \| `Alpine:v3.19` \| … |
| `severity` | no | — | `critical` \| `high` \| `medium` \| `low` |
| `limit` | no | 20 | 1–100 |

```sh
curl "https://advisor.bumper.sh/cve/search?q=prototype+pollution+lodash&limit=1"
```

```jsonc
{
  "query": "prototype pollution lodash",
  "results": [
    {
      "id": "CVE-2018-3721", "title": "Prototype Pollution in lodash",
      "severity": "medium", "cvss": 6.5,
      "ecosystems": ["npm", "Debian:12", "RubyGems", …],
      "packages": ["lodash", "lodash-rails", "node-lodash"],
      "cwe": ["CWE-1321", "CWE-471"],
      "has_ai_insight": false
    }
  ],
  "count": 1
}
```

### `GET /cve/lookup` — CVEs for an exact package version

The secure-coding check before you pin a dependency: which known CVEs affect this exact
`package@version`. Version-aware (uses the ecosystem's own version semantics).
**Vulnerabilities only — known-malicious packages are handled by
[`/malware-check`](#post-malware-check--is-a-package-known-malicious).**

| param | required | notes |
| --- | --- | --- |
| `ecosystem` | yes | as in `/cve/search` |
| `package` | yes | package name |
| `version` | yes | exact version |

```sh
curl "https://advisor.bumper.sh/cve/lookup?ecosystem=npm&package=lodash&version=4.17.4"
```

```jsonc
{
  "ecosystem": "npm", "package": "lodash", "version": "4.17.4",
  "status": "ok",
  "vulns": [
    {
      "id": "CVE-2019-10744", "severity": "critical",
      "fixed_version": "4.17.12", "summary": "Prototype Pollution in lodash",
      "aliases": ["CVE-2019-10744"], "cwe": ["CWE-1321", "CWE-20"],
      "refs": [ … up to 5 … ], "has_ai_insight": true
    }
  ],
  "count": 1
}
```

`status` is `ok` even when `count` is `0` (genuinely clean). It is **never** silently
"clean" when the data isn't there — see [Limits & status](#limits--status).

### `GET /vuln` — one CVE, in full

| param | required | notes |
| --- | --- | --- |
| `id` | yes | a CVE / GHSA / OSV id (matched directly or via aliases) |
| `include_insight` | no | `true` (default) \| `false` |

```sh
curl "https://advisor.bumper.sh/vuln?id=CVE-2019-10744"
```

Returns `summary`, `details`, `severity`, `cwe`, `refs`, `published`, `modified`, and —
when enriched — an `ai_insight` object + `has_ai_insight: true`.

### `POST /malware-check` — is a package known-malicious?

The pre-install safety gate. **Name-level** match against OSV `MAL-` advisories
(typosquats, backdoors, install-time payloads) on the packages you name — a malicious
package is bad at *every* version, so `version` is accepted but ignored. Returns only the
**malicious** subset, each with its advisories (including the source write-up verbatim, so
you can show *why* it's blocked).

```sh
curl -X POST https://advisor.bumper.sh/malware-check \
  -H 'Content-Type: application/json' \
  -d '{"deps":[{"ecosystem":"npm","package":"npm-security-testing"},
               {"ecosystem":"npm","package":"express"}]}'
```

```jsonc
{
  "status": "ok", "checked": 2, "malicious_count": 1,
  "skipped": 0, "truncated": false,
  "results": [
    {
      "ecosystem": "npm", "package": "npm-security-testing", "malicious": true,
      "advisories": [
        { "id": "MAL-2026-997",
          "summary": "Malicious code in npm-security-testing (npm)",
          "details": "…source write-up: should be considered fully compromised…",
          "refs": [ { "url": "https://github.com/advisories/GHSA-…", "type": "ADVISORY" } ] }
      ]
    }
  ]
}
```

Treat `malicious_count > 0` as **block**. An empty `results` is **not** proof of safety:
`status: "unavailable"` means the mirror isn't ready, and an unmirrored ecosystem is
simply skipped (counted in `skipped`).

### `POST /scan` — scan a dependency list

The post-install / CI gate. Version-aware vulnerability scan over a whole lockfile (or an
SBOM). Returns only the **vulnerable** subset, lean and severity-sorted, and — by default
— folds in any **malicious** packages found anywhere in the list (defense in depth: a
transitive malicious dep the named-only `/malware-check` never saw).

| body field | required | default | notes |
| --- | --- | --- | --- |
| `deps` | yes | — | `[{ecosystem, package, version}]` |
| `include_malware` | no | `true` | also flag `MAL-` packages in `findings[].malware` |

```sh
curl -X POST https://advisor.bumper.sh/scan \
  -H 'Content-Type: application/json' \
  -d '{"deps":[{"ecosystem":"npm","package":"lodash","version":"4.17.4"}]}'
```

```jsonc
{
  "status": "ok", "scanned": 1,
  "vulnerable_count": 1, "malware_count": 0,
  "skipped": 0, "truncated": false,
  "findings": [
    {
      "ecosystem": "npm", "package": "lodash", "version": "4.17.4",
      "vulns": [
        { "id": "CVE-2019-10744", "severity": "critical",
          "fixed_version": "4.17.12", "has_ai_insight": true },
        { "id": "CVE-2021-23337", "severity": "high", "fixed_version": "4.17.21",
          "has_ai_insight": false }
        // … severity-sorted: critical → high → medium → low
      ],
      "malware": []
    }
  ]
}
```

Pull the full AI insight only for what you act on, via [`/vuln`](#get-vuln--one-cve-in-full)
(or the `get_vuln` MCP tool) — keeping the scan response itself lean.

### `GET /healthz`

Liveness + corpus counts + cache stats.

```sh
curl https://advisor.bumper.sh/healthz
```

```jsonc
{ "status": "ok", "model": "minishlab/potion-retrieval-32M",
  "corpora": { "iac": 2707, "cve_search": 78177, "cve_affected": 3417888 },
  "cache": { "hits": 0, "misses": 0, "size": 0 } }
```

---

## AI insights

Detail records can carry an `ai_insight` — an AI-generated explanation of the rule or CVE.
It is **illustrative, not authoritative**: the deterministic advisory/rule data is the
source of truth; the insight helps you understand and remediate it.

```jsonc
"ai_insight": {
  "explanation": "…",
  "vulnerable_example": "…",
  "fixed_example": "…",
  "key_takeaway": "…",
  "provenance": {
    "model": "claude-sonnet-4-6",
    "generated_at": "2026-06-06T15:09:26Z",
    "disclaimer": "AI-generated from the advisory — illustrative; verify before applying."
  }
}
```

Insights are **precomputed**, never generated at request time. Because not everything is
enriched, every record carries a cheap **`has_ai_insight`** boolean — so a list can flag
which items have a deep-dive available without carrying the payload. Lists and scans are
lean (flag only); detail endpoints attach the full insight by default and accept
`include_insight=false` to drop it.

## Limits & status

- **String cap:** every argument is trimmed to 512 chars.
- **Batch cap:** `/malware-check` and `/scan` process up to **5,000** deps per call. Over
  that, the first 5,000 are processed and **`truncated: true`** is set — never a silent
  drop. Chunk very large lockfiles client-side.
- **Malformed entries** (missing `ecosystem`/`package`, or `version` for `/scan`) and
  **unmirrored ecosystems** are skipped and counted in **`skipped`** — one bad line never
  fails the whole batch.
- **`status` is honest.** A security tool must never imply "safe" when it simply has no
  data. `ok` = answered (even if nothing found); `unavailable` = the mirror isn't ready
  (e.g. mid-rebuild) — do **not** read this as clean; `ecosystem_unsupported` (on
  `/cve/lookup`) = we don't mirror that ecosystem, so we can't speak to it.

## Privacy

**Lookup-not-upload.** You send a query, a package coordinate, or a list of dependency
coordinates (`ecosystem` / `name` / `version`) — never your code, plan, or state. Request
bodies (your dependency lists) are **not logged**. If even sending coordinates is too much
for your org, [self-host](#self-hosting).

## Self-hosting

The Advisor is part of the open-core bumper project and can be run yourself — point your
clients at your own base URL instead of `advisor.bumper.sh`. The data is built from public
OSV + the federated rule catalog. See the repository for the compose setup.
