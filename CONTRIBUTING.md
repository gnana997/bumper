# Contributing to bumper

Thanks for helping make `apply` less scary. The most valuable contributions are
**new rules** and **real-world plan fixtures** — but bug fixes, docs, and
features are all welcome.

## Ground rules

- Be honest about what a rule catches and what it doesn't. bumper's whole value is
  trust — a noisy or wrong rule is worse than no rule.
- Every rule is deterministic and inspectable. No rule may depend on the AI layer.
- New code comes with tests. New rules come with a passing **and** a negative
  fixture.

## Dev setup

Requires Go 1.26+ (see [go.mod](go.mod)).

```sh
git clone https://github.com/gnana997/bumper
cd bumper
make hooks    # installs lefthook + gitleaks and wires up the git hooks
make build    # -> ./bumper
make test     # go test ./...
```

Git hooks: **pre-commit** runs a gitleaks secret scan + `gofmt` check;
**pre-push** runs `go vet ./...` and `go test ./...`. To bypass in an emergency:
`git commit --no-verify`.

## Adding a rule

Rules live in [internal/rules/builtin/&lt;provider&gt;/](internal/rules/builtin/)
as declarative YAML with a [CEL](https://github.com/google/cel-go) predicate.
There's a merged Trivy + Checkov worklist in
[docs/rule-catalog/](docs/rule-catalog/) — pick an intent, then:

1. **Write the rule** in `internal/rules/builtin/<provider>/<provider>_<service>.yaml`:

   ```yaml
   - id: GCP_FIREWALL_PUBLIC_INGRESS_SENSITIVE
     source: trivy            # "trivy" (with an avd:) or "custom"
     avd: AVD-GCP-0027        # the upstream id, for provenance — required for source: trivy
     severity: critical       # critical | high | medium | low
     resource: google_compute_firewall   # resource-type filter ("" = any; then guard on `type`)
     on: [create, update]     # change actions ("" = any; use [delete, replace] for destruction rules)
     when: |                  # CEL; true => finding. Guard every field with has(...)
       has(after.source_ranges) && "0.0.0.0/0" in after.source_ranges && ...
     title: "Firewall rule exposes a sensitive port to the entire internet (0.0.0.0/0)"
     fix: "Restrict source_ranges to known CIDRs, or narrow the allowed ports."
     refs: ["https://cloud.google.com/vpc/docs/firewalls"]
   ```

2. **Add a fixture** in `internal/engine/testdata/` — a plan that the rule *should*
   fire on, **and** a negative case it must not. Real `terraform show -json`
   output is best.

3. **Run the tests**: `make test`. The loader validates every rule has a valid
   `source` and unique id; provenance and the rule set are covered by tests.

### Rule conventions (learned the hard way)

- **Null vs absent.** A real plan renders an *unset* optional field as `null`,
  not absent. So `(!has(x) || x == false)` silently fails to fire when `x` is
  `null`. Prefer `(!has(x) || x != true)` for optional booleans.
- **Guard with `has(...)`** before reading any `before`/`after` field — a rule
  that errors on a resource is treated as "no match", so missing guards hide bugs.
- **Provenance is required.** `source: trivy` needs an `avd:`; `source: custom`
  must have no `avd:`.
- Helpful CEL functions: `parse_json`, `as_list`, `hits_sensitive_port`,
  `ports_hit_sensitive` (see [internal/rules/celfuncs.go](internal/rules/celfuncs.go)).

You can also test rules against real anti-pattern repos with
`make corpus` (needs `terraform` on PATH) — see
[tools/corpus/README.md](tools/corpus/README.md).

## Code style

- `gofmt` is enforced by the pre-commit hook; run `make fmt` if needed.
- Keep the deterministic core free of the TUI / enrich packages (they're outer
  shells). The engine must never import them.

## Commits & PRs

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `ci:`, …) — the release changelog is generated from them.
- Open a PR against `main` with tests green. CI runs build/test, CodeQL, and
  govulncheck.

## Security

Please **do not** open a public issue for security vulnerabilities. Use private
disclosure as described in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree your contributions are licensed under the
[Apache-2.0](LICENSE) license.
