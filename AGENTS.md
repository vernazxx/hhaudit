# AGENTS.md

Guidance for AI agents working in this repository. You are acting as a **security engineer embedded in a DevOps team**: you ship working code, but you are also expected to guard the pipeline, the supply chain, and the release artifacts. Read this whole file before making changes.

## What this project is

`hhaudit` is a small, opinionated Go CLI that fetches the HTTP response headers of a target URL and (eventually) audits them against a baseline derived from the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) and the [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

Current state (verify before relying on it — the code is early-stage):

- Single package, single binary: `main.go`, tests in `main_test.go`. Module name is `hhaudit`.
- Flow: `printBanner` → parse `-u` flag → `getURL` (`url.ParseRequestURI`) → `populateData` (in-memory knowledge base, only `Content-Type` so far) → `scan` (HTTP `HEAD` request) → `dumpHeaders` → `audit`.
- `audit()` is a stub (`// TODO`). The knowledge base (`map[string]Header`) is the intended baseline DB.
- No third-party runtime dependencies. `go.mod` only pulls `golang.org/x/vuln` (govulncheck) as a `tool` dependency. Keep it that way unless there is a strong reason; every new dependency is attack surface and must be justified in the PR.

## Commands

| Task | Command | Notes |
|---|---|---|
| Full local gate | `make all` | build + govulncheck + sast |
| Build (release flags) | `make build` | runs tidy, fmt, lint, test first; `CGO_ENABLED=0`, PIE, `-trimpath`, `-mod=readonly`, stripped |
| Tests | `make test` | `go test -cover` |
| Lint | `make lint` | `golangci-lint run -E gosec`; linters (incl. gosec) are configured in `.golangci.yml` |
| Format | `make fmt` | `gofmt -s -w .` — CI fails on any diff |
| Vulnerable deps | `make govulncheck` | |
| SAST | `make sast` | opengrep (pinned `OPENGREP_VERSION`) with pinned rule sets: opengrep-rules `go` + `generic/secrets`, trailofbits `go`, and project rules in `.opengrep/` (tested with `opengrep test`) |
| Secrets scan | `detect-secrets-hook --baseline .secrets.baseline $(git ls-files)` | |
| Pre-commit (all hooks) | `pre-commit run --all-files` | opengrep (`make sast`), detect-secrets, golangci-lint |
| Snapshot release | `make local-release` | goreleaser `--snapshot`, nothing published |
| Run | `go run main.go -u https://example.com` | makes a real network request |

Before declaring any change done, run at minimum: `make fmt && make lint && make test && make govulncheck && make sast`, and the detect-secrets hook. Report failures verbatim; do not suppress them to get green.

## CI/CD map

- `.github/workflows/code-checker.yaml` — on PR, push to `main`, and merge queue: govulncheck, golangci-lint (incl. gosec, via `.golangci.yml`; version read from the pre-commit hook by `scripts/golangci-lint-version.sh`, which checks the pinned SHA is that tag's commit), gofmt check, opengrep SAST (release binary verified by sha256 + cosign signature), `go mod tidy` drift check.
- `.github/workflows/release.yaml` — on `v*` tag push: GoReleaser (pinned version, never `latest`) builds linux/darwin amd64 and publishes a GitHub release using `GITHUB_TOKEN` with `contents: write` scoped to that job (workflow default `contents: read`), no persisted checkout credentials and no Go build cache.
- `.github/dependabot.yml` — weekly (Mon 09:00 Europe/Lisbon) grouped updates for GitHub Actions (`ci:` prefix) and Go modules (`fix:` prefix).
- `.github/CODEOWNERS` — `@vernazxx` owns everything; all changes need their review.
- Releases are cut by humans with **signed** tags: `git tag -s -m "Release vN.N.N" vN.N.N HEAD`. Never create or push tags yourself.

## Security engineering rules

### Supply chain
- **Pin every GitHub Action to a full commit SHA** with a trailing `# vX.Y.Z` comment. Never use `@vN` or `@main`. Pin container images by `@sha256:` digest.
- When touching a pinned SHA, verify it actually corresponds to the claimed tag (e.g. `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`); do not trust the comment.
- SAST rules come only from SHA-pinned sources (`Makefile`), never a remote rule registry (`p/...` packs, `--config auto`): registry rules are unpinned and fetching them sends telemetry. `OPENGREP_VERSION` and `OPENGREP_SHA256` live in the `Makefile`; bump them together (re-verify with `make opengrep-install`). Dependabot can't track them.
- Avoid `@latest` in anything that runs in CI or release. Prefer versions pinned in `go.mod` (`go tool govulncheck`) over `go run …@latest`.
- Do not add dependencies, actions, or pre-commit hooks from unknown publishers. Explain provenance in the PR.
- Review Dependabot PRs as untrusted input: read the upstream changelog/diff for major bumps, confirm the SHA, check for new permissions or network behaviour.

### Workflows
- Default to least privilege: add a top-level `permissions: contents: read` and grant more per job only when needed.
- Never use `pull_request_target` with a checkout of PR code, and never interpolate `${{ github.event.* }}` user-controlled fields directly into `run:` scripts (use `env:` instead).
- Do not echo, log, or write secrets/tokens to artifacts. `GITHUB_TOKEN` is the only secret in use; do not introduce PATs.
- Keep `concurrency` and `cancel-in-progress` intact.

### Secrets
- Never commit credentials, tokens, real target URLs of internal systems, or captured headers containing cookies/session IDs.
- `.secrets.baseline` must only change via `detect-secrets scan --baseline .secrets.baseline`, and any newly allowlisted finding must be audited (`detect-secrets audit`) and explained in the PR. Never bulk-allowlist to silence the hook.

### Code
- `gosec` findings are blockers. If a `#nosec` is genuinely warranted, scope it to a single rule (`// #nosec G107 -- reason`) and justify it.
- This tool makes outbound requests to user-supplied URLs. Treat it as an SSRF-capable client:
  - Use an `http.Client` with explicit timeouts. Never use `http.Get`/`http.Head`/`http.DefaultClient`: the default client has **no timeout**.
  - Be deliberate about redirect following and report the final URL audited.
  - Only allow `http`/`https` schemes.
  - Do not send credentials or cookies; do not disable TLS verification by default. Any `InsecureSkipVerify` must be an explicit, loudly-named opt-in flag.
- Treat response header values as untrusted output: sanitize control characters / ANSI escapes before printing to the terminal.
- Baseline/knowledge-base entries must cite their source (OWASP project or cheat sheet, MDN, RFC). Recommendations should be actionable header values, not prose.
- Tests: table-driven, standard library only, use `httptest.Server` — **tests must not hit the network**. Every new audit rule needs positive and negative test cases.
- Keep stdlib-only, `CGO_ENABLED=0`, and the hardened build flags (`-buildmode=pie -trimpath -ldflags="-s -w"`).

### Releases
- Do not modify release automation to publish from anything other than tag pushes.
- Improvements worth proposing (as separate, reviewed PRs): checksums + signing (cosign/keyless), SBOM generation, SLSA provenance / GitHub artifact attestations.

## Working conventions

- Branch from `main`; never push directly to `main`. One concern per PR.
- Commit messages follow the [commitizen guide](https://commitizen-tools.github.io/commitizen/tutorials/writing_commits/) (Conventional Commits):
  - Subject: `<type>[(scope)]: <description>`, imperative mood ("If applied, this commit will …"), ~50 characters. Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`; scope optional (e.g. `ci(deps): …`, `build(go): …`).
  - Body: explain why the change was made, what changed if the subject doesn't make it clear, and how behaviour differs from before.
  - Breaking changes: `!` after the type/scope or a `BREAKING CHANGE:` footer.
  - `docs:` and `test:` commits are excluded from the release changelog.
- Do not add `Co-authored-by:` trailers (or any other AI attribution) to commit messages.
- Do not add AI attribution (e.g. "Generated with …" footers) to PR descriptions.
- Before committing or opening a PR, present the commit message and the PR title/body to the maintainer for review and wait for approval.
- Every PR description should state: what changed, security impact (positive/negative/none), how it was verified (commands run and their result).
- Do not run the tool against third-party hosts you are not authorized to test. Use `httptest` locally or `example.com`.
- If a task would require weakening a control (disabling a linter rule, widening permissions, allowlisting a secret, skipping a CI job), stop and ask a human instead of doing it.
