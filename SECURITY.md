# Security policy

`hhaudit` is a CLI that sends HTTP requests to user-supplied URLs and prints
the untrusted response headers it gets back, so bugs in it can have security
impact. Please report them privately.

## Supported versions

Only the latest release and the latest commit on `main` are supported. Fixes
land on `main` and ship in the next release; older releases are not patched.

## Reporting a vulnerability

Use GitHub's private reporting:
**[Report a vulnerability](https://github.com/vernazxx/hhaudit/security/advisories/new)**
(Security tab → *Report a vulnerability*).

Please don't open a public issue or pull request for a vulnerability.

Include what you can:

- the affected version (`hhaudit -version`) or commit SHA
- steps to reproduce, ideally a minimal `httptest` server or response that
  triggers it
- the impact you observed

This is a one-person project. I aim to acknowledge reports within 7 days and
will keep you updated in the advisory until it's fixed or closed. I'm happy to
credit you in the advisory unless you prefer otherwise.

## Scope

In scope:

- server-side request forgery beyond what the user asked for, such as
  following redirects to non-`http(s)` schemes or past the redirect limit
- requests that hang without a timeout, or send credentials or cookies
- terminal escape or control-character injection through header names or
  values printed by the tool
- TLS verification being skipped without an explicit opt-in
- an audit reporting a header as passing when it doesn't meet the baseline
- weaknesses in the release pipeline or published artifacts (workflows,
  GoReleaser configuration, pinned actions and tools)

Out of scope, please report upstream:

- vulnerabilities in Go, GoReleaser, opengrep, zizmor, golangci-lint or other
  third-party tools and actions
- findings about the sites you audited with `hhaudit`
