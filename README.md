# HTTP Headers Auditor

Check HTTP headers of a running service against a baseline. Like most auditors this is an opinionated tool.

An excellent reference followed through out the development of this tool is [OWASP Secure Headers Project]. If you haven't heard about it you should check it out.

Other projects with similar goals as `hhaudit`:

* [OWASP Secure Headers Project validator]

## Usage

If you want to see if the tool is working, just run it.

```sh
 __     __                   __ __ __
|  |--.|  |--.---.-.--.--.--|  |__|  |_
|     ||     |  _  |  |  |  _  |  |   _|
|__|__||__|__|___._|_____|_____|__|____|

:: Audit those HTTP headers ::

Usage of bin/hhaudit:
  -u string
        The URL of the target website to audit (default "http://example.com")
```

### As a library

All functionality lives in the `audit` package; `main.go` is only the CLI entrypoint.

```sh
go get github.com/vernazxx/hhaudit/audit
```

```go
import "github.com/vernazxx/hhaudit/audit"

target, err := audit.ParseTarget("https://example.com")
if err != nil {
	return err
}
client, err := audit.NewClient(audit.DefaultTimeout, audit.DefaultMaxRedirects)
if err != nil {
	return err
}
res, err := audit.Scan(ctx, client, target)
if err != nil {
	return err
}
fmt.Println("Final URL:", res.Final)
err = audit.DumpHeaders(os.Stdout, res.Header) // sanitizes control characters
```

Inputs are validated at every entry point; invalid input returns errors you can match with `errors.Is` (`audit.ErrUnsupportedScheme`, `audit.ErrNoHost`, `audit.ErrNilClient`, `audit.ErrNilTarget`, `audit.ErrNilWriter`, `audit.ErrInvalidOption`).

## Local development

### Install requirements

#### Arch

```sh
sudo pacman -S pre-commit cosign
pipx install detect-secrets
yay -S golangci-lint
```

#### macOS

```sh
brew install pre-commit cosign detect-secrets golangci-lint
```

#### opengrep

SAST runs [opengrep] at the version pinned in the `Makefile` (`OPENGREP_VERSION`, `OPENGREP_SHA256`). On Linux x86_64, install it with:

```sh
make opengrep-install            # downloads, checks sha256 + cosign signature
export PATH="$HOME/.cache/hhaudit/opengrep-v1.30.1:$PATH"
```

On other platforms, download the matching asset of that release and verify it the same way as `scripts/install-opengrep.sh` (`cosign verify-blob` with certificate identity `https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-<version>` and issuer `https://token.actions.githubusercontent.com`).

`make sast` fetches the rule sets at pinned commits into `~/.cache/hhaudit/sast-rules/`, runs the tests for the project rules in `.opengrep/`, and scans the repository.

### Pre-commit hook

#### Install

```sh
pre-commit install
```

This installs both the `pre-commit` hooks (opengrep via `make sast`, detect-secrets, golangci-lint) and a `commit-msg` hook that checks commit messages with [commitizen]. Messages must follow the [commitizen commit guide][commitizen writing commits], e.g. `fix(make): correct build-dev target name`.

#### Run

```sh
pre-commit run
```

### Running detect-secrets on-demand

>detect-secrets is an aptly named module for (surprise, surprise) detecting secrets within a code base.

Source: [detect-secrets][]

#### Create a baseline

```sh
detect-secrets scan > .secrets.baseline
```

#### Run an audit against the baseline

```sh
detect-secrets audit .secrets.baseline
```

#### Run an audit for all tracked files against the current baseline

```sh
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
```

#### Update the baseline

```sh
detect-secrets scan --baseline .secrets.baseline
```

## Build

To create the tool binary, run:

```sh
make build
```

## Releases

Releases are done using the GoReleaser [GitHub action][GoReleaser GitHub action] when a `v*` tag is pushed. Cut one from an up-to-date, clean `main` with:

```sh
make release VERSION=vN.N.N
```

This checks the version format, that you're on `main` at `origin/main` with no uncommitted changes, and that the tag doesn't exist yet. It then runs the full local gate (`make all`), creates a signed tag, verifies the signature, asks for confirmation, and pushes only that tag. Expect three key touches with a hardware signing key: fetching, signing and pushing. Answering anything but `y` deletes the local tag and pushes nothing.

Don't use `git push --tags`: it pushes every local tag, and each `v*` tag starts a release.

## More information

* [pre-commit]
* [opengrep]
* [commitizen]
* [detect-secrets]
* [GoReleaser]
* [GoReleaser GitHub action]


[opengrep]: https://github.com/opengrep/opengrep
[commitizen]: https://commitizen-tools.github.io/commitizen/
[commitizen writing commits]: https://commitizen-tools.github.io/commitizen/tutorials/writing_commits/
[pre-commit]: https://pre-commit.com/
[detect-secrets]: https://github.com/Yelp/detect-secrets
[GoReleaser]: https://goreleaser.com/
[GoReleaser GitHub action]: https://github.com/goreleaser/goreleaser-action
[OWASP Secure Headers Project]: https://owasp.org/www-project-secure-headers/
[OWASP HTTP Security Response Headers Cheat Sheet]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
[OWASP Secure Headers Project validator]: https://github.com/oshp/oshp-validator?tab=readme-ov-file
