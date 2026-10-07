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
sudo pacman -S pre-commit
yay -Sy semgrep-bin
pipx install semgrep
pipx install detect-secrets
yay -S golangci-lint
```

#### macOS

```sh
brew install pre-commit semgrep detect-secrets golangci-lint
```

### Pre-commit hook

#### Install

```sh
pre-commit install
```

This installs both the `pre-commit` hooks (semgrep, detect-secrets, golangci-lint) and a `commit-msg` hook that checks commit messages with [commitizen]. Messages must follow the [commitizen commit guide][commitizen writing commits], e.g. `fix(make): correct build-dev target name`.

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

Releases are done using the GoReleaser [GitHub action][GoReleaser GitHub action] when a new tag is added.

Example:

```sh
git tag -s -m "Release vN.N.N" vN.N.N HEAD
git push --tags
```

## More information

* [pre-commit]
* [Semgrep]
* [commitizen]
* [detect-secrets]
* [GoReleaser]
* [GoReleaser GitHub action]


[Semgrep]: https://semgrep.dev/
[commitizen]: https://commitizen-tools.github.io/commitizen/
[commitizen writing commits]: https://commitizen-tools.github.io/commitizen/tutorials/writing_commits/
[pre-commit]: https://pre-commit.com/
[detect-secrets]: https://github.com/Yelp/detect-secrets
[GoReleaser]: https://goreleaser.com/
[GoReleaser GitHub action]: https://github.com/goreleaser/goreleaser-action
[OWASP Secure Headers Project]: https://owasp.org/www-project-secure-headers/
[OWASP HTTP Security Response Headers Cheat Sheet]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
[OWASP Secure Headers Project validator]: https://github.com/oshp/oshp-validator?tab=readme-ov-file
