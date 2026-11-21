# HTTP Headers Auditor

Check HTTP headers of a running service against a baseline. Like most auditors this is an opinionated tool.

An excellent reference followed through out the development of this tool is [OWASP Secure Headers Project]. If you haven't heard about it you should check it out.

Other projects with similar goals as `hhaudit`:

* [OWASP Secure Headers Project validator]

## Usage

Pass the URL to audit with `-u`. With no flags it audits `http://example.com`.

```sh
hhaudit -u https://example.com
```

It prints a banner, the target and the final URL after redirects, then the response headers, sorted and with control characters replaced.

```console
$ hhaudit -h
Usage of hhaudit:
  -u string
    	The URL of the target website to audit (default "http://example.com")
  -version
    	Print version information and exit
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
export PATH="$HOME/.cache/hhaudit/opengrep-v1.33.1:$PATH"
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

### Verifying a release

Each release includes `hhaudit_X.Y.Z_checksums.txt` and a keyless [cosign] signature bundle for it, `hhaudit_X.Y.Z_checksums.txt.sigstore.json`. The signature is tied to this repository's release workflow running for that tag, and is recorded in Sigstore's public transparency log. Download the archive, the checksums file and the bundle, then run the commands below. They need cosign v3 or later, which reads this bundle format by default:

```sh
cosign verify-blob \
  --bundle hhaudit_X.Y.Z_checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/vernazxx/hhaudit/.github/workflows/release.yaml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  hhaudit_X.Y.Z_checksums.txt
sha256sum --ignore-missing -c hhaudit_X.Y.Z_checksums.txt
```

Both commands must succeed. The first proves the checksums file came from the release workflow; the second proves your archive matches it.

## More information

* [pre-commit]
* [opengrep]
* [commitizen]
* [detect-secrets]
* [GoReleaser]
* [GoReleaser GitHub action]
* [cosign]


[opengrep]: https://github.com/opengrep/opengrep
[commitizen]: https://commitizen-tools.github.io/commitizen/
[commitizen writing commits]: https://commitizen-tools.github.io/commitizen/tutorials/writing_commits/
[pre-commit]: https://pre-commit.com/
[detect-secrets]: https://github.com/Yelp/detect-secrets
[GoReleaser]: https://goreleaser.com/
[GoReleaser GitHub action]: https://github.com/goreleaser/goreleaser-action
[cosign]: https://docs.sigstore.dev/cosign/signing/overview/
[OWASP Secure Headers Project]: https://owasp.org/www-project-secure-headers/
[OWASP HTTP Security Response Headers Cheat Sheet]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
[OWASP Secure Headers Project validator]: https://github.com/oshp/oshp-validator?tab=readme-ov-file
