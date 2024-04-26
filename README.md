# HTTP Headers Auditor

Check HTTP headers of a running service against a baseline. Like most auditors this is an opinionated tool.

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

## Local development

### Install requirements

#### Arch

```sh
sudo pacman -S pre-commit
yay -Sy semgrep-bin
pipx install detect-secrets
```

#### macOS

```sh
brew install pre-commit semgrep detect-secrets
```

### Pre-commit hook

#### Install

```sh
pre-commit install
```

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
* [detect-secrets]
* [GoReleaser]
* [GoReleaser GitHub action]


[Semgrep]: https://semgrep.dev/
[pre-commit]: https://pre-commit.com/
[detect-secrets]: https://github.com/Yelp/detect-secrets
[GoReleaser]: https://goreleaser.com/
[GoReleaser GitHub action]: https://github.com/goreleaser/goreleaser-action
