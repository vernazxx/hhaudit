# HTTP Headers Auditor
Check HTTP headers of a running service against a baseline. Like most auditors this is an opinionated tool.

## Local development

### Install requirements

#### Arch

```shell
sudo pacman -S pre-commit
yay -Sy semgrep-bin
pipx install detect-secrets
```

#### macOS

```shell
brew install pre-commit semgrep detect-secrets
```

### Pre-commit hook

#### Install

```shell
pre-commit install
```

#### Run

```shell
pre-commit run
```

### Running detect-secrets on-demand

>detect-secrets is an aptly named module for (surprise, surprise) detecting secrets within a code base.

Source: [detect-secrets][]

#### Create a baseline

```shell
detect-secrets scan > .secrets.baseline
```

#### Run an audit against the baseline

```shell
detect-secrets audit .secrets.baseline
```

#### Run an audit for all tracked files against the current baseline

```shell
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
```

#### Update the baseline

```shell
detect-secrets scan --baseline .secrets.baseline
```

## More information

* [pre-commit][]
* [Semgrep][]
* [detect-secrets][]


[Semgrep]: https://semgrep.dev/
[pre-commit]: https://pre-commit.com/
[detect-secrets]: https://github.com/Yelp/detect-secrets

