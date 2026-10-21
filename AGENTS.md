# modgudr

A local secret broker for coding agents and scripts. Python 3.12+, uv workspace under packages/.

- Run everything through uv: `uv sync --locked`, `sh scripts/check.sh <pytest args>` (ruff, pyright, pytest).
- No fallbacks. Fail closed: unknown keys, parse failures and missing pins are refusals.
- Never touch real credentials or config (~/.kube, ~/.azure, keychain, Bitwarden, ~/.claude). Tests use the fakes
  in tests/fixtures/bin and short temp dirs from tests/support/shortdir.py.
- The command is `modgudr`, never `mg` (/usr/bin/mg is an editor on macOS).
- No company hostnames, users or policies in this repository (it is public, Apache-2.0).
