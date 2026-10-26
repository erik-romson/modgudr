# To do

Small fixes and improvements that came up while using modgudr. Larger plans live in
`future-plans.md`.

## `agent-setup`: keep the allowed domains when adding one

`modgudr agent-setup claude --allow-domain D` replaces the default list instead of adding to it. To
allow one more domain, a developer has to retype every domain that the installed drop-in already
allows, and a forgotten domain silently disappears.

The generator should read `allowedDomains` from the installed drop-in and keep them. A separate flag
such as `--remove-domain` would then take one away. The install notes should also print the
difference between the installed drop-in and the new one, so the developer can review the change
before running `sudo`.

## `agent-setup`: domain presets for GitHub and Maven

GitHub now redirects release downloads to `release-assets.githubusercontent.com`. A developer who
allows `github.com` expects downloads to work, but they fail until someone finds the second host.
The `readable` skill hit this when uv fetched a spaCy model.

Presets would name every host that one service needs. For example, `--allow-preset github` would
add `github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com` and
`release-assets.githubusercontent.com`. A `maven` preset would add `repo.maven.apache.org` and
`repo1.maven.org`.

## The uv cache inside the sandbox

The sandbox cannot write to `~/.cache/uv`, so `uv run` fails with "Operation not permitted". Setting
`UV_CACHE_DIR` to a directory under `$TMPDIR` works around it.

We should not let the sandbox write to `~/.cache/uv`. The developer runs uv from that cache outside
the sandbox, so an agent that could write there could plant code that the developer later runs.
Instead, `modgudr agent run claude` should set `UV_CACHE_DIR` to a cache that only the agent uses,
and `modgudr doctor --agent claude` should report when that variable is missing.
