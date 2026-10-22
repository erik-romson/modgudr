---
title: "uv tool install --with does not put the extra packages' commands on the PATH"
date: 2026-10-22
category: integration-issues
module: dist
problem_type: integration_issue
component: tooling
severity: high
symptoms:
  - "After running the installer, `modgudr` is not found on the PATH"
  - "The short alias created by the installer points at a missing binary"
  - "The bats test passed but the installed command was absent"
root_cause: incomplete_setup
resolution_type: code_fix
tags:
  - uv
  - installer
  - console-scripts
  - packaging
  - pathing
---

# uv tool install --with does not put the extra packages' commands on the PATH

## Problem

`dist/install-l0.sh` installed the broker as a uv tool with the client added through `--with`:

`uv tool install --from "$REPO/packages/broker" modgudr-broker --with modgudr-client ...`

This was meant to leave both `modgudr` and `modgudr-broker` in the bin directory. It did not. The run concluded that, with the uv 0.7.19 version this repo uses, `uv tool install` links only the executables of the named tool. Packages added with `--with` go into the tool environment, but their console scripts are not linked into the bin directory.

## Symptoms

- After `sh dist/install-l0.sh`, the README quick start and the installer's own "NEXT" notes (`modgudr unlock`, `modgudr status`, `modgudr agent-setup claude`) fail with `command not found`.
- The short alias the installer links to `modgudr` in `$BIN` is dangling.
- `uv` printed `Installed 1 executable: modgudr-broker`, which was the only sign of the problem.
- The bats test used a fake `uv` and only checked the printed install line, so it passed.

## What Didn't Work

- Relying on `--with` to expose the client's `modgudr` command. The command existed only inside the broker's tool environment under `UV_TOOL_DIR`, not in `$BIN`.
- Trusting the bats test. It asserted the command line that was printed, not the result on disk, so the defect was invisible to it.
- Leaving the non-dry-run install unexercised. The run report said so, and that gap hid the defect until a review ran the exact `uv tool install` line against a temporary `UV_TOOL_DIR` and `UV_TOOL_BIN_DIR`.

## Solution

Install the client as its own uv tool, so its executable is linked into `$BIN`. The fix is a second command in `dist/install-l0.sh`:

`run uv tool install --from "$REPO/packages/client" modgudr-client`

The short alias is created only after `modgudr` is in `$BIN`. The broker install stays unchanged, so `modgudr-broker` is still linked. The bats test and the unit test in `tests/unit/test_dist_examples.py` now assert that both install lines are printed. The unit test also asserts that the alias comes after the client install.

The review confirmed the fix by running the client install line with `UV_TOOL_DIR` and `UV_TOOL_BIN_DIR` in a temporary directory. uv printed `Installed 1 executable: modgudr`, and the linked binary ran `--help`.

## Why This Works

`uv tool install` exposes the executables of the package it is given. Each tool gets its own environment, and only that package's scripts are linked into the bin directory. The client has no dependencies beyond the standard library, so a separate tool environment costs nothing. Giving it its own install makes the link explicit instead of relying on a side effect of `--with`.

## Prevention

- When a script must put a command on the PATH, check the linked binary in the bin directory after the install, not only the printed install line.
- Do not use `uv tool install --with` to expose a command from an extra package. Install that package as its own tool.
- Run the non-dry-run install by hand once before relying on it. A fake `uv` cannot show what gets linked.
- The bats and unit tests for the installer must fail if a required install line is missing.

## Related

none
