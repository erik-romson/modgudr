---
title: "Sandbox test runs hide socket-backed failures; only the unsandboxed run counts as proof"
date: 2026-11-08
category: workflow-issues
module: tests
problem_type: workflow_issue
component: testing_framework
severity: medium
applies_when:
  - "Changing tests that need a broker Unix socket, or that inspect source files of the code under test"
  - "Running the test suite inside the agent sandbox and planning to rely on the result"
  - "Moving a checkout to a new path while pytest caches still exist"
tags:
  - sandbox
  - testing
  - skipped-tests
  - pytest
  - pycache
  - validation
  - workflow
---

# Sandbox test runs hide socket-backed failures; only the unsandboxed run counts as proof

## Context

The modgudr test suite has two kinds of tests that matter for agent work. Socket-backed tests need to bind a Unix socket to a broker. The agent sandbox refuses those binds, so this run concluded that most of those tests skip there. Step 02 added `tests/support/sandbox.py`, which reports a test the sandbox blocks (a refused bind, for instance) as skipped instead of failed, plus `skipif` marks where that report hook cannot tell. A green sandbox run therefore says little about the broker-backed behaviour.

## Guidance

- Treat a sandbox run as a partial check. In the final review, 160 tests passed and 123 were skipped as sandbox-blocked. The socket tests, the broad suite and bats only ran outside the sandbox.
- Before relying on a change that touches broker-backed behaviour, run the suite outside the sandbox. In this run, the failure in `tests/unit/client/test_agent_setup.py` only appeared in the test run that could execute the broker-backed scenarios, and the broad suite's failure in `tests/integration/broker/test_server.py` appeared only in the pipeline's full run.
- When a test inspects source text (for example, a probe that looks for a `bind(` line in the module it tests), a stale `__pycache__` from an older checkout path can make it fail. The run saw this in two probe tests. The workaround this run used was `PYTHONPYCACHEPREFIX` pointed at a temporary directory, together with `UV_CACHE_DIR` pointed at a temporary directory, so that no cache from the old path is read. Its clean rerun gave 2095 passed, 454 skipped, 0 failed.
- Do not treat a skip count as coverage. Report which scenarios skipped and why, and say which command has yet to run.

## Why This Matters

A sandbox run that reports green can look like full verification while the broker-backed scenarios were skipped. Step 03's first attempt failed a test that a sandbox run would have skipped. The run concluded that a reviewer who only saw the sandbox result would not have known the change was untested. Stale cache failures look like product bugs and can send a fix in the wrong direction. This run also concluded that the timing fix in the broad suite (raising a `delayMs` from 100 to 500) reduced the odds of a race but did not remove it, so the outside run remains the only proof. The first outside run after the plan then failed `test_the_cache_serves_when_the_broker_is_gone` once: on a busy machine the stub broker missed the hook's 0.3 s timeout, and the hook failed open. Every rerun passed, and the hook tests now give the stub broker 5 s. A socket test with a real-time deadline can be flaky, and only the outside run shows it.

## When to Apply

- Before reporting a change to socket-backed tests as verified.
- After moving or copying a checkout, when tests that read source files fail with missing-line errors.
- When a validation step is summarised, so the report names the scenarios that were skipped.

## Examples

- Sandbox result: 160 passed, 123 skipped (sandbox-blocked). Report it as "unit and contract tests pass in the sandbox; socket scenarios are unverified until `sh scripts/check.sh` runs outside the sandbox."
- Stale cache: rerun with `PYTHONPYCACHEPREFIX=$TMPDIR/pyc` and `UV_CACHE_DIR=$TMPDIR/uvc` before deciding that the probe itself is broken.

## Related

none
