# modgudr MVP run report

## Deviations

- **Step 06, the `maxConcurrent` row "a fourth that would be denied → `throttled`".** The row comes from edge case
  EN-08, which assumed the pre-plan's throttle-first order (§7.5). M6 fixes the order as classify and decide
  (step 4) before the slot (step 5), and a denial returns at step 4. The broker follows M6: a call that phase 1
  denies gets `denied` (exit 2) even while every slot is taken, and it never holds a slot. A call that phase 1
  allows but that would fail only after the slot (at M6 step 7, here a secret missing from the store) gets
  `throttled` (exit 7) with `retryAfter`. `tests/integration/broker/test_server.py` asserts both
  (`test_max_concurrent_throttles_without_queueing_and_never_leaks`).
- **Step 07, step 06 tests changed beyond the unlock seam.** Step 07's "done when" allows step 06 tests to change
  only where the test-only unlock seam was replaced. Three changed for other reasons that step 07's own rules force:
  - `test_auth_failure_is_upstream_then_the_next_open_works` expected the second login to succeed after a failed
    one with an unchanged secret. M8 forbids that: an unchanged value is not retried and the target is latched for
    5 minutes. The test is now `test_auth_failure_is_upstream_and_latches_the_target`, and the completion's `stage`
    is `login`.
  - `test_admin_ops_on_human_sock_have_no_handler_yet` now covers only `audit-tail` and `login-info`, because
    `unlock` and `lock` have handlers.
  - `test_dev_mode_banner_and_stamps` expects six records instead of four: the `unlock` record (M9) and the `lock`
    record with reason `shutdown` (M7) that an unlocked broker writes when it stops.
- **Step 07, malformed `modgudr-` note lines refuse the secret.** M8 says note lines other than the strict
  `modgudr-hosts:`/`modgudr-env:` forms are ignored with a warning. A line that starts with `modgudr-` but is not a
  strict form (wrong case, indented, an unknown `modgudr-` key, two environment names) refuses the secret instead
  (`denied`, layer `pinning`, rule `note`). Otherwise a mistyped `modgudr-env` line would be dropped silently and
  the secret would lose its environment pin, which widens access. AGENTS.md makes parse failures refusals. Other
  lines are still ignored with a warning. In the same spirit, a `modgudr-hosts` value with a scheme, userinfo or
  path "is rejected" by refusing the secret, never by dropping that one value. The message never repeats the value,
  because userinfo may hold a password.
