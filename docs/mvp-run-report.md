# modgudr MVP run report

## Deviations

- **Step 06, the `maxConcurrent` row "a fourth that would be denied → `throttled`".** The row comes from edge case
  EN-08, which assumed the pre-plan's throttle-first order (§7.5). M6 fixes the order as classify and decide
  (step 4) before the slot (step 5), and a denial returns at step 4. The broker follows M6: a call that phase 1
  denies gets `denied` (exit 2) even while every slot is taken, and it never holds a slot. A call that phase 1
  allows but that would fail only after the slot (at M6 step 7, here a secret missing from the store) gets
  `throttled` (exit 7) with `retryAfter`. `tests/integration/broker/test_server.py` asserts both
  (`test_max_concurrent_throttles_without_queueing_and_never_leaks`).
