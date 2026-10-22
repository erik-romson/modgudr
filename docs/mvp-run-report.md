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
- **Step 09, `sqlglot` is forced to 30.24.0 for fakesnow too.** M12 pins `sqlglot==30.24.0` exactly (30.23 is the
  floor for Oracle `q'…'` literals). `fakesnow`, already in the dev group for step 10, declares
  `sqlglot>=30.22.0,<30.23` in its newest release (0.11.22), so the workspace did not resolve. The root
  `pyproject.toml` now sets `[tool.uv] override-dependencies = ["sqlglot==30.24.0"]`, and `uv.lock` records the
  override. fakesnow therefore runs on a sqlglot it does not declare. A throwaway smoke run outside the repository
  (fakesnow 0.11.22, `snowflake-connector-python` 4.8.0, sqlglot 30.24.0) passed: `paramstyle="numeric"` binds, a
  VARIANT path with a cast, `UPDATE` `rowcount`, rollback and `information_schema`. Step 10's fakesnow suite is the
  real check. Remove the override once a fakesnow release accepts sqlglot 30.24.
- **Step 16, Oracle sessions come from the connector's pool, not `oracledb.create_pool`.** M16 says
  `create_pool(min=0, max=maxConcurrent, timeout=300)`. The `sql` connector already pools sessions per target with
  the same bounds (at most `maxConcurrent`, idle 300 s), and every login must go through `Secrets.login`, so that
  the M8 latch, the single flight and "authentication fails only while connecting" hold. An `oracledb` pool would log
  in on its own, outside that path. The driver opens standalone thin connections with
  `oracledb.connect(params=ConnectParams(...), password=...)`. The tags (`module`, `action`, `client_identifier`)
  and `current_schema` are reset before the closing rollback or commit of every call.
- **Step 16, `TIMESTAMP WITH TIME ZONE` does not keep its offset.** M16 says it does. python-oracledb 26.0.1 in thin
  mode returns a naive `datetime` (the wall clock of the value's own zone) for `TIMESTAMP WITH TIME ZONE` and `WITH
  LOCAL TIME ZONE`, and an output type handler to `VARCHAR` converts on the client with the same loss. Getting the
  offset would mean rewriting the caller's SQL, which M12 forbids (the executed text is the classified text). The
  wire therefore carries these columns as `timestamp` (ISO wall clock, no offset), never as `timestamp_tz` with an
  offset it does not have. `tests/integration/oracle/test_types.py` asserts this.
- **Step 16, the container publishes the listener with `-p 127.0.0.1::1521`, not `-P`.** The `gvenzl/oracle-free`
  image declares no `EXPOSE`, so `docker run -P` publishes nothing. The fixture maps the listener to a random port
  on 127.0.0.1 only.
- **Step 16, a LOB limit is named in the audit record, not on the wire.** The trailer has no field for it (M4), so
  the completion record carries `limit` ("column 'C' holds at least N bytes, more than the M left of maxBytes").
- **Step 16, `describe` on Oracle returns the columns of a `select … where 1 = 0`.** The header carries the names
  and wire types and there are no rows. The `describe` op contract accepts a `select` as well as a `describe`
  statement for it.
- **Step 17, `kubectl cp` is a plugin invariant, not only `admin`.** M17 classes `cp` as admin, which an
  admin-ceiling environment could allow. `cp` always has a local side, and the broker runs kubectl as the
  developer: `cp ~/.azure/… pod:/tmp` would hand the agent the developer's Azure refresh token or prod
  kubeconfig, and `cp pod:/x ~/…` would write the developer's files. That is the reason M17 gives for refusing
  path-taking flags. The classifier still returns `kubectl:cp/pods` with risk `admin`, and the connector's
  invariant rule `kubectl:cp/*` refuses it at layer `plugin-invariant` in every environment.
- **Step 17, every kubectl call that names `secrets` is `secret`.** M17 names `get`/`describe` of secrets and
  "any list containing `secrets`". The classifier applies it to every verb (`delete secret x`,
  `create secret …`, `label secret x … -o yaml`, `logs secret/x`, `explain secrets`), because a write that
  prints the object (`-o yaml`) shows its data. These calls are never allowed.
- **Step 18, a failed process's exit code rides on the `error` frame.** M5 puts the raw exit code of a failed
  `kubectl` "in the trailer", but M4 says an error line replaces the trailer. The `error` frame of a failed call
  therefore carries `exitCode` when the connector reported one, the message says "kubectl exited with code N", and
  the completion record has `exitCode` as well.
- **Step 18, `az rest` also gets `-o json`.** M18's endpoint command has no output flag. In the `borrowed` tier
  `az` reads the developer's own `~/.azure/config`, whose `core.output` may be `table` or `yaml`, which the parser
  would refuse. `-o json` pins the format, as M18 already does for `az account get-access-token`.
- **Step 18, `--allow-truncated` on the `kubectl` op.** The client decides per operation whether an op is a read
  (an op without `--dry-run`), and the `kubectl` passthrough op is classified per call. So `--allow-truncated` also
  turns a timed-out kubectl write (for example a `delete` that hangs) into exit 0, while M5 limits it to reads. The
  broker still ends the call `timeout` and records it `cancelled: timeout`; only the client's exit code differs.
