# modgudr MVP run report

This is the document to read after the run. It first covers what the run built, the test results and the measured
spike answers. It then lists where the run deviated from the pre-plan and which gaps it accepts. It ends with the
post-run checklist (R1 to R12), the pre-plan items still open, and a proposed §14.4 ledger row. Section 9 records
the checks run by hand after the report was written. Everything here comes from the developer's Mac (macOS 27.0.1,
Python 3.12.11). Only the CI workflow exercises the Linux paths, and that workflow has never run.

## 1. What was built

**Distributions** (a uv workspace under `packages/`, the namespace package `modgudr`):

| Distribution         | Package                         | What it holds                                                                                                                          |
|----------------------|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `modgudr-client`     | `modgudr`, `modgudr.client`     | stdlib-only client: CLI, `import modgudr`, `agent-setup`, hook, `agent run`, `doctor`, the Claude Code skill                           |
| `modgudr-broker`     | `modgudr.broker`, `modgudr.spi` | daemon with `agent.sock` and `human.sock`, policy, rule engine, session, secrets, pins, audit, scrubber, start-up hardening, providers |
| `modgudr-sql`        | `modgudr.sql`                   | `sql` connector, Snowflake and Oracle dialects                                                                                         |
| `modgudr-kubectl`    | `modgudr.kubectl`               | `kubectl` connector, `azure-cli` credential provider (`borrowed` and `custody`)                                                        |
| `modgudr-store-file` | `modgudr.store_file`            | the `file` store (development and tests)                                                                                               |
| `modgudr-store-bws`  | `modgudr.store_bws`             | the attended Bitwarden Secrets Manager store, through the `bws` CLI as a subprocess                                                    |

**Console scripts:** `modgudr` (client) and `modgudr-broker` (daemon). `modgudr-broker lint` checks the policy
offline.

**Commands:** `targets`, `describe`, `<target> <op>`, `explain`, `actions`, `policy show|lint`, `status`,
`unlock`, `lock`, `audit tail`, `login azure`, `agent-setup claude`, `agent run claude`, `doctor [--agent claude]`,
`agent-docs claude`.

**Operations:** SQL has `query`, `write` (`--dry-run`), `tables`, `describe`, `count` and `sample`. On Oracle it also
has `plan` and `--schema`. The kubectl connector passes any kubectl command line through one `kubectl` operation and
classifies each call on its own. Metadata operations (`status`, `targets`, `describe`, `explain`, `actions`,
`policy show`, `policy lint`) work while the store is locked. `unlock`, `lock`, `audit-tail` and the login info are
admin operations, and only `human.sock` accepts them.

**Entry points:**

| Group                          | Names                 |
|--------------------------------|-----------------------|
| `modgudr.connectors`           | `sql`, `kubectl`      |
| `modgudr.sql_dialects`         | `snowflake`, `oracle` |
| `modgudr.secret_stores`        | `file`, `bws`         |
| `modgudr.credential_providers` | `azure-cli`           |

**Tooling and files:** `dist/install-l0.sh`, `dist/policy.d/00-company.example.yaml`,
`dist/policy.d/50-targets.example.yaml`, `scripts/check.sh`, `scripts/sql_corpus_report.py`,
`.github/workflows/ci.yml`.

**Docs:** `README.md` covers the quick start, the commands, the exit codes and the boundary that the Bitwarden licence
sets. `docs/protocol.md` describes version 1 of the wire protocol. The rest are this report and the Claude Code skill
(`packages/client/src/modgudr/client/docs/SKILL.md`), which `modgudr agent-docs claude` prints.

**Steps that landed** (`git log`):

- 01 workspace skeleton
- 02 client protocol/params/paths/errors
- 03 policy model, loader and lint
- 04 SPI types and rule engine
- 05 scrubber, sink and audit writer
- 06 broker server, channels and file store
- 07 store session, secrets and pins
- 08 CLI, Python API and audit tail
- 09 SQL classifier and Snowflake dialect
- 10 Snowflake execution and SQL operations
- 11 `agent-setup` and the hook
- 12 `agent run`, `doctor` and the skill
- 13 start-up hardening
- 14 the `bws` store and unlock flow
- 15 Oracle classifier and corpus report
- 16 Oracle execution
- 17 kubectl parser and classifier
- 18 kubectl execution and the `azure-cli` provider
- 19 dist, docs and CI
- 20 this regression, the naming check and the report

## 2. Test results

The full check is `sh scripts/check.sh tests -rs`. It runs ruff check, ruff format check and pyright strict, then
pytest over `tests/unit`, `tests/contract`, `tests/integration` and `tests/e2e`:

| Result  | Count |
|---------|-------|
| passed  | 2505  |
| skipped | 4     |
| failed  | 0     |

The check took 341 s of wall time. ruff and pyright report no findings. The BATS suite, `bats bats/`, covers
`bats/modgudr_cli.bats` and `bats/install_l0.bats`. It ran 14 tests: 14 ok, none skipped.

Skips, with the reason:

| Skip                                              | Why                                                                                                                                         |
|---------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `tests/integration/kubectl_kind/test_kind.py` (1) | opt-in: set `MODGUDR_TEST_KIND=1` (and `MODGUDR_KIND_KUBECONFIG`, `MODGUDR_KIND_TOKEN`). The kind test has never run against a real cluster |
| `tests/integration/snowflake/test_live.py` (2)    | opt-in: set `MODGUDR_SF_LIVE=1` with a real account (R3, 22c)                                                                               |
| `tests/unit/broker/test_harden.py:171` (1)        | `/proc` exists on Linux only; CI runs it                                                                                                    |

The Oracle suite, `tests/integration/oracle`, ran against the Oracle Free container and passed, since Docker was up.
When Docker is missing, the suite fails rather than skips. The Snowflake suites run in process on
fakesnow.

One test failed once, on a first full run launched from a backgrounded shell:
`test_ctrl_c_mid_stream_is_exit_130_without_a_traceback`. A non-interactive shell starts background jobs with SIGINT
ignored. Python then installs no handler, and the child exited 0. In the foreground the test passed five times, both
alone and in the full run. The test relies on SIGINT keeping its default handler.

The naming rule M24 has a new test, `tests/unit/test_naming.py`. It scans the README, `docs/`, `dist/`, `scripts/`,
`.github/`, and every `packages/*/src` file and `pyproject.toml` for a bare short-name token. The `docs/` scan
includes this report. The test also checks the `--help` output of the client's commands and of `modgudr-broker`, the
skill text, and the files and stdout of `agent-setup`.

## 3. Measured spike answers

| Spike                                  | Result                                                                                                                                                                                                                                                          |
|----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Start-up time, `modgudr --help`        | median of 10 runs of `.venv/bin/modgudr`: **91 ms** (min 82, max 133)                                                                                                                                                                                           |
| Start-up time, `modgudr status`        | median of 10 runs: **111 ms** (min 82, max 265). Measured with **no broker running**, so each run exits 6 after a refused connect. A run against a live dev-mode broker was not measured                                                                        |
| Anti-debug (`PT_DENY_ATTACH`, step 13) | `ptrace(PT_DENY_ATTACH)` returned **0** in the hardened child (`tests/unit/broker/test_harden.py::test_macos_ptrace_deny_attach_returns_zero` passes). It closes the ptrace path only. The Linux `PR_SET_DUMPABLE` branch is exercised only in CI               |
| Peer credentials (step 06)             | `socket.LOCAL_PEERCRED == 1` exists in this Python; `SOL_LOCAL` and `LOCAL_PEERPID` are not exported by `socket`, so the code passes level 0 and option 1 as numbers and parses the 76-byte `struct xucred`. A live `AF_UNIX` pair returned uid 501 for uid 501 |
| `sqlglot`                              | 30.24.0, forced by `override-dependencies` because fakesnow 0.11.22 declares `<30.23` (see Deviations)                                                                                                                                                          |
| `snowflake-connector-python`           | 4.8.0 (5.x not used: fakesnow cannot import it)                                                                                                                                                                                                                 |
| `oracledb`                             | 26.0.1 (thin mode)                                                                                                                                                                                                                                              |
| `fakesnow`                             | 0.11.22                                                                                                                                                                                                                                                         |
| `pydantic`                             | 2.14.1                                                                                                                                                                                                                                                          |
| `PyYAML`                               | 6.0.3                                                                                                                                                                                                                                                           |

Section 6 lists the spikes that need the real world. They are Oracle by SID over the VPN (R4), a real Snowflake
account (R3), and a real AKS cluster and conditional access (R5). They also include the sandbox facts about the
keychain, `launchctl` and SSH (R7, R9), and `Edit(...)` deny with bypass mode (R8).

## 4. Deviations from the pre-plan

The M-rules that change a pre-plan statement:

- **M1, `human.sock` location.** `human.sock` lives in `$MODGUDR_HOME/run/` instead of beside `agent.sock`. Every
  generated deny list already hides that directory. The broker canonicalises `MODGUDR_HOME` and reports it in
  `status --json`. `agent-setup` denies that path, and the isolation check passes only when the deny entry is there.
- **M2, state under `~/.modgudr`.** Policy, audit, the Azure caches of the `custody` tier, the `bws` config, state
  and child `HOME`, and the `run/` sockets all live under `MODGUDR_HOME`. This widens §4.2's "holds only the policy"
  on purpose.
- **M5, exit codes.** The §6.1 table gains several codes. Exit 2 now also covers a write rolled back for
  `maxAffectedRows` and a `--max-rows` above `maxRowsHard`. 64 is for usage errors, and 69 is for when `agent run` or
  `doctor --agent` cannot run. 70 is for `internal`, 78 for a refused start-up, and 130 and 141 for Ctrl-C and a
  closed pipe. `--allow-truncated` turns 4 into 0 for reads only.
- **M15, connector line.** `snowflake-connector-python>=4.8,<5` instead of the current 5.x.
- **M17, path flags and no discovery.** modgudr refuses kubectl flags that take local paths. A static resource
  catalogue replaces `api-resources` discovery, so modgudr refuses CRDs as unknown.
- **M18, `listClusterUserCredential` instead of kubelogin.** The cluster endpoint and CA come from `az rest` on
  `listClusterUserCredential`, and the token comes from `az account get-access-token`. The provider never calls
  `az aks get-credentials`, because that command may invoke `kubelogin`.
- **M20, hook interpreter and drop-in.** The hook runs with `/usr/bin/python3 -I` from a root-owned
  `/opt/modgudr/bin/` path and is compatible with Python 3.9. The settings are a drop-in
  `managed-settings.d/50-modgudr.json`, so modgudr never touches the company's `managed-settings.json`.

The steps recorded the deviations below, and this list keeps their wording. Those of step 20 come last:

- **Step 06, the `maxConcurrent` row "a fourth that would be denied → `throttled`".** The row comes from edge case
  EN-08, which assumed the pre-plan's throttle-first order (§7.5). M6 fixes a different order: classify and decide
  (step 4) come before the slot (step 5), and a denied call returns at step 4. The broker follows M6. A call that
  phase 1 denies gets `denied` (exit 2) even while every slot is busy, and it never holds a slot. Another call may
  pass phase 1 but fail only after the slot, at M6 step 7. Here that failure is a secret missing from the store. Such
  a call gets `throttled` (exit 7) with `retryAfter`. `tests/integration/broker/test_server.py` asserts both cases in
  `test_max_concurrent_throttles_without_queueing_and_never_leaks`.
- **Step 07, step 06 tests changed beyond the unlock seam.** Step 07's "done when" allows step 06 tests to change
  only where step 07 replaced the test-only unlock seam. Three tests changed for other reasons, which step 07's own
  rules force:
    - The first, `test_auth_failure_is_upstream_then_the_next_open_works`, expected the second login to succeed after
      a failed one with an unchanged secret. M8 forbids that. The broker does not retry an unchanged value, and it
      latches the target for 5 minutes. The test is now `test_auth_failure_is_upstream_and_latches_the_target`, and
      the completion's `stage` is `login`.
    - The second, `test_admin_ops_on_human_sock_have_no_handler_yet`, now covers only `audit-tail` and `login-info`,
      because `unlock` and `lock` have handlers.
    - The third, `test_dev_mode_banner_and_stamps`, expects six records instead of four. The two new ones are the
      `unlock` record (M9) and the `lock` record with reason `shutdown` (M7). An unlocked broker writes them when it
      stops.
- **Step 07, malformed `modgudr-` note lines refuse the secret.** M8 says the broker ignores note lines other than
  the strict `modgudr-hosts:`/`modgudr-env:` forms, with a warning. Step 07 is stricter about a line that starts with
  `modgudr-` but is not a strict form. Such a line has the wrong case, is indented, uses an unknown `modgudr-` key,
  or names two environments. The broker refuses the secret instead (`denied`, layer `pinning`, rule `note`).
  Otherwise the broker would silently drop a mistyped `modgudr-env` line. The secret would then lose its environment
  pin, which widens access. AGENTS.md says that a parser which fails must refuse. The broker still ignores other lines
  with a warning. In the same spirit, a `modgudr-hosts` value with a scheme, userinfo or path "is rejected" by
  refusing the secret, never by dropping that one value. The message never repeats the value, because userinfo may
  hold a password.
- **Step 09, an override forces `sqlglot` 30.24.0 on fakesnow too.** M12 pins `sqlglot==30.24.0` exactly, because
  30.23 is the floor for Oracle `q'…'` literals. `fakesnow` is already in the dev group for step 10. Its newest
  release (0.11.22) declares `sqlglot>=30.22.0,<30.23`, so the workspace did not resolve. The root `pyproject.toml`
  now sets `[tool.uv] override-dependencies = ["sqlglot==30.24.0"]`, and `uv.lock` records the override. fakesnow
  therefore runs on a sqlglot it does not declare. A throwaway smoke run outside the repository passed, with fakesnow
  0.11.22, `snowflake-connector-python` 4.8.0 and sqlglot 30.24.0. It covered `paramstyle="numeric"` binds, a
  VARIANT path with a cast, `UPDATE` `rowcount`, rollback and `information_schema`. Step 10's fakesnow suite is the
  real check. Remove the override once a fakesnow release accepts sqlglot 30.24.
- **Step 16, Oracle sessions come from the connector's pool, not `oracledb.create_pool`.** M16 says
  `create_pool(min=0, max=maxConcurrent, timeout=300)`. The `sql` connector already pools sessions per target with
  the same bounds: at most `maxConcurrent`, idle 300 s. Every login must also go through `Secrets.login`. Only then
  do the M8 latch, the single flight and "authentication fails only while connecting" hold. An `oracledb` pool would
  log in on its own, outside that path. The driver therefore opens standalone thin connections with
  `oracledb.connect(params=ConnectParams(...), password=...)`. Before the closing rollback or commit of every call,
  the driver resets the tags (`module`, `action`, `client_identifier`) and `current_schema`.
- **Step 16, `TIMESTAMP WITH TIME ZONE` does not keep its offset.** M16 says it does. python-oracledb 26.0.1 in thin
  mode returns a naive `datetime` for `TIMESTAMP WITH TIME ZONE` and `WITH LOCAL TIME ZONE`. That value holds the
  wall clock of the value's own zone. An output type handler to `VARCHAR` converts on the client and loses the offset
  the same way. Getting the offset would mean rewriting the caller's SQL. M12 forbids that, because the executed
  text must be the classified text. The wire therefore carries these columns as `timestamp`, which holds the ISO
  wall clock without an offset. It never carries them as `timestamp_tz` with an offset it does not have.
  `tests/integration/oracle/test_types.py` asserts this.
- **Step 16, the container publishes the listener with `-p 127.0.0.1::1521`, not `-P`.** The `gvenzl/oracle-free`
  image declares no `EXPOSE`, so `docker run -P` publishes nothing. The fixture maps the listener to a random port
  on 127.0.0.1 only.
- **Step 16, the audit record names a LOB limit, the wire does not.** The trailer has no field for it (M4). The
  completion record therefore carries `limit`, with a text such as "column 'C' holds at least N bytes, more than the
  M left of maxBytes".
- **Step 16, `describe` on Oracle returns the columns of a `select … where 1 = 0`.** The header carries the names
  and wire types, and there are no rows. The contract of the `describe` op accepts a `select` as well as a `describe`
  statement for it.
- **Step 17, `kubectl cp` is a plugin invariant, not only `admin`.** M17 classes `cp` as admin, which an
  admin-ceiling environment could allow. But `cp` always has a local side, and the broker runs kubectl as the
  developer. So `cp ~/.azure/… pod:/tmp` would hand the agent the developer's Azure refresh token or prod
  kubeconfig. `cp pod:/x ~/…` would write the developer's files. M17 gives that same reason for refusing path-taking
  flags. The classifier still returns `kubectl:cp/pods` with risk `admin`. The connector's invariant rule
  `kubectl:cp/*` then refuses it at layer `plugin-invariant` in every environment.
- **Step 17, every kubectl call that names `secrets` is `secret`.** M17 names `get`/`describe` of secrets and
  "any list containing `secrets`". The classifier applies the rule to every verb (`delete secret x`,
  `create secret …`, `label secret x … -o yaml`, `logs secret/x`, `explain secrets`), because a write that prints
  the object (`-o yaml`) shows its data. modgudr never allows these calls.
- **Step 18, a failed process's exit code rides on the `error` frame.** M5 puts the raw exit code of a failed
  `kubectl` "in the trailer", but M4 says an error line replaces the trailer. The `error` frame of a failed call
  therefore carries `exitCode` when the connector reported one. The message says "kubectl exited with code N", and
  the completion record has `exitCode` as well.
- **Step 18, `az rest` also gets `-o json`.** M18's endpoint command has no output flag. In the `borrowed` tier
  `az` reads the developer's own `~/.azure/config`. Its `core.output` may be `table` or `yaml`, which the parser
  would refuse. `-o json` pins the format, as M18 already does for `az account get-access-token`.
- **Step 18, `--allow-truncated` on the `kubectl` op.** The client decides per operation whether an op is a read: an
  op is a read when it has no `--dry-run`. The broker classifies the `kubectl` passthrough op per call. So
  `--allow-truncated` also turns a timed-out kubectl write into exit 0, for example a `delete` that hangs. M5 limits
  it to reads. The broker still ends the call with `timeout` and records it as `cancelled: timeout`. Only the
  client's exit code differs.

- **Step 20, three lines keep the bare short name, on an exact-line allowlist.** `tests/unit/test_naming.py`
  allows two lines of the alias block in `dist/install-l0.sh`. One is the `command -v` lookup. The other is the
  `ln -s` that creates the alias of M24, and it runs only when nothing else has that name. The test also allows the
  one `ctx.which(...)` call in `packages/client/src/modgudr/client/agent/doctor.py`, the PATH lookup for the `doctor`
  INFO line. The test weakens the regex for nothing else. The name of the hook file and the prefix of the temporary
  directory pass, because the regex requires that no `-` follows the token. Step 20 also reworded the messages
  around those lines. The `doctor` INFO line now reads one of two messages. One is "<path> is on PATH and is not
  modgudr (on macOS it is an editor); the command is modgudr". The other is "no other command shadows the short
  name; the command is modgudr". `install-l0.sh` says "the short alias name is already taken". Step 20 changed the
  two `test_doctor.py` assertions and the `api.py` docstring example to match.

## 5. Accepted gaps

These items come from "Considered and not built". For each one, the plan says what would make it worth building:

| Item                                                                                              | Why not now                                                                                                                                                                                                                                                                                       |
|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `bitwarden-sdk` in-process instead of the `bws` CLI                                               | It would make modgudr an application built on a proprietary, beta SDK and put the SDK into the public Apache-2.0 repository's lockfile. The licence forbids derivative works and offering the application to third parties (confirmed by the Q5 answer). The CLI is a tool the developer installs |
| Bundling, downloading or installing `bws` from `install-l0.sh`, CI or an image                    | The licence forbids redistribution; written permission from Bitwarden would change it                                                                                                                                                                                                             |
| A `bw` (Password Manager vault) store                                                             | Q1 and Q6 chose Secrets Manager (`bws`); the MVP builds one store                                                                                                                                                                                                                                 |
| `snowflake-connector-python` 5.x                                                                  | fakesnow cannot import it (measured); released six days before the plan                                                                                                                                                                                                                           |
| `kubectl api-resources` discovery for CRDs                                                        | One more cluster call before deciding; the trial's resources are core kinds                                                                                                                                                                                                                       |
| Environment and host pins for `provider:` (AKS) targets                                           | At L0 the agent cannot edit the targets file under the managed settings, and any other same-uid process can use `~/.azure` directly, so the pin adds nothing; it matters at L1                                                                                                                    |
| `reload` on `human.sock` and `SIGHUP`                                                             | Not in §14.1; a restart plus unlock is enough for one developer                                                                                                                                                                                                                                   |
| Policy-driven extra environment for `agent run`                                                   | `--pass-env` covers it without a schema key                                                                                                                                                                                                                                                       |
| `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, `blockReadsOutsideWorkingDirectories` | They break `--allowedTools` for the self-test, kill the developer's own hooks, and make `modgudr` under `$HOME` unreadable. R8 decides                                                                                                                                                            |
| Sandbox runtime (`srt`) settings from `agent-setup`                                               | I6 per §14.3; the `borrowed` AKS target runs at L0 with the Bash sandbox only                                                                                                                                                                                                                     |
| Keeping the `bws` token out of the child's environment                                            | `bws` takes the token only from `BWS_ACCESS_TOKEN` or `--access-token` (argv is worse); the in-process SDK is the only way to avoid it and it is not built. R2 checks it                                                                                                                          |
| Snowflake per-call cancel with `execute_async` + `SYSTEM$CANCEL_QUERY`                            | Statement timeout plus discarding the connection bounds the cost; fakesnow cannot exercise it. R3 checks it                                                                                                                                                                                       |
| Classifying `v$sql`/`v$sql_bind_capture` as `secret`                                              | The Oracle diagnostics skills need them; SQL text and bind values are data (§1)                                                                                                                                                                                                                   |
| An Oracle `currentSchema` target key                                                              | `--schema` per call (Q3) covers the skills                                                                                                                                                                                                                                                        |
| `columns`, `batch`, `tx`, breaker, rights probe, `unattended`                                     | Explicitly outside §14.1 (I5, I8, I2)                                                                                                                                                                                                                                                             |
| A `pilot` meta-extra on `modgudr-broker`                                                          | It would create a dependency cycle (connectors depend on the broker for `spi`); `install-l0.sh` lists the distributions                                                                                                                                                                           |
| `Bash(security:*)`-style blocks presented as protection                                           | Bash rules match text only; they are listed for steering                                                                                                                                                                                                                                          |
| testcontainers for Oracle                                                                         | Its Oracle class moved in 4.15 and its docs are stale; the `docker` CLI fixture is simpler                                                                                                                                                                                                        |
| Refusing a non-default `MODGUDR_HOME` outside `--dev`                                             | Tests and any second install need it; the deny list and the isolation predicate follow the canonical path instead                                                                                                                                                                                 |
| A Linux CI test of the real Claude Code sandbox against `human.sock`                              | CI has no logged-in Claude Code; the predicate and generator are unit-tested, and `doctor --agent` probes the broker-reported `human.sock` on the developer's machine (R7)                                                                                                                        |
| A subprocess-runner seam in place of the fake executables                                         | It would bypass the child-environment allowlists that the fake logs prove                                                                                                                                                                                                                         |
| `fetch_lobs=False`                                                                                | The driver materialises the whole value before any budget check, so `maxBytes` would not bound memory (M16)                                                                                                                                                                                       |
| `audit tail --follow`                                                                             | `-n` and the filters cover inspection after a session                                                                                                                                                                                                                                             |

Also accepted:

- **Memory for LONG / LONG RAW (M16).** The driver fetches Oracle `LONG` and `LONG RAW` columns whole before
  `maxBytes` can apply. The connector refuses a LOB over the budget only after reading it, and the audit record names
  the limit.
- **The hook bypass:** `bash -c "kubectl …"` gets past the hook (step 11). The hook only steers the agent. The sandbox
  is the boundary.
- **Short secrets in row data:** the scrubber protects secrets under 8 characters only partially (step 05).
- **An unknown user function classifies as `read`** (A9). On `custody` targets a user-defined function with an
  autonomous transaction can write from a `SELECT`. The admin and secret catalogues must therefore be complete.
- **A redirect from an Oracle RAC listener:** a SCAN listener can redirect to a host that is not in the pin. Pinning
  checks the configured host and port (step 16).
- **The keychain is reachable from the sandbox:** `doctor --agent` reports it as WARN.
- **A SIGKILL loses the completion records,** and kubectl children and database sessions can run on until they next
  write or time out. Snowflake's statement timeout bounds its sessions.
- **No row cap per channel for the agent** (step 08): the agent may request `maxRowsHard` (50,000) rows into its
  transcript.
- **Edge-case report §5** (`secret-broker-pilot-final-plan-research/edge-cases.md`) adds these to the above.
  `v$sql`, `v$sql_bind_capture` and `INFORMATION_SCHEMA.QUERY_HISTORY` expose the SQL text and bind values of other
  sessions. Those are data, not credentials. Snowflake has no read-only transaction. The `bw` master password would
  pass through a child environment, but the MVP does not build the `bw` store and the plan prefers `bws`. Policy
  changes need a restart, and a restart locks the store.
- **Never exercised for real:** the CI workflow, the kind test, `install-l0.sh` without `--dry-run`, and the
  Oracle, Snowflake and AKS paths against real systems.

## 6. Post-run checklist

Run these by hand. `modgudr` is the installed command; every host below is an example.

| #   | Check                                                                                            | Commands and what to look for                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|-----|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| R1  | Install at L0; install the company file root-owned; start the broker                             | `sh dist/install-l0.sh`; `mkdir -p -m 0700 ~/.modgudr ~/.modgudr/policy.d`; `sudo install -o root -m 0644 dist/policy.d/00-company.example.yaml ~/.modgudr/policy.d/00-company.yaml`; `install -m 0644 dist/policy.d/50-targets.example.yaml ~/.modgudr/policy.d/50-targets.yaml` (the script prints the exact commands); `modgudr-broker lint`; `modgudr-broker` in its own terminal                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| R2  | Bitwarden Secrets Manager                                                                        | In the web vault create a Free organisation, subscribe it to Secrets Manager, create one project `modgudr` (its uuid goes into `store.bws.project` of the company file, and `store.bws.serverUrl: https://vault.bitwarden.eu` when the vault is the EU cloud) and one machine account with **read-only** access to that project only, and give its access token an expiry. Install `bws` from the pinned GitHub release zip and check it against the published checksum file (no Homebrew formula; no pipe-to-shell). Store each secret with `modgudr-hosts:` and `modgudr-env:` lines in its note. **Never export `BWS_ACCESS_TOKEN` in your shell**; type it only at `modgudr unlock`. Check the idle lock and that a pin mismatch is refused and audited (`modgudr audit tail`). After `modgudr unlock` and one resolve, `ls -A ~/.modgudr/bws/` must show only `config` and empty state directories. Beyond the trial the secrets move to the company's paid organisation; only the company file changes |
| R3  | Snowflake, real account                                                                          | `modgudr sf query -p …` with the key from Bitwarden, which must be the key registered on the target's `user` (its fingerprint equals `RSA_PUBLIC_KEY_FP` in `DESC USER`); `modgudr.connect().sql("sf")`; Ctrl-C cancels a slow read such as `select count(*) from table(generator(timelimit => 20))`; `QUERY_TAG` visible in query history; decide 22b in the company file; ask about 22c. Optionally `MODGUDR_SF_LIVE=1 sh scripts/check.sh tests/integration/snowflake/test_live.py`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| R4  | Oracle over the VPN                                                                              | A test database by SID with the read-only diagnostics user; `dba_users` refused; the VPN-down message names the host; a `stage` or `prod` target (24b)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| R5  | AKS                                                                                              | `modgudr aks@test kubectl get pods -n <ns>` through your login; `delete pods --all`, `--as` and `get secrets` refused; your own `kubectl` still works; `modgudr login azure aks-test` and what conditional access does; 13b: `az aks get-credentials --admin` must fail. Optionally the kind test with `MODGUDR_TEST_KIND=1`, `MODGUDR_KIND_KUBECONFIG`, `MODGUDR_KIND_TOKEN`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| R6  | Managed settings                                                                                 | `modgudr agent-setup claude`; install the drop-in and the hook with the printed `sudo` steps; `claude doctor` and `/status` show the drop-in and no skipped sources                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| R7  | `doctor --agent`                                                                                 | `modgudr doctor --agent claude` passes with the managed settings; run it without them and record that it fails (it spends API tokens)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| R8  | Manual red-team at L0 (§13, five tasks)                                                          | Against the Snowflake target, then one target per tier; repeat with bypass mode forced on and with no isolation, and record what each stops. Decide the "not built" managed-settings keys of section 5 from this                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| R9  | Sandbox facts the docs leave open                                                                | Inside the sandboxed Bash tool: `security find-generic-password`, `launchctl`, `git push` over SSH; whether `claude -p` accepts `--max-turns`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| R10 | Real-query corpus                                                                                | `uv run --locked python scripts/sql_corpus_report.py --dialect oracle <dir>` and `--dialect snowflake <dir>`; put the unknown rate and the missing catalogue names into the ledger                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| R11 | Convert the existing Oracle diagnostics skills (another repository) per the answers to Q3 and Q4 | §15.2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| R12 | The one-week trial (§14.2 step 6)                                                                | Then apply the ledger row of section 8 to §14.4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

## 7. Still open (pre-plan §17)

- **22b.** Does the single Snowflake environment hold production data (ceiling `read`) or test data? The plan assumes
  `read` until told otherwise.
- **22c.** Can CI run the integration and leak tests on a trial account in Snowflake?
- **24b.** Which Oracle database is the `stage` or `prod` target for the MVP trial, and does the read-only
  diagnostics user exist there yet?
- **13b.** Do the AKS clusters have local accounts disabled, so that `az aks get-credentials --admin` fails?

## 8. Proposed §14.4 ledger row

**Built:** the L0 MVP of §14.1. It consists of a stdlib-only client, a broker with two sockets, the two-layer policy
and the rule engine with six layers. It adds the `file` and `bws` stores, the `sql` connector (Snowflake, Oracle),
and the `kubectl` connector with the `azure-cli` provider. The rest is `agent-setup`/`agent run`/`doctor`, the Claude
Code skill, start-up hardening, audit and scrubber, dist, docs and CI. 2505 tests pass, 4 skip by design, and 14 BATS
tests pass. Start-up takes about 90 ms (`--help`) and 110 ms (`status`, no broker).

**What planning taught:**

- The M-rules changed the pre-plan in the places that section 4 lists. `human.sock` moved inside `MODGUDR_HOME`, and
  all state lives under `~/.modgudr`. The exit codes grew, and the Snowflake connector stays on 4.x. kubectl runs
  without discovery or path flags, and it uses `listClusterUserCredential` instead of kubelogin. The settings ship as
  a managed drop-in, with a root-owned hook that is compatible with Python 3.9.
- The Bitwarden licence: both the SDK and `bws` fall under the proprietary Bitwarden SDK License. modgudr therefore
  calls the `bws` CLI that the developer installs. It never bundles, downloads or depends on either.
- How Linux protects the socket: `allowUnixSockets` is macOS only and matches by `subpath`. On Linux the deny entry
  for the directory that holds `human.sock` is what protects it.
- The macOS keychain is reachable from the sandbox, because the sandbox profile allows `com.apple.SecurityServer`.
  The design no longer assumes that the sandbox hides the keychain, and `doctor --agent` warns.
- Git over SSH fails inside the macOS sandbox. R9 records the facts the docs leave open.
- fakesnow forced two pins: sqlglot 30.24.0 by override, and the connector below 5.

**Suggested next increment:** I1 (L1), unless R7 or R8 show that the managed settings do not hold at L0, in which
case fix that first.

## 9. Post-run checks so far

The developer ran R1 to R5 by hand on 2026-10-23, against the real Bitwarden cloud, a real Snowflake account, the
CBSLink Oracle databases over the VPN and a real AKS cluster. R1, R2 and R5 pass. R3 passes except for 22b and 22c,
which stay open. R4 found one bug, now fixed; its VPN-down check is still to run.

**R1, install.** `install-l0.sh` ran without `--dry-run` for the first time. The R1 row first left out the `mkdir` of
the policy directory, and `install` does not create a missing parent: it failed with
`install: …/policy.d/INS@…: No such file or directory`. The row now lists the `mkdir` and the install of the targets
file, as the script's own output does.

**R2, Bitwarden Secrets Manager.** `bws` 2.1.0 is installed by hand. `modgudr unlock` accepted the machine-account
token, and the broker resolved the Snowflake secret. After the unlock and the resolve, `~/.modgudr/bws/` holds only
`config` (mode `0600`). Two findings:

- The broker caches a resolved secret for 10 minutes, its note included. The first resolve read the secret before
  its note held the pin lines, so the broker refused it ("has no destination pins"). After `modgudr lock` and
  `modgudr unlock` the broker read the note again and used the secret.
- The pin check holds. With `modgudr-hosts: wrong.snowflakecomputing.com` in the note, the broker refused the call
  before it contacted Snowflake (`layer: pinning`, `rule: hosts`, `stage: secret`), and the audit log has the
  `denied` record under the same id.

**R3, Snowflake.** The account is `wss.west-europe.azure` (`CURRENT_ACCOUNT()` is `WSS`), the user an existing
service user that already had a key pair. `query`, `tables` and `modgudr.connect().sql(...).query(...)` work.
Findings:

- The key in the store must be the key registered on the target's `user`. The first target named another user, and
  Snowflake answered "JWT token is invalid". The broker then latched the target for 5 minutes, as M8 says. A new key
  pair helps only when someone with ownership of the user registers its public key. For an existing service user,
  store the key it already uses, and check it first: the base64 SHA-256 of the public key's DER must equal
  `RSA_PUBLIC_KEY_FP` in `DESC USER`.
- The connector signs the JWT with the account up to the first `.`, uppercased (`WSS`), and the user uppercased.
- Snowflake ignores a `database` that the role cannot use and opens the session without one. `tables` then fails
  with "This session does not have a current database". `database`, `schema` and `warehouse` must be ones the
  target's role can use.
- `select system$wait(20)` is refused in `prod` as `sql:select (admin)`, because every `SYSTEM$*` function is `admin`.
  A slow read for the Ctrl-C check is `select count(*) from table(generator(timelimit => 20))`.
- Ctrl-C cancels on the server. The client exited 130 without a traceback. In the query history the query ended
  `FAILED_WITH_ERROR` after 2.7 s, and the broker's `SYSTEM$CANCEL_ALL_QUERIES(<session>)` followed at once. This
  answers the R3 check of the gap "Snowflake per-call cancel" in section 5: the session cancel stops the query on
  the server, without `execute_async`.
- `QUERY_TAG` holds the audit id of the call, so each Snowflake query maps to one audit record. Every read ends with
  a `ROLLBACK`. A client that leaves before the trailer, such as a Python `Result` that is never read, gets the
  session cancel instead.
- A service user (`TYPE = SERVICE`) cannot log in to Snowsight. The same user reads its own history with
  `INFORMATION_SCHEMA.QUERY_HISTORY_BY_USER`.
- The Python API names an unaliased expression column `_0`; `select current_user() as u` gives `Row(u=…)`.

**R4, Oracle.** Three targets reach the CBSLink databases by SID as `CBSLINK_DIAG`, the read-only diagnostics user
(`create session`, `select_catalog_role`, `select any table`). `ora-sol` (`cbsltest`) and `ora-vfy` (`cbslver`) share
one host, and `ora-prod` (`cbslprod`) has its own. This answers 24b: `ora-vfy` is the `stage` target and `ora-prod`
the `prod` one. A query on `ora-sol` and a count on `ora-prod` work, and `select username from dba_users` is refused
as `secret` (`plugin-invariant`). Findings:

- sol and vfy share a host, so their host pins are equal. The `modgudr-env` line of each secret is what keeps the vfy
  password from running under sol's laxer rules.
- **Bug, fixed:** `tables --schema CBSLINK_PROD` listed every schema the user can see and stopped at `maxRows`.
  `--schema` sets `CURRENT_SCHEMA`, which `all_objects` ignores. With `--schema`, the Oracle `tables` statement now
  also filters on `owner = sys_context('USERENV', 'CURRENT_SCHEMA')`. `tests/integration/oracle/test_ops.py` asserts
  that every listed owner is the schema of the call.
- Still to run: the VPN-down message must name the host.

**R5, AKS.** The target is a `test` (alias `sol`) cluster in the `borrowed` tier, so it uses the developer's own
`az` login. `get pods` works in the default namespace and in another listed one. The broker refused, each with an
audit record:

- `get pods -n kube-system`: the namespace is not in the `namespaces` constraint;
- `get secrets`: `plugin-invariant`;
- `delete pods --all`: the `requireName` constraint;
- `get pods --as admin`: `plugin-invariant`.

The developer's own kubectl works beside modgudr on the same cluster. Findings:

- The `namespaces` constraint matches exact names, with no wildcards. A cluster with many namespaces needs every
  allowed one listed in the company file. Cluster-scoped calls such as `get ns` are refused under the constraint.
- `az aks get-credentials --format azure` writes a kubeconfig entry for the `azure` auth plugin, which kubectl has
  removed. The developer's own kubectl then fails until `kubelogin convert-kubeconfig -l azurecli`. modgudr does not
  read the kubeconfig, so it is not affected (M18).
- 13b for this cluster: `az aks show` reports `disableLocalAccounts: true`, with Entra ID and Azure RBAC, so
  `--admin` credentials cannot work. The `stage` and `prod` clusters are not checked yet.
- In zsh a trailing `# comment` on an interactive command line is passed as arguments, unless
  `interactive_comments` is set. kubectl then looked up pods named `#` and so on.

**Before R6.** The example Oracle targets were still in `50-targets.yaml`, so `broker.start` listed their hosts in
`denyHosts`. `agent-setup` would put them into the deny lists it generates. Remove the targets you do not use.
