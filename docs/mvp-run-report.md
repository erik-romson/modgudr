# modgudr MVP run report

This is the document to read after the run. It covers, in order: what was built, the test results,
the measured spike answers, the deviations, the accepted gaps, the post-run checklist (R1–R12), the
pre-plan items still open, and a proposed §14.4 ledger row. Everything here was produced on the
developer's Mac (macOS 27.0.1, Python 3.12.11); Linux paths are exercised only by the CI workflow,
which has never run.

## 1. What was built

**Distributions** (a uv workspace under `packages/`, the namespace package `modgudr`):

| Distribution | Package | What it holds |
| --- | --- | --- |
| `modgudr-client` | `modgudr`, `modgudr.client` | stdlib-only client: CLI, `import modgudr`, `agent-setup`, hook, `agent run`, `doctor`, the Claude Code skill |
| `modgudr-broker` | `modgudr.broker`, `modgudr.spi` | daemon with `agent.sock` and `human.sock`, policy, rule engine, session, secrets, pins, audit, scrubber, start-up hardening, providers |
| `modgudr-sql` | `modgudr.sql` | `sql` connector, Snowflake and Oracle dialects |
| `modgudr-kubectl` | `modgudr.kubectl` | `kubectl` connector, `azure-cli` credential provider (`borrowed` and `custody`) |
| `modgudr-store-file` | `modgudr.store_file` | the `file` store (development and tests) |
| `modgudr-store-bws` | `modgudr.store_bws` | the attended Bitwarden Secrets Manager store, through the `bws` CLI as a subprocess |

**Console scripts:** `modgudr` (client) and `modgudr-broker` (daemon; `modgudr-broker lint` checks the policy
offline).

**Commands:** `targets`, `describe`, `<target> <op>`, `explain`, `actions`, `policy show|lint`, `status`,
`unlock`, `lock`, `audit tail`, `login azure`, `agent-setup claude`, `agent run claude`, `doctor [--agent claude]`,
`agent-docs claude`.

**Operations:** SQL `query`, `write` (`--dry-run`), `tables`, `describe`, `count`, `sample`, and on Oracle `plan`
and `--schema`; kubectl passes any kubectl command line through one `kubectl` operation, classified per call.
Metadata operations (`status`, `targets`, `describe`, `explain`, `actions`, `policy show`, `policy lint`) work
while locked. `unlock`, `lock`, `audit-tail` and the login info are admin operations on `human.sock` only.

**Entry points:**

| Group | Names |
| --- | --- |
| `modgudr.connectors` | `sql`, `kubectl` |
| `modgudr.sql_dialects` | `snowflake`, `oracle` |
| `modgudr.secret_stores` | `file`, `bws` |
| `modgudr.credential_providers` | `azure-cli` |

**Tooling and files:** `dist/install-l0.sh`, `dist/policy.d/00-company.example.yaml`,
`dist/policy.d/50-targets.example.yaml`, `scripts/check.sh`, `scripts/sql_corpus_report.py`,
`.github/workflows/ci.yml`.

**Docs:** `README.md` (quick start, commands, exit codes, the Bitwarden licence boundary),
`docs/protocol.md` (wire protocol v1), this report, and the Claude Code skill
(`packages/client/src/modgudr/client/docs/SKILL.md`, printed by `modgudr agent-docs claude`).

**Steps that landed** (`git log`): 01 workspace skeleton, 02 client protocol/params/paths/errors, 03 policy model,
loader and lint, 04 SPI types and rule engine, 05 scrubber, sink and audit writer, 06 broker server, channels and
file store, 07 store session, secrets and pins, 08 CLI, Python API and audit tail, 09 SQL classifier and Snowflake
dialect, 10 Snowflake execution and SQL operations, 11 `agent-setup` and the hook, 12 `agent run`, `doctor` and the
skill, 13 start-up hardening, 14 the `bws` store and unlock flow, 15 Oracle classifier and corpus report, 16 Oracle
execution, 17 kubectl parser and classifier, 18 kubectl execution and the `azure-cli` provider, 19 dist, docs and CI,
20 this regression, the naming check and the report.

## 2. Test results

`sh scripts/check.sh tests -rs` (ruff check, ruff format check, pyright strict, then pytest over `tests/unit`,
`tests/contract`, `tests/integration` and `tests/e2e`):

| Result | Count |
| --- | --- |
| passed | 2505 |
| skipped | 4 |
| failed | 0 |

Wall time 341 s. ruff and pyright report no findings. `bats bats/` (`bats/modgudr_cli.bats` and
`bats/install_l0.bats`): 14 tests, 14 ok, none skipped.

Skips, with the reason:

| Skip | Why |
| --- | --- |
| `tests/integration/kubectl_kind/test_kind.py` (1) | opt-in: set `MODGUDR_TEST_KIND=1` (and `MODGUDR_KIND_KUBECONFIG`, `MODGUDR_KIND_TOKEN`). The kind test has never run against a real cluster |
| `tests/integration/snowflake/test_live.py` (2) | opt-in: set `MODGUDR_SF_LIVE=1` with a real account (R3, 22c) |
| `tests/unit/broker/test_harden.py:171` (1) | `/proc` exists on Linux only; CI runs it |

`tests/integration/oracle` ran against the Oracle Free container (Docker was up) and passed; it fails, never
skips, when Docker is missing. The Snowflake suites run in process on fakesnow.

A first full run launched from a backgrounded shell failed
`test_ctrl_c_mid_stream_is_exit_130_without_a_traceback` once: a non-interactive shell starts background jobs with
SIGINT ignored, Python then installs no handler, and the child exited 0. Run in the foreground, the test passed
five times alone and in the full run. The test relies on the default SIGINT disposition.

The new `tests/unit/test_naming.py` (M24) scans the README, `docs/` (this report included), `dist/`,
`scripts/`, `.github/`, and every `packages/*/src` file and `pyproject.toml` for a bare short-name token. It also
checks the `--help` output of the client's commands and of `modgudr-broker`, the skill text, and the files and
stdout of `agent-setup`.

## 3. Measured spike answers

| Spike | Result |
| --- | --- |
| Start-up time, `modgudr --help` | median of 10 runs of `.venv/bin/modgudr`: **91 ms** (min 82, max 133) |
| Start-up time, `modgudr status` | median of 10 runs: **111 ms** (min 82, max 265). Measured with **no broker running**, so each run exits 6 after a refused connect. A run against a live dev-mode broker was not measured |
| Anti-debug (`PT_DENY_ATTACH`, step 13) | `ptrace(PT_DENY_ATTACH)` returned **0** in the hardened child (`tests/unit/broker/test_harden.py::test_macos_ptrace_deny_attach_returns_zero` passes). It closes the ptrace path only. The Linux `PR_SET_DUMPABLE` branch is exercised only in CI |
| Peer credentials (step 06) | `socket.LOCAL_PEERCRED == 1` exists in this Python; `SOL_LOCAL` and `LOCAL_PEERPID` are not exported by `socket`, so the code passes level 0 and option 1 as numbers and parses the 76-byte `struct xucred`. A live `AF_UNIX` pair returned uid 501 for uid 501 |
| `sqlglot` | 30.24.0, forced by `override-dependencies` because fakesnow 0.11.22 declares `<30.23` (see Deviations) |
| `snowflake-connector-python` | 4.8.0 (5.x not used: fakesnow cannot import it) |
| `oracledb` | 26.0.1 (thin mode) |
| `fakesnow` | 0.11.22 |
| `pydantic` | 2.14.1 |
| `PyYAML` | 6.0.3 |

Spikes that need the real world are in section 6: Oracle by SID over the VPN (R4), a real Snowflake account (R3),
a real AKS cluster and conditional access (R5), the sandbox facts about the keychain, `launchctl` and SSH (R7, R9),
and `Edit(...)` deny with bypass mode (R8).

## 4. Deviations from the pre-plan

The M-rules that change a pre-plan statement:

- **M1, `human.sock` location.** `human.sock` lives in `$MODGUDR_HOME/run/`, inside the directory every generated
  deny list already hides, instead of beside `agent.sock`. `MODGUDR_HOME` is canonicalised and reported by
  `status --json`; `agent-setup` denies that path and isolation detection requires the denial.
- **M2, state under `~/.modgudr`.** Policy, audit, custody Azure caches, the `bws` config, state and child `HOME`,
  and the `run/` sockets all live under `MODGUDR_HOME`. This widens §4.2's "holds only the policy" on purpose.
- **M5, exit codes.** The §6.1 table gains 2 for a write rolled back for `maxAffectedRows` and for `--max-rows` above
  `maxRowsHard`, 64 for usage errors, 69 when `agent run` or `doctor --agent` cannot run, 70 for `internal`, 78 for a
  refused start-up, 130 and 141 for Ctrl-C and a closed pipe. `--allow-truncated` turns 4 into 0 for reads only.
- **M15, connector line.** `snowflake-connector-python>=4.8,<5` instead of the current 5.x.
- **M17, path flags and no discovery.** kubectl flags that take local paths are refused, and a static resource
  catalogue replaces `api-resources` discovery, so CRDs are refused as unknown.
- **M18, `listClusterUserCredential` instead of kubelogin.** The cluster endpoint and CA come from `az rest` on
  `listClusterUserCredential`, the token from `az account get-access-token`; `az aks get-credentials` is not used
  because it may invoke `kubelogin`.
- **M20, hook interpreter and drop-in.** The hook runs with `/usr/bin/python3 -I` from a root-owned
  `/opt/modgudr/bin/` path and is compatible with Python 3.9. The settings are a drop-in
  `managed-settings.d/50-modgudr.json`, so the company's `managed-settings.json` is never touched.

Deviations recorded by the steps (kept as written), then those of step 20:

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

- **Step 20, three lines keep the bare short name, on an exact-line allowlist.** `tests/unit/test_naming.py`
  allows two lines of the alias block in `dist/install-l0.sh` (the `command -v` lookup and the `ln -s` that creates
  the alias of M24 only when nothing else has that name) and the one `ctx.which(...)` call in
  `packages/client/src/modgudr/client/agent/doctor.py` (the PATH lookup for the `doctor` INFO line). The regex is
  not weakened for anything else; the hook file name and the temporary-directory prefix pass because the token
  must not be followed by `-`. The messages around them were reworded: the `doctor` INFO line now reads "<path> is
  on PATH and is not modgudr (on macOS it is an editor); the command is modgudr" or "no other command shadows the
  short name; the command is modgudr", and `install-l0.sh` says "the short alias name is already taken". The two
  `test_doctor.py` assertions and the `api.py` docstring example changed with them.

## 5. Accepted gaps

From "Considered and not built" (what would change the call is in the plan):

| Item | Why not now |
| --- | --- |
| `bitwarden-sdk` in-process instead of the `bws` CLI | It would make modgudr an application built on a proprietary, beta SDK and put the SDK into the public Apache-2.0 repository's lockfile. The licence forbids derivative works and offering the application to third parties (confirmed by the Q5 answer). The CLI is a tool the developer installs |
| Bundling, downloading or installing `bws` from `install-l0.sh`, CI or an image | The licence forbids redistribution; written permission from Bitwarden would change it |
| A `bw` (Password Manager vault) store | Q1 and Q6 chose Secrets Manager (`bws`); the MVP builds one store |
| `snowflake-connector-python` 5.x | fakesnow cannot import it (measured); released six days before the plan |
| `kubectl api-resources` discovery for CRDs | One more cluster call before deciding; the trial's resources are core kinds |
| Environment and host pins for `provider:` (AKS) targets | At L0 the agent cannot edit the targets file under the managed settings, and any other same-uid process can use `~/.azure` directly, so the pin adds nothing; it matters at L1 |
| `reload` on `human.sock` and `SIGHUP` | Not in §14.1; a restart plus unlock is enough for one developer |
| Policy-driven extra environment for `agent run` | `--pass-env` covers it without a schema key |
| `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, `blockReadsOutsideWorkingDirectories` | They break `--allowedTools` for the self-test, kill the developer's own hooks, and make `modgudr` under `$HOME` unreadable. R8 decides |
| Sandbox runtime (`srt`) settings from `agent-setup` | I6 per §14.3; the `borrowed` AKS target runs at L0 with the Bash sandbox only |
| Keeping the `bws` token out of the child's environment | `bws` takes the token only from `BWS_ACCESS_TOKEN` or `--access-token` (argv is worse); the in-process SDK is the only way to avoid it and it is not built. R2 checks it |
| Snowflake per-call cancel with `execute_async` + `SYSTEM$CANCEL_QUERY` | Statement timeout plus discarding the connection bounds the cost; fakesnow cannot exercise it. R3 checks it |
| Classifying `v$sql`/`v$sql_bind_capture` as `secret` | The Oracle diagnostics skills need them; SQL text and bind values are data (§1) |
| An Oracle `currentSchema` target key | `--schema` per call (Q3) covers the skills |
| `columns`, `batch`, `tx`, breaker, rights probe, `unattended` | Explicitly outside §14.1 (I5, I8, I2) |
| A `pilot` meta-extra on `modgudr-broker` | It would create a dependency cycle (connectors depend on the broker for `spi`); `install-l0.sh` lists the distributions |
| `Bash(security:*)`-style blocks presented as protection | Bash rules match text only; they are listed for steering |
| testcontainers for Oracle | Its Oracle class moved in 4.15 and its docs are stale; the `docker` CLI fixture is simpler |
| Refusing a non-default `MODGUDR_HOME` outside `--dev` | Tests and any second install need it; the deny list and the isolation predicate follow the canonical path instead |
| A Linux CI test of the real Claude Code sandbox against `human.sock` | CI has no logged-in Claude Code; the predicate and generator are unit-tested, and `doctor --agent` probes the broker-reported `human.sock` on the developer's machine (R7) |
| A subprocess-runner seam in place of the fake executables | It would bypass the child-environment allowlists that the fake logs prove |
| `fetch_lobs=False` | The driver materialises the whole value before any budget check, so `maxBytes` would not bound memory (M16) |
| `audit tail --follow` | `-n` and the filters cover inspection after a session |

Also accepted:

- **LONG / LONG RAW memory (M16).** Oracle `LONG` and `LONG RAW` columns are fetched whole by the driver before
  `maxBytes` can apply. A LOB over the budget is refused after it was read, and the limit is named in the audit
  record.
- **The hook bypass:** `bash -c "kubectl …"` gets past the hook (step 11). The hook is steering; the sandbox is the
  boundary.
- **Short secrets in row data:** the scrubber protects secrets under 8 characters only partially (step 05).
- **An unknown user function classifies as `read`** (A9). On `custody` targets a user-defined function with an
  autonomous transaction can write from a `SELECT`; the admin and secret catalogues must be complete.
- **Oracle RAC listener redirect:** a SCAN listener can redirect to a host that is not in the pin; pinning checks the
  configured host and port (step 16).
- **The keychain is reachable from the sandbox:** `doctor --agent` reports it as WARN.
- **Completion records are lost on SIGKILL,** and kubectl children and database sessions can run on until they
  next write or time out (Snowflake is bounded by its statement timeout).
- **No per-channel row cap for the agent** (step 08): the agent may request `maxRowsHard` (50,000) rows into its
  transcript.
- **Edge-case report §5** (`secret-broker-pilot-final-plan-research/edge-cases.md`), in addition to the above:
  `v$sql`, `v$sql_bind_capture` and `INFORMATION_SCHEMA.QUERY_HISTORY` expose other sessions' SQL text and bind
  values (data, not credentials); Snowflake has no read-only transaction; the `bw` master password would pass
  through a child environment (not built; prefer `bws`); policy changes need a restart, and a restart locks the
  store.
- **Never exercised for real:** the CI workflow, the kind test, `install-l0.sh` without `--dry-run`, and the
  Oracle, Snowflake and AKS paths against real systems.

## 6. Post-run checklist

Run these by hand. `modgudr` is the installed command; every host below is an example.

| # | Check | Commands and what to look for |
| --- | --- | --- |
| R1 | Install at L0; install the company file root-owned; start the broker | `sh dist/install-l0.sh`; `sudo install -o root -m 0644 dist/policy.d/00-company.example.yaml ~/.modgudr/policy.d/00-company.yaml` (the script prints the exact command); `modgudr-broker lint`; `modgudr-broker` in its own terminal |
| R2 | Bitwarden Secrets Manager | In the web vault create a Free organisation, subscribe it to Secrets Manager, create one project `modgudr` and one machine account with **read-only** access to that project only, and give its access token an expiry. Install `bws` from the pinned GitHub release zip and check it against the published checksum file (no Homebrew formula; no pipe-to-shell). Store each secret with `modgudr-hosts:` and `modgudr-env:` lines in its note. **Never export `BWS_ACCESS_TOKEN` in your shell**; type it only at `modgudr unlock`. Check the idle lock and that a pin mismatch is refused and audited (`modgudr audit tail`). After `modgudr unlock` and one resolve, `ls -A ~/.modgudr/bws/` must show only `config` and empty state directories. Beyond the trial the secrets move to the company's paid organisation; only the company file changes |
| R3 | Snowflake, real account | `modgudr sf query -p …` with the key from Bitwarden; `modgudr.connect().sql("sf")`; Ctrl-C cancels; `QUERY_TAG` visible in query history; decide 22b in the company file; ask about 22c. Optionally `MODGUDR_SF_LIVE=1 sh scripts/check.sh tests/integration/snowflake/test_live.py` |
| R4 | Oracle over the VPN | A test database by SID with the read-only diagnostics user; `dba_users` refused; the VPN-down message names the host; a `stage` or `prod` target (24b) |
| R5 | AKS | `modgudr aks@test kubectl get pods -n <ns>` through your login; `delete pods --all`, `--as` and `get secrets` refused; your own `kubectl` still works; `modgudr login azure aks-test` and what conditional access does; 13b: `az aks get-credentials --admin` must fail. Optionally the kind test with `MODGUDR_TEST_KIND=1`, `MODGUDR_KIND_KUBECONFIG`, `MODGUDR_KIND_TOKEN` |
| R6 | Managed settings | `modgudr agent-setup claude`; install the drop-in and the hook with the printed `sudo` steps; `claude doctor` and `/status` show the drop-in and no skipped sources |
| R7 | `doctor --agent` | `modgudr doctor --agent claude` passes with the managed settings; run it without them and record that it fails (it spends API tokens) |
| R8 | Manual red-team at L0 (§13, five tasks) | Against the Snowflake target, then one target per tier; repeat with bypass mode forced on and with no isolation, and record what each stops. Decide the "not built" managed-settings keys of section 5 from this |
| R9 | Sandbox facts the docs leave open | Inside the sandboxed Bash tool: `security find-generic-password`, `launchctl`, `git push` over SSH; whether `claude -p` accepts `--max-turns` |
| R10 | Real-query corpus | `uv run --locked python scripts/sql_corpus_report.py --dialect oracle <dir>` and `--dialect snowflake <dir>`; put the unknown rate and the missing catalogue names into the ledger |
| R11 | Convert the existing Oracle diagnostics skills (another repository) per the answers to Q3 and Q4 | §15.2 |
| R12 | The one-week trial (§14.2 step 6) | Then apply the ledger row of section 8 to §14.4 |

## 7. Still open (pre-plan §17)

- **22b.** Is the single Snowflake environment production data (ceiling `read`) or test data? The plan assumes `read`
  until told otherwise.
- **22c.** Can a Snowflake trial account be used for the integration and leak tests in CI?
- **24b.** Which Oracle database is the `stage` or `prod` target for the MVP trial, and does the read-only
  diagnostics user exist there yet?
- **13b.** Do the AKS clusters have local accounts disabled (`az aks get-credentials --admin` must not work)?

## 8. Proposed §14.4 ledger row

**Built:** the L0 MVP of §14.1: a stdlib-only client, a broker with two sockets, the two-layer policy and six-layer
rule engine, the `file` and `bws` stores, the `sql` connector (Snowflake, Oracle), the `kubectl` connector with the
`azure-cli` provider, `agent-setup`/`agent run`/`doctor`, the Claude Code skill, start-up hardening, audit and
scrubber, dist, docs and CI. 2505 tests pass, 4 skip by design, 14 BATS tests pass. Start-up is about 90 ms
(`--help`) and 110 ms (`status`, no broker).

**What planning taught:**

- The M-rules changed the pre-plan in the places listed in section 4: `human.sock` inside `MODGUDR_HOME`, all state
  under `~/.modgudr`, the extended exit codes, the 4.x Snowflake connector, kubectl without discovery or path
  flags, `listClusterUserCredential` instead of kubelogin, and the managed drop-in with a root-owned Python 3.9
  hook.
- The Bitwarden licence finding: both the SDK and `bws` are under the proprietary Bitwarden SDK License, so
  modgudr calls the `bws` CLI the developer installs and never bundles, downloads or depends on either.
- The Linux socket mechanism: `allowUnixSockets` is macOS only and matches by `subpath`, so on Linux the protection
  of `human.sock` comes from the deny entry for the directory that holds it.
- The macOS keychain is reachable from the sandbox: the sandbox profile allows `com.apple.SecurityServer`, so the
  design no longer assumes the keychain is hidden, and `doctor --agent` warns.
- Git over SSH fails inside the macOS sandbox (R9 records the facts the docs leave open).
- fakesnow forced two pins (sqlglot 30.24.0 by override, the connector below 5).

**Suggested next increment:** I1 (L1), unless R7 or R8 show that the managed settings do not hold at L0, in which
case fix that first.
