---
name: modgudr
description: Reach databases and Kubernetes clusters through the modgudr broker, which holds the credentials. Use it for any query, write or kubectl command against a configured target; never ask the user for a password or a token.
---

# modgudr

modgudr is a local secret broker. The credentials for databases and clusters live in the broker,
not in this session. You call a target through the `modgudr` command; the broker decides, runs the
call, hides secrets in the output and writes an audit record.

Never ask the user for a password, a token or a connection string. Never look for credentials in
files or environment variables, and never run `kubectl`, `az`, `sqlplus`, `snowsql` or a database
driver yourself: the sandbox blocks them on purpose. If you need access that no target gives you,
say so and stop.

## Start here

1. `modgudr targets` lists the targets: name, type, environment, tier and operations.
2. `modgudr describe <target>` shows one target's operations, limits and facts.
3. `modgudr explain <target> <op> ...` says what the policy would decide for a call, without running
   anything. Use it when a call was denied, or before a call you are unsure about.
4. `modgudr <target> <op> ...` runs the operation. `system@env` (for example `orders@test`) picks
   the environment; without it the session's environment or the policy's default applies.

The target list comes from `modgudr targets` at run time; do not guess names.

## Working with SQL targets

- Look before you read wide: `modgudr <target> tables`, `describe <table>`, `count <table>` and
  `sample <table>` first, then a narrow `query`.
- **Bind values with `-p`, never by pasting them into SQL.** `-p name=value` binds a string;
  `-p name:int=42`, `-p name:decimal=1.50`, `-p name:date=2026-10-21`,
  `-p name:timestamp=2026-10-21T08:00:00` and `-p name:null` give other types. Refer to a
  bind in the statement as `:name`.

      modgudr orders-test query "select id, status from orders where id = :id" -p id:int=42

- Run a write with `--dry-run` first. It runs in a transaction and rolls it back, and reports the
  affected rows. Run the real write only after you have seen the dry run.

      modgudr orders-test write --dry-run "update orders set status = :s where id = :id" \
          -p s=shipped -p id:int=42

- Keep results small. The broker truncates at its row and byte limits (exit 4); narrow the query
  or lower `--max-rows` instead of asking for more. `--allow-truncated` accepts a truncated read.
- Output formats: `--format tsv|csv|json|ndjson|table`, and `--no-header`.

## Kubernetes targets

`modgudr <target> kubectl get pods -n app` runs `kubectl` with the arguments as separate words.
The broker classifies the command; reads are allowed, changes are checked against the policy, and
some commands are never allowed.

## Python scripts

When you write a Python script that needs data, use `import modgudr` and `modgudr.connect()`, not a
database driver with a password:

    import modgudr
    rows = modgudr.connect().sql("orders-test").query(
        "select id from orders where status = :s", params={"s": "new"}
    )

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | ok | |
| 2 | denied by the policy, the pinning, a ceiling or a constraint; also a write rolled back for `maxAffectedRows`, and `--max-rows` above the hard limit | Read the message. `modgudr explain` shows the rule. Do not try to get around it; tell the user |
| 3 | locked: the broker's store is locked | Tell the user to run `modgudr unlock` in their own terminal. You cannot unlock |
| 4 | truncated by a row or byte limit, or timed out | Narrow the query; do not repeat it unchanged |
| 5 | upstream error: the database, `kubectl` or the store failed | Read the message; the cause is usually the statement or the target |
| 6 | broker unavailable, or an admin command (`unlock`, `lock`, `audit tail`) that an agent session cannot run | Tell the user to start the broker or run the admin command themselves |
| 7 | throttled: too many calls at once or too many failed unlocks | Wait the number of seconds in the message, then try once more |
| 64 | usage error: a bad option, bind or name; the message lists the valid values | Fix the command |
| 70 | internal error, including an audit log that cannot be written | Report it to the user |

## Sessions

`modgudr agent run claude` starts Claude Code with a clean environment and sets
`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`. That variable turns the sandbox's automatic approval of Bash
commands off: a Bash command that is not in the allow list asks the user to approve it. The
`modgudr` command itself is allowed. Expect a prompt for anything else, and keep commands plain so
that the user can read them.
