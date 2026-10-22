# modgudr wire protocol, version 1

The client (`modgudr` on the command line, `import modgudr` in Python) and the broker talk over a
Unix socket with newline-delimited JSON. This page is the whole contract. Both ends are written
against it, and the broker's tests pin it.

## Sockets

| Socket | Path | Operations |
| --- | --- | --- |
| `agent.sock` | macOS `~/Library/Caches/modgudr/run/agent.sock`; Linux `$XDG_RUNTIME_DIR/modgudr/agent.sock`, else `/tmp/modgudr-<uid>/agent.sock`. Override: `MODGUDR_SOCKET` | target operations and the metadata operations |
| `human.sock` | `$MODGUDR_HOME/run/human.sock` (`MODGUDR_HOME` defaults to `~/.modgudr`) | everything on `agent.sock`, plus `unlock`, `lock`, `audit-tail`, `login-info` |

An admin operation sent to `agent.sock` is refused with `unavailable` and audited. A socket path
longer than 103 bytes is an error.

## One request per connection

The client connects, writes **one** request line, and reads response lines until the broker closes
the connection. There is no pipelining and no second request on a connection.

The broker gives a client 10 seconds to deliver the request line. A request line larger than
`maxRequestBytes` (policy default 1 MiB) is `bad_request`.

## Request

A single JSON object on one line, UTF-8, ending in `\n`:

```json
{"v":1,"op":"query","target":"ora-test","env":"test","args":{"sql":"select 1 from dual"},
 "client":{"name":"cli","version":"0.1.0","script":"report.py","agentHint":"claude","cwd":"/work","session":"s-1f3c"}}
```

(Shown on two lines here; on the wire it is one.)

| Key | Type | Meaning |
| --- | --- | --- |
| `v` | integer | the protocol version, `1` |
| `op` | string | the operation: `query`, `write`, `tables`, `describe`, `count`, `sample`, `plan`, `kubectl`, `status`, `targets`, `explain`, `actions`, `policy-show`, `policy-lint`, `unlock`, `lock`, `audit-tail`, `login-info`, … |
| `target` | string, optional | a target name, or `system@env` |
| `env` | string, optional | the client's `MODGUDR_ENV` |
| `args` | object | operation-specific arguments |
| `client` | object, optional | `name`, `version`, `script`, `agentHint`, `cwd`, `session`; audit context only, never trusted |

**Unknown keys.** Unknown top-level keys and unknown keys inside `client` are ignored. Unknown
keys inside `args` are `bad_request`.

**Target resolution.** An exact target name wins, and `env` is then ignored. Otherwise `system@env`
(aliases allowed). Otherwise the system plus the request's `env`, else the policy's `defaults.env`.
A system without a target in the environment gives `not_found`, which names where the environment
came from.

### Bind parameters

Bind parameters travel in `args.params`, never inside the SQL text:

```json
{"params":{"id":{"t":"int","v":42},"status":{"t":"str","v":"new"},"note":{"t":"null","v":null}}}
```

| `t` | `v` |
| --- | --- |
| `str` | a JSON string |
| `int` | a JSON integer |
| `decimal` | a string in plain notation, for example `"1.50"` |
| `date` | an ISO 8601 date string |
| `timestamp` | an ISO 8601 timestamp string |
| `bytes` | a base64 string |
| `null` | `null` |

In SQL a bind is written `:name`. A bind that the statement does not use, or a placeholder without
a bind, is `bad_request`.

## Response frames

The response is a stream of JSON lines. Each has a `t` key naming its type.

| `t` | Fields | Used for |
| --- | --- | --- |
| `header` | `columns`: `[{"name": …, "type": …}]` | the start of a result set |
| `row` | `v`: an array with one cell per column | one result row |
| `text` | `stream` (`stdout`, `stderr`, `audit`), `data` | `kubectl` output and `audit tail` lines |
| `result` | `data` | the answer of a metadata operation |
| `trailer` | `rows`, `bytes`, `truncated`, `reason`, `durationMs`, `auditId`, `scrubbed`; for writes also `affectedRows`, `committed`, `dryRun`; for commands `exitCode` | the end of a successful or truncated call |
| `error` | `code`, `message`, `auditId`; optionally `layer`, `rule`, `retryAfter` | the end of a failed call |

Column types: `integer`, `number`, `string`, `date`, `timestamp`, `timestamp_tz`, `time`, `binary`,
`boolean`, `variant`, `interval`, `other`.

A call that returns rows sends one `header`, then `row` frames, then a `trailer`:

```json
{"t":"header","columns":[{"name":"ID","type":"integer"},{"name":"NAME","type":"string"}]}
{"t":"row","v":["1","alice"]}
{"t":"trailer","rows":1,"bytes":24,"truncated":false,"reason":null,"durationMs":12,"auditId":"a-01","scrubbed":0}
```

**The end of a stream.** Every response ends in exactly one `trailer` or one `error`. An `error`
may follow data frames and then replaces the trailer. A connection that ends with neither is an
error at the client (`unavailable`, exit 6).

**Truncation.** A call cut off by `maxRows` or `maxBytes` ends in a `trailer` with
`truncated: true` and `reason` (`rows` or `bytes`). A timeout ends in an `error` with code
`timeout`. The client maps both to exit 4.

## Values

- Numbers are strings in plain notation: no exponent and no float loss. `"1E+3"` is sent as
  `"1000"`. The exception is `boolean`, which is a JSON boolean.
- Dates and timestamps are ISO 8601 strings; `timestamp_tz` carries its offset.
- `binary` is base64.
- NULL is JSON `null`, for every type.
- `variant`, objects and arrays are JSON text inside a string cell.
- Secrets that the broker knows are replaced in every string before it is sent, and the trailer's
  `scrubbed` counts the replacements.

## Versioning

`v` is `1`. A request with another `v` gets `bad_request` and a message naming the supported
versions, `[1]`. `modgudr status` prints the client's and the broker's protocol versions.

## Cancellation

The broker reads the request socket while the call executes. **End of file cancels the call**: the
broker stops the statement or the child process, rolls back an uncommitted write, and audits the
call as cancelled. Clients must therefore not half-close their side of the socket after sending the
request. A client that wants to stop a call closes the connection.

A write whose COMMIT was already sent when the connection closed is recorded `committed: true`; any
other interrupted write is rolled back (`committed: false`).

## Error codes

| `code` | Meaning | Client exit |
| --- | --- | --- |
| `denied` | policy, pinning, ceiling or a constraint; also a write rolled back for `maxAffectedRows`, and `--max-rows` above `maxRowsHard`. `layer` and `rule` say which | 2 |
| `locked` | the store is locked; a human must `unlock` | 3 |
| `limit` | the call was truncated by `maxRows` or `maxBytes` | 4 |
| `timeout` | the call ran past its timeout; a write is rolled back | 4 |
| `upstream` | the database, `az` or `kubectl` failed (the raw exit code is in `exitCode`), a store item is missing, or authentication failed after the retry | 5 |
| `unavailable` | the broker is down, an admin operation came from an agent session, or the connection was lost without a trailer | 6 |
| `throttled` | `maxConcurrent` is used up, or too many failed unlocks; `retryAfter` gives the seconds. Calls are never queued | 7 |
| `bad_request`, `not_found` | a malformed request, an unknown operation or target; the message lists the valid values | 64 |
| `internal` | a broker fault, including an audit log that cannot be written | 70 |

Exits 130 (Ctrl-C) and 141 (the reader closed the pipe) come from the client's own process and have
no frame.

## Call order

The broker handles a call in a fixed order: frame the request, resolve the target, validate the
arguments, classify and decide with the declared environment, take the `maxConcurrent` slot, check
that the store is unlocked, resolve the secret and its pins and decide again with the effective
environment, write the audit `decision` record, execute, then commit or roll back and write the
`completion` record. A denial returns early and costs no slot. Metadata operations (`status`,
`targets`, `describe`, `explain`, `actions`, `policy-show`, `policy-lint`) work while the store is
locked and are not audited.
