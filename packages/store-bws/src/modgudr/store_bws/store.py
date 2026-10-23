"""The Bitwarden Secrets Manager store, `bws` (M19), at L0.

The store drives the `bws` CLI as a subprocess: an argv array, stdin closed, a 30 s limit and an
environment built from an allowlist. The machine-account access token is typed at `modgudr unlock`,
arrives over `human.sock`, is kept in memory only and reaches a child only as `BWS_ACCESS_TOKEN`,
never on argv. `bws` is installed and licensed by the developer; modgudr contains no Bitwarden
code and never imports the SDK.

- **Unlock** checks the token with `bws project list --output json`: the command must succeed and
  list the configured project.
- **Resolve** is `bws secret get <uuid> --output json`: one secret object, or a one-element array.
  The secret must be in the configured project. The `note` goes back to the broker, which parses
  its strict `modgudr-hosts:` / `modgudr-env:` pin lines (M8).
- **Lock** drops the token, ends running children and empties both state paths.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import shutil
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from modgudr.spi import (
    ResolvedSecret,
    SecretRef,
    StoreConfigError,
    StoreContext,
    StoreError,
    StoreSessionInvalid,
    UnlockRefused,
)

from .settings import BwsSettings, parse_settings
from .state import CONFIG_NAME, bws_dir, empty_state, write_config

log = logging.getLogger("modgudr.broker")

SCHEME = "bws"
#: A `bws` child is ended after this many seconds.
CHILD_TIMEOUT = 30.0
#: What a `bws` child may print to stdout and stderr.
MAX_OUTPUT = 4 * 1024 * 1024

WARNING = (
    "the bws access token is handed to each `bws` child through its environment; any process "
    "running as you can read it while the child runs. The 10-minute secret cache keeps children "
    "rare, and L1 closes this exposure"
)

#: `Error:` and the `0: ` numbering of the cause chain, before the cause itself.
_ERROR_PREFIX = re.compile(r"^(Error:\s*)?(\d+:\s*)?")
#: Words in `bws` stderr that mean the access token was refused (revoked, expired, wrong).
_AUTH_MARKERS = ("access token", "invalid_client", "unauthorized", "401")


class _Failed(Exception):
    """A `bws` child that did not succeed. Never shown: it may hold what `bws` printed."""

    def __init__(self, stderr: str, *, code: int | None = None, reason: str | None = None) -> None:
        super().__init__(reason or "bws failed")
        self.stderr = stderr
        self.code = code
        self.reason = reason

    @property
    def auth(self) -> bool:
        text = self.stderr.lower()
        return any(marker in text for marker in _AUTH_MARKERS)


class BwsStore:
    """The `SecretStore` for scheme `bws`."""

    scheme = SCHEME

    def __init__(self, context: StoreContext) -> None:
        if context.dev:
            raise StoreConfigError("dev mode refuses the bws store: use the file store with --dev")
        try:
            self._settings: BwsSettings = parse_settings(context.settings)
        except ValueError as exc:
            raise StoreConfigError(str(exc)) from None
        self._home = context.home
        found = shutil.which("bws", path=context.path) if context.path else None
        self._bws: str | None = str(Path(found).absolute()) if found else None
        self._path = context.path
        uid = os.getuid()
        try:
            self._config = write_config(self._home, self._settings.serverUrl, uid=uid)
            removed = empty_state(self._home)
        except OSError as exc:
            raise StoreConfigError(str(exc)) from None
        if removed:
            log.warning("bws: removed state found at start: %s", ", ".join(removed))
        self._token: str | None = None
        self._children: set[asyncio.subprocess.Process] = set()

    # --- what the broker reports ----------------------------------------------------------------

    def facts(self) -> Mapping[str, object]:
        facts: dict[str, object] = {
            "bws": self._bws,
            "project": self._settings.project,
        }
        if self._bws is None:
            facts["problem"] = "bws not found on the broker's PATH; unlock will fail"
        return facts

    def warnings(self) -> Sequence[str]:
        return (WARNING,)

    # --- the SecretStore interface --------------------------------------------------------------

    def is_unlocked(self) -> bool:
        return self._token is not None

    async def unlock(self, credential: str) -> None:
        if self._bws is None:
            raise StoreError("bws not found on the broker's PATH")
        if not credential or any(c in credential for c in "\r\n\x00"):
            raise UnlockRefused("the access token is empty or malformed")
        project = self._settings.project
        try:
            out = await self._run(credential, "project", "list", "--output", "json")
        except _Failed as exc:
            if exc.auth:
                raise UnlockRefused("bws refused the access token") from None
            why = _first_line(exc, credential)
            raise StoreError(f"bws could not check the access token: {why}") from None
        if project not in _project_ids(out):
            raise UnlockRefused(f"the access token cannot see the configured project {project}")
        self._token = credential

    async def resolve(self, ref: SecretRef) -> ResolvedSecret:
        token = self._token
        if token is None:
            raise StoreError("the bws store is locked")
        if ref.store != SCHEME:
            raise StoreError(f"the bws store cannot resolve {ref}")
        try:
            item = str(uuid.UUID(ref.item))
        except ValueError:
            raise StoreError(f"secret {ref} is not a bws secret uuid") from None
        try:
            out = await self._run(token, "secret", "get", item, "--output", "json")
        except _Failed as exc:
            if self._token is None:
                raise StoreError("the bws store was locked") from None
            if exc.auth:
                raise StoreSessionInvalid("bws rejected the access token") from None
            raise StoreError(f"secret {ref} cannot be fetched: {_first_line(exc, token)}") from None
        secret = _one_secret(out, ref, item)
        if secret.get("projectId") != self._settings.project:
            raise StoreError(f"secret {ref} is not in the configured project")
        value = secret.get("value")
        if not isinstance(value, str) or not value:
            raise StoreError(f"secret {ref} has no value")
        note = secret.get("note")
        return ResolvedSecret(ref=ref, value=value, note=note if isinstance(note, str) else None)

    async def lock(self) -> None:
        self._token = None
        for child in list(self._children):
            with contextlib.suppress(ProcessLookupError):
                child.kill()
        try:
            empty_state(self._home)
        except OSError as exc:
            log.warning("bws: state could not be emptied: %s", exc.strerror)

    # --- children -------------------------------------------------------------------------------

    def _environment(self, token: str) -> dict[str, str]:
        return {
            "PATH": self._path,
            "HOME": str(bws_dir(self._home)),
            "BWS_CONFIG_FILE": str(bws_dir(self._home) / CONFIG_NAME),
            "BWS_ACCESS_TOKEN": token,
        }

    async def _run(self, token: str, *args: str) -> str:
        """One `bws` child: argv array, stdin closed, the allowlisted environment, 30 s."""
        assert self._bws is not None
        try:
            child = await asyncio.create_subprocess_exec(
                self._bws,
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._environment(token),
                cwd=str(bws_dir(self._home)),
                start_new_session=True,
                limit=MAX_OUTPUT,
            )
        except OSError as exc:
            raise _Failed("", reason=f"bws cannot be started: {exc.strerror}") from None
        self._children.add(child)
        try:
            try:
                async with asyncio.timeout(CHILD_TIMEOUT):
                    stdout, stderr = await child.communicate()
            except TimeoutError:
                raise _Failed("", reason=f"bws did not answer within {CHILD_TIMEOUT:g} s") from None
        finally:
            self._children.discard(child)
            if child.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    child.kill()
                await child.wait()
        text = stderr.decode("utf-8", "replace")
        if child.returncode != 0:
            raise _Failed(text, code=child.returncode)
        return stdout.decode("utf-8", "replace")


def _first_line(exc: _Failed, token: str) -> str:
    """The first line of `bws` stderr, with the token removed; the broker scrubs the rest.

    `bws` 2.x prints `Error:` on a line of its own and the cause below it as `0: <cause>`, so both
    prefixes are dropped.
    """
    if exc.reason:
        return exc.reason
    for line in exc.stderr.splitlines():
        text = _ERROR_PREFIX.sub("", line.strip().replace(token, "[redacted]"))
        if text:
            return text[:300]
    return f"exit {exc.code}"


def _project_ids(out: str) -> set[str]:
    try:
        data: object = json.loads(out)
    except ValueError:
        raise StoreError("bws printed something that is not JSON for `project list`") from None
    if not isinstance(data, list):
        raise StoreError("bws printed something other than a list for `project list`")
    ids: set[str] = set()
    for entry in cast("list[object]", data):
        if isinstance(entry, dict):
            value = cast("dict[str, object]", entry).get("id")
            if isinstance(value, str):
                with contextlib.suppress(ValueError):
                    ids.add(str(uuid.UUID(value)))
    return ids


def _one_secret(out: str, ref: SecretRef, item: str) -> dict[str, object]:
    """One secret object, or a one-element array (the docs disagree); anything else is refused."""
    try:
        data: object = json.loads(out)
    except ValueError:
        raise StoreError(f"bws printed something that is not JSON for secret {ref}") from None
    if isinstance(data, list):
        items = cast("list[object]", data)
        if len(items) != 1:
            raise StoreError(f"bws printed {len(items)} secrets for {ref}; exactly one is expected")
        data = items[0]
    if not isinstance(data, dict):
        raise StoreError(f"bws printed something other than a secret for {ref}")
    secret = cast("dict[str, object]", data)
    got = secret.get("id")
    if got is not None:
        try:
            same = isinstance(got, str) and str(uuid.UUID(got)) == item
        except ValueError:
            same = False
        if not same:
            raise StoreError(f"bws printed a different secret than {ref}")
    return secret
