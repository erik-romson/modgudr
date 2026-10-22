"""The `azure-cli` credential provider (§8.4, M18): AKS endpoints and tokens from the Azure CLI.

- **Endpoint.** `az rest --method post --url https://management.azure.com/subscriptions/<S>/
  resourceGroups/<RG>/providers/Microsoft.ContainerService/managedClusters/<N>/
  listClusterUserCredential?api-version=2025-10-01`. Only the server URL and
  `certificate-authority-data` are taken from the decoded kubeconfig; the rest (an exec user, or
  a client certificate and a static token on a cluster without Entra ID) is discarded. Not
  `az aks get-credentials`: it may run `kubelogin convert-kubeconfig`. Cached until lock.
- **Token.** `az account get-access-token --resource <AKS server app> -o json`; `accessToken` and
  `expires_on` are used. Cached until 5 minutes before it expires, single-flight.
- **Children.** `az` runs as an argv array with stdin closed, a 30 s limit, its own process group
  and an environment built from an allowlist, never inherited (M3): `PATH`, `HOME` (the `pwd`
  home), `LANG`, `LC_*`, and `AZURE_CONFIG_DIR` for `custody` only.
- **Tiers.** `borrowed` uses the developer's own login (`AZURE_CONFIG_DIR` unset, so `az` reads
  `~/.azure` of the `pwd` home). `custody` uses `$MODGUDR_HOME/azure/<system or target>/` (0700),
  which `modgudr login azure <target>` fills.
- **Errors.** "Please run 'az login'" and AADSTS errors say how to log in again; other failures
  give `az`'s first error line, which the broker scrubs. Every failure is `UpstreamFailure`.

`az` is found on the broker's `PATH` at start; a missing one shows in `status` and `targets`.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import json
import logging
import os
import shutil
import signal
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import quote, urlsplit

from modgudr.broker.policy.yaml_strict import StrictYamlError, load_strict
from modgudr.broker.server import StartError, ensure_private_dir
from modgudr.spi import (
    Destination,
    Endpoint,
    EndpointRequest,
    MintedToken,
    ProviderContext,
    ProviderTarget,
    TokenRequest,
    UpstreamFailure,
)

log = logging.getLogger("modgudr.broker")

NAME = "azure-cli"
TIERS = frozenset({"borrowed", "custody"})

#: Azure Resource Manager and the API version of `listClusterUserCredential` (M18).
ARM = "https://management.azure.com"
API_VERSION = "2025-10-01"
#: An `az` child is ended after this many seconds.
AZ_TIMEOUT = 30.0
#: A cached token is used until this many seconds before it expires.
REFRESH_MARGIN = 300.0
#: The most of a decoded kubeconfig that is parsed.
MAX_KUBECONFIG = 1024 * 1024
#: The cluster keys the endpoint request must carry.
CLUSTER_KEYS = ("subscription", "resourceGroup", "name")

_LOGIN_MARKERS = ("please run 'az login'", 'please run "az login"', "aadsts")


@dataclass(frozen=True)
class _Login:
    """Which Azure CLI login a target uses: the developer's (borrowed) or its own (custody)."""

    target: str
    config_dir: Path | None

    @property
    def key(self) -> str:
        return "borrowed" if self.config_dir is None else str(self.config_dir)


class AzureCliProvider:
    """The `CredentialProvider` named `azure-cli`."""

    def __init__(self, context: ProviderContext) -> None:
        self._context = context
        found = shutil.which("az", path=context.path) if context.path else None
        self._az: str | None = str(Path(found).absolute()) if found else None
        self._endpoints: dict[tuple[str, str], Endpoint] = {}
        self._tokens: dict[tuple[str, str], MintedToken] = {}
        self._flights: dict[tuple[str, str, str], asyncio.Lock] = {}
        #: Changes on every lock: a result that arrives after a lock is not cached.
        self._generation = 0
        self._children: set[asyncio.subprocess.Process] = set()

    @property
    def name(self) -> str:
        return NAME

    @property
    def tiers(self) -> frozenset[str]:
        return TIERS

    def facts(self) -> Mapping[str, object]:
        facts: dict[str, object] = {"az": self._az}
        if self._az is None:
            facts["problem"] = (
                "az (the Azure CLI) is not on the broker's PATH; calls of azure-cli targets fail"
            )
        return facts

    def state_dir(self, target: ProviderTarget) -> Path | None:
        if target.tier != "custody":
            return None
        directory = self._context.home / "azure" / target.system
        try:
            ensure_private_dir(directory, uid=os.getuid(), warn=log.warning)
        except StartError as exc:
            raise UpstreamFailure(f"the custody directory cannot be used: {exc}") from None
        return directory

    # --- endpoint and token ---------------------------------------------------------------------

    async def endpoint(self, request: EndpointRequest) -> Endpoint:
        url = credential_url(dict(request.cluster))
        login = self._login(request.target)
        key = (login.key, url)
        async with self._flight("endpoint", key):
            cached = self._endpoints.get(key)
            if cached is not None:
                return cached
            generation = self._generation
            out = await self._run(login, "rest", "--method", "post", "--url", url, "-o", "json")
            found = parse_cluster_credential(out)
            if generation == self._generation:
                self._endpoints[key] = found
            return found

    async def mint(self, request: TokenRequest) -> MintedToken:
        login = self._login(request.target)
        key = (login.key, request.resource)
        async with self._flight("token", key):
            cached = self._tokens.get(key)
            if cached is not None and time.time() < cached.expires_at - REFRESH_MARGIN:
                return cached
            generation = self._generation
            out = await self._run(
                login,
                "account",
                "get-access-token",
                "--resource",
                request.resource,
                "-o",
                "json",
            )
            token = parse_access_token(out)
            if generation == self._generation:
                self._tokens[key] = token
            return token

    async def lock(self) -> None:
        self._generation += 1
        self._endpoints.clear()
        self._tokens.clear()
        for child in list(self._children):
            _kill_group(child)

    # --- children -------------------------------------------------------------------------------

    def _flight(self, kind: str, key: tuple[str, str]) -> asyncio.Lock:
        """One `az` at a time per endpoint or token (single-flight)."""
        return self._flights.setdefault((kind, *key), asyncio.Lock())

    def _login(self, target: ProviderTarget) -> _Login:
        if target.tier not in TIERS:
            raise UpstreamFailure(f"the {NAME} provider does not serve the tier {target.tier}")
        return _Login(target.name, self.state_dir(target))

    def _environment(self, login: _Login) -> dict[str, str]:
        context = self._context
        env = {
            key: value
            for key, value in context.locale.items()
            if key == "LANG" or key.startswith("LC_")
        }
        env["PATH"] = context.path
        env["HOME"] = str(context.user_home)
        if login.config_dir is not None:
            env["AZURE_CONFIG_DIR"] = str(login.config_dir)
        return env

    async def _run(self, login: _Login, *args: str) -> str:
        """One `az` child: argv array, stdin closed, the allowlisted environment, 30 s."""
        command = " ".join(args[:2])
        if self._az is None:
            raise UpstreamFailure(
                "az (the Azure CLI) is not on the broker's PATH; install it, or start the broker "
                "with it on PATH"
            )
        try:
            child = await asyncio.create_subprocess_exec(
                self._az,
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._environment(login),
                cwd=str(self._context.home),
                start_new_session=True,
            )
        except OSError as exc:
            raise UpstreamFailure(f"az cannot be started: {exc.strerror or exc}") from None
        self._children.add(child)
        try:
            try:
                async with asyncio.timeout(AZ_TIMEOUT):
                    stdout, stderr = await child.communicate()
            except TimeoutError:
                raise UpstreamFailure(
                    f"az {command} did not answer within {AZ_TIMEOUT:g} s"
                ) from None
        finally:
            self._children.discard(child)
            if child.returncode is None:
                _kill_group(child)
                await child.wait()
        if child.returncode != 0:
            raise UpstreamFailure(self._failure(login, command, child.returncode, stderr))
        return stdout.decode("utf-8", "replace")

    def _failure(self, login: _Login, command: str, code: int | None, stderr: bytes) -> str:
        text = stderr.decode("utf-8", "replace")
        if any(marker in text.lower() for marker in _LOGIN_MARKERS):
            if login.config_dir is None:
                azure = self._context.user_home / ".azure"
                return (
                    f"the Azure CLI login in {azure} is missing or expired; run `az login` in "
                    "your own terminal"
                )
            return (
                f"the custody Azure CLI login of target {login.target} ({login.config_dir}) is "
                f"missing or expired; run `modgudr login azure {login.target}` in your own "
                "terminal"
            )
        line = _first_line(text)
        if line is None:
            return f"az {command} failed with exit {code}"
        return f"az {command} failed (exit {code}): {line}"


# --- parsing --------------------------------------------------------------------------------------


def credential_url(cluster: Mapping[str, str]) -> str:
    """The `listClusterUserCredential` URL of a cluster (M18)."""
    missing = [key for key in CLUSTER_KEYS if not cluster.get(key)]
    if missing:
        raise UpstreamFailure(f"the cluster has no {', '.join(missing)}")
    subscription, group, name = (quote(cluster[key], safe="") for key in CLUSTER_KEYS)
    return (
        f"{ARM}/subscriptions/{subscription}/resourceGroups/{group}/providers/"
        f"Microsoft.ContainerService/managedClusters/{name}/listClusterUserCredential"
        f"?api-version={API_VERSION}"
    )


def _not_credential(why: str) -> UpstreamFailure:
    return UpstreamFailure(f"az rest returned no usable cluster credential: {why}")


def parse_cluster_credential(text: str) -> Endpoint:
    """The server URL and CA of `listClusterUserCredential`'s one kubeconfig; nothing else."""
    try:
        data: object = json.loads(text)
    except ValueError:
        raise _not_credential("the output is not JSON") from None
    if not isinstance(data, dict):
        raise _not_credential("the output is not a JSON object")
    configs = cast("dict[str, object]", data).get("kubeconfigs")
    if not isinstance(configs, list) or len(cast("list[object]", configs)) != 1:
        raise _not_credential("expected exactly one kubeconfig")
    entry = cast("list[object]", configs)[0]
    value = cast("dict[str, object]", entry).get("value") if isinstance(entry, dict) else None
    if not isinstance(value, str):
        raise _not_credential("the kubeconfig has no value")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise _not_credential("the kubeconfig is not base64") from None
    if len(raw) > MAX_KUBECONFIG:
        raise _not_credential("the kubeconfig is too large")
    try:
        document = load_strict(raw.decode("utf-8"), "listClusterUserCredential")
    except (StrictYamlError, UnicodeDecodeError) as exc:
        raise _not_credential(f"the kubeconfig cannot be read ({exc})") from None
    clusters = (
        cast("dict[str, object]", document).get("clusters") if isinstance(document, dict) else None
    )
    if not isinstance(clusters, list) or len(cast("list[object]", clusters)) != 1:
        raise _not_credential("expected exactly one cluster in the kubeconfig")
    item = cast("list[object]", clusters)[0]
    cluster = cast("dict[str, object]", item).get("cluster") if isinstance(item, dict) else None
    if not isinstance(cluster, dict):
        raise _not_credential("the kubeconfig's cluster is not a mapping")
    fields = cast("dict[str, object]", cluster)
    server = fields.get("server")
    ca_data = fields.get("certificate-authority-data")
    if not isinstance(server, str):
        raise _not_credential("the cluster has no server")
    if not isinstance(ca_data, str) or not ca_data:
        raise _not_credential("the cluster has no certificate-authority-data")
    try:
        base64.b64decode(ca_data, validate=True)
    except (binascii.Error, ValueError):
        raise _not_credential("certificate-authority-data is not base64") from None
    return Endpoint(server=server, ca_data=ca_data, destination=server_destination(server))


def server_destination(server: str) -> Destination:
    """The host and port of an API server URL: `https://host[:port]`, 443 by default. Anything
    else (another scheme, userinfo, a path, a query) is refused."""
    try:
        parts = urlsplit(server)
        port = parts.port
    except ValueError:
        raise _not_credential("the server URL is malformed") from None
    if parts.scheme != "https":
        raise _not_credential("the server URL is not https")
    if parts.username is not None or parts.password is not None:
        raise _not_credential("the server URL carries userinfo")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise _not_credential("the server URL has a path or query")
    host = parts.hostname
    if not host:
        raise _not_credential("the server URL has no host")
    return Destination(host.rstrip("."), port or 443)


def parse_access_token(text: str) -> MintedToken:
    """`accessToken` and `expires_on` (POSIX seconds) of `az account get-access-token -o json`."""
    try:
        data: object = json.loads(text)
    except ValueError:
        raise UpstreamFailure(
            "az account get-access-token printed something that is not JSON"
        ) from None
    if not isinstance(data, dict):
        raise UpstreamFailure("az account get-access-token printed no token object")
    fields = cast("dict[str, object]", data)
    token = fields.get("accessToken")
    expires = fields.get("expires_on")
    if not isinstance(token, str) or not token:
        raise UpstreamFailure("az account get-access-token printed no accessToken")
    if isinstance(expires, str) and expires.isascii() and expires.isdigit():
        expires = int(expires)
    if not isinstance(expires, int) or isinstance(expires, bool):
        raise UpstreamFailure(
            "az account get-access-token printed no expires_on; update the Azure CLI"
        )
    return MintedToken(value=token, expires_at=float(expires))


def _first_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:300]
    return None


def _kill_group(child: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(child.pid, signal.SIGKILL)
