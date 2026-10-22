"""The per-call kubeconfig (M18): the server and CA Azure gave, and an exec-plugin user.

The file never holds a token. Its user is an exec credential plugin
(`client.authentication.k8s.io/v1`, `interactiveMode: Never`) that runs
`<sys.executable> -I -m modgudr.kubectl.exec_credential <socket>`: the plugin asks the broker for
this call's token over the call's own socket, which only the broker's uid may use.

The context's namespace is the target's `defaultNamespace` (else `default`), the namespace the
classifier assumed for a call without `-n` (M17).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from modgudr.spi import Endpoint

from .exec_credential import API_VERSION

#: The file name inside the per-call directory.
KUBECONFIG_NAME = "kubeconfig"
#: The name of the one cluster, user and context in the file.
CONTEXT = "modgudr"
#: The module the exec plugin runs.
EXEC_MODULE = "modgudr.kubectl.exec_credential"


def exec_command(socket_path: Path) -> list[str]:
    """The exec plugin's command line: this interpreter, isolated (`-I`), and the socket."""
    return [sys.executable, "-I", "-m", EXEC_MODULE, os.fspath(socket_path)]


def kubeconfig(endpoint: Endpoint, socket_path: Path, namespace: str) -> dict[str, object]:
    """The kubeconfig document: one cluster, one exec-plugin user, one context."""
    command = exec_command(socket_path)
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": CONTEXT,
                "cluster": {
                    "server": endpoint.server,
                    "certificate-authority-data": endpoint.ca_data,
                },
            }
        ],
        "users": [
            {
                "name": CONTEXT,
                "user": {
                    "exec": {
                        "apiVersion": API_VERSION,
                        "command": command[0],
                        "args": command[1:],
                        "interactiveMode": "Never",
                        "provideClusterInfo": False,
                    }
                },
            }
        ],
        "contexts": [
            {
                "name": CONTEXT,
                "context": {"cluster": CONTEXT, "user": CONTEXT, "namespace": namespace},
            }
        ],
        "current-context": CONTEXT,
        "preferences": {},
    }


def write_kubeconfig(
    directory: Path, endpoint: Endpoint, socket_path: Path, namespace: str
) -> Path:
    """Write the kubeconfig (JSON, which kubectl reads as YAML) as a new 0600 file."""
    path = directory / KUBECONFIG_NAME
    text = json.dumps(kubeconfig(endpoint, socket_path, namespace), indent=2) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path
