"""MVP step 5, "done when" (§14.2), against the fakes: `modgudr aks@test kubectl get pods -n
app-test` works through the developer's (fake) Azure login; `delete pods --all` is refused;
`--as` is refused; `get secrets` is refused. Streams end at the timeout, `modgudr login azure`
runs `az login` into the custody directory, and a missing `kubectl` shows in `status`.

The broker runs on its own thread in this process with `PATH=<fake bin>:/usr/bin:/bin`; the CLI
is a subprocess with an allowlisted environment.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.support.brokerfx import BrokerEnv, read_audit
from tests.support.brokerthread import BrokerThread, cli_environ, run_cli
from tests.support.fakebin import FakeBin
from tests.support.kubectlfx import (
    GET_PODS,
    custody_dir,
    kube_env,
    pid_gone,
    set_scenario,
)
from tests.support.shortdir import make_shortdir


@pytest.fixture
def served(shortdir: Path, fakebin: FakeBin) -> Iterator[BrokerThread]:
    set_scenario(fakebin)
    with BrokerThread(kube_env(shortdir, fakebin)) as thread:
        thread.unlock()
        yield thread


def cli(env: BrokerEnv, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
    return run_cli(cli_environ(env, **extra), *args)


def test_get_pods_works_through_the_developers_azure_login(
    served: BrokerThread, fakebin: FakeBin
) -> None:
    done = cli(served.env, "aks@test", "kubectl", "get", "pods", "-n", "app-test")
    assert (done.returncode, done.stdout, done.stderr) == (0, GET_PODS, "")
    decision = next(r for r in read_audit(served.env.audit_dir) if r["type"] == "decision")
    assert (decision["action"], decision["decision"], decision["target"]) == (
        "kubectl:get/pods",
        "allow",
        "aks-test",
    )
    assert "AZURE_CONFIG_DIR" not in fakebin.entries("az")[0]["env"]


@pytest.mark.parametrize(
    ("argv", "says"),
    [
        (("delete", "pods", "--all", "-n", "app-test"), "--all is refused; name the objects"),
        (("--as=admin", "get", "pods"), "--as"),
        (("get", "secrets", "-n", "app-test"), "secret"),
    ],
)
def test_the_refusals_of_the_7_8_policy(
    served: BrokerThread, fakebin: FakeBin, argv: tuple[str, ...], says: str
) -> None:
    done = cli(served.env, "aks@test", "kubectl", *argv)
    assert done.returncode == 2, done.stderr
    assert says in done.stderr and done.stdout == ""
    assert fakebin.entries("az") == [] and fakebin.entries("kubectl") == []


def test_explain_names_the_layer_and_shows_the_endpoint_not_fetched(served: BrokerThread) -> None:
    done = cli(served.env, "explain", "aks@test", "kubectl", "delete", "pods", "--all")
    assert done.returncode == 0, done.stderr
    assert "layer: constraint  rule: requireName" in done.stdout
    assert "facts: endpoint=not fetched" in done.stdout
    described = cli(served.env, "describe", "aks-test")
    assert "facts: endpoint=not fetched" in described.stdout
    assert "destinations: none" in described.stdout


def test_a_follow_stream_ends_at_the_timeout(served: BrokerThread, fakebin: FakeBin) -> None:
    env = served.env
    cut = cli(env, "aks-fast", "kubectl", "logs", "-f", "pod/x")
    assert cut.returncode == 4, cut.stderr
    assert cut.stdout.startswith("log line a\n")
    allowed = cli(env, "aks-fast", "--allow-truncated", "kubectl", "logs", "-f", "pod/x")
    assert allowed.returncode == 0, allowed.stderr
    assert allowed.stdout.startswith("log line a\n")
    for run in fakebin.entries("kubectl"):
        assert pid_gone(int(run["pid"]))


def test_a_failing_kubectl_is_exit_5(served: BrokerThread, fakebin: FakeBin) -> None:
    set_scenario(
        fakebin, kubectl={"exit_code": 1, "stderr": 'Error from server (NotFound): pods "x"\n'}
    )
    done = cli(served.env, "aks-test", "kubectl", "get", "pods", "x")
    assert done.returncode == 5
    assert 'Error from server (NotFound): pods "x"' in done.stderr
    assert "kubectl exited with code 1" in done.stderr


def test_login_azure_needs_human_sock(served: BrokerThread) -> None:
    other = make_shortdir()
    try:
        done = cli(served.env, "login", "azure", "aks-test", MODGUDR_HOME=str(other))
    finally:
        other.rmdir()
    assert done.returncode == 6
    assert "admin commands are not available from an agent session" in done.stderr


def test_login_azure_runs_az_login_into_the_custody_directory(
    shortdir: Path, fakebin: FakeBin
) -> None:
    set_scenario(fakebin)
    env = kube_env(shortdir, fakebin, tier="custody")
    with BrokerThread(env):
        plain = cli(env, "login", "azure", "aks-test", PATH=fakebin.path_env())
        device = cli(env, "login", "azure", "aks-test", "--device-code", PATH=fakebin.path_env())
        borrowed = cli(env, "login", "azure", "aks-prod", PATH=fakebin.path_env())
    assert plain.returncode == 0, plain.stderr
    assert device.returncode == 0, device.stderr
    first, second = fakebin.entries("az")
    assert (first["argv"], second["argv"]) == (["login"], ["login", "--use-device-code"])
    assert first["env"]["AZURE_CONFIG_DIR"] == second["env"]["AZURE_CONFIG_DIR"] == custody_dir(env)
    assert borrowed.returncode == 64
    assert "uses the borrowed tier" in borrowed.stderr


def test_a_missing_kubectl_shows_in_status_and_calls_fail(shortdir: Path, fakebin: FakeBin) -> None:
    (fakebin.bin / "kubectl").unlink()
    set_scenario(fakebin)
    with BrokerThread(kube_env(shortdir, fakebin)) as thread:
        thread.unlock()
        env = thread.env
        status = cli(env, "status")
        targets = cli(env, "targets")
        done = cli(env, "aks-test", "kubectl", "get", "pods")
    problem = "target aks-test: kubectl is not on the broker's PATH; calls fail"
    assert f"problem: {problem}" in status.stdout
    assert f"warning: {problem}" in targets.stderr
    assert done.returncode == 5
    assert "kubectl is not on the broker's PATH" in done.stderr
