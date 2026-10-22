"""The kubectl corpus (tests/data/kubectl-corpus.yaml) through the classifier.

Every row is classified without a cluster: nothing runs kubectl.
"""

from __future__ import annotations

import pytest

from modgudr.kubectl.catalogue import KINDS
from modgudr.kubectl.classify import classify
from tests.support.kubectlcorpus import CorpusRow, check_row, load_corpus

CORPUS = load_corpus()

#: Inputs the step 17 table names; the corpus must keep every one of them.
REQUIRED = frozenset(
    {
        "-n app-test delete po web-1",
        "delete pod/web-1 pod/web-2",
        "delete pods --all",
        "delete pods -l app=x",
        "delete pods",
        "get pods -n app",
        "get pods -napp",
        "get pods -n=app",
        "get pods --namespace app",
        "get pods --namespace=app",
        "get pods -n a -n b",
        "get pods",
        "get pods -A",
        "get nodes",
        "get secrets",
        "describe secret x",
        "get pods,secrets",
        "get secret/foo -o yaml",
        "config view --raw",
        "create token sa",
        "exec -it p -- sh",
        "cp p:/x .",
        "attach p",
        "port-forward p 8080",
        "debug p",
        "proxy",
        "edit deploy x",
        "config use-context x",
        "foo",
        "get certificates.cert-manager.io",
        "--as=admin get pods",
        "--token x get pods",
        "--kubeconfig f get pods",
        "-s https://x get pods",
        "--context c get pods",
        "apply -f x.yaml",
        "get -f x.yaml",
        "apply -k dir",
        "get --raw /api/v1/namespaces/x/secrets",
        "get pods -o go-template-file=/etc/x",
        "create cm x --from-file=~/.azure/f",
        "get pods -v=9",
        "logs -f pod/x",
        "logs --follow x",
        "get pods -w",
        "rollout restart deploy/po",
        "rollout status deploy/po",
        "scale --replicas=0 deploy/po",
        "replace --force -f x",
        "delete pods,jobs x",
    }
)


def test_the_corpus_keeps_every_required_row() -> None:
    missing = REQUIRED - CORPUS.argvs()
    assert not missing, f"rows missing from the corpus: {sorted(missing)}"


@pytest.mark.parametrize("row", CORPUS.rows, ids=[row.id for row in CORPUS.rows])
def test_row(row: CorpusRow) -> None:
    check_row(row, classify(row.words, row.default_namespace), CORPUS.namespaces)


def test_the_identity_and_connection_flags_are_all_covered() -> None:
    """Every M17 identity and connection flag has a row that the flag refuses."""
    flags = {
        "--token",
        "--kubeconfig",
        "--as",
        "--as-group",
        "--as-uid",
        "--server",
        "--context",
        "--cluster",
        "--user",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--tls-server-name",
        "--username",
        "--password",
        "--cache-dir",
        "--insecure-skip-tls-verify",
    }
    covered = {row.invariant for row in CORPUS.rows}
    assert flags <= covered, sorted(flags - covered)


def test_every_catalogue_kind_classifies_by_every_name() -> None:
    for kind in KINDS:
        for name in (*kind.names, kind.kind, f"{kind.plural}.{kind.group}"):
            action = classify(["get", name])
            want = "secret" if kind.plural == "secrets" else "read"
            assert action.name == f"kubectl:get/{kind.plural}", (name, action)
            assert action.risk.value == want, (name, action)
            assert action.facts["clusterScoped"] is (not kind.namespaced), name
