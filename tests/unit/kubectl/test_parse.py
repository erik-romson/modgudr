"""The kubectl argv parser, the resource catalogue and the classifier's edges (M17).

The parser follows cobra and pflag: these tests pin the forms kubectl itself accepts, so that the
classifier sees the namespace, flags and arguments kubectl would act on.
"""

from __future__ import annotations

import random

import pytest

from modgudr.kubectl.catalogue import KINDS, Kind, lookup
from modgudr.kubectl.classify import classify
from modgudr.kubectl.parse import Parsed, ParseError, parse
from modgudr.spi import Risk


def p(argv: str) -> Parsed:
    return parse(argv.split())


def refused(argv: list[str]) -> ParseError:
    with pytest.raises(ParseError) as caught:
        parse(argv)
    return caught.value


# --- flags -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        "get pods -n app",
        "get pods -napp",
        "get pods -n=app",
        "get pods --namespace app",
        "get pods --namespace=app",
        "-n app get pods",
        "--namespace=app get pods",
        "-n other get pods -n app",
    ],
)
def test_every_namespace_form_and_the_last_wins(argv: str) -> None:
    parsed = p(argv)
    assert parsed.path == ("get",)
    assert parsed.last("namespace") == "app"
    assert parsed.args == ("pods",)


def test_combined_short_booleans_and_a_value_at_the_end() -> None:
    parsed = p("exec -itc app p -- sh -c ls")
    assert (parsed.boolean("stdin"), parsed.boolean("tty")) == (True, True)
    assert parsed.last("container") == "app"
    assert parsed.args == ("p", "sh", "-c", "ls")
    assert parsed.dash == 1


def test_a_short_flag_with_an_equals_sign_sets_its_value() -> None:
    assert p("exec -c=app p -- sh").last("container") == "app"
    assert p("get pods -A=false").boolean("all-namespaces") is False
    # pflag reads `-n=` as the value "=" (only a longer `-n=x` strips the sign).
    assert p("get pods -n=").last("namespace") == "="


def test_a_value_flag_takes_the_next_argument_even_when_it_starts_with_a_dash() -> None:
    parsed = parse(["get", "pods", "-l", "-x", "--namespace", "--all-namespaces"])
    assert parsed.last("selector") == "-x"
    assert parsed.last("namespace") == "--all-namespaces"
    assert not parsed.has("all-namespaces")


@pytest.mark.parametrize(
    ("value", "want"),
    [("true", True), ("1", True), ("T", True), ("False", False), ("0", False), ("f", False)],
)
def test_booleans_take_the_values_go_accepts(value: str, want: bool) -> None:
    assert p(f"get pods --all-namespaces={value}").boolean("all-namespaces") is want


@pytest.mark.parametrize("value", ["yes", "", "TrUe", "2"])
def test_a_boolean_with_another_value_is_refused(value: str) -> None:
    error = refused(["get", "pods", f"--all-namespaces={value}"])
    assert "takes true or false" in error.detail


def test_a_boolean_never_takes_the_next_argument() -> None:
    parsed = p("get pods --all-namespaces false")
    assert parsed.boolean("all-namespaces") is True
    assert parsed.args == ("pods", "false")


def test_an_optional_value_is_set_only_with_an_equals_sign() -> None:
    parsed = p("delete pods --dry-run --cascade orphan")
    assert parsed.last("dry-run") == "unchanged"
    assert parsed.last("cascade") == "background"
    assert parsed.args == ("pods", "orphan")
    assert p("delete pods --cascade=orphan").last("cascade") == "orphan"


def test_underscores_in_a_flag_name_are_dashes() -> None:
    parsed = p("get pods --all_namespaces --field_selector=a=b")
    assert parsed.boolean("all-namespaces")
    assert parsed.last("field-selector") == "a=b"
    assert parsed.flags[0].spelled == "--all-namespaces"


def test_logs_dash_f_is_follow_and_get_dash_f_is_a_file() -> None:
    logs = p("logs -f x")
    assert logs.boolean("follow") and logs.args == ("x",)
    get = p("get -f x")
    assert get.last("filename") == "x" and get.args == ()


def test_double_dash_ends_the_flags() -> None:
    parsed = parse(["get", "--", "pods", "--as=admin"])
    assert parsed.args == ("pods", "--as=admin")
    assert parsed.dash == 0
    assert not parsed.has("as")
    assert p("get pods").dash == 1


@pytest.mark.parametrize(
    ("argv", "detail"),
    [
        ("get pods --nope", "unknown flag --nope"),
        ("get pods -Z", "unknown flag -Z"),
        ("get pods -AZ", "unknown flag -Z"),
        ("get pods ---x", "bad flag syntax"),
        ("get pods --=x", "bad flag syntax"),
        ("get pods -n", "-n needs a value"),
        ("get pods --selector", "--selector needs a value"),
        ("get pods -v=high", "takes a number"),
        ("logs x --raw=/api", "unknown flag --raw"),
    ],
)
def test_what_the_parser_refuses(argv: str, detail: str) -> None:
    assert detail in refused(argv.split()).detail


def test_a_refusal_keeps_the_flags_parsed_before_it() -> None:
    error = refused(["--as=admin", "-s", "https://x", "get", "pods", "--nope"])
    assert [(use.name, use.value) for use in error.flags] == [
        ("as", "admin"),
        ("server", "https://x"),
    ]


def test_verbosity_is_a_number() -> None:
    assert p("get pods -v=9").last("v") == "9"
    assert p("get pods -v9").last("v") == "9"
    assert p("get pods --v 3").last("v") == "3"


# --- the command path ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "path"),
    [
        ("-n x delete po y", ("delete",)),
        ("--as=admin get pods", ("get",)),
        ("rollout restart deploy/po", ("rollout", "restart")),
        ("rollout -n x status deploy/po", ("rollout", "status")),
        ("top po", ("top", "pod")),
        ("top nodes", ("top", "node")),
        ("create cm x", ("create", "configmap")),
        ("create deploy web --image=nginx", ("create", "deployment")),
        ("create svc clusterip web", ("create", "service", "clusterip")),
        ("create secret generic x", ("create", "secret", "generic")),
        ("create -f x.yaml", ("create",)),
        ("auth can-i --list", ("auth", "can-i")),
        ("config view --raw", ("config", "view")),
    ],
)
def test_the_command_path(argv: str, path: tuple[str, ...]) -> None:
    assert p(argv).path == path


@pytest.mark.parametrize(
    ("argv", "detail"),
    [
        ("", "no kubectl verb"),
        ("-n x", "no kubectl verb"),
        ("-- get pods", "no kubectl verb before --"),
        ("foo pods", "unknown verb 'foo': kubectl plugins are not run"),
        ("proxy --port=8001", "kubectl proxy is not supported through the broker"),
        ("rollout", "kubectl rollout needs a subcommand"),
        ("rollout frob x", "kubectl rollout frob is not supported"),
        ("rollout --watch status x", "unknown flag --watch"),
        ("create secret", "kubectl create secret needs a subcommand"),
        ("create frob x", "kubectl create frob is not supported"),
        ("create -o yaml cm x", "-o must come after 'kubectl create configmap'"),
        ("config set-credentials x --token=y", "kubectl config set-credentials is not supported"),
        ("-A get pods", "unknown flag -A"),
        ("-l app=x get pods", "unknown flag -l"),
    ],
)
def test_what_the_command_path_refuses(argv: str, detail: str) -> None:
    assert detail in refused(argv.split()).detail


def test_a_boolean_global_flag_does_not_take_the_verb_as_its_value() -> None:
    # cobra finds the command the same way: `false` is the verb, which kubectl does not know.
    error = refused(["--insecure-skip-tls-verify", "false", "get", "pods"])
    assert "unknown verb 'false'" in error.detail
    assert error.flags[0].name == "insecure-skip-tls-verify"


def test_a_value_global_flag_takes_the_word_after_it_even_a_verb() -> None:
    error = refused(["-n", "get", "pods"])
    assert "unknown verb 'pods'" in error.detail


# --- the catalogue ---------------------------------------------------------------------------

M17_KINDS = [
    "pods",
    "deployments",
    "replicasets",
    "statefulsets",
    "daemonsets",
    "jobs",
    "cronjobs",
    "services",
    "endpoints",
    "configmaps",
    "secrets",
    "namespaces",
    "nodes",
    "events",
    "ingresses",
    "persistentvolumeclaims",
    "persistentvolumes",
    "serviceaccounts",
    "roles",
    "rolebindings",
    "clusterroles",
    "clusterrolebindings",
    "horizontalpodautoscalers",
    "networkpolicies",
    "poddisruptionbudgets",
    "limitranges",
    "resourcequotas",
    "storageclasses",
    "customresourcedefinitions",
]


def test_the_catalogue_holds_exactly_the_m17_kinds() -> None:
    assert sorted(kind.plural for kind in KINDS) == sorted(M17_KINDS)


def test_no_name_belongs_to_two_kinds() -> None:
    owners: dict[str, Kind] = {}
    for kind in KINDS:
        for name in kind.names:
            assert owners.setdefault(name, kind) is kind, name


@pytest.mark.parametrize(
    ("name", "plural"),
    [
        ("po", "pods"),
        ("Pod", "pods"),
        ("PODS", "pods"),
        ("deploy", "deployments"),
        ("svc", "services"),
        ("cm", "configmaps"),
        ("crds", "customresourcedefinitions"),
        ("hpa", "horizontalpodautoscalers"),
        ("Secret", "secrets"),
        ("deployments.apps", "deployments"),
        ("deploy.v1.apps", "deployments"),
        ("Deployment.v1.apps", "deployments"),
        ("hpa.v2.autoscaling", "horizontalpodautoscalers"),
        ("ingresses.networking.k8s.io", "ingresses"),
        ("ingresses.v1.networking.k8s.io", "ingresses"),
        ("Secret.v1.", "secrets"),
        ("pods.", "pods"),
        ("cronjobs.v1beta1.batch", "cronjobs"),
    ],
)
def test_lookup(name: str, plural: str) -> None:
    kind = lookup(name)
    assert kind is not None and kind.plural == plural


@pytest.mark.parametrize(
    "name",
    [
        "all",
        "certificates.cert-manager.io",
        "events.events.k8s.io",
        "deployments.v1",
        "deployments.extensions",
        "pods.v1.core",
        "deployments.vfoo.apps",
        "deployments.v0.apps",
        "secret.v1.apps",
        "",
        "pods,secrets",
    ],
)
def test_lookup_refuses(name: str) -> None:
    assert lookup(name) is None


# --- the classifier never raises -------------------------------------------------------------


def test_the_arguments_must_be_a_list_of_strings() -> None:
    assert classify("get pods").name == "kubectl:unknown"
    assert classify(["get", 1]).name == "kubectl:unknown"
    assert classify([]).risk is Risk.UNKNOWN


def test_the_default_namespace_is_the_targets_then_default() -> None:
    assert classify(["get", "pods"]).facts["namespace"] == "default"
    assert classify(["get", "pods"], "app-test").facts["namespace"] == "app-test"
    assert classify(["get", "pods", "-n", "x"], "app-test").facts["namespace"] == "x"


_WORDS = [
    "get",
    "delete",
    "logs",
    "exec",
    "cp",
    "rollout",
    "restart",
    "create",
    "cm",
    "secret",
    "top",
    "pod",
    "config",
    "view",
    "auth",
    "can-i",
    "pods",
    "po",
    "secrets",
    "deploy/x",
    "pod/",
    "/x",
    "a,b",
    ",",
    "-n",
    "-n=",
    "-nx",
    "--namespace",
    "--namespace=",
    "-A",
    "--all",
    "-l",
    "a=b",
    "-f",
    "-k",
    "--raw",
    "-o",
    "-ojson",
    "-o=yaml",
    "go-template-file=/x",
    "-v",
    "-v=9",
    "-it",
    "-c",
    "--",
    "-",
    "--as=x",
    "-s",
    "--dry-run",
    "--cascade",
    "--watch=false",
    "--follow",
    "x",
    "y:z",
    "ns/p:/f",
    "=",
    "-",
]


def test_random_argv_never_raises() -> None:
    rng = random.Random(17)
    for _ in range(3000):
        argv = [rng.choice(_WORDS) for _ in range(rng.randint(0, 8))]
        action = classify(argv)
        assert action.name.startswith("kubectl:")
        assert (action.risk is Risk.UNKNOWN) == (action.name == "kubectl:unknown"), argv
