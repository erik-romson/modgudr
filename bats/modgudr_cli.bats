#!/usr/bin/env bats
export BATS_LIB_PATH="/usr/local/lib/bats/:$BATS_LIB_PATH"
bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-file
PROJECT_DIR="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"

setup_file() {
    cd "$PROJECT_DIR" || fail "Could not cd to project dir"
    unset VIRTUAL_ENV
    if ! command -v uv > /dev/null 2>&1; then skip "uv is not installed"; fi
    run uv sync --locked
    assert_success
}

setup() {
    cd "$PROJECT_DIR" || fail "Could not cd to project dir"
    unset VIRTUAL_ENV
    # Short paths: a unix socket path may not pass 103 bytes. Nothing listens there.
    TEST_ROOT="$(mktemp -d /tmp/mg-bats-XXXXXX)"
    export HOME="$TEST_ROOT/home"
    export MODGUDR_HOME="$TEST_ROOT/modgudr"
    export MODGUDR_SOCKET="$TEST_ROOT/agent.sock"
    mkdir -p "$HOME"
}

teardown() {
    rm -rf "$TEST_ROOT"
}

@test "modgudr --help exits 0 and shows the usage" {
    run uv run --locked modgudr --help
    assert_success
    assert_output --partial "usage: modgudr"
}

@test "modgudr --nosuch exits 64" {
    run uv run --locked modgudr --nosuch
    assert_failure 64
    assert_output --partial "unknown option"
}

@test "modgudr targets --nosuch exits 64" {
    run uv run --locked modgudr targets --nosuch
    assert_failure 64
}

@test "modgudr targets with the broker down exits 6" {
    run uv run --locked modgudr targets
    assert_failure 6
    assert_output --partial "broker not running; start it in your own terminal"
}

@test "modgudr status --quiet with the broker down exits 6 and prints nothing" {
    run uv run --locked modgudr status --quiet
    assert_failure 6
    assert_output ""
}

@test "modgudr unlock with the broker down exits 6" {
    run uv run --locked modgudr unlock
    assert_failure 6
    assert_output --partial "broker not running; start it in your own terminal"
}

@test "modgudr-broker --help exits 0" {
    run uv run --locked modgudr-broker --help
    assert_success
    assert_output --partial "usage: modgudr-broker"
}

@test "modgudr-broker with an unknown option exits 64" {
    run uv run --locked modgudr-broker --nosuch
    assert_failure 64
}
