#!/usr/bin/env bats
export BATS_LIB_PATH="/usr/local/lib/bats/:$BATS_LIB_PATH"
bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-file
PROJECT_DIR="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
INSTALL="$PROJECT_DIR/dist/install-l0.sh"
FAKE_BIN="$PROJECT_DIR/bats/testfiles/install_l0/bin"

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
    TEST_ROOT="$(mktemp -d /tmp/mg-bats-XXXXXX)"
    export HOME="$TEST_ROOT/home"
    export MODGUDR_HOME="$TEST_ROOT/modgudr"
    export MODGUDR_SOCKET="$TEST_ROOT/agent.sock"
    mkdir -p "$HOME"
}

teardown() {
    rm -rf "$TEST_ROOT"
}

@test "install-l0.sh --help exits 0 and shows the usage" {
    run sh "$INSTALL" --help
    assert_success
    assert_output --partial "usage: install-l0.sh"
    assert_output --partial "--dry-run"
    assert_output --partial "--prefix"
}

@test "install-l0.sh --nosuch exits 64 with the usage" {
    run sh "$INSTALL" --nosuch
    assert_failure 64
    assert_output --partial "unknown option"
    assert_output --partial "usage: install-l0.sh"
}

@test "install-l0.sh --prefix without a directory exits 64" {
    run sh "$INSTALL" --prefix
    assert_failure 64
    assert_output --partial "--prefix needs a directory"
}

@test "install-l0.sh --dry-run prints the uv tool install line and no alias when mg resolves" {
    mkdir -p "$TEST_ROOT/mgbin"
    printf '#!/bin/sh\nexit 0\n' > "$TEST_ROOT/mgbin/mg"
    chmod +x "$TEST_ROOT/mgbin/mg"
    PATH="$FAKE_BIN:$TEST_ROOT/mgbin:/usr/bin:/bin" run sh "$INSTALL" --dry-run --prefix "$TEST_ROOT/prefix"
    assert_success
    assert_output --partial "+ uv tool install --from $PROJECT_DIR/packages/broker modgudr-broker"
    assert_output --partial "modgudr-sql[snowflake,oracle]"
    assert_output --partial "sudo install -o root -m 0644"
    assert_output --partial "modgudr-broker"
    assert_output --partial "modgudr unlock"
    assert_output --partial "modgudr agent-setup claude"
    assert_output --partial "https://github.com/bitwarden/sdk-sm/releases"
    refute_output --partial "ln -s"
    assert_file_not_exist "$TEST_ROOT/prefix"
    assert_file_not_exist "$HOME/fake-uv.log"
}

@test "install-l0.sh --dry-run plans the alias when no mg exists" {
    # A PATH with only the tools the script needs, so that no mg (macOS has one in /usr/bin) resolves.
    mkdir -p "$TEST_ROOT/tools"
    for tool in dirname cat; do
        ln -s "$(command -v "$tool")" "$TEST_ROOT/tools/$tool"
    done
    PATH="$FAKE_BIN:$TEST_ROOT/tools" run /bin/sh "$INSTALL" --dry-run --prefix "$TEST_ROOT/prefix"
    assert_success
    assert_output --partial "+ ln -s modgudr $TEST_ROOT/prefix/bin/mg"
    assert_file_not_exist "$TEST_ROOT/prefix"
}

@test "install-l0.sh runs uv with the tool bin directory and installs nothing itself" {
    mkdir -p "$TEST_ROOT/prefix/bin"
    PATH="$FAKE_BIN:/usr/bin:/bin" run sh "$INSTALL" --prefix "$TEST_ROOT/prefix"
    assert_success
    assert_file_exist "$HOME/fake-uv.log"
    run cat "$HOME/fake-uv.log"
    assert_output --partial "tool install --from $PROJECT_DIR/packages/broker modgudr-broker --with"
    assert_output --partial "modgudr-store-bws"
}
