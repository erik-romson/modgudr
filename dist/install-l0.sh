#!/bin/sh
# Install modgudr at L0 (the broker runs as your own user) with `uv tool install`.
#
# This script installs the broker and the client from this checkout. It does not install `bws`
# and never fetches anything from Bitwarden: see the notes it prints at the end.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${HOME:-}/.local
DRY_RUN=0

usage() {
    cat <<'USAGE'
usage: install-l0.sh [--dry-run] [--prefix DIR]
       install-l0.sh --help

Install modgudr-broker and the modgudr client from this checkout with `uv tool install`.

  --dry-run     print every command instead of running it
  --prefix DIR  put the commands in DIR/bin (default: ~/.local/bin)
  --help        show this text

Nothing here installs `bws`, the Bitwarden Secrets Manager command line. Install it yourself;
the notes at the end of this script say where from and under which licence.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --help)
            usage
            exit 0
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        --prefix)
            if [ $# -lt 2 ]; then
                echo "install-l0.sh: --prefix needs a directory" >&2
                usage >&2
                exit 64
            fi
            PREFIX=$2
            shift
            ;;
        *)
            echo "install-l0.sh: unknown option: $1" >&2
            usage >&2
            exit 64
            ;;
    esac
    shift
done

BIN="$PREFIX/bin"

# Run a command, or print it with --dry-run.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "+ $*"
    else
        "$@"
    fi
}

if [ "$DRY_RUN" -eq 0 ] && ! command -v uv > /dev/null 2>&1; then
    echo "install-l0.sh: uv is not installed (https://docs.astral.sh/uv/)" >&2
    exit 69
fi

UV_TOOL_BIN_DIR="$BIN"
export UV_TOOL_BIN_DIR
if [ "$DRY_RUN" -eq 1 ]; then
    echo "# UV_TOOL_BIN_DIR=$UV_TOOL_BIN_DIR"
fi

run uv tool install --reinstall --from "$REPO/packages/broker" modgudr-broker \
    --with "modgudr-client @ file://$REPO/packages/client" \
    --with "modgudr-sql[snowflake,oracle] @ file://$REPO/packages/sql" \
    --with "modgudr-kubectl @ file://$REPO/packages/kubectl" \
    --with "modgudr-store-bws @ file://$REPO/packages/store-bws"

# uv links only the executables of the named tool, so `modgudr` needs its own tool install. The
# client is stdlib-only, so a separate tool environment costs nothing.
run uv tool install --reinstall --from "$REPO/packages/client" modgudr-client

# The short alias, only when nothing else is called that. It comes after the client install, so
# that it never dangles.
if command -v mg > /dev/null 2>&1; then
    echo "# the short alias name is already taken on this machine; no alias is created"
else
    run ln -s modgudr "$BIN/mg"
fi

cat <<NEXT

modgudr is installed in $BIN (put it on your PATH).

WARNING: at L0 modgudr runs as your own user. Until agent isolation is configured, both sockets,
         the policy and the unlock are reachable by anything you run, including coding agents.
         This set-up protects against accidents only.

1. Create the policy directory and install the company file as root, so that nothing running as
   you can widen it. Edit the example first: it holds example hosts and users only. Set
   store.bws.project to your Bitwarden project uuid, and store.bws.serverUrl if your vault is
   not the US cloud (for the EU cloud: https://vault.bitwarden.eu).

     mkdir -p -m 0700 "\$HOME/.modgudr" "\$HOME/.modgudr/policy.d"
     sudo install -o root -m 0644 $REPO/dist/policy.d/00-company.example.yaml \\
         "\$HOME/.modgudr/policy.d/00-company.yaml"
     install -m 0644 $REPO/dist/policy.d/50-targets.example.yaml \\
         "\$HOME/.modgudr/policy.d/50-targets.yaml"

2. Start the broker in a terminal and leave it running:

     modgudr-broker

3. In another terminal, unlock the store and check it:

     modgudr unlock
     modgudr status

4. Make Claude Code use modgudr inside its sandbox, and install the output as it tells you:

     modgudr agent-setup claude

The bws command line (not installed by this script)
---------------------------------------------------
The 'bws' store calls the Bitwarden Secrets Manager CLI, which you install yourself:

  Release page: https://github.com/bitwarden/sdk-sm/releases

Download the release zip for your platform from that page in your browser, check it against the
checksum file published on the same release (for example with 'shasum -a 256 -c'), unzip it and put
'bws' on your PATH. modgudr does not bundle, download or install it.

Licence: 'bws' is Bitwarden's software under Bitwarden's own agreement, not modgudr's licence. Read
that agreement before you use it; it permits, among other uses, developing, testing and
demonstrating a compatible application, personal or family use, and internal business use with a
paid Bitwarden server licence.
NEXT
