#!/bin/sh
# Offline installer regression tests; no network or systemd calls are made.
set -e
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT HUP INT TERM
sed '/^main "\$@"$/d' "$SCRIPT_DIR/../scripts/cnode.sh" > "$ROOT/functions.sh"

run_case() (
    CASE_NAME=$1
    MODE=$2
    ACTIVE=$3
    . "$ROOT/functions.sh"
    CONFIG_DIR="$ROOT/$CASE_NAME"
    mkdir -p "$CONFIG_DIR"
    printf 'old-ip' > "$CONFIG_DIR/geoip.dat"
    printf 'old-site' > "$CONFIG_DIR/geosite.dat"
    for f in config.json inbounds.json outbounds.json routing.json; do
        printf 'preserve-me' > "$CONFIG_DIR/$f"
    done
    CALLS="$CONFIG_DIR/calls"
    : > "$CALLS"
    install_dependency() { return 0; }
    install_cnode() { echo binary >> "$CALLS"; }
    install_service() { echo forbidden-config-write >> "$CALLS"; }
    init_config() { echo forbidden-config-write >> "$CALLS"; }
    add_panel() { echo forbidden-config-write >> "$CALLS"; }
    systemctl() {
        if [ "$1" = is-active ]; then
            [ "$ACTIVE" = 1 ]
        else
            echo "$1" >> "$CALLS"
            [ "$MODE" != restart-failure ]
        fi
    }
    curl() {
        while [ "$1" != -o ]; do shift; done
        target=$2
        case "$target" in
            */geoip.dat)
                if [ "$MODE" = unchanged ]; then
                    printf old-ip > "$target"
                else
                    printf new-ip > "$target"
                fi
                ;;
            */geosite.dat)
                case "$MODE" in
                    failure) printf partial > "$target"; return 22 ;;
                    empty) : > "$target" ;;
                    unchanged) printf old-site > "$target" ;;
                    *) printf new-site > "$target" ;;
                esac
                ;;
        esac
    }
    status=0
    if [ "$CASE_NAME" = options ]; then
        (main -debug_file true) > "$CONFIG_DIR/output" 2>&1 || status=$?
    else
        (main) > "$CONFIG_DIR/output" 2>&1 || status=$?
    fi
    for f in config.json inbounds.json outbounds.json routing.json; do
        [ "$(cat "$CONFIG_DIR/$f")" = preserve-me ]
    done
    ! grep -q forbidden-config-write "$CALLS"
    [ -z "$(find "$CONFIG_DIR" -name '.geodata.*' -print)" ]
    case "$MODE" in
        failure|empty)
            [ "$status" -ne 0 ]
            [ "$(cat "$CONFIG_DIR/geoip.dat")" = old-ip ]
            [ "$(cat "$CONFIG_DIR/geosite.dat")" = old-site ]
            [ ! -s "$CALLS" ]
            ;;
        *)
            if [ "$MODE" = restart-failure ]; then
                [ "$status" -ne 0 ]
            else
                [ "$status" -eq 0 ]
            fi
            grep -qx binary "$CALLS"
            if [ "$MODE" = unchanged ]; then
                [ "$(cat "$CONFIG_DIR/geosite.dat")" = old-site ]
                grep -qx start "$CALLS"
                ! grep -qx restart "$CALLS"
            else
                [ "$(cat "$CONFIG_DIR/geoip.dat")" = new-ip ]
                [ "$(cat "$CONFIG_DIR/geosite.dat")" = new-site ]
                if [ "$ACTIVE" = 1 ]; then
                    grep -qx restart "$CALLS"
                else
                    [ "$(cat "$CALLS")" = binary ]
                fi
            fi
            ;;
    esac
    echo "PASS $CASE_NAME"
)

run_case no-arguments changed 1
run_case unchanged unchanged 1
run_case download-failure failure 1
run_case empty-download empty 1
run_case inactive-service changed 0
run_case options changed 1
run_case restart-failure restart-failure 1
