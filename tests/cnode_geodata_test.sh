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
    install_cnode() {
        echo binary >> "$CALLS"
        BINARY_UPDATED=0
        [ "$MODE" != binary-only ] || BINARY_UPDATED=1
    }
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
                if [ "$MODE" = unchanged ] || [ "$MODE" = binary-only ]; then
                    printf old-ip > "$target"
                else
                    printf new-ip > "$target"
                fi
                ;;
            */geosite.dat)
                case "$MODE" in
                    unchanged|binary-only) printf old-site > "$target" ;;
                    empty) : > "$target" ;;
                    failure) printf partial > "$target"; return 22 ;;
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
            if [ "$MODE" = unchanged ] || [ "$MODE" = binary-only ]; then
                [ "$(cat "$CONFIG_DIR/geosite.dat")" = old-site ]
                if [ "$MODE" = binary-only ]; then
                    grep -qx restart "$CALLS"
                else
                    grep -qx start "$CALLS"
                    ! grep -qx restart "$CALLS"
                fi
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
run_case binary-only binary-only 1

run_panel_case() (
    MODE=$1
    . "$ROOT/functions.sh"
    CONFIG_DIR="$ROOT/panel-$MODE"
    CONFIG_JSON="$CONFIG_DIR/config.json"
    mkdir -p "$CONFIG_DIR"
    name="KeepCase"
    api_host="https://Example.invalid/API"
    api_key="SecretCase"
    node_id=7
    node_type=vless
    tls_enable=false
    case "$MODE" in
        lowercase)
            printf '%s' '{"panels":[{"name":"KeepCase","key":"Old"},{"name":"keepcase","key":"Distinct"}],"KeepField":"ValueCase"}' > "$CONFIG_JSON"
            ;;
        mixed)
            printf '%s' '{"PaNeLs":[{"nAmE":"KeepCase","key":"Old"}],"KeepField":"ValueCase"}' > "$CONFIG_JSON"
            ;;
        malformed)
            printf '%s' '{"panels":[{"name":"first"} {"name":"second"}]}' > "$CONFIG_JSON"
            ;;
        duplicate)
            printf '%s' '{"panels":[],"PANELS":[]}' > "$CONFIG_JSON"
            ;;
        scalar)
            printf '%s' '{"panels":17}' > "$CONFIG_JSON"
            ;;
    esac
    cp "$CONFIG_JSON" "$CONFIG_DIR/before"
    status=0
    (add_panel_json) > "$CONFIG_DIR/output" 2>&1 || status=$?
    case "$MODE" in
        malformed|duplicate|scalar)
            [ "$status" -ne 0 ]
            cmp -s "$CONFIG_JSON" "$CONFIG_DIR/before"
            ;;
        *)
            [ "$status" -eq 0 ]
            jq -e --arg mode "$MODE" '
                .KeepField == "ValueCase" and
                ([to_entries[] | select(.key | ascii_downcase == "panels") | .value[]] |
                    length == (if $mode == "lowercase" then 2 else 1 end) and
                    ([.[] | with_entries(.key |= ascii_downcase) | select(.name == "KeepCase")] |
                        length == 1 and .[0].key == "SecretCase" and
                        .[0].apihost == "https://Example.invalid/API"))
            ' "$CONFIG_JSON" >/dev/null
            ;;
    esac
    echo "PASS panel-$MODE"
)

run_panel_case lowercase
run_panel_case mixed
run_panel_case malformed
run_panel_case duplicate
run_panel_case scalar

run_binary_case() (
    MODE=$1
    . "$ROOT/functions.sh"
    INSTALL_DIR="$ROOT/binary-$MODE"
    BIN_PATH="$INSTALL_DIR/cnode"
    mkdir -p "$INSTALL_DIR"
    printf '#!/bin/sh\nprintf "release:old\\n"\n' > "$BIN_PATH"
    chmod +x "$BIN_PATH"
    cp "$BIN_PATH" "$INSTALL_DIR/before"
    CALLS="$INSTALL_DIR/calls"
    : > "$CALLS"
    install_dependency() { return 0; }
    systemctl() { echo "$*" >> "$CALLS"; return 0; }
    pkill() { echo kill >> "$CALLS"; }
    sleep() { :; }
    curl() {
        output=""
        while [ $# -gt 0 ]; do
            case "$1" in
                -o) output=$2; shift 2 ;;
                *) shift ;;
            esac
        done
        if [ -z "$output" ]; then
            printf '%s' '{"body":"build_id: new","assets":[]}'
            return
        fi
        case "$MODE" in
            failure) printf partial > "$output"; return 22 ;;
            empty) : > "$output" ;;
            mismatch) printf '#!/bin/sh\nprintf "release:wrong\\n"\n' > "$output" ;;
            *) printf '#!/bin/sh\nprintf "release:new\\n"\n' > "$output" ;;
        esac
    }
    status=0
    (install_cnode) > "$INSTALL_DIR/output" 2>&1 || status=$?
    case "$MODE" in
        success)
            [ "$status" -eq 0 ]
            [ "$("$BIN_PATH" -v)" = release:new ]
            [ "$(cat "$INSTALL_DIR/.cnode-asset")" = cnode-linux-amd64 ]
            ;;
        *)
            [ "$status" -ne 0 ]
            cmp -s "$BIN_PATH" "$INSTALL_DIR/before"
            ;;
    esac
    [ ! -s "$CALLS" ]
    [ -z "$(find "$INSTALL_DIR" -name '.cnode.*' -print)" ]
    echo "PASS binary-$MODE"
)

run_binary_case failure
run_binary_case empty
run_binary_case mismatch
run_binary_case success
