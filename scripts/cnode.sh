#!/bin/sh

# cnode 一键部署脚本
# 用法: bash <(curl -sL <url>) -name xxx -api_host xxx -api_key xxx -node_id 1,2 -node_type vmess
# 无参数时更新二进制和 geodata；部署模式添加/覆盖一个 panel，已有 config.json 不会被覆盖，
# 指定 URL 的 sidecar 文件会覆盖下载。

ALLOWED_OPTIONS="name api_host api_key node_id node_type dns tls_enable tls_cert tls_key outbound_url route_url inbound_url v debug_file"
REQUIRED_OPTIONS="name api_host api_key node_id node_type"

INSTALL_DIR="/opt/cnode"
CONFIG_DIR="$INSTALL_DIR/config"
BIN_PATH="$INSTALL_DIR/cnode"
SERVICE_NAME="cnode"
REPO="grrhuipp/cnode"
LOG_DIR="$INSTALL_DIR/log"
CONFIG_JSON="$CONFIG_DIR/config.json"

# ============================================================================
# 参数解析
# ============================================================================

usage() {
    echo "用法: bash <(curl -sL ...) [选项]"
    echo ""
    echo "不带参数时：更新 cnode 二进制（默认 cnode-latest release）和 geoip/geosite 数据"
    echo ""
    echo "必填选项:"
    for opt in $REQUIRED_OPTIONS; do
        echo "  -$opt <value>"
    done
    echo ""
    echo "可选选项:"
    echo "  -dns <ip>              DNS 服务器（默认使用系统 /etc/resolv.conf）"
    echo "  -tls_enable true       启用 TLS（trojan 需要）"
    echo "  -tls_cert <path>       TLS 证书路径"
    echo "  -tls_key <path>        TLS 私钥路径"
    echo "  -outbound_url <url>    远程 outbounds.json 下载地址（指定则覆盖下载）"
    echo "  -route_url <url>       远程 routing.json 下载地址（指定则覆盖下载）"
    echo "  -inbound_url <url>     远程 inbounds.json 下载地址（指定则覆盖下载）"
    echo "  -v <version>           指定 release tag（默认 cnode-latest；latest 表示 GitHub latest）"
    echo "  -debug_file true       额外下载 release 对应的 .debug 符号文件"
    exit 1
}

parse_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -*)
                opt="${1#-}"
                valid=0
                for allowed in $ALLOWED_OPTIONS; do
                    if [ "$opt" = "$allowed" ]; then
                        valid=1
                        break
                    fi
                done
                if [ "$valid" -eq 0 ]; then
                    echo "未知选项: $1"
                    usage
                fi
                shift
                if [ $# -eq 0 ]; then
                    echo "选项 -$opt 缺少参数"
                    usage
                fi
                eval "$opt=\$1"
                ;;
            *)
                echo "无法识别的参数: $1"
                usage
                ;;
        esac
        shift
    done
}

has_deploy_options() {
    for req in $REQUIRED_OPTIONS; do
        eval "value=\$$req"
        if [ -n "$value" ]; then
            return 0
        fi
    done
    return 1
}

# ============================================================================
# 依赖安装
# ============================================================================

install_dependency() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    fi
    echo "$1 未安装，尝试自动安装..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq "$2"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "$2"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "$2"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --needed --noconfirm "$2"
    elif command -v zypper >/dev/null 2>&1; then
        zypper install -y "$2"
    else
        echo "未找到支持的包管理器，请手动安装 $1。"
        return 1
    fi
}

# ============================================================================
# cnode 二进制安装/更新
# ============================================================================

install_cnode() {
    BINARY_UPDATED=0
    install_dependency curl curl
    install_dependency jq jq

    mkdir -p "$INSTALL_DIR"

    DEBUG_FILE="${debug_file:-false}"
    case "$DEBUG_FILE" in
        true|false) ;;
        *)
            echo "无效的 debug_file: $DEBUG_FILE（仅支持 true/false）"
            exit 1
            ;;
    esac

    ASSET_NAME="cnode-linux-amd64"

    # 获取远程 build_id。GitHub API 在部分机房偶发不可达，API 失败时
    # 回退到 release 直链下载，只跳过 build_id 强校验。
    RELEASE_TAG="${v:-cnode-latest}"
    if [ "$RELEASE_TAG" = "latest" ]; then
        RELEASE_API_URL="https://api.github.com/repos/$REPO/releases/latest"
        RELEASE_ASSET_BASE="https://github.com/$REPO/releases/latest/download"
    else
        RELEASE_API_URL="https://api.github.com/repos/$REPO/releases/tags/$RELEASE_TAG"
        RELEASE_ASSET_BASE="https://github.com/$REPO/releases/download/$RELEASE_TAG"
    fi
    RELEASE_INFO=$(curl -fsSL --connect-timeout 10 --retry 2 \
        -H "Accept: application/vnd.github+json" \
        -H "User-Agent: cnode-installer" \
        "$RELEASE_API_URL" 2>/dev/null || true)

    REMOTE_ID=""
    REMOTE_VERSION=""
    if [ -n "$RELEASE_INFO" ]; then
        REMOTE_ID=$(echo "$RELEASE_INFO" \
            | jq -r '.body // ""' 2>/dev/null \
            | sed -n 's/.*build_id: \([^,[:space:]]*\).*/\1/p' \
            | head -1)
        if [ -n "$REMOTE_ID" ]; then
            REMOTE_VERSION="release:$REMOTE_ID"
        else
            echo "警告: 无法解析远程 build_id，将跳过版本号校验。"
        fi
    else
        echo "警告: 无法获取远程版本信息，回退到 release 直链下载。"
    fi

    DEBUG_PATH="$INSTALL_DIR/$ASSET_NAME.debug"

    # 比对本地版本，相同则跳过
    LOCAL_ID=""
    if [ -x "$BIN_PATH" ]; then
        LOCAL_ID=$(timeout 3 "$BIN_PATH" -v 2>/dev/null | tr -d '[:space:]')
    fi

    NEED_BINARY_UPDATE=1
    if [ -n "$REMOTE_VERSION" ] && [ "$LOCAL_ID" = "$REMOTE_VERSION" ]; then
        NEED_BINARY_UPDATE=0
    fi

    LATEST_URL=""
    if [ -n "$RELEASE_INFO" ]; then
        LATEST_URL=$(echo "$RELEASE_INFO" \
            | jq -r --arg asset "$ASSET_NAME" '.assets[] | select(.name == $asset) | .browser_download_url' 2>/dev/null \
            | head -1)
    fi

    if [ -z "$LATEST_URL" ] || [ "$LATEST_URL" = "null" ]; then
        LATEST_URL="$RELEASE_ASSET_BASE/$ASSET_NAME"
    fi

    NEED_DEBUG_DOWNLOAD=0
    DEBUG_URL=""
    if [ "$DEBUG_FILE" = "true" ]; then
        NEED_DEBUG_DOWNLOAD=1
        if [ -n "$RELEASE_INFO" ]; then
            DEBUG_URL=$(echo "$RELEASE_INFO" \
                | jq -r --arg asset "$ASSET_NAME.debug" '.assets[] | select(.name == $asset) | .browser_download_url' 2>/dev/null \
                | head -1)
        fi
        if [ -z "$DEBUG_URL" ] || [ "$DEBUG_URL" = "null" ]; then
            DEBUG_URL="$RELEASE_ASSET_BASE/$ASSET_NAME.debug"
        fi
    fi

    if [ "$NEED_BINARY_UPDATE" -eq 0 ] && [ "$NEED_DEBUG_DOWNLOAD" -eq 0 ]; then
        echo "cnode 已是最新版本: $REMOTE_VERSION"
        return 0
    fi

    if [ "$NEED_BINARY_UPDATE" -eq 1 ]; then

        UPDATE_TARGET="$REMOTE_VERSION"
        if [ -z "$UPDATE_TARGET" ]; then
            UPDATE_TARGET="release:$RELEASE_TAG"
        fi
        echo "更新 cnode: ${LOCAL_ID:-none} -> $UPDATE_TARGET"
        BINARY_TMP=$(mktemp "$INSTALL_DIR/.cnode.XXXXXX") || exit 1
        if ! curl -fsSL --connect-timeout 10 --max-time 180 --retry 3 \
            "$LATEST_URL" -o "$BINARY_TMP" || [ ! -s "$BINARY_TMP" ] ||
            ! chmod 0755 "$BINARY_TMP"; then
            rm -f "$BINARY_TMP"
            echo "cnode 下载失败，保留原二进制和运行中的服务。"
            exit 1
        fi

        # Validate the candidate before replacing the executable. Atomic rename
        # leaves a running process on its old inode until main restarts it.
        NEW_ID=$(timeout 3 "$BINARY_TMP" -v 2>/dev/null | tr -d '[:space:]')
        if [ -z "$NEW_ID" ] || { [ -n "$REMOTE_VERSION" ] && [ "$NEW_ID" != "$REMOTE_VERSION" ]; }; then
            rm -f "$BINARY_TMP"
            echo "版本校验失败，保留原二进制: 期望 ${REMOTE_VERSION:-有效版本标识}，实际 $NEW_ID"
            exit 1
        fi
        if ! mv -f "$BINARY_TMP" "$BIN_PATH"; then
            rm -f "$BINARY_TMP"
            echo "cnode 替换失败，保留原二进制。"
            exit 1
        fi
        BINARY_UPDATED=1
        echo "cnode 已更新: $NEW_ID"
    else
        echo "cnode 已是最新版本: $REMOTE_VERSION"
    fi

    if [ "$NEED_DEBUG_DOWNLOAD" -eq 1 ]; then
        echo "下载符号文件: $DEBUG_PATH"
        DEBUG_TMP=$(mktemp "$INSTALL_DIR/.cnode-debug.XXXXXX") || exit 1
        if ! curl -fsSL --connect-timeout 10 --max-time 180 --retry 3 \
            "$DEBUG_URL" -o "$DEBUG_TMP" || [ ! -s "$DEBUG_TMP" ] ||
            ! chmod 0644 "$DEBUG_TMP" || ! mv -f "$DEBUG_TMP" "$DEBUG_PATH"; then
            rm -f "$DEBUG_TMP"
            echo ".debug 文件下载失败，保留原符号文件。"
            exit 1
        fi
        echo ".debug 文件已下载: $DEBUG_PATH"
    fi
}

# ============================================================================
# geodata 更新（下载完成后替换；失败时保留旧文件）
# ============================================================================

update_geodata() {
    GEODATA_UPDATED=0
    install_dependency curl curl || return 1
    mkdir -p "$CONFIG_DIR" || return 1
    GEO_TMP_DIR=$(mktemp -d "$CONFIG_DIR/.geodata.XXXXXX") || return 1

    if ! curl -fsSL --connect-timeout 10 --max-time 180 --retry 3 \
        "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" \
        -o "$GEO_TMP_DIR/geoip.dat" \
        || ! curl -fsSL --connect-timeout 10 --max-time 180 --retry 3 \
        "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat" \
        -o "$GEO_TMP_DIR/geosite.dat" \
        || [ ! -s "$GEO_TMP_DIR/geoip.dat" ] || [ ! -s "$GEO_TMP_DIR/geosite.dat" ]; then
        rm -f "$GEO_TMP_DIR/geoip.dat" "$GEO_TMP_DIR/geosite.dat"
        rmdir "$GEO_TMP_DIR"
        echo "geodata 下载失败或文件为空，保留现有数据。"
        return 1
    fi

    for GEO_FILE in geoip.dat geosite.dat; do
        if cmp -s "$GEO_TMP_DIR/$GEO_FILE" "$CONFIG_DIR/$GEO_FILE"; then
            rm -f "$GEO_TMP_DIR/$GEO_FILE"
            echo "$GEO_FILE 已是最新数据"
        else
            if ! chmod 0644 "$GEO_TMP_DIR/$GEO_FILE" \
                || ! mv -f "$GEO_TMP_DIR/$GEO_FILE" "$CONFIG_DIR/$GEO_FILE"; then
                rm -f "$GEO_TMP_DIR/geoip.dat" "$GEO_TMP_DIR/geosite.dat"
                rmdir "$GEO_TMP_DIR"
                echo "$GEO_FILE 替换失败。"
                return 1
            fi
            GEODATA_UPDATED=1
            echo "已更新: $GEO_FILE"
        fi
    done
    rmdir "$GEO_TMP_DIR"
}

# ============================================================================
# systemd 服务
# ============================================================================

install_service() {
    cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=cnode proxy server
After=network.target

[Service]
Type=simple
ExecStart=$BIN_PATH --config-dir $CONFIG_DIR
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    echo "systemd 服务已创建: $SERVICE_NAME"
}

# ============================================================================
# 初始化配置（文件已存在则不动）
# ============================================================================

init_config() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"

    # config.json（cnode 配置；仅新安装创建。已有配置文件不覆盖）
    if [ ! -f "$CONFIG_JSON" ]; then
        # 未指定 -dns 时不写 servers，cnode 使用 /etc/resolv.conf 中的系统 DNS。
        DNS_SERVERS_LINE=""
        if [ -n "$dns" ] && echo "$dns" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
            DNS_SERVERS_LINE="    \"servers\": [\"$dns\"],
"
        fi

        cat > "$CONFIG_JSON" <<EOF
{
  "log": {
    "loglevel": "info",
    "access": "$LOG_DIR/access.log",
    "error": "$LOG_DIR/error.log",
    "logDir": "$LOG_DIR"
  },
  "workers": 0,
  "dns": {
${DNS_SERVERS_LINE}    "timeout": 5,
    "cacheSize": 10000,
    "minTTL": 60,
    "maxTTL": 3600
  },
  "timeouts": {
    "handshake": 60,
    "dial": 10,
    "read": 15,
    "write": 30,
    "connIdle": 300
  },
  "panels": []
}
EOF
        echo "已创建: config.json"
    fi

    # 远程配置文件（指定了 url 则每次覆盖下载）
    download_sidecar "$inbound_url" inbounds.json
    download_sidecar "$outbound_url" outbounds.json
    download_sidecar "$route_url" routing.json
}

# 下载到临时文件并通过 JSON 校验后再替换；失败时保留旧文件并退出。
download_sidecar() {
    [ -n "$1" ] || return 0
    echo "下载 $2: $1"
    SIDECAR_TMP=$(mktemp "$CONFIG_DIR/.$2.XXXXXX") || exit 1
    if ! curl -fsSL --connect-timeout 10 --max-time 180 --retry 3 \
        "$1" -o "$SIDECAR_TMP" \
        || ! jq -e . "$SIDECAR_TMP" >/dev/null 2>&1 \
        || ! chmod 0644 "$SIDECAR_TMP" \
        || ! mv -f "$SIDECAR_TMP" "$CONFIG_DIR/$2"; then
        rm -f "$SIDECAR_TMP"
        echo "错误: $2 下载失败或不是有效 JSON，保留原文件。"
        exit 1
    fi
}

# ============================================================================
# 配置文件校验
# ============================================================================

ensure_config_json_valid() {
    if [ ! -f "$CONFIG_JSON" ]; then
        return 0
    fi

    # Never guess repairs for broken input, or publish a case-folded collision.
    if ! jq -e '
        def validkeys:
            if type == "object" then
                ((keys_unsorted | map(ascii_downcase)) as $keys |
                    ($keys | length) == ($keys | unique | length)) and
                all(.[]; validkeys)
            elif type == "array" then all(.[]; validkeys)
            else true end;
        type == "object" and validkeys and
        all(to_entries[] | select(.key | ascii_downcase == "panels");
            .value | type == "array" and all(.[]; type == "object"))
    ' "$CONFIG_JSON" >/dev/null 2>&1; then
        echo "错误: config.json 无效或存在大小写冲突的字段，保留原文件，请手动修复"
        exit 1
    fi
}

# ============================================================================
# 添加/覆盖 panel
# ============================================================================

upsert_panel() {
    NODE_ID_JSON=$(echo "$node_id" | tr ',' '\n' | jq -s '.')
    PANEL_JSON=$(jq -n \
        --arg name "$name" \
        --arg api_host "$api_host" \
        --arg api_key "$api_key" \
        --argjson node_ids "$NODE_ID_JSON" \
        --arg node_type "$node_type" \
        '{
            name: $name,
            type: "V2board",
            apihost: $api_host,
            key: $api_key,
            nodeids: $node_ids,
            nodetype: $node_type,
            listenip: "auto",
            sendip: "auto",
            enabledns: true,
            tlsenable: false,
            tlscert: "",
            tlskey: ""
        }')

    if [ "$tls_enable" = "true" ]; then
        PANEL_JSON=$(echo "$PANEL_JSON" | jq \
            --arg cert "$tls_cert" \
            --arg key  "$tls_key" \
            '.tlsenable = true
             | if $cert != "" then .tlscert = $cert else . end
             | if $key  != "" then .tlskey = $key else . end')
    fi

    ensure_config_json_valid

    # Match keys case-insensitively, but preserve names, values and unrelated
    # configuration spelling. Panel identity itself remains case-sensitive.
    PANEL_TMP=$(mktemp "$CONFIG_JSON.XXXXXX") || exit 1
    if ! jq --arg name "$name" --argjson panel "$PANEL_JSON" '
        (keys_unsorted | map(select(ascii_downcase == "panels")) | .[0] // "panels") as $key |
        .[$key] = [(.[$key] // [])[] |
            select((with_entries(.key |= ascii_downcase) | .name) != $name)] + [$panel]
    ' "$CONFIG_JSON" > "$PANEL_TMP" || ! mv "$PANEL_TMP" "$CONFIG_JSON"; then
        rm -f "$PANEL_TMP"
        echo "错误: panel 配置写入失败，保留原文件"
        exit 1
    fi

    echo "已添加 panel: $name (nodeType=$node_type, NodeIDs=$node_id)"
}

# ============================================================================
# 主流程
# ============================================================================

main() {
    parse_options "$@"

    if ! has_deploy_options; then
        WAS_ACTIVE=0
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            WAS_ACTIVE=1
        fi
        update_geodata || exit 1
        install_cnode
        if [ "$WAS_ACTIVE" -eq 1 ]; then
            if [ "$GEODATA_UPDATED" -eq 1 ] || [ "${BINARY_UPDATED:-0}" -eq 1 ]; then
                systemctl restart "$SERVICE_NAME" || exit 1
            else
                systemctl start "$SERVICE_NAME" || exit 1
            fi
        fi
        exit 0
    fi

    for req in $REQUIRED_OPTIONS; do
        eval "value=\$$req"
        if [ -z "$value" ]; then
            echo "缺少必填选项: -$req"
            usage
        fi
    done

    update_geodata || exit 1
    install_cnode
    install_service
    init_config
    upsert_panel

    # 重启 cnode
    systemctl restart "$SERVICE_NAME"
    sleep 1

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo ""
        echo "========================================="
        echo " cnode 部署成功"
        echo "========================================="
        echo " 安装目录: $INSTALL_DIR"
        echo " 配置目录: $CONFIG_DIR"
        echo " 日志目录: $LOG_DIR"
        echo " 服务状态: $(systemctl is-active $SERVICE_NAME)"
        echo ""
        echo " 管理命令:"
        echo "   systemctl status $SERVICE_NAME"
        echo "   systemctl restart $SERVICE_NAME"
        echo "   systemctl stop $SERVICE_NAME"
        echo "   journalctl -u $SERVICE_NAME -f"
        echo ""
        echo " 再次添加 panel（同一 cnode 实例）:"
        echo "   bash <(curl -sL https://raw.githubusercontent.com/$REPO/master/scripts/cnode.sh) -name xxx -api_host xxx -api_key xxx -node_id 1,2 -node_type vmess"
        echo "========================================="
    else
        echo "cnode 启动失败，请检查日志:"
        echo "  journalctl -u $SERVICE_NAME --no-pager -n 50"
        exit 1
    fi
}

main "$@"
