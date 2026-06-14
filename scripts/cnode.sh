#!/bin/sh

# cnode 一键部署脚本
# 用法: bash <(curl -sL <url>) -name xxx -api_host xxx -api_key xxx -node_id 1,2 -node_type vmess
# 每次执行添加/覆盖一个 panel 到同一个 cnode 实例，已有配置文件不会被覆盖

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
    echo "不带参数时：仅更新 cnode 二进制（默认 release）"
    echo ""
    echo "必填选项:"
    for opt in $REQUIRED_OPTIONS; do
        echo "  -$opt <value>"
    done
    echo ""
    echo "可选选项:"
    echo "  -dns <ip>              DNS 服务器（默认 1.1.1.1）"
    echo "  -tls_enable true       启用 TLS（trojan 需要）"
    echo "  -tls_cert <path>       TLS 证书路径"
    echo "  -tls_key <path>        TLS 私钥路径"
    echo "  -outbound_url <url>    远程 outbounds.json 下载地址（文件已存在则跳过）"
    echo "  -route_url <url>       远程 routing.json 下载地址（文件已存在则跳过）"
    echo "  -inbound_url <url>     远程 inbounds.json 下载地址（文件已存在则跳过）"
    echo "  -v <version>           指定 release 版本（默认 master）"
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
        pacman -Syu --noconfirm "$2"
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

    # 获取远程 build_id。GitHub API 在部分机房偶发不可达，API 失败时
    # 回退到 release 直链下载，只跳过 build_id 强校验。
    RELEASE_TAG="${v:-master}"
    RELEASE_ASSET_BASE="https://github.com/$REPO/releases/download/$RELEASE_TAG"
    RELEASE_INFO=$(curl -fsSL --connect-timeout 10 --retry 2 \
        -H "Accept: application/vnd.github+json" \
        -H "User-Agent: cnode-installer" \
        "https://api.github.com/repos/$REPO/releases/tags/$RELEASE_TAG" 2>/dev/null || true)

    REMOTE_ID=""
    REMOTE_VERSION=""
    if [ -n "$RELEASE_INFO" ]; then
        REMOTE_ID=$(echo "$RELEASE_INFO" \
            | jq -r '.body // ""' 2>/dev/null \
            | sed -n 's/.*build_id: \([^[:space:]]*\).*/\1/p' \
            | head -1)
        if [ -n "$REMOTE_ID" ]; then
            REMOTE_VERSION="release:$REMOTE_ID"
        else
            echo "警告: 无法解析远程 build_id，将跳过版本号校验。"
        fi
    else
        echo "警告: 无法获取远程版本信息，回退到 release 直链下载。"
    fi

    DEBUG_PATH="$INSTALL_DIR/cnode-linux-amd64.debug"

    # 比对本地版本，相同则跳过（早期版本不支持 -v，用 timeout 防止挂起）
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
            | jq -r --arg asset "cnode-linux-amd64" '.assets[] | select(.name == $asset) | .browser_download_url' 2>/dev/null \
            | head -1)
    fi

    if [ -z "$LATEST_URL" ] || [ "$LATEST_URL" = "null" ]; then
        LATEST_URL="$RELEASE_ASSET_BASE/cnode-linux-amd64"
    fi

    NEED_DEBUG_DOWNLOAD=0
    DEBUG_URL=""
    if [ "$DEBUG_FILE" = "true" ]; then
        NEED_DEBUG_DOWNLOAD=1
        if [ -n "$RELEASE_INFO" ]; then
            DEBUG_URL=$(echo "$RELEASE_INFO" \
                | jq -r --arg asset "cnode-linux-amd64.debug" '.assets[] | select(.name == $asset) | .browser_download_url' 2>/dev/null \
                | head -1)
        fi
        if [ -z "$DEBUG_URL" ] || [ "$DEBUG_URL" = "null" ]; then
            DEBUG_URL="$RELEASE_ASSET_BASE/cnode-linux-amd64.debug"
        fi
    fi

    if [ "$NEED_BINARY_UPDATE" -eq 0 ] && [ "$NEED_DEBUG_DOWNLOAD" -eq 0 ]; then
        echo "cnode 已是最新版本: $REMOTE_VERSION"
        return 0
    fi

    if [ "$NEED_BINARY_UPDATE" -eq 1 ]; then
        # 运行中的二进制无法覆盖（Text file busy），先停服务并杀残留进程
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            echo "停止 cnode 服务..."
            systemctl stop "$SERVICE_NAME"
        fi
        pkill -f "$BIN_PATH" 2>/dev/null || true
        sleep 1

        UPDATE_TARGET="$REMOTE_VERSION"
        if [ -z "$UPDATE_TARGET" ]; then
            UPDATE_TARGET="release:$RELEASE_TAG"
        fi
        echo "更新 cnode: ${LOCAL_ID:-none} -> $UPDATE_TARGET"
        if ! curl -fsSL --connect-timeout 10 --retry 3 "$LATEST_URL" -o "$BIN_PATH"; then
            echo "cnode 下载失败。"
            exit 1
        fi
        chmod +x "$BIN_PATH"

        # 验证下载的版本
        NEW_ID=$(timeout 3 "$BIN_PATH" -v 2>/dev/null | tr -d '[:space:]')
        if [ -n "$REMOTE_VERSION" ]; then
            if [ "$NEW_ID" != "$REMOTE_VERSION" ]; then
                echo "版本校验失败: 期望 $REMOTE_VERSION，实际 $NEW_ID"
                exit 1
            fi
            echo "cnode 已更新到 $REMOTE_VERSION"
        elif [ -n "$NEW_ID" ]; then
            echo "cnode 已更新: $NEW_ID"
        else
            echo "cnode 已更新: $BIN_PATH"
        fi
    else
        echo "cnode 已是最新版本: $REMOTE_VERSION"
    fi

    if [ "$NEED_DEBUG_DOWNLOAD" -eq 1 ]; then
        echo "下载符号文件: $DEBUG_PATH"
        if ! curl -fsSL --connect-timeout 10 --retry 3 "$DEBUG_URL" -o "$DEBUG_PATH"; then
            echo ".debug 文件下载失败。"
            exit 1
        fi
        chmod 0644 "$DEBUG_PATH"
        echo ".debug 文件已下载: $DEBUG_PATH"
    fi
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
ExecStart=$BIN_PATH -c $CONFIG_DIR
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
        DNS_SERVER="1.1.1.1"
        if [ -n "$dns" ] && echo "$dns" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
            DNS_SERVER="$dns"
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
    "servers": ["$DNS_SERVER"],
    "timeout": 5,
    "cacheSize": 10000,
    "minTTL": 60,
    "maxTTL": 3600
  },
  "timeouts": {
    "handshake": 60,
    "dial": 10,
    "read": 15,
    "write": 30,
    "idle": 300
  },
  "panels": []
}
EOF
        echo "已创建: config.json"
    fi

    # 远程配置文件（指定了 url 则每次覆盖下载）
    if [ -n "$inbound_url" ]; then
        echo "下载 inbounds.json: $inbound_url"
        curl -sfL "$inbound_url" -o "$CONFIG_DIR/inbounds.json" || echo "警告: inbounds.json 下载失败"
    fi
    if [ -n "$outbound_url" ]; then
        echo "下载 outbounds.json: $outbound_url"
        curl -sfL "$outbound_url" -o "$CONFIG_DIR/outbounds.json" || echo "警告: outbounds.json 下载失败"
    fi
    if [ -n "$route_url" ]; then
        echo "下载 routing.json: $route_url"
        curl -sfL "$route_url" -o "$CONFIG_DIR/routing.json" || echo "警告: routing.json 下载失败"
    fi

    # 每次更新 geo 数据
    curl -sfL "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" \
        -o "$CONFIG_DIR/geoip.dat" || echo "警告: geoip.dat 下载失败"
    curl -sfL "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat" \
        -o "$CONFIG_DIR/geosite.dat" || echo "警告: geosite.dat 下载失败"
}

# ============================================================================
# 配置文件校验
# ============================================================================

ensure_config_json_valid() {
    if [ ! -f "$CONFIG_JSON" ]; then
        return 0
    fi

    # 校验现有 config.json 是否合法
    if ! jq empty "$CONFIG_JSON" 2>/dev/null; then
        echo "警告: config.json 格式损坏，尝试自动修复..."
        # 用 python/sed 尝试修复常见问题（缺逗号等），若失败则重建
        if command -v python3 >/dev/null 2>&1; then
            python3 -c "
import json, re, sys
with open('$CONFIG_JSON') as f:
    text = f.read()
# 修复对象/数组元素之间缺少逗号: }{ -> },{  或 ]{ -> ],{
text = re.sub(r'(\})\s*(\{)', r'\1,\2', text)
text = re.sub(r'(\])\s*(\{)', r'\1,\2', text)
try:
    obj = json.loads(text)
    with open('$CONFIG_JSON', 'w') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    print('自动修复成功')
except Exception as e:
    print(f'自动修复失败: {e}', file=sys.stderr)
    sys.exit(1)
" || {
                echo "错误: config.json 无法自动修复，请手动检查"
                exit 1
            }
        else
            echo "错误: config.json 格式损坏且无 python3 可用，请手动修复"
            exit 1
        fi
    fi
}

# ============================================================================
# 添加/覆盖 panel
# ============================================================================

add_panel() {
    add_panel_json
}

add_panel_json() {
    # config.json 分支：写入最终 panel schema。
    NODE_ID_JSON=$(echo "$node_id" | tr ',' '\n' | jq -s '.')
    PANEL_JSON=$(jq -n \
        --arg name "$name" \
        --arg api_host "$api_host" \
        --arg api_key "$api_key" \
        --argjson node_ids "$NODE_ID_JSON" \
        --arg node_type "$node_type" \
        '{
            Name: $name,
            Type: "V2board",
            APIHost: $api_host,
            Key: $api_key,
            NodeIDs: $node_ids,
            NodeType: $node_type,
            ListenIP: "auto",
            SendIP: "auto",
            EnableDNS: true,
            TLSEnable: false,
            TLSCert: "",
            TLSKey: ""
        }')

    if [ "$tls_enable" = "true" ]; then
        PANEL_JSON=$(echo "$PANEL_JSON" | jq \
            --arg cert "$tls_cert" \
            --arg key  "$tls_key" \
            '.TLSEnable = true
             | if $cert != "" then .TLSCert = $cert else . end
             | if $key  != "" then .TLSKey  = $key  else . end')
    fi

    ensure_config_json_valid

    # 先删除同名 panel（去重），再追加
    jq --arg name "$name" --argjson panel "$PANEL_JSON" \
        '.panels = [.panels[] | select(.Name != $name)] + [$panel]' \
        "$CONFIG_JSON" > "$CONFIG_JSON.tmp" \
        && mv "$CONFIG_JSON.tmp" "$CONFIG_JSON"

    echo "已添加 panel: $name (nodeType=$node_type, NodeIDs=$node_id)"
}

# ============================================================================
# 主流程
# ============================================================================

main() {
    if [ $# -eq 0 ]; then
        WAS_ACTIVE=0
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            WAS_ACTIVE=1
        fi
        install_cnode
        if [ "$WAS_ACTIVE" -eq 1 ]; then
            systemctl start "$SERVICE_NAME"
        fi
        exit 0
    fi

    parse_options "$@"

    if ! has_deploy_options; then
        WAS_ACTIVE=0
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            WAS_ACTIVE=1
        fi
        install_cnode
        if [ "$WAS_ACTIVE" -eq 1 ]; then
            systemctl start "$SERVICE_NAME"
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

    install_cnode
    install_service
    init_config
    add_panel

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
