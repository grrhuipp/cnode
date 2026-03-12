#!/bin/sh

# cnode 一键部署脚本
# 用法: bash <(curl -sL <url>) -name xxx -api_host xxx -api_key xxx -node_id 1,2 -node_type vmess
# 每次执行添加/覆盖一个 panel 到同一个 cnode 实例，已有配置文件不会被覆盖

ALLOWED_OPTIONS="name api_host api_key node_id node_type dns tls_enable tls_cert tls_key outbound_url route_url inbound_url v"
REQUIRED_OPTIONS="name api_host api_key node_id node_type"

INSTALL_DIR="/opt/cnode"
CONFIG_DIR="$INSTALL_DIR/config"
BIN_PATH="$INSTALL_DIR/cnode"
SERVICE_NAME="cnode"
REPO="grrhuipp/cnode"
LOG_DIR="$INSTALL_DIR/log"

# ============================================================================
# 参数解析
# ============================================================================

usage() {
    echo "用法: bash <(curl -sL ...) [选项]"
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
    echo "  -outbound_url <url>    远程 outbound.json 下载地址（文件已存在则跳过）"
    echo "  -route_url <url>       远程 route.json 下载地址（文件已存在则跳过）"
    echo "  -inbound_url <url>     远程 inbound.json 下载地址（文件已存在则跳过）"
    echo "  -v <version>           指定 release 版本（默认 master）"
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
    for req in $REQUIRED_OPTIONS; do
        eval "value=\$$req"
        if [ -z "$value" ]; then
            echo "缺少必填选项: -$req"
            usage
        fi
    done
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

    # 获取远程 build_id
    RELEASE_TAG="${v:-master}"
    RELEASE_INFO=$(curl -sf "https://api.github.com/repos/$REPO/releases/tags/$RELEASE_TAG")
    if [ -z "$RELEASE_INFO" ]; then
        echo "无法获取远程版本信息。"
        exit 1
    fi

    REMOTE_ID=$(echo "$RELEASE_INFO" | grep -o 'build_id: [0-9a-f]*' | awk '{print $2}')
    if [ -z "$REMOTE_ID" ]; then
        echo "无法解析远程 build_id。"
        exit 1
    fi

    # 比对本地版本，相同则跳过（早期版本不支持 -v，用 timeout 防止挂起）
    LOCAL_ID=""
    if [ -x "$BIN_PATH" ]; then
        LOCAL_ID=$(timeout 3 "$BIN_PATH" -v 2>/dev/null | tr -d '[:space:]')
    fi

    if [ "$LOCAL_ID" = "$REMOTE_ID" ]; then
        echo "cnode 已是最新版本: $REMOTE_ID"
        return 0
    fi

    LATEST_URL=$(echo "$RELEASE_INFO" \
        | jq -r '.assets[] | select(.name | test("linux.*amd64")) | .browser_download_url' \
        | head -1)

    if [ -z "$LATEST_URL" ] || [ "$LATEST_URL" = "null" ]; then
        LATEST_URL="https://github.com/$REPO/releases/download/$RELEASE_TAG/cnode-linux-amd64"
    fi

    # 运行中的二进制无法覆盖（Text file busy），先停服务并杀残留进程
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "停止 cnode 服务..."
        systemctl stop "$SERVICE_NAME"
    fi
    pkill -f "$BIN_PATH" 2>/dev/null || true
    sleep 1

    echo "更新 cnode: ${LOCAL_ID:-none} -> $REMOTE_ID"
    if ! curl -sfL "$LATEST_URL" -o "$BIN_PATH"; then
        echo "cnode 下载失败。"
        exit 1
    fi
    chmod +x "$BIN_PATH"

    # 验证下载的版本
    NEW_ID=$(timeout 3 "$BIN_PATH" -v 2>/dev/null | tr -d '[:space:]')
    if [ "$NEW_ID" != "$REMOTE_ID" ]; then
        echo "版本校验失败: 期望 $REMOTE_ID，实际 $NEW_ID"
        exit 1
    fi
    echo "cnode 已更新到 $REMOTE_ID"
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

    # config.json（仅不存在时创建）
    if [ ! -f "$CONFIG_DIR/config.json" ]; then
        DNS_SERVER="1.1.1.1"
        if [ -n "$dns" ] && echo "$dns" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
            DNS_SERVER="$dns"
        fi

        cat > "$CONFIG_DIR/config.json" <<EOF
{
  "log": {
    "loglevel": "info",
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
  "panels": []
}
EOF
        echo "已创建: config.json"
    fi

    # 远程配置文件（指定了 url 则每次覆盖下载）
    if [ -n "$inbound_url" ]; then
        echo "下载 inbound.json: $inbound_url"
        curl -sfL "$inbound_url" -o "$CONFIG_DIR/inbound.json" || echo "警告: inbound.json 下载失败"
    fi
    if [ -n "$outbound_url" ]; then
        echo "下载 outbound.json: $outbound_url"
        curl -sfL "$outbound_url" -o "$CONFIG_DIR/outbound.json" || echo "警告: outbound.json 下载失败"
    fi
    if [ -n "$route_url" ]; then
        echo "下载 route.json: $route_url"
        curl -sfL "$route_url" -o "$CONFIG_DIR/route.json" || echo "警告: route.json 下载失败"
    fi

    # 每次更新 geo 数据
    curl -sfL "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" \
        -o "$CONFIG_DIR/geoip.dat" || echo "警告: geoip.dat 下载失败"
    curl -sfL "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat" \
        -o "$CONFIG_DIR/geosite.dat" || echo "警告: geosite.dat 下载失败"
}

# ============================================================================
# 添加/覆盖 panel（jq 同名覆盖）
# ============================================================================

add_panel() {
    # 解析 node_id 为 JSON 数组: "1,2,3" -> [1,2,3]
    NODE_ID_JSON=$(echo "$node_id" | tr ',' '\n' | jq -s '.')

    # 构建 panel JSON
    PANEL_JSON=$(jq -n \
        --arg name "$name" \
        --arg api_host "$api_host" \
        --arg api_key "$api_key" \
        --argjson node_ids "$NODE_ID_JSON" \
        --arg node_type "$node_type" \
        '{
            name: $name,
            type: "V2Board",
            apiHost: $api_host,
            apiKey: $api_key,
            nodeID: $node_ids,
            nodeType: $node_type
        }')

    # TLS 配置（单次 jq 调用完成）
    if [ "$tls_enable" = "true" ]; then
        PANEL_JSON=$(echo "$PANEL_JSON" | jq \
            --arg cert "$tls_cert" \
            --arg key  "$tls_key" \
            '.tlsEnable = true
             | if $cert != "" then .tlsCert = $cert else . end
             | if $key  != "" then .tlsKey  = $key  else . end')
    fi

    # 先删除同名 panel（去重），再追加
    jq --arg name "$name" --argjson panel "$PANEL_JSON" \
        '.panels = [.panels[] | select(.name != $name)] + [$panel]' \
        "$CONFIG_DIR/config.json" > "$CONFIG_DIR/config.json.tmp" \
        && mv "$CONFIG_DIR/config.json.tmp" "$CONFIG_DIR/config.json"

    echo "已添加 panel: $name (nodeType=$node_type, nodeID=$node_id)"
}

# ============================================================================
# 主流程
# ============================================================================

main() {
    parse_options "$@"
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
