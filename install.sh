#!/bin/bash

# 服务器管理面板 - Debian 安装/更新脚本

set -e

APP_DIR="/opt/server-dashboard"
SERVICE_NAME="server-dashboard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "  服务器管理面板 - 安装/更新脚本"
    echo "========================================"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_info() {
    echo -e "${BLUE}→ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# 检查是否为 root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用 root 用户运行此脚本"
        echo "sudo bash install.sh [install|update|uninstall|status]"
        exit 1
    fi
}

# 检查是否已安装
is_installed() {
    [ -d "$APP_DIR" ] && [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]
}

# 安装 Node.js
install_nodejs() {
    if ! command -v node &> /dev/null; then
        print_info "安装 Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
        print_success "Node.js 安装完成: $(node -v)"
    else
        print_success "Node.js 已安装: $(node -v)"
    fi
}

# 复制应用文件
copy_files() {
    print_info "复制应用文件..."
    mkdir -p "$APP_DIR"

    # 核心文件
    cp "$SCRIPT_DIR/package.json" "$APP_DIR/"
    cp "$SCRIPT_DIR/server.js" "$APP_DIR/"
    cp "$SCRIPT_DIR/index.html" "$APP_DIR/"

    # VNC 模块
    if [ -f "$SCRIPT_DIR/vnc.js" ]; then
        cp "$SCRIPT_DIR/vnc.js" "$APP_DIR/"
    fi
    if [ -f "$SCRIPT_DIR/vnc-client.js" ]; then
        cp "$SCRIPT_DIR/vnc-client.js" "$APP_DIR/"
    fi

    print_success "文件复制完成"
}

# 安装依赖
install_deps() {
    print_info "安装 npm 依赖..."
    cd "$APP_DIR"
    npm install --production --silent
    print_success "依赖安装完成"
}

# 创建 systemd 服务
create_service() {
    print_info "创建系统服务..."
    cat > /etc/systemd/system/${SERVICE_NAME}.service << 'EOF'
[Unit]
Description=Server Management Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/server-dashboard
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME} --quiet
    print_success "服务创建完成"
}

# 启动服务
start_service() {
    print_info "启动服务..."
    systemctl restart ${SERVICE_NAME}
    sleep 2
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败，请查看日志: journalctl -u ${SERVICE_NAME} -f"
        exit 1
    fi
}

# 停止服务
stop_service() {
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        print_info "停止服务..."
        systemctl stop ${SERVICE_NAME}
        print_success "服务已停止"
    fi
}

# 显示安装信息
show_info() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}========================================"
    echo "  操作完成!"
    echo -e "========================================${NC}"
    echo ""
    echo -e "访问地址: ${BLUE}http://$SERVER_IP:3000${NC}"
    echo -e "登录账号: ${YELLOW}admin${NC}"
    echo -e "登录密码: ${YELLOW}admin${NC}"
    echo ""
    echo "常用命令:"
    echo "  查看状态: systemctl status ${SERVICE_NAME}"
    echo "  查看日志: journalctl -u ${SERVICE_NAME} -f"
    echo "  重启服务: systemctl restart ${SERVICE_NAME}"
    echo "  停止服务: systemctl stop ${SERVICE_NAME}"
    echo "  更新应用: bash install.sh update"
    echo ""
}

# 安装
do_install() {
    print_banner

    if is_installed; then
        print_warning "检测到已安装，将执行更新操作"
        do_update
        return
    fi

    print_info "[1/5] 更新系统包..."
    apt-get update -qq
    print_success "系统包更新完成"

    echo ""
    print_info "[2/5] 安装 Node.js..."
    install_nodejs

    echo ""
    print_info "[3/5] 部署应用文件..."
    copy_files

    echo ""
    print_info "[4/5] 安装依赖..."
    install_deps

    echo ""
    print_info "[5/5] 配置系统服务..."
    create_service
    start_service

    show_info
}

# 更新
do_update() {
    print_banner
    echo -e "${YELLOW}执行更新...${NC}"
    echo ""

    if ! is_installed; then
        print_error "应用未安装，请先运行: bash install.sh install"
        exit 1
    fi

    # 备份用户数据
    print_info "[1/4] 备份用户数据..."
    BACKUP_DIR="/tmp/server-dashboard-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    if [ -f "$APP_DIR/users.json" ]; then
        cp "$APP_DIR/users.json" "$BACKUP_DIR/"
    fi
    if [ -d "$APP_DIR/userdata" ]; then
        cp -r "$APP_DIR/userdata" "$BACKUP_DIR/"
    fi
    print_success "用户数据已备份到: $BACKUP_DIR"

    # 停止服务
    echo ""
    print_info "[2/4] 停止服务..."
    stop_service

    # 更新文件
    echo ""
    print_info "[3/4] 更新应用文件..."
    copy_files
    install_deps

    # 恢复用户数据
    if [ -f "$BACKUP_DIR/users.json" ]; then
        cp "$BACKUP_DIR/users.json" "$APP_DIR/"
    fi
    if [ -d "$BACKUP_DIR/userdata" ]; then
        cp -r "$BACKUP_DIR/userdata" "$APP_DIR/"
    fi
    print_success "用户数据已恢复"

    # 启动服务
    echo ""
    print_info "[4/4] 启动服务..."
    start_service

    show_info
    print_success "更新完成!"
}

# 卸载
do_uninstall() {
    print_banner
    echo -e "${RED}执行卸载...${NC}"
    echo ""

    read -p "确定要卸载吗？用户数据将被删除！(y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "取消卸载"
        exit 0
    fi

    print_info "停止并禁用服务..."
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    print_success "服务已移除"

    print_info "删除应用目录..."
    rm -rf "$APP_DIR"
    print_success "应用目录已删除"

    echo ""
    print_success "卸载完成!"
}

# 查看状态
do_status() {
    print_banner

    if ! is_installed; then
        print_warning "应用未安装"
        exit 0
    fi

    echo -e "${BLUE}服务状态:${NC}"
    systemctl status ${SERVICE_NAME} --no-pager || true

    echo ""
    echo -e "${BLUE}应用版本:${NC}"
    if [ -f "$APP_DIR/package.json" ]; then
        grep '"version"' "$APP_DIR/package.json" | head -1
    fi

    echo ""
    echo -e "${BLUE}磁盘使用:${NC}"
    du -sh "$APP_DIR" 2>/dev/null || echo "无法获取"
}

# 主入口
main() {
    check_root

    case "${1:-install}" in
        install)
            do_install
            ;;
        update)
            do_update
            ;;
        uninstall|remove)
            do_uninstall
            ;;
        status)
            do_status
            ;;
        *)
            echo "用法: bash install.sh [install|update|uninstall|status]"
            echo ""
            echo "命令:"
            echo "  install    安装应用（默认）"
            echo "  update     更新应用（保留用户数据）"
            echo "  uninstall  卸载应用"
            echo "  status     查看状态"
            exit 1
            ;;
    esac
}

main "$@"
