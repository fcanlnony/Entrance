#!/bin/bash

# 服务器管理面板 - Debian 安装脚本

set -e

echo "========================================"
echo "  服务器管理面板 - 安装脚本"
echo "========================================"

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then
    echo "请使用 root 用户运行此脚本"
    echo "sudo bash install.sh"
    exit 1
fi

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/server-dashboard"
SERVICE_USER="serverdash"

echo ""
echo "[1/6] 更新系统包..."
apt-get update -qq

echo ""
echo "[2/6] 安装 Node.js..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
else
    echo "Node.js 已安装: $(node -v)"
fi

echo ""
echo "[3/6] 创建应用目录..."
mkdir -p "$APP_DIR"
cp "$SCRIPT_DIR/package.json" "$APP_DIR/"
cp "$SCRIPT_DIR/server.js" "$APP_DIR/"
cp "$SCRIPT_DIR/index.html" "$APP_DIR/"

echo ""
echo "[4/6] 安装依赖..."
cd "$APP_DIR"
npm install --production

echo ""
echo "[5/6] 创建系统服务..."
cat > /etc/systemd/system/server-dashboard.service << 'EOF'
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

echo ""
echo "[6/6] 启动服务..."
systemctl daemon-reload
systemctl enable server-dashboard
systemctl restart server-dashboard

# 获取服务器 IP
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "========================================"
echo "  安装完成!"
echo "========================================"
echo ""
echo "访问地址: http://$SERVER_IP:3000"
echo "登录账号: admin"
echo "登录密码: admin"
echo ""
echo "常用命令:"
echo "  查看状态: systemctl status server-dashboard"
echo "  查看日志: journalctl -u server-dashboard -f"
echo "  重启服务: systemctl restart server-dashboard"
echo "  停止服务: systemctl stop server-dashboard"
echo ""
echo "修改端口: 编辑 /etc/systemd/system/server-dashboard.service"
echo "         修改 Environment=PORT=3000 中的端口号"
echo "         然后执行: systemctl daemon-reload && systemctl restart server-dashboard"
echo ""
