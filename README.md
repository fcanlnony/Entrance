# Server Management Dashboard

基于 Web 的服务器管理面板，支持 SSH 终端、VNC 远程桌面、WebSerial 串口终端和 SFTP 文件管理。采用 Microsoft Fluent Design 设计风格，支持亮色/暗色主题。

## 功能特性

### SSH 终端
- 基于 WebSocket 的实时 SSH 连接
- xterm.js 终端模拟器
- 支持终端窗口大小自适应
- 连接状态实时显示

### VNC 远程桌面
- 基于 noVNC 的远程桌面连接
- 支持 WebSocket 代理连接
- 全屏模式支持
- 实时画面传输

### WebSerial 串口终端
- 浏览器原生串口通信（Web Serial API）
- 支持自定义波特率配置
- xterm.js 终端显示
- 适用于硬件调试、嵌入式开发

### SFTP 文件管理
- 远程文件浏览与导航
- 前进/后退/上级目录导航
- 文件/文件夹上传（支持拖拽）
- 单文件下载
- 多文件/文件夹打包下载（ZIP）
- 新建文件夹
- 删除文件/文件夹
- Ctrl+点击 多选文件

### 用户管理
- 多用户支持（管理员/普通用户）
- 用户添加/删除/密码修改
- 访客登录（关闭网页自动清除数据）
- 用户数据隔离（每个用户独立的主机列表）

### 界面特性
- Microsoft Fluent Design 设计风格
- 亮色/暗色主题切换
- 亚克力效果（Acrylic）
- Reveal 高亮效果
- 响应式侧边栏

## 快速开始

### 环境要求
- Node.js >= 16.0.0
- npm

### 本地运行

```bash
# 克隆仓库
git clone git@github.com:fcanlnony/Entrance.git
cd Entrance

# 安装依赖
npm install

# 启动服务
npm start
```

访问 http://localhost:3000

### Debian 服务器部署

```bash
# 下载并运行安装脚本
sudo bash install.sh
```

安装脚本会：
1. 安装 Node.js 20.x
2. 复制文件到 `/opt/server-dashboard`
3. 创建 systemd 服务
4. 启动服务并设置开机自启

### 服务管理命令

```bash
# 查看状态
systemctl status server-dashboard

# 查看日志
journalctl -u server-dashboard -f

# 重启服务
systemctl restart server-dashboard

# 停止服务
systemctl stop server-dashboard
```

### 修改端口

编辑 `/etc/systemd/system/server-dashboard.service`：
```ini
Environment=PORT=3000  # 修改为你想要的端口
```

然后重新加载并重启：
```bash
systemctl daemon-reload
systemctl restart server-dashboard
```

## 默认账号

| 用户名 | 密码 | 角色 |
|-------|------|------|
| admin | admin | 管理员 |

> ⚠️ **安全提示**：请在首次登录后立即修改默认密码！

## 项目结构

```
.
├── index.html      # 前端页面（单文件）
├── server.js       # 后端服务器
├── package.json    # 依赖配置
├── install.sh      # Debian 安装脚本
├── users.json      # 用户数据（自动生成）
└── userdata/       # 用户数据目录（自动生成）
    ├── admin.json  # admin 的主机列表
    └── user1.json  # user1 的主机列表
```

## 技术栈

### 前端
- 原生 HTML/CSS/JavaScript
- [xterm.js](https://xtermjs.org/) - 终端模拟器
- [Font Awesome](https://fontawesome.com/) - 图标库

### 后端
- [Express](https://expressjs.com/) - Web 框架
- [ws](https://github.com/websockets/ws) - WebSocket
- [ssh2](https://github.com/mscdex/ssh2) - SSH 客户端
- [multer](https://github.com/expressjs/multer) - 文件上传
- [archiver](https://github.com/archiverjs/node-archiver) - ZIP 打包

## API 接口

### 认证
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/guest` - 访客登录
- `POST /api/auth/guest/logout/:guestId` - 访客登出

### 用户管理
- `GET /api/users` - 获取用户列表
- `POST /api/users` - 添加用户
- `DELETE /api/users/:username` - 删除用户
- `PUT /api/users/:username/password` - 修改密码

### 用户数据
- `GET /api/userdata/:userId/hosts` - 获取主机列表
- `POST /api/userdata/:userId/hosts` - 添加主机
- `DELETE /api/userdata/:userId/hosts/:index` - 删除主机

### SFTP
- `POST /api/sftp/connect` - 建立连接
- `POST /api/sftp/disconnect/:sessionId` - 断开连接
- `GET /api/sftp/list/:sessionId` - 列出目录
- `GET /api/sftp/home/:sessionId` - 获取家目录
- `POST /api/sftp/mkdir/:sessionId` - 创建目录
- `DELETE /api/sftp/delete/:sessionId` - 删除文件/目录
- `POST /api/sftp/upload/:sessionId` - 上传文件
- `GET /api/sftp/download/:sessionId` - 下载文件
- `POST /api/sftp/download-zip/:sessionId` - 打包下载

### SSH (WebSocket)

WebSocket 连接到 `ws://host:port/ssh`，消息格式：

```javascript
// 连接
{ "type": "connect", "host": "192.168.1.1", "port": 22, "username": "root", "password": "xxx" }

// 发送数据
{ "type": "data", "data": "ls -la\n" }

// 调整窗口大小
{ "type": "resize", "cols": 80, "rows": 24 }

// 断开连接
{ "type": "disconnect" }
```

### VNC (WebSocket)

WebSocket 连接到 `ws://host:port/vnc`，代理转发到目标 VNC 服务器。

消息格式：
```javascript
// 初始连接时发送目标信息
{ "type": "connect", "host": "192.168.1.1", "port": 5900 }
```

## 截图

### 暗色主题
![Dark Theme](https://via.placeholder.com/800x500/1a1a1a/0078D7?text=Dark+Theme)

### 亮色主题
![Light Theme](https://via.placeholder.com/800x500/ffffff/0078D7?text=Light+Theme)

## 安全说明

- 密码以明文存储在 `users.json`，生产环境建议：
  - 使用 bcrypt 加密密码
  - 配置 HTTPS（使用 nginx 反向代理）
  - 配置防火墙限制访问 IP
  - 定期更新依赖包
- SSH/SFTP 凭据仅保存在用户浏览器本地或服务端用户数据中
- 访客数据在关闭网页后自动清除

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
