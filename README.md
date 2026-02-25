# Entrance Tools

基于 Web 的服务器管理工具，支持 SSH 终端、本地 Shell 终端、VNC 远程桌面、WebSerial 串口终端和 SFTP 文件管理。采用 Microsoft Fluent Design 设计风格，支持亮色/暗色主题。

## 功能特性

### SSH 终端
- 基于 WebSocket 的实时 SSH 连接
- xterm.js 终端模拟器
- 支持终端窗口大小自适应
- 连接状态实时显示
- **系统监控** - 实时性能监控功能
  - 连接后自动开始采集，状态栏显示 CPU / 内存 / 磁盘 I/O
  - 点击状态栏展开 Chart.js 折线图查看历史趋势
  - 基于 /proc/stat、/proc/meminfo、/proc/diskstats
  - 1秒采样间隔，最多显示60个数据点
- **进程管理 (TOP)** - 实时进程监控面板
  - 连接后自动采集进程信息，状态栏显示进程数 / 运行数 / 负载
  - 点击状态栏展开查看完整进程列表
  - 显示 PID、用户、CPU%、内存%、VSZ、RSS、状态、时间、命令
  - 支持按 CPU / 内存 / PID / 时间排序
  - 支持设置显示数量（15/30/50/100）
  - **杀进程功能** - 支持发送多种信号
    - SIGTERM (15) - 优雅终止
    - SIGKILL (9) - 强制终止
    - SIGINT (2) - 中断信号
    - SIGHUP (1) - 挂起/重载配置
    - SIGSTOP (19) - 暂停进程
    - SIGCONT (18) - 继续进程

### 本地 Shell 终端
- 在浏览器中访问服务器本地终端
- 基于 script + child_process 实现，无需编译原生模块
- **仅支持 Linux 系统**
- 仅允许 PATH 内的 Shell（bash/zsh/fish 等）
- 256 色彩支持
- 终端大小自适应

### VNC 远程桌面
- 基于 noVNC 的远程桌面连接
- 支持 WebSocket 代理连接
- 全屏模式支持
- 实时画面传输

### WebSerial 串口终端
- 浏览器原生串口通信（Web Serial API）
- 支持自定义波特率配置
- xterm.js 终端显示
- 仅允许 /dev 平台访问（Windows 默认禁用）
- **实时波形可视化** - 类示波器功能
  - 自动检测 `Variable:Value` 格式数据
  - 动态创建多变量曲线
  - 滑动窗口显示（可调节 50-1000 采样点）
  - 实时图例显示当前值
  - 暂停/继续/清除功能
- **统计图可视化** - 柱状图对比功能
  - 支持 `var:[a:2, b:3, c:5, d:6]` 格式数据
  - 不同子变量自动分配不同颜色
  - 支持多变量同时显示
- **演示模式** - 无需真实串口即可测试波形和统计图功能
- 适用于硬件调试、嵌入式开发、ADC 数据可视化

### SFTP 文件管理
- 远程文件浏览与导航
- 前进/后退/上级目录导航
- 文件/文件夹上传（支持拖拽）
- 单文件下载
- 多文件/文件夹打包下载（ZIP）
- 新建文件夹
- 删除文件/文件夹
- Ctrl+点击 多选文件

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

访问 http://localhost:3000，使用账号登录后进入工具面板。

### 最小运行示例

```bash
export AUTH_SECRET=$(openssl rand -base64 32)
export SSH_PASSWORD_KEY=$(openssl rand -base64 32)
npm start
```

默认账号为 `admin/admin`（首次启动自动生成）。

### Podman 启动示例（Host 网络 + 串口）

```bash
# 构建镜像
podman build -t entrance-tools .

# 运行（Host 网络 + 串口设备 + 持久化数据）
export AUTH_SECRET=$(openssl rand -base64 32)
export SSH_PASSWORD_KEY=$(openssl rand -base64 32)
podman run -d --name entrance-tools \
  --network host \
  --device /dev/ttyS0 \
  --device /dev/ttyS1 \
  -e AUTH_SECRET \
  -e SSH_PASSWORD_KEY \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

> 将 `--device /dev/ttyS*` 替换为你机器上实际存在的串口设备（例如 `/dev/ttyUSB0`、`/dev/ttyACM0`）。Host 网络模式下无需 `-p` 映射端口。

## 项目结构

```
.
├── public/         # 前端静态资源
│   ├── index.html
│   └── vnc-client.js
├── server.js       # 后端服务器
├── local-shell.js  # 本地 Shell 模块
├── vnc.js          # VNC 代理模块
├── nginx/          # 反向代理示例配置
├── package.json    # 依赖配置
├── users.json      # 用户数据（自动生成）
├── known_hosts.json  # SSH 主机指纹（自动生成）
├── private-networks.json  # 私有网络白名单（自动生成，已加密）
└── userdata/       # 用户数据目录（自动生成）
    ├── admin.json  # admin 的主机列表
    └── user1.json  # user1 的主机列表
```

## 技术栈

### 前端
- 原生 HTML/CSS/JavaScript
- [xterm.js](https://xtermjs.org/) - 终端模拟器
- [Chart.js](https://www.chartjs.org/) - 波形可视化图表
- [noVNC](https://novnc.com/) - VNC 客户端
- [Font Awesome](https://fontawesome.com/) - 图标库

### 后端
- [Express](https://expressjs.com/) - Web 框架
- [ws](https://github.com/websockets/ws) - WebSocket
- [ssh2](https://github.com/mscdex/ssh2) - SSH 客户端
- script + child_process - 本地终端（Linux 原生，无需编译）
- [multer](https://github.com/expressjs/multer) - 文件上传
- [archiver](https://github.com/archiverjs/node-archiver) - ZIP 打包

> **注意**：本地 Shell 功能仅支持 Linux 系统，使用 `script` 命令实现 PTY 功能，无需额外编译依赖。

## API 接口

### 认证
- `POST /api/auth/login` - 登录并返回 token
- `POST /api/auth/verify` - 校验 token

所有 API 需在请求头携带 `Authorization: Bearer <token>`。

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

SFTP 连接参数示例：

```javascript
// 密码登录
{
  "host": "192.168.1.10",
  "port": 22,
  "username": "root",
  "authType": "password",
  "password": "xxx"
}

// 私钥登录
{
  "host": "192.168.1.10",
  "port": 22,
  "username": "root",
  "authType": "key",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "passphrase": "optional"
}
```

### 安全配置
- `GET /api/security/private-networks` - 获取私有网段白名单（管理员）
- `PUT /api/security/private-networks` - 更新私有网段白名单（管理员）

### SSH (WebSocket)

WebSocket 连接到 `ws://host:port/ssh?token=...`，消息格式：

```javascript
// 连接
{ "type": "connect", "host": "192.168.1.1", "port": 22, "username": "root", "password": "xxx" }

// 使用私钥连接
{
  "type": "connect",
  "host": "192.168.1.1",
  "port": 22,
  "username": "root",
  "authType": "key",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "passphrase": "optional"
}

// 发送数据
{ "type": "data", "data": "ls -la\n" }

// 调整窗口大小
{ "type": "resize", "cols": 80, "rows": 24 }

// 断开连接
{ "type": "disconnect" }

// 开始系统监控（每秒采集 /proc/stat, /proc/meminfo, /proc/diskstats）
{ "type": "startStats" }

// 停止系统监控
{ "type": "stopStats" }

// 开始进程监控（每2秒采集 uptime 和 ps aux）
{ "type": "startTop" }

// 停止进程监控
{ "type": "stopTop" }

// 手动刷新进程列表
{ "type": "refreshTop" }

// 发送信号给进程（杀进程）
{ "type": "kill", "pid": 1234, "signal": 15 }
```

服务器返回的系统监控数据格式：
```javascript
{
  "type": "stats",
  "data": {
    "stat": "cpu  12345 678 ...",      // /proc/stat 内容
    "meminfo": "MemTotal: ...",         // /proc/meminfo 内容
    "diskstats": "8 0 sda ..."          // /proc/diskstats 内容
  }
}
```

服务器返回的进程监控数据格式：
```javascript
{
  "type": "top",
  "data": {
    "uptime": "10:15:03 up 5 days...",  // uptime 命令输出
    "ps": "USER PID %CPU %MEM ..."       // ps aux 命令输出
  }
}
```

服务器返回的杀进程结果：
```javascript
{
  "type": "killResult",
  "data": {
    "success": true,
    "message": "已发送 SIGTERM 到 PID 1234"
  }
}
```

### VNC (WebSocket)

WebSocket 连接到 `ws://host:port/vnc`，代理转发到目标 VNC 服务器。

消息格式：
```javascript
// 初始连接时发送目标信息
{ "type": "connect", "host": "192.168.1.1", "port": 5900 }
```

### 本地 Shell (WebSocket)

WebSocket 连接到 `ws://host:port/localshell`，访问服务器本地终端。

消息格式：
```javascript
// 启动 shell
{ "type": "start", "cols": 80, "rows": 24, "cwd": "/home/user" }

// 发送输入
{ "type": "data", "data": "ls -la\n" }

// 调整窗口大小
{ "type": "resize", "cols": 120, "rows": 40 }

// 停止 shell
{ "type": "stop" }
```

状态检查 API：
- `GET /api/localshell/status` - 获取本地 shell 服务状态

### 串口数据格式 (WebSerial)

串口终端支持两种数据格式的自动解析，两种格式互斥，不会相互干扰：

#### 波形数据格式

用于实时波形显示，格式为 `VariableName:NumericValue`：

```
ADC1:1024
Temp:25.5
Sin:-0.866
Voltage:3.3
```

也支持单行多变量（逗号分隔）：
```
a:2, b:4, temp:25.5
```

- 变量名：字母或下划线开头，可包含字母、数字、下划线
- 数值：整数或浮点数，支持负数
- 每行一个或多个数据点，以换行符分隔
- 自动为每个变量分配不同颜色

#### 统计图数据格式

用于柱状图对比显示，格式为 `varName:[key1:value1, key2:value2, ...]`：

```
stats:[a:2, b:3, c:5, d:6]
```

支持单行多变量：
```
var1:[a:4, b:6], var2:[a:6, b:3, c:2]
```

支持多行解析（每行独立解析）：
```
cpu:[user:45, system:12, idle:43]
memory:[used:8192, free:4096, cached:2048]
```

- 变量名（如 `stats`、`var1`）：作为 X 轴标签
- 子变量名（如 `a`、`b`、`c`）：每个子变量使用不同颜色
- 数值：整数或浮点数，支持负数
- 相同子变量名在不同变量中会使用相同颜色，方便对比

## 安全说明

- 当前版本默认不启用登录保护，请部署在受信任网络内，并在反向代理层增加认证与 HTTPS。
- SSH/SFTP 凭据（密码、私钥、私钥口令）仅保存在用户浏览器本地或服务端用户数据中，服务端落盘会使用 `SSH_PASSWORD_KEY` 进行 AES-256-GCM 加密。
- `SSH_PASSWORD_KEY` 变更后，历史已加密凭据将无法解密；需要恢复原密钥或在界面中重新录入对应主机凭据。
- **本地 Shell 安全提示**（仅 Linux）：本地 Shell 功能允许直接访问服务器终端，请确保：
  - 仅在受信任的网络环境中使用
  - 限制访问权限给授权用户
  - 生产环境中考虑禁用此功能或添加额外认证

## 许可证

GPL-3.0 License

## 贡献

欢迎提交 Issue 和 Pull Request！
