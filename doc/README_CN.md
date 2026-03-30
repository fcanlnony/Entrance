# Entrance Tools

基于 Web 的服务器管理工具，支持 SSH 终端、本地 Shell 终端、VNC 远程桌面、WebSerial 串口终端、烧录调试和 SFTP 文件管理。采用 Microsoft Fluent Design 设计风格，支持亮色/暗色主题，并提供中文/英文界面切换。
![Screenshot](screenshot_cn.png)

## 友链

- EK-OmniProbe https://github.com/EmbeddedKitOrg/EK-OmniProbe
- Clion-Waveform-Plotter https://github.com/Szturin/Clion-Waveform-Plotter

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
- **Docker 监控** - 容器资源监控面板
  - 连接后自动检测远程主机 Docker 环境，状态栏显示容器数 / CPU / 内存
  - 点击状态栏展开查看详细指标
  - SVG 圆环图展示 CPU、MEM、NET I/O、BLOCK I/O 四项指标
  - **总计模式** - 叠加显示所有容器的资源占用
  - **单个模式** - 左侧容器列表可选择，右侧显示选中容器的详细数据
  - 基于 `docker stats --no-stream` 命令，每 3 秒采样一次
  - 自动处理 Docker 未安装或权限不足等异常情况

### 本地 Shell 终端
- 在浏览器中访问服务器本地终端
- Linux/macOS 使用 `script + child_process`
- Windows 通过本机 `OpenSSH Server` + `127.0.0.1` SSH 会话获取 PTY/ConPTY 语义，无需 `node-pty`
- 支持 Linux、macOS、Windows
- 仅允许 PATH 内的 Shell（bash/zsh/fish/cmd/powershell 等）
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
- 支持 Linux `/dev/tty*`、macOS `/dev/cu.*`、Windows `COM*` 串口
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

### 烧录调试
- 支持 `OpenOCD`、`pyOCD`、`probe-rs` 三类本机烧录/调试工具
- 支持 GUI 选择烧录器、目标芯片/配置、速率、附加参数，并实时展示最终 CLI 与输出日志
- 支持本地固件文件上传到当前 Entrance 主机临时目录后再执行烧录
- `OpenOCD` 支持 target/interface 配置自动发现，`pyOCD` / `probe-rs` 支持自动枚举 probe
- **目标搜索补全** - 目标输入框支持按工具类型进行本地实时搜索补全
  - `OpenOCD` 支持搜索 `target/*.cfg` 与 `interface/*.cfg`
  - `pyOCD` 支持搜索内置 target 目录
  - `probe-rs` 支持搜索 `probe-rs chip list` 返回的芯片目录
  - 支持前缀匹配、片段匹配与简单模糊匹配，仍允许手动自由输入
  - 各工具的 placeholder、帮助提示、候选数量提示，以及 probe/目录回退说明会随当前界面语言自动切换
- **管理员/root 权限请求** - 可在启动烧录或调试前请求系统级提权
  - Linux 优先使用 `pkexec`，否则回退到 `sudo + zenity/kdialog`
  - macOS 使用 `sudo + osascript`
  - Windows 优先使用 `gsudo`，否则使用系统 `sudo`
- 仅管理员可启动本机烧录或调试任务

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
- **Material You 配色方案** - 6 套可选强调色方案
  - 默认方案（中性石墨）
  - 樱花粉（柔和花瓣）
  - 海洋蓝（清澈潮汐）
  - 森林绿（苔藓林地）
  - 暮光紫（柔雾暮色）
  - 琥珀橙（温暖日落）
- **界面国际化** - 默认英文，支持中文/英文即时切换
  - 在设置页“配色方案”卡片下方提供独立“语言”卡片
  - 当前支持简体中文与英文
  - 语言选择自动保存到浏览器本地存储
- 亚克力效果（Acrylic）
- Reveal 高亮效果
- 响应式侧边栏

### 设置
- **修改密码** - 用户可在设置页面修改自己的登录密码（Argon2id 加密）
- 当 `ENTRANCE_DESKTOP_NOLOGIN=1` 时，密码修改功能禁用并显示提示
- **内网白名单** - 管理员可在设置页中通过位于修改密码卡片下方的独立卡片管理 SSH、SFTP、VNC 使用的私有网段白名单
- **配色方案切换** - 在设置页面选择 Material You Design 风格的配色方案，选择自动保存
- **语言切换** - 在设置页面配色方案下方的独立卡片中切换界面语言，默认英文，当前支持中文和英文

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

如需指定端口，可使用环境变量或命令行参数：

```bash
PORT=4000 npm start
# 或
npm start -- --port 4000
```

此时访问 `http://localhost:4000`。

### 最小运行示例

```bash
mkdir -p ./.data
[ -f ./.data/auth_secret ] || openssl rand -base64 32 > ./.data/auth_secret

export ENTRANCE_DATA_DIR="$(pwd)/.data"
export AUTH_SECRET="$(tr -d '\n' < ./.data/auth_secret)"
npm start
```

上面的示例会把运行时数据固定到 `./.data`，并让 Entrance 在 `./.data/.ssh_password_key` 中自动生成并复用 SSH 凭据加密密钥。不要在每次重启前重新生成 `SSH_PASSWORD_KEY`，否则历史白名单、密码和私钥将无法解密。

默认账号为 `admin/admin`（首次启动自动生成）。

### Docker 启动示例

```bash
# 构建镜像
docker build -t entrance-tools .

# 仅首次创建一次运行环境
docker volume create entrance-tools-data
[ -f ./.docker-auth_secret ] || openssl rand -base64 32 > ./.docker-auth_secret

# 运行（端口映射 + 持久化数据）
docker run -d --name entrance-tools \
  -p 3000:3000 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.docker-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

如果要让容器监听其他端口，例如 `4000`，需要同时修改容器内监听端口与宿主机映射：

```bash
docker run -d --name entrance-tools \
  -p 4000:4000 \
  -e PORT=4000 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.docker-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

这里故意不传 `SSH_PASSWORD_KEY`。容器会在持久化卷 `/data/.ssh_password_key` 中自动生成并长期复用它；只要卷不丢，重建容器也不会导致历史加密数据失效。

### Docker Compose 启动示例

项目已包含 `compose.yml`，默认将宿主机 `./data` 挂载到容器内 `/data`：

```bash
mkdir -p ./data
[ -f ./.compose-auth_secret ] || openssl rand -base64 32 > ./.compose-auth_secret

export AUTH_SECRET="$(tr -d '\n' < ./.compose-auth_secret)"
docker compose up -d --build
```

若需指定端口，可在启动前设置 `PORT`，例如：

```bash
export PORT=4000
docker compose up -d --build
```

同样建议不要在每次 `docker compose up` 前重新生成 `SSH_PASSWORD_KEY`。保留 `./data` 目录后，Entrance 会自动复用 `./data/.ssh_password_key`。

### Podman 用户说明

Podman 用户将上述示例中的 `docker` 替换为 `podman` 即可。如果需要 Host 网络和串口设备，可参考：

```bash
[ -f ./.podman-auth_secret ] || openssl rand -base64 32 > ./.podman-auth_secret

podman run -d --name entrance-tools \
  --network host \
  --device /dev/ttyS0 \
  --device /dev/ttyS1 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.podman-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

> 将 `--device /dev/ttyS*` 替换为你机器上实际存在的串口设备（例如 `/dev/ttyUSB0`、`/dev/ttyACM0`）。Host 网络模式下无需 `-p` 映射端口。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `3000` | HTTP 服务监听端口，也可通过 `npm start -- --port 4000` 覆盖 |
| `ENTRANCE_DATA_DIR` | 项目根目录 | 持久化数据目录，包含 `users.json`、`userdata/`、`known_hosts.json`、`private-networks.json`、`.ssh_password_key` |
| `AUTH_SECRET` | 无，必填 | 登录 token 签名密钥，要求至少 32 字节（base64 或 64 字符十六进制） |
| `SSH_PASSWORD_KEY` | 未设置时自动生成 `.ssh_password_key` | 用于加密 SSH/SFTP 凭据与私有网络白名单的 32 字节密钥；如果手动设置，必须在重启后保持不变 |
| `AUTH_TOKEN_TTL` | `43200` | 登录 token 有效期（秒） |
| `LOGIN_WINDOW_MS` | `900000` | 登录失败限流时间窗口（毫秒） |
| `LOGIN_MAX_ATTEMPTS` | `5` | 时间窗口内允许的最大失败登录次数 |
| `STRICT_HOST_KEY_CHECKING` | `false` | 设为 `true` 时拒绝未知 SSH 主机指纹 |
| `ALLOWED_TARGETS` | 空 | 允许连接的目标主机白名单，逗号分隔，支持 `*.example.com` |
| `ALLOW_PRIVATE_NETWORKS` | `false` | 设为 `true` 时允许直接访问私有地址；否则需通过管理员白名单放行 |
| `ENTRANCE_DESKTOP_NOLOGIN` | `0` | 设为 `1` 时跳过登录，直接以 `admin` 身份访问，仅建议在受信任环境使用 |

## 项目结构

```
.
├── compose.yml          # Docker Compose 配置
├── Dockerfile           # Docker 镜像构建文件
├── public/              # 前端静态资源
│   ├── index.html
│   └── vnc-client.js
├── server.js            # 后端服务器
├── local-shell.js       # 本地 Shell 模块（跨平台）
├── flash-debug.js       # 本机烧录/调试模块（OpenOCD / pyOCD / probe-rs）
├── vnc.js               # VNC 代理模块
├── nginx/               # 反向代理示例配置
├── package.json         # 依赖配置
├── users.json           # 用户数据（自动生成，可位于 ENTRANCE_DATA_DIR）
├── .ssh_password_key    # SSH 凭据加密密钥（自动生成）
├── known_hosts.json     # SSH 主机指纹（自动生成）
├── private-networks.json  # 私有网络白名单（自动生成，已加密）
└── userdata/            # 用户数据目录（自动生成）
    ├── admin.json       # admin 的主机列表
    └── user1.json       # user1 的主机列表
```

## 技术栈

### 前端
- 原生 HTML/CSS/JavaScript
- 单文件前端内置主题、配色方案与界面语言切换逻辑
- [xterm.js](https://xtermjs.org/) - 终端模拟器
- [Chart.js](https://www.chartjs.org/) - 波形可视化图表
- [noVNC](https://novnc.com/) - VNC 客户端
- [Font Awesome](https://fontawesome.com/) - 图标库

### 后端
- [Express](https://expressjs.com/) - Web 框架
- [ws](https://github.com/websockets/ws) - WebSocket
- [ssh2](https://github.com/mscdex/ssh2) - SSH 客户端
- script + child_process / localhost SSH - 本地终端（Linux/macOS/Windows，无需编译）
- OpenOCD / pyOCD / probe-rs - 本机烧录与调试工具链
- [argon2](https://github.com/ranisalt/node-argon2) - 用户密码 Argon2id 哈希
- [multer](https://github.com/expressjs/multer) - 文件上传
- [archiver](https://github.com/archiverjs/node-archiver) - ZIP 打包

> **注意**：本地 Shell 功能支持 Linux、macOS 与 Windows。Linux/macOS 使用 `script` 创建 PTY；Windows 不再直接 `spawn` `COMSPEC`/PowerShell，而是通过本机 `OpenSSH Server` 连接 `127.0.0.1` 来获得正确的终端编辑行为。

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

// 开始 Docker 监控（每3秒采集 docker stats --no-stream）
{ "type": "startDockerStats" }

// 停止 Docker 监控
{ "type": "stopDockerStats" }

// 手动刷新 Docker 数据
{ "type": "refreshDockerStats" }
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

服务器返回的 Docker 监控数据格式：

```javascript
{
  "type": "dockerStats",
  "data": {
    "available": true,                // Docker 是否可用
    "error": null,                    // 错误信息（不可用时）
    "containers": [                   // 容器列表（docker stats --format json 输出）
      {
        "ID": "abc123...",
        "Name": "my-container",
        "CPUPerc": "1.25%",
        "MemPerc": "12.50%",
        "MemUsage": "256MiB / 2GiB",
        "NetIO": "1.2MB / 3.4MB",
        "BlockIO": "10MB / 20MB",
        "PIDs": "15"
      }
    ]
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

Linux/macOS 下通过 `ws://host:port/localshell` 访问服务器本地终端；Windows Web 终端页面内部会改走 `ws://host:port/ssh` 并连接到 `127.0.0.1`。

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

### 烧录调试

- `GET /api/flashdebug/tooling?tool=openocd|pyocd|probe-rs[&path=/abs/path]` - 检测工具路径、probe 列表、OpenOCD 配置目录，以及当前平台的提权能力
- `POST /api/flashdebug/upload` - 上传固件文件到当前 Entrance 主机临时目录

WebSocket 连接到 `ws://host:port/flashdebug?token=...`，消息格式：

```javascript
// 启动烧录
{
  "type": "start",
  "action": "flash",
  "tool": "openocd",
  "requestElevation": true,
  "executablePath": "",
  "options": {
    "probeSelection": "cmsis-dap",
    "targetConfig": "target/stm32f4x.cfg",
    "interfaceConfig": "",
    "speed": "4000",
    "firmwarePath": "/tmp/app.bin",
    "verify": true,
    "resetAfterFlash": true,
    "extraArgs": ""
  }
}

// 启动实时调试
{
  "type": "start",
  "action": "debug",
  "tool": "pyocd",
  "requestElevation": false,
  "options": {
    "probeSelection": "",
    "target": "stm32f103rc",
    "speed": "1000000",
    "gdbPort": 3333,
    "telnetPort": 4444,
    "elfPath": "/tmp/app.elf",
    "extraArgs": ""
  }
}

// 停止当前任务
{ "type": "stop" }
```

服务器会返回：
- `started` - 任务已启动，包含最终执行命令预览
- `output` - stdout/stderr/system 输出流
- `exit` - 进程退出状态
- `error` - 启动失败或运行时错误

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

- 登录默认启用，登录 token 使用 `AUTH_SECRET` 进行签名；仅在 `ENTRANCE_DESKTOP_NOLOGIN=1` 时跳过登录流程。
- `users.json` 中的密码使用 `Argon2id` 哈希存储；旧版明文密码会在用户成功登录后自动迁移。
- SSH/SFTP 凭据（密码、私钥、私钥口令）仅保存在用户浏览器本地或服务端用户数据中，服务端落盘会使用 `SSH_PASSWORD_KEY` 进行 AES-256-GCM 加密。
- 私有网络白名单存储在 `private-networks.json` 中，服务端落盘同样使用 `SSH_PASSWORD_KEY` 进行 AES-256-GCM 加密。
- `SSH_PASSWORD_KEY` 变更后，历史已加密凭据和白名单将无法解密；需要恢复原密钥或重新录入数据。
- **本地 Shell 安全提示**（Linux/macOS/Windows，仅管理员可用）：本地 Shell 功能允许直接访问服务器终端，请确保：
  - 仅在受信任的网络环境中使用
  - 限制访问权限给授权管理员
  - Windows 场景仅启用本机 `OpenSSH Server`，并限制允许登录的本地账号
  - 生产环境中考虑禁用此功能或在反向代理层增加额外认证
- **烧录调试安全提示**（仅管理员可用）：烧录/调试功能可直接调用本机工具链，并且可选请求系统级管理员/root 权限，请确保：
  - 仅在受信任的开发机或实验环境中启用
  - 将 `OpenOCD`、`pyOCD`、`probe-rs`、`pkexec`、`sudo`、`gsudo` 等可执行文件来源控制在可信范围
  - 仅在确有设备访问或驱动权限需求时启用“请求管理员/root 权限”
  - 若使用 Linux 图形密码对话框模式，请确认 `zenity` 或 `kdialog` 来自系统包管理器

## 许可证

GPL-3.0 License

## 贡献

欢迎提交 Issue 和 Pull Request！
