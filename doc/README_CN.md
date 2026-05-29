# Entrance Tools

[English README](../README.md)

基于 Web 的服务器管理工具，支持 SSH 终端、本地 Shell 终端、VNC 远程桌面、WebSerial 串口终端、烧录调试和 SFTP 文件管理。采用 Microsoft Fluent Design 设计风格，支持亮色/暗色主题，并提供中文/英文界面切换。
![Screenshot](screenshot_cn.png)

安装脚本请见 [Install](https://github.com/EntranceToolBox/Entrance-Installer)。

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

### 插件系统
- 侧边栏在设置上方提供 **插件安装** 和 **插件导航**
- 管理员可在 Fluent Design 卡片界面上传 ZIP 插件包并删除已安装插件
- 插件卡片显示插件名称、版本、作者、描述、入口文件和项目主页
- 插件导航会在工作台内打开已安装插件，体验类似串口终端等内置页面
- 已安装插件保存到 `ENTRANCE_DATA_DIR` 下的 `.plugins/`（默认是仓库根目录 `.plugins/`）
- 仓库根目录 `api/` 提供插件包契约示例：`version.json`、`index.js` 和 `index.html`

### 界面特性
- Microsoft Fluent Design 设计风格
- 亮色/暗色主题切换
- **分阶段启动动画**
  - 当存在可恢复的登录态且未启用 `ENTRANCE_DESKTOP_NOLOGIN=1` 时，界面会显示 Material You 风格的波浪启动页，并在中央展示带圆角矩形裁剪的 `logo.png`
  - 即使启动很快，也会保留至少 3 秒的进度条动画
  - 启动顺序为先渲染前端工作台外壳，再分阶段初始化终端、串口、VNC、本机 Shell 与安全设置等模块
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
- **登录保持** - 密码登录默认保持 7 天，可在设置页使用预设（`7d`、`14d`、`1m`、`never`）或自定义表达式修改
- 只要 `AUTH_SECRET` 保持不变，重启后仍可复用已保存的登录态；若 `AUTH_SECRET` 改变，则会强制重新登录
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

# 使用 ./.data 里的持久化本地运行数据启动服务
./start.sh
# 或在需要局域网 / 反向代理 / 内网穿透浏览器访问时放宽 CORS
./start_nocors.sh
```

`./start.sh` 是推荐的本地启动入口。首次运行且 `./.data` 还不存在时，它会创建 `./.data`、写入 `./.data/auth_secret`、导出 `ENTRANCE_DATA_DIR` 和 `AUTH_SECRET`，然后再执行 `npm start`。它也支持 `--port=4000`，传入后会改为执行 `npm start -- --port 4000`。

`./start_nocors.sh` 走的是同一套启动流程，只是在调用 `start.sh` 前额外导出 `ENTRANCE_CORS_DISABLE=1`。只有在你明确需要通过局域网 IP、反向代理或内网穿透域名从浏览器访问时才建议使用它。

`npm start` 仍然会先从 `webui-src/` 重建模块化 WebUI，再启动服务，但前提是你已经提前导出了 `AUTH_SECRET`。如果只想刷新生成后的前端静态资源，可单独执行 `npm run build:webui`。

访问 http://localhost:3000，使用账号登录后进入工具面板。

修改插件安装、插件导航或插件包约定时，可运行插件冒烟测试：

```bash
npm run test:plugins
```

如需指定端口，可使用环境变量或命令行参数：

```bash
./start.sh --port=4000
# 或
./start_nocors.sh --port=4000
# 或者在已经导出 AUTH_SECRET 时
PORT=4000 npm start
# 或
npm start -- --port 4000
```

此时访问 `http://localhost:4000`。

### `start.sh` 的手动等价流程

```bash
if [ ! -d ./.data ]; then
  mkdir -p ./.data
  [ -f ./.data/auth_secret ] || openssl rand -base64 32 > ./.data/auth_secret
fi

export ENTRANCE_DATA_DIR="$(pwd)/.data"
export AUTH_SECRET="$(tr -d '\n' < ./.data/auth_secret)"
npm start
```

这对应的是未传自定义端口时的 `./start.sh` 行为。如果执行 `./start.sh --port=4000`，最后一行则会变成 `npm start -- --port 4000`。如果 `./.data` 已经存在，脚本不会重新生成 `./.data/auth_secret`，所以重启前要确保这个文件仍然存在。运行时数据会固定在 `./.data`，Entrance 也会在 `./.data/.ssh_password_key` 中自动生成并复用 SSH 凭据加密密钥。不要在每次重启前重新生成 `SSH_PASSWORD_KEY`，否则历史白名单、密码和私钥将无法解密。

默认账号为 `admin/admin`（首次启动自动生成）。

### 容器部署

Docker、Docker Compose 与 Podman 容器部署方式见 [container_CN.md](container_CN.md)。

## 环境变量

如果你想看“某个变量改了以后 Entrance 会变成什么行为”的说明、风险点和部署建议，可以直接查看 [environment-variables_CN.md](environment-variables_CN.md)。

## 项目结构

```
.
├── compose.yml          # Docker Compose 配置
├── Dockerfile           # Docker 镜像构建文件
├── public/              # 前端静态资源
│   ├── assets/          # 由 webui-src/ 生成的 CSS/JS 产物
│   ├── index.html       # 生成后的前端入口
│   └── vnc-client.js
├── api/                 # 插件包契约示例
├── webui-src/           # 可编辑的 WebUI 源文件与 HTML 分块
│   ├── index.template.html
│   ├── partials/
│   ├── scripts/app.js
│   └── styles/app.css
├── server.js            # 后端服务器
├── local-shell.js       # 本地 Shell 模块（跨平台）
├── flash-debug.js       # 本机烧录/调试模块（OpenOCD / pyOCD / probe-rs）
├── vnc.js               # VNC 代理模块
├── nginx/               # 反向代理示例配置
├── package.json         # 依赖配置
├── start.sh             # 本地启动辅助脚本，从 ./.data 导出 ENTRANCE_DATA_DIR 和 AUTH_SECRET，并支持 --port=4000
├── start_nocors.sh      # 在调用 start.sh 前额外导出 ENTRANCE_CORS_DISABLE=1 的包装脚本
├── users.json           # 用户数据（自动生成，可位于 ENTRANCE_DATA_DIR）
├── .ssh_password_key    # SSH 凭据加密密钥（自动生成）
├── .plugins/            # 已安装插件（在 ENTRANCE_DATA_DIR 下自动生成）
├── LOGIN_KEEP           # 用于登录保持的密码登录时间戳（已加密）
├── known_hosts.json     # SSH 主机指纹（自动生成）
├── private-networks.json  # 私有网络白名单（自动生成，已加密）
└── userdata/            # 用户数据目录（自动生成）
    ├── admin.json       # admin 的主机列表
    └── user1.json       # user1 的主机列表
```

WebUI 源码按职责拆分：

- `webui-src/partials/auth-overlay.html` 放登录遮罩与分阶段加载/启动页的 HTML 结构。
- `webui-src/styles/app.css` 放认证遮罩与启动动画相关样式。
- `webui-src/scripts/app.js` 放认证/加载控制逻辑（`showLoading`、`updateLoadingProgress`）以及工作台分阶段启动流程（`startDashboardBoot`）。
- `public/index.html` 与 `public/assets/*` 都是由上述源文件生成的产物。

## 技术栈

见 [TechnologyStack_CN.md](TechnologyStack_CN.md)。

## API 接口

见 [api_CN.md](api_CN.md)。

## 安全说明

见 [security_note_CN.md](security_note_CN.md)。

### 友链

- EK-OmniProbe https://github.com/EmbeddedKitOrg/EK-OmniProbe
- Clion-Waveform-Plotter https://github.com/Szturin/Clion-Waveform-Plotter

## 许可证

GPL-3.0 License

## 贡献

欢迎提交 Issue 和 Pull Request！
