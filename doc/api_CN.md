# API

## 认证

- `POST /api/auth/login` - 登录并返回 token
- `POST /api/auth/session` - 使用新的登录保持时间刷新当前 token
- `POST /api/auth/verify` - 校验 token

所有 API 请求都需要在请求头中携带 `Authorization: Bearer <token>`。

## 用户数据

- `GET /api/userdata/:userId/hosts` - 获取保存的主机
- `POST /api/userdata/:userId/hosts` - 添加主机
- `DELETE /api/userdata/:userId/hosts/:index` - 删除主机

## SFTP

- `POST /api/sftp/connect` - 打开连接
- `POST /api/sftp/disconnect/:sessionId` - 关闭连接
- `GET /api/sftp/list/:sessionId` - 列出目录
- `GET /api/sftp/home/:sessionId` - 获取家目录
- `POST /api/sftp/mkdir/:sessionId` - 创建目录
- `DELETE /api/sftp/delete/:sessionId` - 删除文件或目录
- `POST /api/sftp/upload/:sessionId` - 上传文件
- `GET /api/sftp/download/:sessionId` - 下载文件
- `POST /api/sftp/download-zip/:sessionId` - 下载 ZIP 打包文件

SFTP 连接参数示例：

```javascript
// 密码认证
{
  "host": "192.168.1.10",
  "port": 22,
  "username": "root",
  "authType": "password",
  "password": "xxx"
}

// 私钥认证
{
  "host": "192.168.1.10",
  "port": 22,
  "username": "root",
  "authType": "key",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "passphrase": "optional"
}
```

## 插件

- `GET /api/plugins` - 列出已安装插件
- `POST /api/plugins/install` - 安装插件 ZIP 包（管理员）
- `DELETE /api/plugins/:id` - 删除已安装插件（管理员）
- `GET /api/plugins/:id/page` - 打开插件运行页面
- `GET /api/plugins/:id/assets/*` - 提供插件根目录内的文件

插件包格式、`api/version.json` 约束和 `index.js` 运行时接口见 [插件 API](../api/plugins.md)。

## 安全配置

- `GET /api/security/private-networks` - 获取私有 CIDR 白名单（管理员）
- `PUT /api/security/private-networks` - 更新私有 CIDR 白名单（管理员）

## SSH (WebSocket)

连接到 `ws://host:port/ssh?token=...`，消息示例：

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

// 调整终端大小
{ "type": "resize", "cols": 80, "rows": 24 }

// 断开连接
{ "type": "disconnect" }

// 开始系统监控（每秒采样 /proc/stat、/proc/meminfo、/proc/diskstats）
{ "type": "startStats" }

// 停止系统监控
{ "type": "stopStats" }

// 开始进程监控（每 2 秒采样 uptime 和 ps aux）
{ "type": "startTop" }

// 停止进程监控
{ "type": "stopTop" }

// 手动刷新进程列表
{ "type": "refreshTop" }

// 向进程发送信号
{ "type": "kill", "pid": 1234, "signal": 15 }

// 开始 Docker 监控（每 3 秒采样 docker stats --no-stream）
{ "type": "startDockerStats" }

// 停止 Docker 监控
{ "type": "stopDockerStats" }

// 手动刷新 Docker 监控
{ "type": "refreshDockerStats" }
```

服务端返回的系统监控数据：

```javascript
{
  "type": "stats",
  "data": {
    "stat": "cpu  12345 678 ...",      // /proc/stat 输出
    "meminfo": "MemTotal: ...",         // /proc/meminfo 输出
    "diskstats": "8 0 sda ..."          // /proc/diskstats 输出
  }
}
```

服务端返回的进程监控数据：

```javascript
{
  "type": "top",
  "data": {
    "uptime": "10:15:03 up 5 days...",  // uptime 输出
    "ps": "USER PID %CPU %MEM ..."       // ps aux 输出
  }
}
```

服务端返回的 Docker 监控数据：

```javascript
{
  "type": "dockerStats",
  "data": {
    "available": true,                // Docker 是否可用
    "error": null,                    // 不可用时的错误信息
    "containers": [                   // docker stats --format json 输出的容器列表
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

服务端返回的杀进程结果：

```javascript
{
  "type": "killResult",
  "data": {
    "success": true,
    "message": "SIGTERM sent to PID 1234"
  }
}
```

## VNC (WebSocket)

连接到 `ws://host:port/vnc`；服务端会把流量代理到目标 VNC 服务。

消息格式：

```javascript
// 初始目标信息
{ "type": "connect", "host": "192.168.1.1", "port": 5900 }
```

## 本地 Shell (WebSocket)

Linux/macOS 使用 `ws://host:port/localshell` 访问服务端本机终端。在 Windows 上，Web 终端页面会在内部切换到 `ws://host:port/ssh` 并连接 `127.0.0.1`。

消息格式：

```javascript
// 启动 shell
{ "type": "start", "cols": 80, "rows": 24, "cwd": "/home/user" }

// 发送输入
{ "type": "data", "data": "ls -la\n" }

// 调整大小
{ "type": "resize", "cols": 120, "rows": 40 }

// 停止 shell
{ "type": "stop" }
```

状态 API：

- `GET /api/localshell/status` - 获取本地 Shell 服务状态

## 烧录与调试

- `GET /api/flashdebug/tooling?tool=openocd|pyocd|probe-rs[&path=/abs/path]` - 检测当前平台的可执行文件路径、probe 列表、OpenOCD 配置目录，以及可用提权方式
- `POST /api/flashdebug/upload` - 上传固件文件到当前 Entrance 主机的临时目录

连接到 `ws://host:port/flashdebug?token=...`，消息示例：

```javascript
// 开始烧录
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

// 开始实时调试
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

服务端会返回：

- `started` - 任务已启动，包含最终命令预览
- `output` - stdout/stderr/system 输出流
- `exit` - 进程退出状态
- `error` - 启动失败或运行时错误

## 串口数据格式 (WebSerial)

串口终端会自动解析两种互斥格式，且两种格式不会相互干扰。

### 波形数据格式

用于实时波形渲染，格式为 `VariableName:NumericValue`：

```text
ADC1:1024
Temp:25.5
Sin:-0.866
Voltage:3.3
```

也支持单行多变量输入：

```text
a:2, b:4, temp:25.5
```

- 变量名：以字母或下划线开头，可包含字母、数字和下划线
- 数值：整数或浮点数，支持负数
- 每行一个或多个数据点，以换行分隔
- 每个变量会自动分配不同颜色

### 统计图数据格式

用于柱状图对比，格式为 `varName:[key1:value1, key2:value2, ...]`：

```text
stats:[a:2, b:3, c:5, d:6]
```

也支持单行多变量：

```text
var1:[a:4, b:6], var2:[a:6, b:3, c:2]
```

也支持多行解析：

```text
cpu:[user:45, system:12, idle:43]
memory:[used:8192, free:4096, cached:2048]
```

- 变量名（如 `stats` 或 `var1`）：作为 X 轴标签
- 子键（如 `a`、`b`、`c`）：每个子键使用不同颜色
- 数值：整数或浮点数，支持负数
- 不同变量中相同的子键名会复用同一颜色，便于对比
