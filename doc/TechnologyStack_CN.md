# 技术栈

## 前端

- 原生 HTML/CSS/JavaScript
- 单文件前端内置主题、配色方案与界面语言切换逻辑
- [xterm.js](https://xtermjs.org/) - 终端模拟器
- [Chart.js](https://www.chartjs.org/) - 波形/统计图可视化
- [noVNC](https://novnc.com/) - VNC 客户端
- [Font Awesome](https://fontawesome.com/) - 图标集

## 后端

- [Express](https://expressjs.com/) - Web 框架
- [ws](https://github.com/websockets/ws) - WebSocket
- [ssh2](https://github.com/mscdex/ssh2) - SSH 客户端
- script + child_process / localhost SSH - 本地终端支持（Linux/macOS/Windows，无需原生编译）
- OpenOCD / pyOCD / probe-rs - 本机烧录与调试工具链
- [argon2](https://github.com/ranisalt/node-argon2) - Argon2id 密码哈希
- [multer](https://github.com/expressjs/multer) - 文件上传
- [archiver](https://github.com/archiverjs/node-archiver) - ZIP 打包
- [adm-zip](https://github.com/cthackers/adm-zip) - 插件 ZIP 解包

> **注意**：本地 Shell 支持 Linux、macOS 与 Windows。Linux/macOS 使用 `script` 创建 PTY。Windows 不再直接启动 `COMSPEC`/PowerShell，而是连接本机 `127.0.0.1` 上的 `OpenSSH Server`，以获得正确的终端编辑语义。
