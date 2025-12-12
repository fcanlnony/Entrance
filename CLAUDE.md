# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Entrance Tools - 基于 Web 的服务器管理工具，支持 SSH 终端、VNC 远程桌面、WebSerial 串口终端和 SFTP 文件管理。

## Build and Development Commands

```bash
# 安装依赖
npm install

# 启动开发服务器
npm start
# 或
npm run dev
# 或
node server.js

# 服务默认运行在 http://localhost:3000
```

## Architecture Overview

### 项目结构
```
.
├── index.html      # 前端单文件应用（HTML + CSS + JavaScript）
├── server.js       # Express 后端服务器
├── package.json    # 依赖配置
├── users.json      # 用户账号数据（运行时生成）
└── userdata/       # 用户数据目录（运行时生成）
```

### 前端架构
- 单文件 HTML 应用，无构建步骤
- 模块化 JavaScript 对象：`State`, `Storage`, `Theme`, `Toast`, `Users`, `Terminal_`, `SFTP`, `Hosts`, `UI`
- CSS 变量实现主题切换
- Microsoft Fluent Design 设计风格

### 后端架构
- Express.js HTTP/REST API 服务器
- WebSocket 服务器处理 SSH 连接
- ssh2 库实现 SSH/SFTP 功能
- 文件存储：用户数据、主机列表

### 核心模块
1. **UserManager** - 用户账号管理（CRUD）
2. **UserDataManager** - 用户数据管理（主机列表、统计）
3. **SFTP Sessions** - SFTP 会话管理
4. **Guest Sessions** - 访客会话管理

## Key Dependencies

### 后端
- `express` - Web 框架
- `ws` - WebSocket 服务器
- `ssh2` - SSH/SFTP 客户端
- `multer` - 文件上传中间件
- `archiver` - ZIP 打包

### 前端 (CDN)
- `xterm.js` - 终端模拟器
- `xterm-addon-fit` - 终端自适应
- `Font Awesome` - 图标库

## Development Workflow

### 添加新功能
1. 后端 API：在 `server.js` 中添加路由
2. 前端功能：在 `index.html` 的相应模块中添加
3. 测试：`npm start` 启动本地服务器测试

### 代码风格
- 使用 ES6+ 语法
- 异步操作使用 async/await
- 错误处理：后端返回 JSON `{ error: "message" }`，前端使用 Toast 提示

### API 命名规范
- RESTful 风格
- 路径：`/api/{resource}/{action}`
- 认证相关：`/api/auth/*`
- 用户管理：`/api/users/*`
- 用户数据：`/api/userdata/:userId/*`
- SFTP 操作：`/api/sftp/*`

## Important Notes

- 默认账号：admin / admin
- 密码存储：明文（生产环境应使用 bcrypt）
- SFTP 会话存储在内存中（Map）
- 访客数据在断开连接时自动清除
- 用户数据隔离：每个用户有独立的 JSON 文件
