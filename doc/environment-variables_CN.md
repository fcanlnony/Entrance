# Entrance 环境变量行为说明

本文按“变量改了以后会发生什么”来说明 Entrance 支持的环境变量。除特别说明外，所有变量都只会在进程启动时读取一次，因此修改后需要重启服务。

## 取值规则

| 规则 | 变量 | 说明 |
| --- | --- | --- |
| `=1` 开关 | `ENTRANCE_CORS_DISABLE`、`ENTRANCE_DESKTOP_NOLOGIN`、`ENTRANCE_DESKTOP_API_ONLY` | 只有字面值 `1` 才算开启 |
| `=true` 开关 | `STRICT_HOST_KEY_CHECKING`、`ALLOW_PRIVATE_NETWORKS` | 只有字面值 `true` 才算开启 |
| 整数值 | `PORT`、`AUTH_TOKEN_TTL`、`LOGIN_WINDOW_MS`、`LOGIN_MAX_ATTEMPTS`、`SSH_*_MAX_LENGTH` | 非法值通常会回退到默认值；`PORT` 非法时会直接报错退出 |
| 字符串值 | 本文中其他变量 | 空字符串通常会回退到文档中的默认值 |

## 启动与存储

| 变量 | 默认值 | 改动后行为 | 备注 |
| --- | --- | --- | --- |
| `PORT` | `3000` | 修改 HTTP 监听端口 | 也可以通过 `npm start -- --port 4000` 覆盖 |
| `ENTRANCE_HOST` | Web 模式为 `0.0.0.0`，桌面 API-only 模式为 `127.0.0.1` | 修改服务绑定地址 | 适合控制只监听 loopback 或指定网卡 |
| `ENTRANCE_DATA_DIR` | 项目根目录 | 改变运行时数据目录，包括 `users.json`、`userdata/`、`known_hosts.json`、`private-networks.json`、`.ssh_password_key`、`LOGIN_KEEP` | 该目录应持久化保存，且不要提交到仓库 |

## 认证与会话

| 变量 | 默认值 | 改动后行为 | 备注 |
| --- | --- | --- | --- |
| `AUTH_SECRET` | 无，必填 | 用于签发登录 token，并派生 `LOGIN_KEEP` 的加密密钥 | 修改后已保存的浏览器登录态会失效 |
| `SSH_PASSWORD_KEY` | 未设置时自动在 `ENTRANCE_DATA_DIR` 下生成 `.ssh_password_key` | 用于加密落盘的 SSH/SFTP 凭据和私有网络白名单 | 如果手动设置，必须在重启后保持不变 |
| `AUTH_TOKEN_TTL` | `604800` 秒 | 修改密码登录的默认 token 时长，也会影响客户端默认登录保持时长 | 用户仍可在设置页里覆盖这个时长 |
| `LOGIN_WINDOW_MS` | `900000` | 修改登录失败计数的限流时间窗口 | 值越小，失败记录清空得越快 |
| `LOGIN_MAX_ATTEMPTS` | `5` | 修改限流窗口内允许的最大失败登录次数 | 值越小，登录限流越严格 |

## 网络访问与目标限制

| 变量 | 默认值 | 改动后行为 | 备注 |
| --- | --- | --- | --- |
| `STRICT_HOST_KEY_CHECKING` | `false` | 设为 `true` 后，SSH 连接会拒绝未知主机指纹，而不是自动学习 | 更安全，但首次连接会更严格 |
| `ALLOWED_TARGETS` | 空 | 用逗号分隔的白名单限制 SSH/VNC 目标主机，支持 `*.example.com` 模式 | 为空时不启用主机名白名单 |
| `ALLOW_PRIVATE_NETWORKS` | `false` | 设为 `true` 后，可直接访问私网地址，不再强制依赖管理员维护的私有网络白名单 | 适合受信任的实验室或内网环境 |
| `ENTRANCE_CORS_DISABLE` | `0` | 设为 `1` 后，Entrance 不再只接受 `localhost`、`127.0.0.1` 或桌面渲染端的 `Origin`，而是会对任意请求来源返回允许跨域的 CORS 响应 | 适合通过局域网 IP、反向代理或内网穿透域名访问。它会削弱浏览器侧的来源保护，不需要时应保持关闭 |

## 桌面模式与 CORS

| 变量 | 默认值 | 改动后行为 | 备注 |
| --- | --- | --- | --- |
| `ENTRANCE_DESKTOP_NOLOGIN` | `0` | 设为 `1` 后启用桌面免登录行为，前端设置页中的改密区域会被隐藏 | 适合安全封装过的桌面壳，不适合直接暴露网页使用 |
| `ENTRANCE_DESKTOP_API_ONLY` | `0` | 设为 `1` 后不再提供 `public/index.html`，只暴露后端 API | 同时会把默认监听地址改为 `127.0.0.1` |
| `ENTRANCE_DESKTOP_ALLOWED_ORIGIN` | `app://entrance` | 在桌面 API-only 模式下，且未启用 `ENTRANCE_CORS_DISABLE` 时，修改允许访问 API 的渲染端 Origin | 主要用于自定义 Electron wrapper 的 Origin |
| `ENTRANCE_DESKTOP_BOOTSTRAP_SECRET` | 空 | 开启后要求桌面壳通过携带 `X-Entrance-Desktop-Secret` 的 `POST /api/auth/desktop/bootstrap` 获取免登录 token | 当 `ENTRANCE_DESKTOP_API_ONLY=1` 且 `ENTRANCE_DESKTOP_NOLOGIN=1` 时必填 |
| `ENTRANCE_DESKTOP_VERSION` | 空 | 修改桌面免登录模式下 `/api/app-info` 暴露的桌面版本号 | 主要用于桌面壳显示或诊断信息 |

## 输入长度限制

| 变量 | 默认值 | 改动后行为 | 备注 |
| --- | --- | --- | --- |
| `SSH_HOST_MAX_LENGTH` | `255` | 修改允许输入的 SSH 主机地址最大长度 | 值更大时可以接受更长的主机输入 |
| `SSH_USERNAME_MAX_LENGTH` | `128` | 修改允许输入的 SSH 用户名最大长度 | 适合极少数超长企业账号场景 |
| `SSH_PASSWORD_MAX_LENGTH` | `2048` | 修改允许输入的 SSH 密码最大长度 | 只影响请求校验 |
| `SSH_PASSPHRASE_MAX_LENGTH` | `4096` | 修改允许输入的私钥口令最大长度 | 只影响请求校验 |
| `SSH_PRIVATE_KEY_MAX_LENGTH` | `65536` | 修改允许输入的 SSH 私钥文本最大长度 | 只有确实需要支持超大私钥文本时才建议增大 |

## 实用建议

- 普通本机浏览器访问场景，保持 `ENTRANCE_CORS_DISABLE` 关闭即可。
- 如果要通过局域网 IP、反向代理或内网穿透域名访问，并且浏览器请求带来的 `Origin` 不再是 `localhost`，再显式设置 `ENTRANCE_CORS_DISABLE=1`。
- 对安全要求更高的 Electron 部署，优先使用 `ENTRANCE_DESKTOP_API_ONLY=1`、loopback 绑定和 `ENTRANCE_DESKTOP_BOOTSTRAP_SECRET`，而不是简单放宽 CORS。
