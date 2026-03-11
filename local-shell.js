/**
 * Local Shell Module
 * Linux/macOS 使用 script + child_process 实现本地终端
 * Windows 直接 spawn shell 进程，无需编译原生模块
 */

const WebSocket = require('ws');
const { spawn } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const platform = process.platform;
const isLinux = platform === 'linux';
const isMacOS = platform === 'darwin';
const isWindows = platform === 'win32';
const SUPPORTED_PLATFORMS = new Set(['linux', 'darwin', 'win32']);

// 获取默认 shell
function getDefaultShell() {
    if (isWindows) {
        return process.env.COMSPEC || 'cmd.exe';
    }
    return process.env.SHELL || '/usr/bin/bash';
}

function getPathShellNames() {
    return (process.env.PATH || '')
        .split(path.delimiter)
        .filter(Boolean)
        .map(dir => dir.trim())
        .filter(Boolean);
}

function resolveShellFromPath(shellName) {
    if (!shellName || shellName.includes('/') || shellName.includes('\\')) {
        return null;
    }

    // Windows: cmd/cmd.exe 直接通过 COMSPEC 解析
    if (isWindows && process.env.COMSPEC) {
        const normalized = shellName.toLowerCase();
        if ((normalized === 'cmd' || normalized === 'cmd.exe') && fs.existsSync(process.env.COMSPEC)) {
            try {
                return fs.realpathSync(process.env.COMSPEC);
            } catch {}
        }
    }

    // Windows 上自动补 .exe 扩展名
    const candidates = [shellName];
    if (isWindows && path.extname(shellName).toLowerCase() !== '.exe') {
        candidates.push(`${shellName}.exe`);
    }

    const dirs = getPathShellNames();
    for (const dir of dirs) {
        for (const name of candidates) {
            const candidate = path.join(dir, name);
            if (!fs.existsSync(candidate)) continue;
            try {
                fs.accessSync(candidate, fs.constants.X_OK);
                return fs.realpathSync(candidate);
            } catch {}
        }
    }
    return null;
}

function getAllowedShell(defaultShell) {
    // Windows 默认 shell 可能是绝对路径（如 COMSPEC）
    if (isWindows && defaultShell && (defaultShell.includes('/') || defaultShell.includes('\\'))) {
        if (fs.existsSync(defaultShell)) {
            try {
                return fs.realpathSync(defaultShell);
            } catch {}
        }
    }

    const defaultName = path.basename(defaultShell || '');
    let resolved = resolveShellFromPath(defaultName);
    if (resolved) {
        return resolved;
    }
    const fallbacks = isWindows ? ['cmd', 'powershell'] : ['bash', 'sh', 'zsh'];
    for (const name of fallbacks) {
        resolved = resolveShellFromPath(name);
        if (resolved) return resolved;
    }
    return null;
}

/**
 * 根据平台构造 shell 启动参数
 */
function getShellSpawnOptions(shell) {
    if (isWindows) {
        return { command: shell, args: [] };
    }
    if (isMacOS) {
        // macOS 的 script 没有 -c 参数
        return { command: 'script', args: ['-q', '/dev/null', shell, '-i'] };
    }
    // Linux
    return { command: 'script', args: ['-q', '/dev/null', '-c', `${shell} -i`] };
}

// 存储活动的 shell 会话
const shellSessions = new Map();

/**
 * 初始化本地 shell WebSocket 服务
 * @param {http.Server} server - HTTP 服务器实例
 * @param {string} wsPath - WebSocket 路径，默认 '/localshell'
 */
// 存储 WebSocket 服务器实例
let localShellWss = null;
let localShellPath = '/localshell';

function init(server, wsPath = '/localshell') {
    if (!isAvailable()) {
        console.warn(`[LocalShell] 跳过初始化 - 当前平台不支持: ${platform}`);
        return { available: false, reason: 'not_supported_platform', wss: null, path: wsPath };
    }

    localShellPath = wsPath;
    localShellWss = new WebSocket.Server({
        noServer: true,
        perMessageDeflate: false
    });

    console.log(`[LocalShell] WebSocket 服务已启动: ${wsPath}`);

    const wss = localShellWss;

    wss.on('connection', (ws, req) => {
        console.log(`[LocalShell] 新连接来自: ${req.socket.remoteAddress}`);

        let shellProcess = null;
        const sessionId = `shell_${typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : crypto.randomBytes(16).toString('hex')}`;

        ws.on('message', (message) => {
            try {
                const data = JSON.parse(message.toString());

                switch (data.type) {
                    case 'start':
                        // 启动新的 shell 会话
                        if (shellProcess) {
                            shellProcess.kill();
                        }

                        // 仅允许 PATH 内的 shell
                        let shell = null;
                        if (data.shell) {
                            shell = resolveShellFromPath(data.shell.trim());
                            if (!shell) {
                                ws.send(JSON.stringify({ type: 'error', message: 'Shell 不在 PATH 中或不可执行' }));
                                return;
                            }
                        } else {
                            shell = getAllowedShell(getDefaultShell());
                            if (!shell) {
                                ws.send(JSON.stringify({ type: 'error', message: '未找到可用的 PATH Shell' }));
                                return;
                            }
                        }

                        const cwd = data.cwd || os.homedir();
                        const cols = data.cols || 80;
                        const rows = data.rows || 24;

                        // 设置环境变量
                        const env = Object.assign({}, process.env, {
                            TERM: 'xterm-256color',
                            COLORTERM: 'truecolor',
                            COLUMNS: cols.toString(),
                            LINES: rows.toString()
                        });

                        console.log(`[LocalShell] 启动 shell: ${shell} (cwd: ${cwd})`);

                        try {
                            // Unix 使用 script 创建 PTY；Windows 直接启动 shell 进程
                            const spawnOpts = getShellSpawnOptions(shell);
                            shellProcess = spawn(spawnOpts.command, spawnOpts.args, {
                                cwd: cwd,
                                env: env,
                                stdio: ['pipe', 'pipe', 'pipe']
                            });

                            shellSessions.set(sessionId, { process: shellProcess, ws, cols, rows });

                            ws.send(JSON.stringify({
                                type: 'started',
                                sessionId,
                                shell,
                                cwd,
                                pid: shellProcess.pid
                            }));

                            // stdout 输出
                            shellProcess.stdout.on('data', (chunk) => {
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(JSON.stringify({ type: 'data', data: chunk.toString('utf8') }));
                                }
                            });

                            // stderr 输出
                            shellProcess.stderr.on('data', (chunk) => {
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(JSON.stringify({ type: 'data', data: chunk.toString('utf8') }));
                                }
                            });

                            // 进程退出
                            shellProcess.on('exit', (exitCode, signal) => {
                                console.log(`[LocalShell] Shell 退出: code=${exitCode}, signal=${signal}`);
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(JSON.stringify({
                                        type: 'exit',
                                        exitCode: exitCode || 0,
                                        signal
                                    }));
                                }
                                shellSessions.delete(sessionId);
                                shellProcess = null;
                            });

                            shellProcess.on('error', (err) => {
                                console.error('[LocalShell] Shell 进程错误:', err.message);
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(JSON.stringify({
                                        type: 'error',
                                        message: `Shell 进程错误: ${err.message}`
                                    }));
                                }
                            });

                        } catch (err) {
                            console.error('[LocalShell] 启动 shell 失败:', err.message);
                            ws.send(JSON.stringify({
                                type: 'error',
                                message: `启动 shell 失败: ${err.message}`
                            }));
                        }
                        break;

                    case 'data':
                        // 输入数据
                        if (shellProcess && shellProcess.stdin.writable) {
                            shellProcess.stdin.write(data.data);
                        }
                        break;

                    case 'resize':
                        // Windows 不支持 stty；Unix 下通过 stty 调整终端大小
                        const session = shellSessions.get(sessionId);
                        if (session) {
                            session.cols = data.cols || 80;
                            session.rows = data.rows || 24;
                            if (!isWindows && shellProcess && shellProcess.stdin.writable) {
                                shellProcess.stdin.write(`stty cols ${session.cols} rows ${session.rows}\n`);
                            }
                        }
                        break;

                    case 'stop':
                        // 停止 shell
                        if (shellProcess) {
                            shellProcess.kill('SIGTERM');
                            setTimeout(() => {
                                if (shellProcess) {
                                    shellProcess.kill('SIGKILL');
                                }
                            }, 1000);
                            shellProcess = null;
                        }
                        break;
                }
            } catch (err) {
                console.error('[LocalShell] 消息处理错误:', err);
                ws.send(JSON.stringify({ type: 'error', message: err.message }));
            }
        });

        ws.on('close', () => {
            console.log(`[LocalShell] 连接关闭: ${sessionId}`);
            if (shellProcess) {
                shellProcess.kill('SIGTERM');
                shellSessions.delete(sessionId);
            }
        });

        ws.on('error', (err) => {
            console.error('[LocalShell] WebSocket 错误:', err.message);
        });
    });

    return { available: true, wss: localShellWss, path: wsPath };
}

/**
 * 处理 WebSocket upgrade 请求
 */
function handleUpgrade(request, socket, head) {
    if (localShellWss) {
        localShellWss.handleUpgrade(request, socket, head, (ws) => {
            localShellWss.emit('connection', ws, request);
        });
    }
}

/**
 * 获取 WebSocket 路径
 */
function getPath() {
    return localShellPath;
}

/**
 * 关闭所有 shell 会话
 */
function closeAll() {
    console.log(`[LocalShell] 关闭所有会话 (${shellSessions.size} 个)`);
    for (const [sessionId, session] of shellSessions) {
        try {
            session.process.kill('SIGTERM');
        } catch (e) {}
    }
    shellSessions.clear();
}

/**
 * 检查当前平台是否支持本地 Shell
 */
function isAvailable() {
    return SUPPORTED_PLATFORMS.has(platform);
}

/**
 * 获取当前活动会话数
 */
function getSessionCount() {
    return shellSessions.size;
}

/**
 * 获取平台信息
 */
function getPlatform() {
    return process.platform;
}

module.exports = {
    init,
    closeAll,
    isAvailable,
    getSessionCount,
    getDefaultShell,
    getPlatform,
    handleUpgrade,
    getPath
};
