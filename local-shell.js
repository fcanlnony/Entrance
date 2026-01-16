/**
 * Local Shell Module (Linux Only)
 * 使用 script + child_process 实现本地终端
 * 无需编译原生模块，仅支持 Linux
 */

const WebSocket = require('ws');
const { spawn } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// 检查是否为 Linux
const isLinux = process.platform === 'linux';

// 获取默认 shell
function getDefaultShell() {
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
    const dirs = getPathShellNames();
    for (const dir of dirs) {
        const candidate = path.join(dir, shellName);
        if (!fs.existsSync(candidate)) continue;
        try {
            fs.accessSync(candidate, fs.constants.X_OK);
            return fs.realpathSync(candidate);
        } catch {}
    }
    return null;
}

function getAllowedShell(defaultShell) {
    const defaultName = path.basename(defaultShell || '');
    let resolved = resolveShellFromPath(defaultName);
    if (resolved) {
        return resolved;
    }
    const fallbacks = ['bash', 'sh', 'zsh'];
    for (const name of fallbacks) {
        resolved = resolveShellFromPath(name);
        if (resolved) return resolved;
    }
    return null;
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
    if (!isLinux) {
        console.warn('[LocalShell] 跳过初始化 - 仅支持 Linux 系统');
        return { available: false, reason: 'not_linux', wss: null, path: wsPath };
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
                            // 使用 script 命令创建伪终端
                            // script -q /dev/null -c "bash -i" 会创建一个带 PTY 的交互式 shell
                            shellProcess = spawn('script', [
                                '-q',           // 静默模式
                                '/dev/null',    // 不保存输出到文件
                                '-c',           // 指定要运行的命令
                                `${shell} -i`   // 交互式 shell
                            ], {
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
                        // script 方式不直接支持 resize，但可以通过 stty 调整
                        // 保存新的尺寸
                        const session = shellSessions.get(sessionId);
                        if (session) {
                            session.cols = data.cols || 80;
                            session.rows = data.rows || 24;
                            // 发送 stty 命令调整终端大小
                            if (shellProcess && shellProcess.stdin.writable) {
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
 * 检查是否可用（仅 Linux）
 */
function isAvailable() {
    return isLinux;
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
