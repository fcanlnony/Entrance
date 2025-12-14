/**
 * Local Shell Module
 * 提供本地 shell 访问功能
 * 通过 WebSocket 连接本地终端
 */

const WebSocket = require('ws');
const os = require('os');
const path = require('path');

// 动态加载 node-pty（可能未安装）
let pty = null;
try {
    pty = require('node-pty');
} catch (e) {
    console.warn('[LocalShell] node-pty 未安装，本地 shell 功能不可用');
    console.warn('[LocalShell] 运行 npm install node-pty 安装依赖');
}

// 获取默认 shell
function getDefaultShell() {
    if (process.platform === 'win32') {
        return process.env.COMSPEC || 'cmd.exe';
    }
    return process.env.SHELL || '/bin/bash';
}

// 存储活动的 shell 会话
const shellSessions = new Map();

/**
 * 初始化本地 shell WebSocket 服务
 * @param {http.Server} server - HTTP 服务器实例
 * @param {string} wsPath - WebSocket 路径，默认 '/localshell'
 */
function init(server, wsPath = '/localshell') {
    if (!pty) {
        console.warn('[LocalShell] 跳过初始化 - node-pty 未安装');
        return { available: false };
    }

    const wss = new WebSocket.Server({
        server,
        path: wsPath,
        perMessageDeflate: false
    });

    console.log(`[LocalShell] WebSocket 服务已启动: ${wsPath}`);

    wss.on('connection', (ws, req) => {
        console.log(`[LocalShell] 新连接来自: ${req.socket.remoteAddress}`);

        let ptyProcess = null;
        const sessionId = `shell_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        ws.on('message', (message) => {
            try {
                const data = JSON.parse(message.toString());

                switch (data.type) {
                    case 'start':
                        // 启动新的 shell 会话
                        if (ptyProcess) {
                            ptyProcess.kill();
                        }

                        const shell = getDefaultShell();
                        const cwd = data.cwd || os.homedir();
                        const env = Object.assign({}, process.env, {
                            TERM: 'xterm-256color',
                            COLORTERM: 'truecolor'
                        });

                        console.log(`[LocalShell] 启动 shell: ${shell} (cwd: ${cwd})`);

                        try {
                            ptyProcess = pty.spawn(shell, [], {
                                name: 'xterm-256color',
                                cols: data.cols || 80,
                                rows: data.rows || 24,
                                cwd: cwd,
                                env: env
                            });

                            shellSessions.set(sessionId, { pty: ptyProcess, ws });

                            ws.send(JSON.stringify({
                                type: 'started',
                                sessionId,
                                shell,
                                cwd,
                                pid: ptyProcess.pid
                            }));

                            // 数据输出
                            ptyProcess.onData((data) => {
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(JSON.stringify({ type: 'data', data }));
                                }
                            });

                            // 进程退出
                            ptyProcess.onExit(({ exitCode, signal }) => {
                                console.log(`[LocalShell] Shell 退出: code=${exitCode}, signal=${signal}`);
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(JSON.stringify({
                                        type: 'exit',
                                        exitCode,
                                        signal
                                    }));
                                }
                                shellSessions.delete(sessionId);
                                ptyProcess = null;
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
                        if (ptyProcess) {
                            ptyProcess.write(data.data);
                        }
                        break;

                    case 'resize':
                        // 调整终端大小
                        if (ptyProcess) {
                            ptyProcess.resize(data.cols || 80, data.rows || 24);
                        }
                        break;

                    case 'stop':
                        // 停止 shell
                        if (ptyProcess) {
                            ptyProcess.kill();
                            ptyProcess = null;
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
            if (ptyProcess) {
                ptyProcess.kill();
                shellSessions.delete(sessionId);
            }
        });

        ws.on('error', (err) => {
            console.error('[LocalShell] WebSocket 错误:', err.message);
        });
    });

    return { available: true, wss };
}

/**
 * 关闭所有 shell 会话
 */
function closeAll() {
    console.log(`[LocalShell] 关闭所有会话 (${shellSessions.size} 个)`);
    for (const [sessionId, session] of shellSessions) {
        try {
            session.pty.kill();
        } catch (e) {}
    }
    shellSessions.clear();
}

/**
 * 检查 node-pty 是否可用
 */
function isAvailable() {
    return pty !== null;
}

/**
 * 获取当前活动会话数
 */
function getSessionCount() {
    return shellSessions.size;
}

module.exports = {
    init,
    closeAll,
    isAvailable,
    getSessionCount,
    getDefaultShell
};
