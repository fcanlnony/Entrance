/**
 * VNC WebSocket Proxy Module
 * 纯透传模式：将 WebSocket 数据直接转发到 VNC 服务器
 * 支持 noVNC 客户端
 */

const net = require('net');
const WebSocket = require('ws');
const url = require('url');

class VNCProxy {
    constructor() {
        this.sessions = new Map();
        this.sessionCounter = 0;
        this.wss = null;
    }

    /**
     * 初始化 VNC WebSocket 服务
     * @param {http.Server} server - HTTP 服务器实例
     * @param {string} path - WebSocket 路径
     */
    init(server, path = '/vnc') {
        // 使用 noServer 模式，手动处理 upgrade
        this.wss = new WebSocket.Server({ noServer: true });
        this.path = path;

        // 监听 HTTP server 的 upgrade 事件
        server.on('upgrade', (request, socket, head) => {
            const pathname = new url.URL(request.url, 'http://localhost').pathname;

            if (pathname === path || pathname.startsWith(path + '?')) {
                this.wss.handleUpgrade(request, socket, head, (ws) => {
                    this.wss.emit('connection', ws, request);
                });
            }
            // 其他路径交给其他 WebSocket.Server 处理
        });

        this.wss.on('connection', (ws, req) => {
            // 从 URL 参数获取连接信息
            const params = new url.URL(req.url, 'http://localhost').searchParams;
            const host = params.get('host');
            const port = parseInt(params.get('port')) || 5900;

            if (!host) {
                console.error('[VNC] 缺少 host 参数');
                ws.close(1008, 'Missing host parameter');
                return;
            }

            console.log(`[VNC] 新连接: ${host}:${port}`);

            const sessionId = this.generateSessionId();
            let tcpSocket = null;

            // 创建到 VNC 服务器的 TCP 连接
            tcpSocket = net.createConnection({ host, port }, () => {
                console.log(`[VNC] TCP 连接成功: ${host}:${port}`);

                this.sessions.set(sessionId, {
                    ws,
                    socket: tcpSocket,
                    host,
                    port,
                    createdAt: new Date()
                });
            });

            // VNC 服务器 -> WebSocket (透传)
            tcpSocket.on('data', (data) => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(data);
                }
            });

            tcpSocket.on('error', (err) => {
                console.error(`[VNC] TCP 错误 (${host}:${port}): ${err.message}`);
                ws.close(1011, err.message);
            });

            tcpSocket.on('close', () => {
                console.log(`[VNC] TCP 连接关闭: ${host}:${port}`);
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close(1000, 'VNC connection closed');
                }
                this.cleanup(sessionId);
            });

            tcpSocket.on('timeout', () => {
                console.log(`[VNC] TCP 连接超时: ${host}:${port}`);
                tcpSocket.destroy();
            });

            tcpSocket.setTimeout(60000);

            // WebSocket -> VNC 服务器 (透传)
            ws.on('message', (message) => {
                if (tcpSocket && !tcpSocket.destroyed) {
                    // 确保发送的是 Buffer
                    if (Buffer.isBuffer(message)) {
                        tcpSocket.write(message);
                    } else if (message instanceof ArrayBuffer) {
                        tcpSocket.write(Buffer.from(message));
                    } else {
                        tcpSocket.write(Buffer.from(message));
                    }
                }
            });

            ws.on('close', () => {
                console.log(`[VNC] WebSocket 关闭: ${host}:${port}`);
                this.cleanup(sessionId);
            });

            ws.on('error', (err) => {
                console.error(`[VNC] WebSocket 错误: ${err.message}`);
                this.cleanup(sessionId);
            });
        });

        console.log(`[VNC] WebSocket 代理服务已启动，路径: ${path}`);
    }

    /**
     * 生成会话 ID
     */
    generateSessionId() {
        return `vnc_${Date.now()}_${++this.sessionCounter}`;
    }

    /**
     * 清理会话
     */
    cleanup(sessionId) {
        if (!sessionId) return;

        const session = this.sessions.get(sessionId);
        if (session) {
            if (session.socket && !session.socket.destroyed) {
                session.socket.destroy();
            }
            this.sessions.delete(sessionId);
            console.log(`[VNC] 会话已清理: ${sessionId}`);
        }
    }

    /**
     * 获取活跃会话数
     */
    getActiveSessionCount() {
        return this.sessions.size;
    }

    /**
     * 关闭所有会话
     */
    closeAll() {
        for (const [sessionId, session] of this.sessions) {
            if (session.socket && !session.socket.destroyed) {
                session.socket.destroy();
            }
            if (session.ws && session.ws.readyState === WebSocket.OPEN) {
                session.ws.close();
            }
        }
        this.sessions.clear();
        console.log('[VNC] 所有会话已关闭');
    }
}

// 导出单例
module.exports = new VNCProxy();
