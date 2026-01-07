/**
 * Server Management Dashboard - Backend Server
 * 支持 SSH 和 SFTP 连接
 * 适用于 Debian 服务器部署
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const archiver = require('archiver');
const vncProxy = require('./vnc');
const localShell = require('./local-shell');

const app = express();
const server = http.createServer(app);

// 配置
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const USERS_FILE = path.join(__dirname, 'users.json');
const USER_DATA_DIR = path.join(__dirname, 'userdata');

// 确保目录存在
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
if (!fs.existsSync(USER_DATA_DIR)) {
    fs.mkdirSync(USER_DATA_DIR, { recursive: true });
}

// 用户管理
const UserManager = {
    defaultUsers: {
        admin: { password: 'admin', role: 'admin', createdAt: new Date().toISOString() }
    },

    load() {
        try {
            if (fs.existsSync(USERS_FILE)) {
                return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
            }
        } catch (e) {
            console.error('加载用户文件失败:', e.message);
        }
        // 首次运行，创建默认用户
        this.save(this.defaultUsers);
        return this.defaultUsers;
    },

    save(users) {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    },

    getAll() {
        return this.load();
    },

    get(username) {
        const users = this.load();
        return users[username];
    },

    add(username, password, role = 'user') {
        const users = this.load();
        if (users[username]) {
            return { success: false, error: '用户已存在' };
        }
        users[username] = {
            password,
            role,
            createdAt: new Date().toISOString()
        };
        this.save(users);
        return { success: true };
    },

    delete(username) {
        const users = this.load();
        if (!users[username]) {
            return { success: false, error: '用户不存在' };
        }
        if (username === 'admin') {
            return { success: false, error: '不能删除管理员账户' };
        }
        delete users[username];
        this.save(users);
        return { success: true };
    },

    updatePassword(username, newPassword) {
        const users = this.load();
        if (!users[username]) {
            return { success: false, error: '用户不存在' };
        }
        users[username].password = newPassword;
        this.save(users);
        return { success: true };
    },

    updateRole(username, newRole) {
        const users = this.load();
        if (!users[username]) {
            return { success: false, error: '用户不存在' };
        }
        if (username === 'admin' && newRole !== 'admin') {
            return { success: false, error: '不能修改管理员角色' };
        }
        users[username].role = newRole;
        this.save(users);
        return { success: true };
    },

    verify(username, password) {
        const users = this.load();
        const user = users[username];
        if (user && user.password === password) {
            return { success: true, role: user.role };
        }
        return { success: false };
    }
};

// 用户数据管理（主机列表、统计等）
const UserDataManager = {
    getFilePath(userId) {
        return path.join(USER_DATA_DIR, `${userId}.json`);
    },

    load(userId) {
        const filePath = this.getFilePath(userId);
        try {
            if (fs.existsSync(filePath)) {
                return JSON.parse(fs.readFileSync(filePath, 'utf8'));
            }
        } catch (e) {
            console.error(`加载用户数据失败 [${userId}]:`, e.message);
        }
        return { hosts: [], filesTransferred: 0 };
    },

    save(userId, data) {
        const filePath = this.getFilePath(userId);
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    },

    getHosts(userId) {
        return this.load(userId).hosts || [];
    },

    addHost(userId, host) {
        const data = this.load(userId);
        // 检查是否已存在
        const exists = data.hosts.some(h => h.host === host.host && h.user === host.user);
        if (exists) {
            return { success: false, error: '主机已存在' };
        }
        data.hosts.push({ ...host, addedAt: new Date().toISOString() });
        this.save(userId, data);
        return { success: true };
    },

    removeHost(userId, index) {
        const data = this.load(userId);
        if (index >= 0 && index < data.hosts.length) {
            data.hosts.splice(index, 1);
            this.save(userId, data);
            return { success: true };
        }
        return { success: false, error: '索引无效' };
    },

    incrementFilesTransferred(userId, count = 1) {
        const data = this.load(userId);
        data.filesTransferred = (data.filesTransferred || 0) + count;
        this.save(userId, data);
        return data.filesTransferred;
    },

    getStats(userId) {
        const data = this.load(userId);
        return {
            hostsCount: data.hosts.length,
            filesTransferred: data.filesTransferred || 0
        };
    },

    delete(userId) {
        const filePath = this.getFilePath(userId);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    }
};

// Multer 配置
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const sessionId = req.params.sessionId || 'default';
        const sessionDir = path.join(UPLOAD_DIR, sessionId);
        if (!fs.existsSync(sessionDir)) {
            fs.mkdirSync(sessionDir, { recursive: true });
        }
        cb(null, sessionDir);
    },
    filename: (req, file, cb) => {
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        cb(null, originalName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 500 * 1024 * 1024 }
});

// 中间件
app.use(express.json());
app.use(express.static(__dirname));

// CORS 支持
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// 存储活动的 SFTP 会话
const sftpSessions = new Map();
let sessionCounter = 0;

// 存储访客会话
const guestSessions = new Map();
let guestCounter = 0;

function generateSessionId() {
    return `session_${Date.now()}_${++sessionCounter}`;
}

function generateGuestId() {
    return `guest_${Date.now()}_${++guestCounter}`;
}

// ============================================
// 用户认证 API
// ============================================

// 登录
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const result = UserManager.verify(username, password);
    if (result.success) {
        res.json({ success: true, username, role: result.role });
    } else {
        res.status(401).json({ success: false, error: '用户名或密码错误' });
    }
});

// 验证已保存的登录状态
app.post('/api/auth/verify', (req, res) => {
    const { username } = req.body;
    const user = UserManager.get(username);
    if (user) {
        res.json({ success: true, username, role: user.role });
    } else {
        res.status(401).json({ success: false, error: '用户不存在' });
    }
});

// 访客登录
app.post('/api/auth/guest', (req, res) => {
    const guestId = generateGuestId();
    const guestName = `访客_${guestCounter}`;
    guestSessions.set(guestId, {
        username: guestName,
        createdAt: new Date().toISOString(),
        sftpSessions: []
    });
    console.log(`[Guest] 访客登录: ${guestName} (${guestId})`);
    res.json({ success: true, guestId, username: guestName, role: 'guest' });
});

// 访客登出（清除数据）
app.post('/api/auth/guest/logout/:guestId', (req, res) => {
    const { guestId } = req.params;
    const guest = guestSessions.get(guestId);

    if (guest) {
        // 关闭访客的所有 SFTP 会话
        for (const sessionId of guest.sftpSessions) {
            const session = sftpSessions.get(sessionId);
            if (session) {
                session.client.end();
                sftpSessions.delete(sessionId);
                // 清理上传目录
                const sessionDir = path.join(UPLOAD_DIR, sessionId);
                if (fs.existsSync(sessionDir)) {
                    fs.rmSync(sessionDir, { recursive: true, force: true });
                }
            }
        }
        // 删除访客用户数据文件
        UserDataManager.delete(guestId);
        guestSessions.delete(guestId);
        console.log(`[Guest] 访客登出: ${guest.username} (${guestId})`);
        res.json({ success: true, message: '访客数据已清除' });
    } else {
        res.json({ success: true, message: '会话已过期' });
    }
});

// 获取在线访客数量
app.get('/api/guests/count', (req, res) => {
    res.json({ count: guestSessions.size });
});

// ============================================
// 用户数据 API（主机、统计）
// ============================================

// 获取用户的主机列表
app.get('/api/userdata/:userId/hosts', (req, res) => {
    const { userId } = req.params;
    const hosts = UserDataManager.getHosts(userId);
    res.json(hosts);
});

// 添加主机
app.post('/api/userdata/:userId/hosts', (req, res) => {
    const { userId } = req.params;
    const { host, port, user, pass } = req.body;
    if (!host || !user) {
        return res.status(400).json({ error: '主机地址和用户名不能为空' });
    }
    const result = UserDataManager.addHost(userId, { host, port: port || 22, user, pass });
    if (result.success) {
        res.json({ message: '主机已保存' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 删除主机
app.delete('/api/userdata/:userId/hosts/:index', (req, res) => {
    const { userId, index } = req.params;
    const result = UserDataManager.removeHost(userId, parseInt(index));
    if (result.success) {
        res.json({ message: '主机已删除' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 获取用户统计
app.get('/api/userdata/:userId/stats', (req, res) => {
    const { userId } = req.params;
    const stats = UserDataManager.getStats(userId);
    res.json(stats);
});

// 获取所有用户（仅管理员）
app.get('/api/users', (req, res) => {
    const users = UserManager.getAll();
    const userList = Object.entries(users).map(([username, data]) => ({
        username,
        role: data.role,
        createdAt: data.createdAt
    }));
    res.json(userList);
});

// 添加用户
app.post('/api/users', (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    const result = UserManager.add(username, password, role || 'user');
    if (result.success) {
        res.json({ message: '用户创建成功' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 删除用户
app.delete('/api/users/:username', (req, res) => {
    const { username } = req.params;
    const result = UserManager.delete(username);
    if (result.success) {
        res.json({ message: '用户删除成功' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 修改密码
app.put('/api/users/:username/password', (req, res) => {
    const { username } = req.params;
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ error: '密码不能为空' });
    }
    const result = UserManager.updatePassword(username, password);
    if (result.success) {
        res.json({ message: '密码修改成功' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 修改角色
app.put('/api/users/:username/role', (req, res) => {
    const { username } = req.params;
    const { role } = req.body;
    if (!role) {
        return res.status(400).json({ error: '角色不能为空' });
    }
    const result = UserManager.updateRole(username, role);
    if (result.success) {
        res.json({ message: '角色修改成功' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// ============================================
// WebSocket 服务器 - SSH 连接
// ============================================
const wss = new WebSocket.Server({
    noServer: true,
    perMessageDeflate: false  // 禁用压缩，避免兼容性问题
});

wss.on('connection', (ws, req) => {
    console.log(`[WS] 新连接来自: ${req.socket.remoteAddress}`);

    let sshClient = null;
    let stream = null;
    let statsInterval = null;
    let topInterval = null;

    // Function to collect system stats via SSH exec
    const collectStats = () => {
        if (!sshClient || ws.readyState !== WebSocket.OPEN) {
            if (statsInterval) {
                clearInterval(statsInterval);
                statsInterval = null;
            }
            return;
        }

        // Execute commands to get /proc stats
        const cmd = 'cat /proc/stat; echo "---SEPARATOR---"; cat /proc/meminfo; echo "---SEPARATOR---"; cat /proc/diskstats';

        sshClient.exec(cmd, (err, execStream) => {
            if (err) {
                console.error('[Stats] 执行命令错误:', err.message);
                return;
            }

            let output = '';
            execStream.on('data', (chunk) => {
                output += chunk.toString();
            });
            execStream.on('close', () => {
                const parts = output.split('---SEPARATOR---');
                if (parts.length >= 3) {
                    try {
                        ws.send(JSON.stringify({
                            type: 'stats',
                            data: {
                                stat: parts[0].trim(),
                                meminfo: parts[1].trim(),
                                diskstats: parts[2].trim()
                            }
                        }));
                    } catch (e) {
                        console.error('[Stats] 发送数据错误:', e.message);
                    }
                }
            });
        });
    };

    // Function to collect TOP (process list) data via SSH exec
    const collectTop = () => {
        if (!sshClient || ws.readyState !== WebSocket.OPEN) {
            if (topInterval) {
                clearInterval(topInterval);
                topInterval = null;
            }
            return;
        }

        // Execute uptime and ps aux commands
        const cmd = 'uptime; echo "---SEPARATOR---"; ps aux --sort=-%cpu';

        sshClient.exec(cmd, (err, execStream) => {
            if (err) {
                console.error('[TOP] 执行命令错误:', err.message);
                return;
            }

            let output = '';
            execStream.on('data', (chunk) => {
                output += chunk.toString();
            });
            execStream.on('close', () => {
                const parts = output.split('---SEPARATOR---');
                if (parts.length >= 2) {
                    try {
                        ws.send(JSON.stringify({
                            type: 'top',
                            data: {
                                uptime: parts[0].trim(),
                                ps: parts[1].trim()
                            }
                        }));
                    } catch (e) {
                        console.error('[TOP] 发送数据错误:', e.message);
                    }
                }
            });
        });
    };

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message.toString());

            switch (data.type) {
                case 'connect':
                    if (sshClient) {
                        sshClient.end();
                    }

                    sshClient = new Client();

                    sshClient.on('ready', () => {
                        console.log(`[SSH] 连接成功: ${data.host}`);
                        ws.send(JSON.stringify({ type: 'connected' }));

                        sshClient.shell({
                            term: 'xterm-256color',
                            cols: 80,
                            rows: 24
                        }, (err, shellStream) => {
                            if (err) {
                                ws.send(JSON.stringify({ type: 'error', message: err.message }));
                                return;
                            }

                            stream = shellStream;

                            stream.on('data', (chunk) => {
                                ws.send(JSON.stringify({ type: 'data', data: chunk.toString('utf8') }));
                            });

                            stream.stderr.on('data', (chunk) => {
                                ws.send(JSON.stringify({ type: 'data', data: chunk.toString('utf8') }));
                            });

                            stream.on('close', () => {
                                ws.send(JSON.stringify({ type: 'disconnected' }));
                            });
                        });
                    });

                    sshClient.on('error', (err) => {
                        console.error('[SSH] 连接错误:', err.message);
                        ws.send(JSON.stringify({ type: 'error', message: err.message }));
                    });

                    sshClient.on('close', () => {
                        ws.send(JSON.stringify({ type: 'disconnected' }));
                    });

                    const config = {
                        host: data.host,
                        port: data.port || 22,
                        username: data.username,
                        readyTimeout: 30000,
                        keepaliveInterval: 10000
                    };

                    if (data.password) {
                        config.password = data.password;
                    }
                    if (data.privateKey) {
                        config.privateKey = data.privateKey;
                    }

                    console.log(`[SSH] 正在连接: ${data.username}@${data.host}:${config.port}`);
                    sshClient.connect(config);
                    break;

                case 'data':
                    if (stream && stream.writable) {
                        stream.write(data.data);
                    }
                    break;

                case 'resize':
                    if (stream) {
                        stream.setWindow(data.rows, data.cols, data.height || 480, data.width || 640);
                    }
                    break;

                case 'disconnect':
                    if (statsInterval) {
                        clearInterval(statsInterval);
                        statsInterval = null;
                    }
                    if (topInterval) {
                        clearInterval(topInterval);
                        topInterval = null;
                    }
                    if (stream) stream.end();
                    if (sshClient) sshClient.end();
                    break;

                case 'startStats':
                    if (sshClient && !statsInterval) {
                        console.log('[Stats] 开始系统监控');
                        // Collect immediately, then every 1 second
                        collectStats();
                        statsInterval = setInterval(collectStats, 1000);
                    }
                    break;

                case 'stopStats':
                    if (statsInterval) {
                        console.log('[Stats] 停止系统监控');
                        clearInterval(statsInterval);
                        statsInterval = null;
                    }
                    break;

                case 'startTop':
                    if (sshClient && !topInterval) {
                        console.log('[TOP] 开始进程监控');
                        // Collect immediately, then every 2 seconds
                        collectTop();
                        topInterval = setInterval(collectTop, 2000);
                    }
                    break;

                case 'stopTop':
                    if (topInterval) {
                        console.log('[TOP] 停止进程监控');
                        clearInterval(topInterval);
                        topInterval = null;
                    }
                    break;

                case 'refreshTop':
                    if (sshClient) {
                        collectTop();
                    }
                    break;

                case 'kill':
                    if (sshClient && data.pid && data.signal !== undefined) {
                        const pid = parseInt(data.pid);
                        const signal = parseInt(data.signal);
                        const signalNames = { 1: 'SIGHUP', 2: 'SIGINT', 9: 'SIGKILL', 15: 'SIGTERM', 18: 'SIGCONT', 19: 'SIGSTOP' };
                        console.log(`[KILL] 发送 ${signalNames[signal] || signal} 到 PID ${pid}`);

                        // Validate PID and signal
                        if (pid <= 0 || isNaN(pid)) {
                            ws.send(JSON.stringify({ type: 'killResult', data: { success: false, message: '无效的 PID' } }));
                            break;
                        }

                        const cmd = `kill -${signal} ${pid} 2>&1 && echo "SUCCESS" || echo "FAILED"`;
                        sshClient.exec(cmd, (err, execStream) => {
                            if (err) {
                                console.error('[KILL] 执行命令错误:', err.message);
                                ws.send(JSON.stringify({ type: 'killResult', data: { success: false, message: err.message } }));
                                return;
                            }

                            let output = '';
                            execStream.on('data', (chunk) => {
                                output += chunk.toString();
                            });
                            execStream.on('close', () => {
                                const success = output.includes('SUCCESS');
                                const message = success
                                    ? `已发送 ${signalNames[signal] || 'signal ' + signal} 到 PID ${pid}`
                                    : `发送信号失败: ${output.trim()}`;
                                console.log(`[KILL] 结果: ${success ? '成功' : '失败'}`);
                                ws.send(JSON.stringify({ type: 'killResult', data: { success, message } }));
                            });
                        });
                    }
                    break;
            }
        } catch (err) {
            console.error('[WS] 消息处理错误:', err);
            ws.send(JSON.stringify({ type: 'error', message: err.message }));
        }
    });

    ws.on('close', () => {
        if (statsInterval) {
            clearInterval(statsInterval);
            statsInterval = null;
        }
        if (topInterval) {
            clearInterval(topInterval);
            topInterval = null;
        }
        if (stream) stream.end();
        if (sshClient) sshClient.end();
    });

    ws.on('error', (err) => {
        console.error('[WS] WebSocket 错误:', err.message);
    });
});

// ============================================
// SFTP REST API
// ============================================

app.post('/api/sftp/connect', (req, res) => {
    const { host, port = 22, username, password, privateKey, guestId } = req.body;
    const sessionId = generateSessionId();

    console.log(`[SFTP] 正在连接: ${username}@${host}:${port}`);

    const sshClient = new Client();

    sshClient.on('ready', () => {
        sshClient.sftp((err, sftp) => {
            if (err) {
                sshClient.end();
                return res.status(500).json({ error: err.message });
            }

            sftpSessions.set(sessionId, { client: sshClient, sftp, host, guestId });

            // 如果是访客，记录其 SFTP 会话
            if (guestId && guestSessions.has(guestId)) {
                guestSessions.get(guestId).sftpSessions.push(sessionId);
            }

            res.json({ sessionId, message: '连接成功' });
        });
    });

    sshClient.on('error', (err) => {
        res.status(500).json({ error: err.message });
    });

    const config = {
        host,
        port: parseInt(port),
        username,
        readyTimeout: 30000
    };

    if (password) config.password = password;
    if (privateKey) config.privateKey = privateKey;

    sshClient.connect(config);
});

app.post('/api/sftp/disconnect/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const session = sftpSessions.get(sessionId);

    if (session) {
        session.client.end();
        sftpSessions.delete(sessionId);

        const sessionDir = path.join(UPLOAD_DIR, sessionId);
        if (fs.existsSync(sessionDir)) {
            fs.rmSync(sessionDir, { recursive: true, force: true });
        }

        res.json({ message: '断开成功' });
    } else {
        res.status(404).json({ error: '会话不存在' });
    }
});

app.get('/api/sftp/home/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const session = sftpSessions.get(sessionId);

    if (!session) {
        return res.status(404).json({ error: '会话不存在' });
    }

    session.sftp.realpath('.', (err, absPath) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ path: absPath });
    });
});

app.get('/api/sftp/list/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const { path: dirPath = '/' } = req.query;
    const session = sftpSessions.get(sessionId);

    if (!session) {
        return res.status(404).json({ error: '会话不存在' });
    }

    session.sftp.readdir(dirPath, (err, list) => {
        if (err) return res.status(500).json({ error: err.message });

        const files = list.map(item => ({
            name: item.filename,
            type: item.attrs.isDirectory() ? 'folder' : 'file',
            size: item.attrs.size,
            modified: new Date(item.attrs.mtime * 1000).toISOString(),
            permissions: item.attrs.mode
        })).sort((a, b) => {
            if (a.type === 'folder' && b.type !== 'folder') return -1;
            if (a.type !== 'folder' && b.type === 'folder') return 1;
            return a.name.localeCompare(b.name);
        });

        res.json({ path: dirPath, files });
    });
});

app.post('/api/sftp/mkdir/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const { path: dirPath } = req.body;
    const session = sftpSessions.get(sessionId);

    if (!session) return res.status(404).json({ error: '会话不存在' });

    session.sftp.mkdir(dirPath, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: '目录创建成功' });
    });
});

app.delete('/api/sftp/delete/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const { path: targetPath, type } = req.query;
    const session = sftpSessions.get(sessionId);

    if (!session) return res.status(404).json({ error: '会话不存在' });

    try {
        if (type === 'folder') {
            await deleteFolderRecursive(session.sftp, targetPath);
        } else {
            await new Promise((resolve, reject) => {
                session.sftp.unlink(targetPath, (err) => err ? reject(err) : resolve());
            });
        }
        res.json({ message: '删除成功' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

async function deleteFolderRecursive(sftp, dirPath) {
    return new Promise((resolve, reject) => {
        sftp.readdir(dirPath, async (err, list) => {
            if (err) return reject(err);
            try {
                for (const item of list) {
                    const itemPath = path.posix.join(dirPath, item.filename);
                    if (item.attrs.isDirectory()) {
                        await deleteFolderRecursive(sftp, itemPath);
                    } else {
                        await new Promise((res, rej) => {
                            sftp.unlink(itemPath, (e) => e ? rej(e) : res());
                        });
                    }
                }
                sftp.rmdir(dirPath, (e) => e ? reject(e) : resolve());
            } catch (e) {
                reject(e);
            }
        });
    });
}

app.post('/api/sftp/upload/:sessionId', upload.array('files', 1000), async (req, res) => {
    const { sessionId } = req.params;
    const { remotePath, paths } = req.body;
    const session = sftpSessions.get(sessionId);

    if (!session) return res.status(404).json({ error: '会话不存在' });
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: '没有文件' });

    let relativePaths = [];
    try {
        relativePaths = JSON.parse(paths || '[]');
    } catch (e) {
        relativePaths = req.files.map(f => f.originalname);
    }

    const results = [];
    const errors = [];

    for (let i = 0; i < req.files.length; i++) {
        const file = req.files[i];
        const localPath = file.path;
        const relativePath = relativePaths[i] || file.originalname;
        const remoteFilePath = path.posix.join(remotePath, relativePath);
        const remoteDir = path.posix.dirname(remoteFilePath);

        try {
            await ensureRemoteDir(session.sftp, remoteDir);
            await new Promise((resolve, reject) => {
                session.sftp.fastPut(localPath, remoteFilePath, (err) => err ? reject(err) : resolve());
            });
            results.push({ file: relativePath, status: 'success' });
            fs.unlinkSync(localPath);
        } catch (err) {
            errors.push({ file: relativePath, error: err.message });
        }
    }

    res.json({ message: `上传了 ${results.length} 个文件`, results, errors });
});

async function ensureRemoteDir(sftp, dirPath) {
    const parts = dirPath.split('/').filter(p => p);
    let currentPath = '';

    for (const part of parts) {
        currentPath += '/' + part;
        try {
            await new Promise((resolve, reject) => {
                sftp.stat(currentPath, (err) => {
                    if (err) {
                        sftp.mkdir(currentPath, (mkErr) => {
                            if (mkErr && mkErr.code !== 4) reject(mkErr);
                            else resolve();
                        });
                    } else {
                        resolve();
                    }
                });
            });
        } catch (err) {
            if (err.code !== 4) throw err;
        }
    }
}

app.get('/api/sftp/download/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const { path: filePath } = req.query;
    const session = sftpSessions.get(sessionId);

    if (!session) return res.status(404).json({ error: '会话不存在' });

    const fileName = path.basename(filePath);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`);

    const readStream = session.sftp.createReadStream(filePath);
    readStream.on('error', (err) => res.status(500).json({ error: err.message }));
    readStream.pipe(res);
});

// 多文件/文件夹下载（打包为 zip）
app.post('/api/sftp/download-zip/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const { files, basePath } = req.body; // files: [{name, type}], basePath: 当前目录
    const session = sftpSessions.get(sessionId);

    if (!session) return res.status(404).json({ error: '会话不存在' });
    if (!files || files.length === 0) return res.status(400).json({ error: '没有选择文件' });

    const zipName = files.length === 1 ? `${files[0].name}.zip` : `download_${Date.now()}.zip`;
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(zipName)}"`);

    const archive = archiver('zip', { zlib: { level: 5 } });
    archive.on('error', (err) => {
        console.error('[ZIP] 打包错误:', err);
        if (!res.headersSent) res.status(500).json({ error: err.message });
    });
    archive.pipe(res);

    try {
        for (const file of files) {
            const fullPath = basePath === '/' ? `/${file.name}` : `${basePath}/${file.name}`;
            if (file.type === 'folder') {
                await addFolderToArchive(session.sftp, archive, fullPath, file.name);
            } else {
                const stream = session.sftp.createReadStream(fullPath);
                archive.append(stream, { name: file.name });
            }
        }
        await archive.finalize();
    } catch (err) {
        console.error('[ZIP] 下载错误:', err);
        if (!res.headersSent) res.status(500).json({ error: err.message });
    }
});

// 递归添加文件夹到 zip
async function addFolderToArchive(sftp, archive, remotePath, archivePath) {
    return new Promise((resolve, reject) => {
        sftp.readdir(remotePath, async (err, list) => {
            if (err) return reject(err);
            try {
                for (const item of list) {
                    const itemRemotePath = path.posix.join(remotePath, item.filename);
                    const itemArchivePath = path.posix.join(archivePath, item.filename);
                    if (item.attrs.isDirectory()) {
                        await addFolderToArchive(sftp, archive, itemRemotePath, itemArchivePath);
                    } else {
                        const stream = sftp.createReadStream(itemRemotePath);
                        archive.append(stream, { name: itemArchivePath });
                    }
                }
                resolve();
            } catch (e) {
                reject(e);
            }
        });
    });
}

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), sessions: sftpSessions.size });
});

// ============================================
// 初始化 VNC 代理服务
// ============================================
vncProxy.init(server, '/vnc');

// ============================================
// 初始化本地 Shell 服务
// ============================================
const localShellService = localShell.init(server, '/localshell');
if (localShellService.available) {
    console.log('[Server] 本地 Shell 服务已启用 (Linux)');
} else {
    console.log('[Server] 本地 Shell 服务不可用 (仅支持 Linux)');
}

// 添加本地 shell 状态检查 API
app.get('/api/localshell/status', (req, res) => {
    res.json({
        available: localShell.isAvailable(),
        sessions: localShell.getSessionCount(),
        shell: localShell.getDefaultShell(),
        platform: localShell.getPlatform()
    });
});

// ============================================
// 统一 WebSocket upgrade 处理
// ============================================
server.on('upgrade', (request, socket, head) => {
    const pathname = new (require('url').URL)(request.url, 'http://localhost').pathname;

    if (pathname === '/ssh') {
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    } else if (pathname === '/localshell' && localShell.isAvailable()) {
        localShell.handleUpgrade(request, socket, head);
    }
    // /vnc 由 vncProxy 自己处理
});

// ============================================
// 启动服务器
// ============================================
server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Server Management Dashboard                             ║
║                                                           ║
║   服务器运行在: http://localhost:${PORT}                     ║
║                                                           ║
║   功能:                                                   ║
║   - SSH 终端 (WebSocket)                                  ║
║   - SFTP 文件管理 (REST API)                              ║
║   - VNC 远程桌面 (WebSocket 代理)                         ║
║   - 文件/文件夹上传                                       ║
║   - 用户管理 (REST API)                                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});

process.on('SIGINT', () => {
    console.log('\n正在关闭服务器...');
    // 关闭 SFTP 会话
    for (const [sessionId, session] of sftpSessions) {
        session.client.end();
    }
    // 关闭 VNC 会话
    vncProxy.closeAll();
    // 关闭本地 Shell 会话
    localShell.closeAll();
    if (fs.existsSync(UPLOAD_DIR)) {
        fs.rmSync(UPLOAD_DIR, { recursive: true, force: true });
    }
    process.exit(0);
});

process.on('SIGTERM', () => {
    process.emit('SIGINT');
});
