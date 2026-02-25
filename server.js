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
const dns = require('dns');
const net = require('net');
const crypto = require('crypto');
const argon2 = require('argon2');
const archiver = require('archiver');
const vncProxy = require('./vnc');
const localShell = require('./local-shell');

const app = express();
const server = http.createServer(app);

app.set('trust proxy', 1);

// 配置
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.resolve(process.env.ENTRANCE_DATA_DIR || __dirname);
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const USER_DATA_DIR = path.join(DATA_DIR, 'userdata');
const KNOWN_HOSTS_FILE = path.join(DATA_DIR, 'known_hosts.json');
const PRIVATE_NETWORKS_FILE = path.join(DATA_DIR, 'private-networks.json');

const AUTH_SECRET_ENV = 'AUTH_SECRET';
const AUTH_TOKEN_TTL = parseInt(process.env.AUTH_TOKEN_TTL || '43200', 10);
const LOGIN_WINDOW_MS = parseInt(process.env.LOGIN_WINDOW_MS || '900000', 10);
const LOGIN_MAX_ATTEMPTS = parseInt(process.env.LOGIN_MAX_ATTEMPTS || '5', 10);
const STRICT_HOST_KEY_CHECKING = process.env.STRICT_HOST_KEY_CHECKING === 'true';
const ALLOWED_TARGETS = (process.env.ALLOWED_TARGETS || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
const ALLOW_PRIVATE_NETWORKS = process.env.ALLOW_PRIVATE_NETWORKS === 'true';

const SSH_PASSWORD_ENV = 'SSH_PASSWORD_KEY';
const SSH_PASSWORD_PREFIX = 'enc:v1:';
const SSH_AUTH_TYPE_PASSWORD = 'password';
const SSH_AUTH_TYPE_KEY = 'key';
const SSH_HOST_MAX_LENGTH = getPositiveIntEnv('SSH_HOST_MAX_LENGTH', 255);
const SSH_USERNAME_MAX_LENGTH = getPositiveIntEnv('SSH_USERNAME_MAX_LENGTH', 128);
const SSH_PASSWORD_MAX_LENGTH = getPositiveIntEnv('SSH_PASSWORD_MAX_LENGTH', 2048);
const SSH_PASSPHRASE_MAX_LENGTH = getPositiveIntEnv('SSH_PASSPHRASE_MAX_LENGTH', 4096);
const SSH_PRIVATE_KEY_MAX_LENGTH = getPositiveIntEnv('SSH_PRIVATE_KEY_MAX_LENGTH', 65536);

function getPositiveIntEnv(name, fallback) {
    const parsed = parseInt(process.env[name] || '', 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return fallback;
    }
    return parsed;
}

function getAuthSecret() {
    const rawKey = process.env[AUTH_SECRET_ENV];
    if (!rawKey) {
        throw new Error(`${AUTH_SECRET_ENV} is required for auth token signing`);
    }
    let key = null;
    if (/^[0-9a-fA-F]{64,}$/.test(rawKey)) {
        key = Buffer.from(rawKey, 'hex');
    } else {
        key = Buffer.from(rawKey, 'base64');
    }
    if (key.length < 32) {
        throw new Error(`${AUTH_SECRET_ENV} must be at least 32 bytes (base64) or 64+ hex chars`);
    }
    return key;
}

function getSshPasswordKey() {
    const rawKey = process.env[SSH_PASSWORD_ENV];
    if (!rawKey) {
        throw new Error(`${SSH_PASSWORD_ENV} is required for SSH password encryption`);
    }
    let key = null;
    if (/^[0-9a-fA-F]{64}$/.test(rawKey)) {
        key = Buffer.from(rawKey, 'hex');
    } else {
        key = Buffer.from(rawKey, 'base64');
    }
    if (key.length !== 32) {
        throw new Error(`${SSH_PASSWORD_ENV} must be 32 bytes (base64) or 64 hex chars`);
    }
    return key;
}

function isEncryptedSecret(value) {
    return typeof value === 'string' && value.startsWith(SSH_PASSWORD_PREFIX);
}

function encryptSshPassword(plaintext) {
    if (!plaintext) return '';
    const key = getSshPasswordKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${SSH_PASSWORD_PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}

function decryptSshPassword(payload) {
    if (!payload || !isEncryptedSecret(payload)) return payload || '';
    const parts = payload.split(':');
    if (parts.length !== 5) {
        throw new Error('Invalid encrypted SSH password format');
    }
    const iv = Buffer.from(parts[2], 'base64');
    const tag = Buffer.from(parts[3], 'base64');
    const encrypted = Buffer.from(parts[4], 'base64');
    const key = getSshPasswordKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
}

function normalizeStringValue(value, fieldName, maxLength, { trim = false } = {}) {
    if (value === undefined || value === null) {
        return '';
    }
    if (typeof value !== 'string') {
        throw new Error(`${fieldName}格式无效`);
    }
    const normalized = trim ? value.trim() : value;
    if (normalized.length > maxLength) {
        throw new Error(`${fieldName}长度超过限制`);
    }
    return normalized;
}

function normalizeRequiredString(value, fieldName, maxLength) {
    const normalized = normalizeStringValue(value, fieldName, maxLength, { trim: true });
    if (!normalized) {
        throw new Error(`${fieldName}不能为空`);
    }
    return normalized;
}

function normalizePrivateKey(privateKey) {
    const normalized = normalizeStringValue(privateKey, '私钥', SSH_PRIVATE_KEY_MAX_LENGTH, { trim: true })
        .replace(/\r\n/g, '\n');
    if (!normalized) {
        return '';
    }
    if (!/^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+-----END [A-Z0-9 ]*PRIVATE KEY-----$/.test(normalized)) {
        throw new Error('私钥格式无效，仅支持 PEM/OpenSSH 私钥');
    }
    return normalized;
}

function normalizeAuthType(authType, hasPrivateKey = false) {
    if (typeof authType === 'string') {
        const lowered = authType.trim().toLowerCase();
        if (lowered === SSH_AUTH_TYPE_PASSWORD || lowered === 'pass') {
            return SSH_AUTH_TYPE_PASSWORD;
        }
        if (lowered === SSH_AUTH_TYPE_KEY || lowered === 'privatekey' || lowered === 'private_key') {
            return SSH_AUTH_TYPE_KEY;
        }
    }
    return hasPrivateKey ? SSH_AUTH_TYPE_KEY : SSH_AUTH_TYPE_PASSWORD;
}

function normalizePort(port, fallback = 22) {
    const parsedPort = parseInt(port, 10);
    if (!Number.isFinite(parsedPort)) {
        return fallback;
    }
    if (parsedPort < 1 || parsedPort > 65535) {
        throw new Error('端口范围必须是 1-65535');
    }
    return parsedPort;
}

function resolveSshCredentials(raw = {}, options = {}) {
    const requireCredential = options.requireCredential !== false;
    const password = normalizeStringValue(raw.password ?? raw.pass ?? '', '密码', SSH_PASSWORD_MAX_LENGTH);
    const privateKey = normalizePrivateKey(raw.privateKey ?? '');
    const passphrase = normalizeStringValue(raw.passphrase ?? '', '私钥口令', SSH_PASSPHRASE_MAX_LENGTH);
    const authType = normalizeAuthType(raw.authType, Boolean(privateKey));

    if (requireCredential && !password && !privateKey) {
        throw new Error('请提供密码或私钥');
    }

    if (authType === SSH_AUTH_TYPE_KEY) {
        if (!privateKey) {
            throw new Error('密钥登录需要提供私钥');
        }
        return {
            authType,
            password: '',
            privateKey,
            passphrase
        };
    }

    if (requireCredential && !password) {
        throw new Error('密码登录需要提供密码');
    }

    return {
        authType: SSH_AUTH_TYPE_PASSWORD,
        password,
        privateKey: '',
        passphrase: ''
    };
}

function applyCredentialsToSshConfig(config, credentials) {
    if (!credentials || !config) return;
    if (credentials.authType === SSH_AUTH_TYPE_KEY) {
        config.privateKey = credentials.privateKey;
        if (credentials.passphrase) {
            config.passphrase = credentials.passphrase;
        }
        return;
    }
    if (credentials.password) {
        config.password = credentials.password;
    }
}

async function hashPassword(password) {
    return argon2.hash(password, { type: argon2.argon2id });
}

function signToken(payload, ttlSeconds) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const body = { ...payload, iat: now, exp: now + ttlSeconds };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedBody = Buffer.from(JSON.stringify(body)).toString('base64url');
    const input = `${encodedHeader}.${encodedBody}`;
    const signature = crypto.createHmac('sha256', getAuthSecret()).update(input).digest('base64url');
    return `${input}.${signature}`;
}

function verifyToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const input = `${parts[0]}.${parts[1]}`;
        const expected = crypto.createHmac('sha256', getAuthSecret()).update(input).digest('base64url');
        const signature = parts[2];
        if (expected.length !== signature.length) return null;
        if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) {
            return null;
        }
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) return null;
        return payload;
    } catch (err) {
        return null;
    }
}

const loginAttempts = new Map();

function getLoginAttemptKey(req) {
    return `${req.ip}:${req.body?.username || ''}`;
}

function isLoginRateLimited(key) {
    const entry = loginAttempts.get(key);
    if (!entry) return false;
    if (Date.now() - entry.firstAttempt > LOGIN_WINDOW_MS) {
        loginAttempts.delete(key);
        return false;
    }
    return entry.count >= LOGIN_MAX_ATTEMPTS;
}

function recordLoginAttempt(key, success) {
    if (success) {
        loginAttempts.delete(key);
        return;
    }
    const now = Date.now();
    const entry = loginAttempts.get(key);
    if (!entry) {
        loginAttempts.set(key, { count: 1, firstAttempt: now });
        return;
    }
    if (now - entry.firstAttempt > LOGIN_WINDOW_MS) {
        loginAttempts.set(key, { count: 1, firstAttempt: now });
    } else {
        entry.count += 1;
    }
}

function getTokenFromRequest(req) {
    const authHeader = req.headers.authorization || '';
    if (authHeader.startsWith('Bearer ')) {
        return authHeader.slice(7).trim();
    }
    try {
        const parsed = new (require('url').URL)(req.url, 'http://localhost');
        return parsed.searchParams.get('token');
    } catch {
        return null;
    }
}

function requireAuth(req, res, next) {
    const token = getTokenFromRequest(req);
    if (!token) {
        return res.status(401).json({ error: '未登录' });
    }
    const payload = verifyToken(token);
    if (!payload) {
        return res.status(401).json({ error: '登录已过期' });
    }
    req.auth = payload;
    next();
}

function requireAdmin(req, res, next) {
    if (!req.auth || req.auth.role !== 'admin') {
        return res.status(403).json({ error: '权限不足' });
    }
    next();
}

function requireSelfOrAdmin(paramName) {
    return (req, res, next) => {
        const target = req.params[paramName];
        if (!req.auth) {
            return res.status(401).json({ error: '未登录' });
        }
        if (req.auth.role === 'admin' || req.auth.sub === target) {
            return next();
        }
        return res.status(403).json({ error: '权限不足' });
    };
}

function rejectUpgrade(socket, statusCode, message) {
    socket.write(`HTTP/1.1 ${statusCode} ${message}\r\n\r\n`);
    socket.destroy();
}

function authenticateUpgrade(request) {
    const token = getTokenFromRequest(request);
    if (!token) return null;
    return verifyToken(token);
}

function hostMatchesAllowlist(host) {
    if (!ALLOWED_TARGETS.length) return false;
    return ALLOWED_TARGETS.some(entry => {
        if (entry.startsWith('*.')) {
            return host.endsWith(entry.slice(1));
        }
        return host === entry;
    });
}

function isValidIpv4(value) {
    return net.isIP(value) === 4;
}

function normalizeCidr(value) {
    const trimmed = value.trim();
    if (!trimmed) return '';
    if (!trimmed.includes('/')) {
        return `${trimmed}/32`;
    }
    return trimmed;
}

function isValidCidr(value) {
    const trimmed = value.trim();
    if (!trimmed) return false;
    const parts = trimmed.split('/');
    if (parts.length === 1) {
        return isValidIpv4(parts[0]);
    }
    if (parts.length !== 2) return false;
    const [ip, prefix] = parts;
    if (!isValidIpv4(ip)) return false;
    const prefixNum = parseInt(prefix, 10);
    return Number.isFinite(prefixNum) && prefixNum >= 0 && prefixNum <= 32;
}

function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isIpInCidr(ip, cidr) {
    if (!isValidIpv4(ip)) return false;
    const normalized = normalizeCidr(cidr);
    const [base, prefixStr] = normalized.split('/');
    if (!isValidIpv4(base)) return false;
    const prefix = parseInt(prefixStr, 10);
    if (!Number.isFinite(prefix)) return false;
    const ipInt = ipv4ToInt(ip);
    const baseInt = ipv4ToInt(base);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipInt & mask) === (baseInt & mask);
}

function isPrivateIp(address) {
    if (!net.isIP(address)) return false;
    if (address.includes(':')) {
        const lower = address.toLowerCase();
        return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80');
    }
    const parts = address.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return false;
}

const PrivateNetworkManager = {
    load() {
        if (!fs.existsSync(PRIVATE_NETWORKS_FILE)) {
            return { networks: [] };
        }
        try {
            return JSON.parse(fs.readFileSync(PRIVATE_NETWORKS_FILE, 'utf8'));
        } catch (err) {
            console.error('加载私有网络白名单失败:', err.message);
            return { networks: [] };
        }
    },
    save(data) {
        fs.writeFileSync(PRIVATE_NETWORKS_FILE, JSON.stringify(data, null, 2));
    },
    getNetworks() {
        const data = this.load();
        const list = Array.isArray(data.networks) ? data.networks : [];
        let updated = false;
        const decrypted = list.map(entry => {
            if (isEncryptedSecret(entry)) {
                return decryptSshPassword(entry);
            }
            if (entry) {
                const encrypted = encryptSshPassword(entry);
                updated = true;
                return decryptSshPassword(encrypted);
            }
            return '';
        }).filter(Boolean);
        if (updated) {
            this.setNetworks(decrypted);
        }
        return decrypted;
    },
    setNetworks(networks) {
        const unique = [...new Set(networks)];
        const encrypted = unique.map(entry => encryptSshPassword(entry));
        this.save({ networks: encrypted });
    }
};

function isIpAllowedByPrivateWhitelist(address) {
    const networks = PrivateNetworkManager.getNetworks();
    if (!networks.length) return false;
    return networks.some(cidr => isIpInCidr(address, cidr));
}

async function validateTargetHost(host) {
    if (!host || typeof host !== 'string') {
        return { ok: false, error: '目标主机无效' };
    }
    const trimmed = host.trim();
    if (ALLOWED_TARGETS.length && !hostMatchesAllowlist(trimmed)) {
        return { ok: false, error: '目标主机不在白名单' };
    }
    try {
        const records = await dns.promises.lookup(trimmed, { all: true });
        if (!records.length) {
            return { ok: false, error: '目标主机无法解析' };
        }
        if (!ALLOW_PRIVATE_NETWORKS) {
            const privateAddresses = records
                .map(record => record.address)
                .filter(address => isPrivateIp(address));
            if (privateAddresses.length) {
                const allAllowed = privateAddresses.every(address => isIpAllowedByPrivateWhitelist(address));
                if (!allAllowed) {
                    return { ok: false, error: '私有网络地址未在白名单' };
                }
            }
        }
        return { ok: true, addresses: records.map(r => r.address) };
    } catch (err) {
        return { ok: false, error: '目标主机解析失败' };
    }
}

function loadKnownHosts() {
    if (!fs.existsSync(KNOWN_HOSTS_FILE)) {
        return {};
    }
    try {
        return JSON.parse(fs.readFileSync(KNOWN_HOSTS_FILE, 'utf8'));
    } catch (err) {
        console.error('加载 known_hosts 失败:', err.message);
        return {};
    }
}

const knownHostsCache = loadKnownHosts();

function saveKnownHosts() {
    fs.writeFileSync(KNOWN_HOSTS_FILE, JSON.stringify(knownHostsCache, null, 2));
}

function getKnownHostId(host, port) {
    return `${host}:${port}`;
}

function createHostVerifier(host, port) {
    return (keyHash) => {
        const id = getKnownHostId(host, port);
        const existing = knownHostsCache[id];
        if (existing && existing.hash) {
            return existing.hash === keyHash;
        }
        if (STRICT_HOST_KEY_CHECKING) {
            console.warn(`[SSH] 未知主机指纹被拒绝: ${id}`);
            return false;
        }
        knownHostsCache[id] = { hash: keyHash, addedAt: new Date().toISOString() };
        try {
            saveKnownHosts();
        } catch (err) {
            console.error('保存 known_hosts 失败:', err.message);
        }
        console.warn(`[SSH] 已记录新的主机指纹: ${id}`);
        return true;
    };
}

// 确保目录存在
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
if (!fs.existsSync(USER_DATA_DIR)) {
    fs.mkdirSync(USER_DATA_DIR, { recursive: true });
}

// 用户管理
const UserManager = {
    async ensureDefaults() {
        if (fs.existsSync(USERS_FILE)) {
            return;
        }
        const users = {
            admin: {
                password: await hashPassword('admin'),
                role: 'admin',
                createdAt: new Date().toISOString()
            }
        };
        this.save(users);
    },

    load() {
        try {
            if (fs.existsSync(USERS_FILE)) {
                return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
            }
        } catch (e) {
            console.error('加载用户文件失败:', e.message);
        }
        return {};
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

    async add(username, password, role = 'user') {
        const users = this.load();
        if (users[username]) {
            return { success: false, error: '用户已存在' };
        }
        users[username] = {
            password: await hashPassword(password),
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

    async updatePassword(username, newPassword) {
        const users = this.load();
        if (!users[username]) {
            return { success: false, error: '用户不存在' };
        }
        users[username].password = await hashPassword(newPassword);
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

    async verify(username, password) {
        const users = this.load();
        const user = users[username];
        if (user) {
            const stored = user.password || '';
            let matches = false;
            if (stored.startsWith('$argon2')) {
                try {
                    matches = await argon2.verify(stored, password || '');
                } catch (err) {
                    console.error('密码校验失败:', err.message);
                    matches = false;
                }
            } else {
                matches = stored === (password || '');
                if (matches) {
                    users[username].password = await hashPassword(password);
                    this.save(users);
                }
            }
            if (matches) {
                return { success: true, role: user.role };
            }
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
        const data = this.load(userId);
        const hosts = data.hosts || [];
        let updated = false;
        const decryptedHosts = hosts.map(host => {
            const entry = { ...host };
            for (const field of ['pass', 'privateKey', 'passphrase']) {
                if (!entry[field]) {
                    continue;
                }
                if (isEncryptedSecret(entry[field])) {
                    try {
                        entry[field] = decryptSshPassword(entry[field]);
                    } catch (err) {
                        console.error(`[Hosts] 解密字段失败 [${userId}] ${field}:`, err.message);
                        entry[field] = '';
                    }
                    continue;
                }
                const plaintext = entry[field];
                host[field] = encryptSshPassword(plaintext);
                entry[field] = plaintext;
                updated = true;
            }
            const normalizedAuthType = normalizeAuthType(entry.authType, Boolean(entry.privateKey));
            if (entry.authType !== normalizedAuthType) {
                entry.authType = normalizedAuthType;
                host.authType = normalizedAuthType;
                updated = true;
            }
            return entry;
        });
        if (updated) {
            this.save(userId, data);
        }
        return decryptedHosts;
    },

    addHost(userId, host) {
        const data = this.load(userId);
        // 检查是否已存在
        const exists = data.hosts.some(h => h.host === host.host && h.user === host.user && `${h.port || 22}` === `${host.port || 22}`);
        if (exists) {
            return { success: false, error: '主机已存在' };
        }
        const encryptedPass = host.pass ? encryptSshPassword(host.pass) : '';
        const encryptedPrivateKey = host.privateKey ? encryptSshPassword(host.privateKey) : '';
        const encryptedPassphrase = host.passphrase ? encryptSshPassword(host.passphrase) : '';
        data.hosts.push({
            host: host.host,
            port: host.port || 22,
            user: host.user,
            authType: normalizeAuthType(host.authType, Boolean(host.privateKey)),
            pass: encryptedPass,
            privateKey: encryptedPrivateKey,
            passphrase: encryptedPassphrase,
            addedAt: new Date().toISOString()
        });
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
        const ext = path.extname(originalName);
        const safeExt = /^[.a-zA-Z0-9]+$/.test(ext) ? ext.toLowerCase() : '';
        const uuid = typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : crypto.randomBytes(16).toString('hex');
        cb(null, `${uuid}${safeExt}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 500 * 1024 * 1024 }
});

// 中间件
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CORS 支持
const corsOriginPattern = /^(https?:\/\/)(localhost|127\.0\.0\.1)(:\d+)?$/;
app.use((req, res, next) => {
    const { origin } = req.headers;
    if (origin && corsOriginPattern.test(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Vary', 'Origin');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    } else if (origin) {
        if (req.method === 'OPTIONS') {
            return res.sendStatus(403);
        }
        return res.status(403).json({ error: 'CORS blocked' });
    }
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// 存储活动的 SFTP 会话
const sftpSessions = new Map();

function generateSessionId() {
    const rand = typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : crypto.randomBytes(16).toString('hex');
    return `session_${rand}`;
}

// ============================================
// 用户认证 API
// ============================================

// 登录
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, error: '用户名和密码不能为空' });
    }
    const rateKey = getLoginAttemptKey(req);
    if (isLoginRateLimited(rateKey)) {
        return res.status(429).json({ success: false, error: '尝试次数过多，请稍后再试' });
    }
    const result = await UserManager.verify(username, password);
    if (result.success) {
        recordLoginAttempt(rateKey, true);
        const token = signToken({ sub: username, role: result.role }, AUTH_TOKEN_TTL);
        res.json({ success: true, token, username, role: result.role });
    } else {
        recordLoginAttempt(rateKey, false);
        res.status(401).json({ success: false, error: '用户名或密码错误' });
    }
});

// 验证已保存的登录状态
app.post('/api/auth/verify', requireAuth, (req, res) => {
    res.json({ success: true, username: req.auth.sub, role: req.auth.role });
});

// 保护所有 API（登录接口除外）
app.use('/api', requireAuth);

// ============================================
// 用户数据 API（主机、统计）
// ============================================

// 获取用户的主机列表
app.get('/api/userdata/:userId/hosts', requireSelfOrAdmin('userId'), (req, res) => {
    const { userId } = req.params;
    try {
        const hosts = UserDataManager.getHosts(userId);
        res.json(hosts);
    } catch (err) {
        console.error('[Hosts] 加载失败:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// 添加主机
app.post('/api/userdata/:userId/hosts', requireSelfOrAdmin('userId'), (req, res) => {
    const { userId } = req.params;
    let host = '';
    let user = '';
    let port = 22;
    let credentials = null;

    try {
        host = normalizeRequiredString(req.body.host, '主机地址', SSH_HOST_MAX_LENGTH);
        user = normalizeRequiredString(req.body.user, '用户名', SSH_USERNAME_MAX_LENGTH);
        port = normalizePort(req.body.port, 22);
        credentials = resolveSshCredentials(req.body, { requireCredential: false });
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }

    try {
        const result = UserDataManager.addHost(userId, {
            host,
            port,
            user,
            authType: credentials.authType,
            pass: credentials.password,
            privateKey: credentials.privateKey,
            passphrase: credentials.passphrase
        });
        if (result.success) {
            res.json({ message: '主机已保存' });
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (err) {
        console.error('[Hosts] 保存失败:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// 删除主机
app.delete('/api/userdata/:userId/hosts/:index', requireSelfOrAdmin('userId'), (req, res) => {
    const { userId, index } = req.params;
    const result = UserDataManager.removeHost(userId, parseInt(index));
    if (result.success) {
        res.json({ message: '主机已删除' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 获取用户统计
app.get('/api/userdata/:userId/stats', requireSelfOrAdmin('userId'), (req, res) => {
    const { userId } = req.params;
    const stats = UserDataManager.getStats(userId);
    res.json(stats);
});

// 获取所有用户（仅管理员）
app.get('/api/users', requireAdmin, (req, res) => {
    const users = UserManager.getAll();
    const userList = Object.entries(users).map(([username, data]) => ({
        username,
        role: data.role,
        createdAt: data.createdAt
    }));
    res.json(userList);
});

// 添加用户
app.post('/api/users', requireAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    const result = await UserManager.add(username, password, role || 'user');
    if (result.success) {
        res.json({ message: '用户创建成功' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 删除用户
app.delete('/api/users/:username', requireAdmin, (req, res) => {
    const { username } = req.params;
    const result = UserManager.delete(username);
    if (result.success) {
        res.json({ message: '用户删除成功' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 修改密码
app.put('/api/users/:username/password', requireSelfOrAdmin('username'), async (req, res) => {
    const { username } = req.params;
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ error: '密码不能为空' });
    }
    const result = await UserManager.updatePassword(username, password);
    if (result.success) {
        res.json({ message: '密码修改成功' });
    } else {
        res.status(400).json({ error: result.error });
    }
});

// 修改角色
app.put('/api/users/:username/role', requireAdmin, (req, res) => {
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

// 私有网络白名单（仅管理员）
app.get('/api/security/private-networks', requireAdmin, (req, res) => {
    try {
        res.json({ networks: PrivateNetworkManager.getNetworks() });
    } catch (err) {
        console.error('[Security] 读取白名单失败:', err.message);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/security/private-networks', requireAdmin, (req, res) => {
    const { networks } = req.body;
    if (!Array.isArray(networks)) {
        return res.status(400).json({ error: 'networks 必须是数组' });
    }
    const normalized = networks.map(item => (item || '').trim()).filter(Boolean).map(normalizeCidr);
    const invalid = normalized.filter(item => !isValidCidr(item));
    if (invalid.length) {
        return res.status(400).json({ error: `无效的网段: ${invalid.join(', ')}` });
    }
    const nonPrivate = normalized.filter(item => {
        const [base] = item.split('/');
        return !isPrivateIp(base);
    });
    if (nonPrivate.length) {
        return res.status(400).json({ error: `仅允许私有网段: ${nonPrivate.join(', ')}` });
    }
    try {
        PrivateNetworkManager.setNetworks(normalized);
        res.json({ message: '白名单已更新', networks: normalized });
    } catch (err) {
        console.error('[Security] 保存白名单失败:', err.message);
        res.status(500).json({ error: err.message });
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

    if (!req.auth) {
        ws.close(1008, 'Unauthorized');
        return;
    }

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

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message.toString());

            switch (data.type) {
                case 'connect':
                    if (sshClient) {
                        sshClient.end();
                    }

                    let host = '';
                    let username = '';
                    let port = 22;
                    let credentials = null;

                    try {
                        host = normalizeRequiredString(data.host, '主机地址', SSH_HOST_MAX_LENGTH);
                        username = normalizeRequiredString(data.username, '用户名', SSH_USERNAME_MAX_LENGTH);
                        port = normalizePort(data.port, 22);
                        credentials = resolveSshCredentials(data);
                    } catch (err) {
                        ws.send(JSON.stringify({ type: 'error', message: err.message }));
                        break;
                    }

                    const hostCheck = await validateTargetHost(host);
                    if (!hostCheck.ok) {
                        ws.send(JSON.stringify({ type: 'error', message: hostCheck.error }));
                        break;
                    }

                    sshClient = new Client();

                    sshClient.on('ready', () => {
                        console.log(`[SSH] 连接成功: ${host}`);
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
                        host: host,
                        port: port,
                        username,
                        readyTimeout: 30000,
                        keepaliveInterval: 10000,
                        hostHash: 'sha256',
                        hostVerifier: createHostVerifier(host, port)
                    };

                    applyCredentialsToSshConfig(config, credentials);

                    console.log(`[SSH] 正在连接: ${username}@${host}:${config.port} (${credentials.authType})`);
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

function getSftpSessionForRequest(sessionId, auth) {
    const session = sftpSessions.get(sessionId);
    if (!session) {
        return { error: { status: 404, message: '会话不存在' } };
    }
    if (auth && session.owner && auth.role !== 'admin' && session.owner !== auth.sub) {
        return { error: { status: 403, message: '无权访问该会话' } };
    }
    if (auth && !session.owner && auth.role !== 'admin') {
        return { error: { status: 403, message: '会话无归属，已拒绝访问' } };
    }
    return { session };
}

app.post('/api/sftp/connect', async (req, res) => {
    const sessionId = generateSessionId();
    let normalizedHost = '';
    let normalizedUsername = '';
    let normalizedPort = 22;
    let credentials = null;

    try {
        normalizedHost = normalizeRequiredString(req.body.host, '主机地址', SSH_HOST_MAX_LENGTH);
        normalizedUsername = normalizeRequiredString(req.body.username, '用户名', SSH_USERNAME_MAX_LENGTH);
        normalizedPort = normalizePort(req.body.port, 22);
        credentials = resolveSshCredentials(req.body);
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }

    const hostCheck = await validateTargetHost(normalizedHost);
    if (!hostCheck.ok) {
        return res.status(400).json({ error: hostCheck.error });
    }

    console.log(`[SFTP] 正在连接: ${normalizedUsername}@${normalizedHost}:${normalizedPort} (${credentials.authType})`);

    const sshClient = new Client();
    let responded = false;

    function fail(status, message) {
        if (responded || res.headersSent) return;
        responded = true;
        res.status(status).json({ error: message });
    }

    function success(payload) {
        if (responded || res.headersSent) return;
        responded = true;
        res.json(payload);
    }

    sshClient.on('ready', () => {
        sshClient.sftp((err, sftp) => {
            if (err) {
                sshClient.end();
                return fail(500, err.message);
            }

            sftpSessions.set(sessionId, { client: sshClient, sftp, host: normalizedHost, owner: req.auth.sub });

            success({ sessionId, message: '连接成功' });
        });
    });

    sshClient.on('error', (err) => {
        fail(500, err.message);
    });

    const config = {
        host: normalizedHost,
        port: normalizedPort,
        username: normalizedUsername,
        readyTimeout: 30000,
        hostHash: 'sha256',
        hostVerifier: createHostVerifier(normalizedHost, normalizedPort)
    };

    applyCredentialsToSshConfig(config, credentials);

    sshClient.connect(config);
});

app.post('/api/sftp/disconnect/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const { session, error } = getSftpSessionForRequest(sessionId, req.auth);

    if (error) {
        return res.status(error.status).json({ error: error.message });
    }

    session.client.end();
    sftpSessions.delete(sessionId);

    const sessionDir = path.join(UPLOAD_DIR, sessionId);
    if (fs.existsSync(sessionDir)) {
        fs.rmSync(sessionDir, { recursive: true, force: true });
    }

    res.json({ message: '断开成功' });
});

app.get('/api/sftp/home/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const { session, error } = getSftpSessionForRequest(sessionId, req.auth);
    if (error) {
        return res.status(error.status).json({ error: error.message });
    }

    session.sftp.realpath('.', (err, absPath) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ path: absPath });
    });
});

app.get('/api/sftp/list/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const { path: dirPath = '/' } = req.query;
    const { session, error } = getSftpSessionForRequest(sessionId, req.auth);
    if (error) {
        return res.status(error.status).json({ error: error.message });
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
    const { session, error } = getSftpSessionForRequest(sessionId, req.auth);
    if (error) {
        return res.status(error.status).json({ error: error.message });
    }

    session.sftp.mkdir(dirPath, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: '目录创建成功' });
    });
});

app.delete('/api/sftp/delete/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const { path: targetPath, type } = req.query;
    const { session, error } = getSftpSessionForRequest(sessionId, req.auth);
    if (error) {
        return res.status(error.status).json({ error: error.message });
    }

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
    const { session, error } = getSftpSessionForRequest(sessionId, req.auth);
    if (error) {
        return res.status(error.status).json({ error: error.message });
    }
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
    const { session, error } = getSftpSessionForRequest(sessionId, req.auth);
    if (error) {
        return res.status(error.status).json({ error: error.message });
    }

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
    const { session, error } = getSftpSessionForRequest(sessionId, req.auth);
    if (error) {
        return res.status(error.status).json({ error: error.message });
    }
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
vncProxy.init(server, '/vnc', { verifyToken, validateTargetHost });

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
app.get('/api/localshell/status', requireAdmin, (req, res) => {
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
        const auth = authenticateUpgrade(request);
        if (!auth) {
            return rejectUpgrade(socket, 401, 'Unauthorized');
        }
        request.auth = auth;
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    } else if (pathname === '/localshell' && localShell.isAvailable()) {
        const auth = authenticateUpgrade(request);
        if (!auth) {
            return rejectUpgrade(socket, 401, 'Unauthorized');
        }
        if (auth.role !== 'admin') {
            return rejectUpgrade(socket, 403, 'Forbidden');
        }
        request.auth = auth;
        localShell.handleUpgrade(request, socket, head);
    }
    // /vnc 由 vncProxy 自己处理
});

// ============================================
// 启动服务器
// ============================================
async function bootstrap() {
    getAuthSecret();
    getSshPasswordKey();
    await UserManager.ensureDefaults();
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
}

bootstrap().catch((err) => {
    console.error('启动失败:', err.message);
    process.exit(1);
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
