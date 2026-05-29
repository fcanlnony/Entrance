const assert = require('assert/strict');
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const AdmZip = require('adm-zip');

const repoRoot = path.resolve(__dirname, '..');
const authSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const sshPasswordKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function getFreePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const address = server.address();
            server.close(() => resolve(address.port));
        });
    });
}

function request(port, method, pathname, options = {}) {
    const body = options.body || null;
    const headers = { ...(options.headers || {}) };
    if (body && !headers['Content-Length']) {
        headers['Content-Length'] = body.length;
    }

    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: '127.0.0.1',
            port,
            method,
            path: pathname,
            headers
        }, (res) => {
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => {
                const text = Buffer.concat(chunks).toString('utf8');
                resolve({ status: res.statusCode, headers: res.headers, text });
            });
        });
        req.once('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

function jsonRequest(port, method, pathname, data, token = '') {
    const body = data === undefined ? null : Buffer.from(JSON.stringify(data));
    const headers = {};
    if (body) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    return request(port, method, pathname, { body, headers }).then(res => ({
        ...res,
        json: res.text ? JSON.parse(res.text) : null
    }));
}

async function waitForServer(port, child) {
    const startedAt = Date.now();
    while (Date.now() - startedAt < 15000) {
        if (child.exitCode !== null) {
            throw new Error(`server exited before becoming ready with code ${child.exitCode}`);
        }
        try {
            const res = await request(port, 'GET', '/api/app-info');
            if (res.status === 200) return;
        } catch {
            // Server is still starting.
        }
        await new Promise(resolve => setTimeout(resolve, 250));
    }
    throw new Error('server did not become ready in time');
}

function createHelloPluginZip(tempDir) {
    const pluginDir = path.join(repoRoot, 'api', 'hello-plugins');
    const zipPath = path.join(tempDir, 'hello-plugins.zip');
    const zip = new AdmZip();
    zip.addLocalFolder(pluginDir, 'hello-plugins');
    zip.writeZip(zipPath);
    return zipPath;
}

async function installPlugin(port, token, zipPath) {
    const boundary = `----EntrancePluginTest${crypto.randomBytes(8).toString('hex')}`;
    const file = fs.readFileSync(zipPath);
    const head = Buffer.from([
        `--${boundary}`,
        'Content-Disposition: form-data; name="plugin"; filename="hello-plugins.zip"',
        'Content-Type: application/zip',
        '',
        ''
    ].join('\r\n'));
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Buffer.concat([head, file, tail]);
    const res = await request(port, 'POST', '/api/plugins/install', {
        body,
        headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': `multipart/form-data; boundary=${boundary}`
        }
    });
    return { ...res, json: JSON.parse(res.text) };
}

function startServer(port, dataDir) {
    const child = childProcess.spawn(process.execPath, ['server.js'], {
        cwd: repoRoot,
        env: {
            ...process.env,
            AUTH_SECRET: authSecret,
            SSH_PASSWORD_KEY: sshPasswordKey,
            ENTRANCE_DATA_DIR: dataDir,
            ENTRANCE_HOST: '127.0.0.1',
            PORT: String(port)
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let output = '';
    child.stdout.on('data', chunk => {
        output += chunk.toString();
    });
    child.stderr.on('data', chunk => {
        output += chunk.toString();
    });
    child.getOutput = () => output.trim();
    return child;
}

async function stopServer(child) {
    if (!child || child.exitCode !== null) return;
    child.kill('SIGTERM');
    await new Promise(resolve => {
        const timer = setTimeout(() => {
            if (child.exitCode === null) child.kill('SIGKILL');
            resolve();
        }, 3000);
        child.once('exit', () => {
            clearTimeout(timer);
            resolve();
        });
    });
}

async function main() {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'entrance-plugin-test-'));
    const dataDir = path.join(tempDir, 'data');
    fs.mkdirSync(dataDir, { recursive: true });
    const port = await getFreePort();
    const child = startServer(port, dataDir);

    try {
        await waitForServer(port, child);

        const login = await jsonRequest(port, 'POST', '/api/auth/login', {
            username: 'admin',
            password: 'admin'
        });
        assert.equal(login.status, 200, login.text);
        assert.equal(login.json.success, true);
        assert.ok(login.json.token);
        const token = login.json.token;

        const zipPath = createHelloPluginZip(tempDir);
        const install = await installPlugin(port, token, zipPath);
        assert.equal(install.status, 200, install.text);
        assert.equal(install.json.success, true);
        assert.equal(install.json.plugin.id, 'hello-plugins');

        const list = await jsonRequest(port, 'GET', '/api/plugins', undefined, token);
        assert.equal(list.status, 200, list.text);
        assert.ok(list.json.plugins.some(plugin => plugin.id === 'hello-plugins'));

        const page = await request(port, 'GET', `/api/plugins/hello-plugins/page?token=${encodeURIComponent(token)}`);
        assert.equal(page.status, 200, page.text);
        assert.match(page.text, /hello plugins/);
        assert.match(page.text, /EntrancePlugin/);

        const asset = await request(port, 'GET', `/api/plugins/hello-plugins/assets/index.js?token=${encodeURIComponent(token)}`);
        assert.equal(asset.status, 200, asset.text);
        assert.match(asset.text, /hello plugins/);

        const remove = await jsonRequest(port, 'DELETE', '/api/plugins/hello-plugins', undefined, token);
        assert.equal(remove.status, 200, remove.text);
        assert.equal(remove.json.success, true);
        assert.ok(!remove.json.plugins.some(plugin => plugin.id === 'hello-plugins'));

        console.log('Plugin install/navigation smoke test passed.');
    } catch (err) {
        const serverOutput = child.getOutput();
        if (serverOutput) {
            console.error(serverOutput);
        }
        throw err;
    } finally {
        await stopServer(child);
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
}

main().catch(err => {
    console.error(err);
    process.exitCode = 1;
});
