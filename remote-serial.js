const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const { SerialPort } = require('serialport');

const SERIAL_PATH_PATTERN = process.platform === 'win32'
    ? /^COM\d+$/i
    : /^\/dev\/(?:tty(?:ACM|USB|AMA|S|THS|XRUSB)\d+|serial\/by-(?:id|path)\/[^/]+)$/;

const DEFAULT_BAUD_RATE = 115200;
const MAX_WRITE_BYTES = 1024 * 1024;

const wss = new WebSocket.Server({
    noServer: true,
    perMessageDeflate: false
});

function safeSend(ws, payload) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
        ws.send(JSON.stringify(payload));
    } catch (err) {
        console.error('[Serial] 发送 WebSocket 消息失败:', err.message);
    }
}

function normalizeSerialPath(value) {
    const raw = String(value || '').trim();
    if (!raw) {
        throw new Error('串口设备路径不能为空');
    }

    const normalized = process.platform === 'win32' ? raw.toUpperCase() : path.posix.normalize(raw);
    if (!SERIAL_PATH_PATTERN.test(normalized)) {
        throw new Error('串口设备路径不在允许范围内');
    }

    return normalized;
}

function normalizePortOptions(input = {}) {
    const baudRate = parseInt(input.baudRate || DEFAULT_BAUD_RATE, 10);
    const dataBits = parseInt(input.dataBits || 8, 10);
    const stopBits = parseInt(input.stopBits || 1, 10);
    const parity = String(input.parity || 'none').trim().toLowerCase();
    const flowControl = String(input.flowControl || 'none').trim().toLowerCase();

    if (!Number.isFinite(baudRate) || baudRate < 1 || baudRate > 4000000) {
        throw new Error('无效的波特率');
    }
    if (![5, 6, 7, 8].includes(dataBits)) {
        throw new Error('无效的数据位');
    }
    if (![1, 1.5, 2].includes(stopBits)) {
        throw new Error('无效的停止位');
    }
    if (!['none', 'even', 'odd', 'mark', 'space'].includes(parity)) {
        throw new Error('无效的校验位');
    }
    if (!['none', 'hardware'].includes(flowControl)) {
        throw new Error('无效的流控制');
    }

    return {
        baudRate,
        dataBits,
        stopBits,
        parity,
        rtscts: flowControl === 'hardware',
        autoOpen: false
    };
}

function normalizeListedPort(port = {}) {
    return {
        path: port.path || '',
        manufacturer: port.manufacturer || '',
        serialNumber: port.serialNumber || '',
        pnpId: port.pnpId || '',
        locationId: port.locationId || '',
        vendorId: port.vendorId || '',
        productId: port.productId || ''
    };
}

async function listPorts() {
    const ports = await SerialPort.list();
    return ports
        .map(normalizeListedPort)
        .filter((port) => {
            try {
                normalizeSerialPath(port.path);
                return true;
            } catch {
                return false;
            }
        })
        .sort((left, right) => left.path.localeCompare(right.path));
}

function buildWriteBuffer(data = {}) {
    const encoding = String(data.encoding || 'utf8').trim().toLowerCase();
    let buffer = null;

    if (encoding === 'base64') {
        buffer = Buffer.from(String(data.data || ''), 'base64');
    } else if (encoding === 'hex') {
        const rawHex = String(data.data || '').replace(/\s+/g, '');
        if (!/^(?:[0-9a-fA-F]{2})*$/.test(rawHex)) {
            throw new Error('HEX 数据格式无效');
        }
        buffer = Buffer.from(rawHex, 'hex');
    } else {
        buffer = Buffer.from(String(data.data || ''), 'utf8');
    }

    if (buffer.length > MAX_WRITE_BYTES) {
        throw new Error('单次写入数据过大');
    }
    return buffer;
}

function handleConnection(ws, req) {
    console.log(`[Serial] 新连接来自: ${req.socket.remoteAddress}`);

    let serialPort = null;
    let connectedPath = '';

    const closePort = () => {
        if (!serialPort) return;
        const port = serialPort;
        serialPort = null;
        connectedPath = '';

        if (port.isOpen) {
            port.close((err) => {
                if (err) {
                    console.error('[Serial] 关闭串口失败:', err.message);
                }
            });
        }
    };

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message.toString());

            switch (data.type) {
                case 'connect': {
                    closePort();

                    const portPath = normalizeSerialPath(data.path);
                    const options = normalizePortOptions(data);

                    if (process.platform !== 'win32' && !fs.existsSync(portPath)) {
                        throw new Error(`串口设备不存在: ${portPath}`);
                    }

                    serialPort = new SerialPort({
                        path: portPath,
                        ...options
                    });
                    connectedPath = portPath;

                    serialPort.on('data', (chunk) => {
                        safeSend(ws, {
                            type: 'data',
                            encoding: 'base64',
                            data: Buffer.from(chunk).toString('base64')
                        });
                    });

                    serialPort.on('error', (err) => {
                        safeSend(ws, { type: 'error', message: err.message });
                    });

                    serialPort.on('close', () => {
                        safeSend(ws, { type: 'disconnected' });
                    });

                    serialPort.open((err) => {
                        if (err) {
                            safeSend(ws, { type: 'error', message: err.message });
                            closePort();
                            return;
                        }
                        safeSend(ws, {
                            type: 'connected',
                            path: connectedPath,
                            baudRate: options.baudRate
                        });
                    });
                    break;
                }

                case 'data': {
                    if (!serialPort || !serialPort.isOpen) {
                        throw new Error('串口尚未连接');
                    }
                    const buffer = buildWriteBuffer(data);
                    serialPort.write(buffer, (err) => {
                        if (err) {
                            safeSend(ws, { type: 'error', message: err.message });
                        }
                    });
                    break;
                }

                case 'disconnect':
                    closePort();
                    safeSend(ws, { type: 'disconnected' });
                    break;
            }
        } catch (err) {
            safeSend(ws, { type: 'error', message: err.message });
        }
    });

    ws.on('close', () => {
        closePort();
    });
}

wss.on('connection', handleConnection);

function handleUpgrade(request, socket, head) {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
}

function closeAll() {
    for (const client of wss.clients) {
        try {
            client.close();
        } catch {}
    }
}

module.exports = {
    listPorts,
    handleUpgrade,
    closeAll
};
