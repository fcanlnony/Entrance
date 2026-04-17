const WebSocket = require('ws');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const TOOL_DEFS = {
    openocd: {
        label: 'OpenOCD',
        commandName: 'openocd',
        manualNamePattern: /(^|[-_.])openocd(\.exe)?$/i,
        notes: [
            'OpenOCD 会优先匹配 interface/<adapter>.cfg；若不存在，则按 adapter driver 自动反查接口配置。',
            '若板卡需要自定义接口文件或脚本目录，可在附加参数中补充。'
        ]
    },
    pyocd: {
        label: 'pyOCD',
        commandName: 'pyocd',
        manualNamePattern: /(^|[-_.])pyocd(\.exe)?$/i,
        notes: [
            'pyOCD 会优先列出当前已连接的 probe；未检测到时可手动填写 UID。',
            '写后校验沿用 pyOCD 内置烧录策略。'
        ]
    },
    'probe-rs': {
        label: 'probe-rs',
        commandName: 'probe-rs',
        manualNamePattern: /(^|[-_.])(probe-rs|probe-rs-cli)(\.exe)?$/i,
        notes: [
            'probe-rs 的实时调试使用 GDB server 模式，请用支持 GDB Remote 的调试器连接。',
            '若本机 CLI 版本参数存在差异，可在附加参数中补充。'
        ]
    }
};

const TOOL_NAMES = Object.keys(TOOL_DEFS);
const GDB_EXECUTABLE_CANDIDATES = [
    'arm-none-eabi-gdb',
    'gdb-multiarch',
    'gdb'
];
const GDB_MANUAL_NAME_PATTERN = /(^|[-_.])(arm-none-eabi-gdb|gdb-multiarch|gdb)(\.exe)?$/i;
const MAX_TEXT_LENGTH = 2048;
const MAX_PATH_LENGTH = 4096;
const PROCESS_KILL_TIMEOUT_MS = 1500;
const ASKPASS_DIR = path.join(os.tmpdir(), 'entrance-tools-askpass');
const DEFAULT_OPENOCD_SCRIPT_DIRS = process.platform === 'win32'
    ? []
    : [
        '/usr/share/openocd/scripts',
        '/usr/local/share/openocd/scripts',
        '/opt/homebrew/share/openocd/scripts',
        '/opt/local/share/openocd/scripts'
    ];
const OPENOCD_INSTALL_RELATIVE_SCRIPT_DIRS = [
    ['..', 'share', 'openocd', 'scripts'],
    ['..', '..', 'share', 'openocd', 'scripts'],
    ['..', 'scripts'],
    ['..', '..', 'scripts'],
    ['scripts']
];
const PROBE_RS_TEMPLATE_PROGRAMMERS = [
    { value: 'VID:PID', label: '模板: VID:PID' },
    { value: 'VID:PID:Serial', label: '模板: VID:PID:Serial' }
];
const OPENOCD_TARGET_ALIASES = {
    'target/xtensa-core-esp32.cfg': 'target/esp32.cfg',
    'target/xtensa-core-esp32s2.cfg': 'target/esp32s2.cfg',
    'target/xtensa-core-esp32s3.cfg': 'target/esp32s3.cfg'
};
const OPENOCD_ESP_USB_BRIDGE_CHIP_IDS = {
    'target/esp32.cfg': 1,
    'target/esp32s2.cfg': 2,
    'target/esp32s3.cfg': 9
};

let flashDebugWss = null;
let flashDebugPath = '/flashdebug';
const activeSessions = new Map();
const askpassHelperCache = new Map();
const targetCatalogCache = new Map();

function normalizeToolName(tool) {
    const normalized = String(tool || '').trim().toLowerCase();
    if (!TOOL_DEFS[normalized]) {
        throw new Error('不支持的工具类型');
    }
    return normalized;
}

function normalizeString(value, fieldName, maxLength = MAX_TEXT_LENGTH, options = {}) {
    if (value === undefined || value === null) {
        return '';
    }
    if (typeof value !== 'string') {
        throw new Error(`${fieldName}格式无效`);
    }
    const normalized = options.trim === false ? value : value.trim();
    if (normalized.length > maxLength) {
        throw new Error(`${fieldName}长度超过限制`);
    }
    return normalized;
}

function normalizeRequiredString(value, fieldName, maxLength = MAX_TEXT_LENGTH) {
    const normalized = normalizeString(value, fieldName, maxLength);
    if (!normalized) {
        throw new Error(`${fieldName}不能为空`);
    }
    return normalized;
}

function normalizeOptionalInteger(value, fieldName, options = {}) {
    if (value === undefined || value === null || value === '') {
        return options.fallback ?? null;
    }
    const parsed = parseInt(value, 10);
    if (!Number.isFinite(parsed)) {
        throw new Error(`${fieldName}必须是整数`);
    }
    const min = options.min ?? 0;
    const max = options.max ?? Number.MAX_SAFE_INTEGER;
    if (parsed < min || parsed > max) {
        throw new Error(`${fieldName}范围无效`);
    }
    return parsed;
}

function normalizeBoolean(value, fallback = false) {
    if (value === undefined || value === null || value === '') {
        return fallback;
    }
    if (typeof value === 'boolean') {
        return value;
    }
    if (typeof value === 'number') {
        return value !== 0;
    }
    const lowered = String(value).trim().toLowerCase();
    return lowered === 'true' || lowered === '1' || lowered === 'yes' || lowered === 'on';
}

function getPathCandidates(commandName) {
    const base = [commandName];
    if (process.platform === 'win32' && path.extname(commandName).toLowerCase() !== '.exe') {
        base.push(`${commandName}.exe`);
    }
    return base;
}

function resolveExecutableFromPath(commandName) {
    const pathEnv = String(process.env.PATH || '');
    const dirs = pathEnv.split(path.delimiter).filter(Boolean);
    const candidates = getPathCandidates(commandName);

    for (const dir of dirs) {
        for (const candidateName of candidates) {
            const candidate = path.join(dir.trim(), candidateName);
            if (!candidate) continue;
            try {
                fs.accessSync(candidate, fs.constants.X_OK);
                return fs.realpathSync(candidate);
            } catch {}
        }
    }

    return '';
}

function resolveExecutableFromCandidates(candidates = []) {
    for (const candidate of candidates) {
        const resolved = resolveExecutableFromPath(candidate);
        if (resolved) {
            return resolved;
        }
    }
    return '';
}

function validateManualExecutablePath(tool, executablePath) {
    const normalizedPath = normalizeRequiredString(executablePath, '工具路径', MAX_PATH_LENGTH);
    const resolvedPath = path.resolve(normalizedPath);

    let stats = null;
    try {
        stats = fs.statSync(resolvedPath);
    } catch {
        throw new Error('手动路径不存在');
    }

    if (!stats.isFile()) {
        throw new Error('手动路径不是可执行文件');
    }

    try {
        fs.accessSync(resolvedPath, fs.constants.X_OK);
    } catch {
        throw new Error('手动路径不可执行');
    }

    const basename = path.basename(resolvedPath);
    if (!TOOL_DEFS[tool].manualNamePattern.test(basename)) {
        throw new Error('手动路径与所选工具不匹配');
    }

    try {
        return fs.realpathSync(resolvedPath);
    } catch {
        return resolvedPath;
    }
}

function inspectExecutable(tool, manualPath = '') {
    const manual = normalizeString(manualPath, '工具路径', MAX_PATH_LENGTH);
    if (manual) {
        try {
            const executablePath = validateManualExecutablePath(tool, manual);
            return {
                executablePath,
                foundInPath: false,
                manualPathRequired: false,
                manualPathProvided: true,
                error: ''
            };
        } catch (err) {
            return {
                executablePath: '',
                foundInPath: false,
                manualPathRequired: true,
                manualPathProvided: true,
                error: err.message
            };
        }
    }

    const executablePath = resolveExecutableFromPath(TOOL_DEFS[tool].commandName);
    return {
        executablePath,
        foundInPath: Boolean(executablePath),
        manualPathRequired: !executablePath,
        manualPathProvided: false,
        error: ''
    };
}

function resolveExecutableOrThrow(tool, manualPath = '') {
    const inspected = inspectExecutable(tool, manualPath);
    if (inspected.executablePath) {
        return inspected.executablePath;
    }
    if (inspected.error) {
        throw new Error(inspected.error);
    }
    throw new Error(`${TOOL_DEFS[tool].label} 不在 PATH 中，请填写手动路径`);
}

function validateGdbExecutablePath(executablePath) {
    const normalizedPath = normalizeRequiredString(executablePath, 'GDB 路径', MAX_PATH_LENGTH);
    const resolvedPath = path.resolve(normalizedPath);

    let stats = null;
    try {
        stats = fs.statSync(resolvedPath);
    } catch {
        throw new Error('GDB 手动路径不存在');
    }

    if (!stats.isFile()) {
        throw new Error('GDB 手动路径不是可执行文件');
    }

    try {
        fs.accessSync(resolvedPath, fs.constants.X_OK);
    } catch {
        throw new Error('GDB 手动路径不可执行');
    }

    const basename = path.basename(resolvedPath);
    if (!GDB_MANUAL_NAME_PATTERN.test(basename)) {
        throw new Error('GDB 手动路径与 gdb / arm-none-eabi-gdb / gdb-multiarch 不匹配');
    }

    try {
        return fs.realpathSync(resolvedPath);
    } catch {
        return resolvedPath;
    }
}

function inspectGdbExecutable(manualPath = '') {
    const manual = normalizeString(manualPath, 'GDB 路径', MAX_PATH_LENGTH);
    if (manual) {
        try {
            const executablePath = validateGdbExecutablePath(manual);
            return {
                executablePath,
                foundInPath: false,
                manualPathProvided: true,
                manualPathRequired: false,
                error: ''
            };
        } catch (err) {
            return {
                executablePath: '',
                foundInPath: false,
                manualPathProvided: true,
                manualPathRequired: true,
                error: err.message
            };
        }
    }

    const executablePath = resolveExecutableFromCandidates(GDB_EXECUTABLE_CANDIDATES);
    return {
        executablePath,
        foundInPath: Boolean(executablePath),
        manualPathProvided: false,
        manualPathRequired: !executablePath,
        error: ''
    };
}

function resolveGdbExecutableOrThrow(manualPath = '') {
    const inspected = inspectGdbExecutable(manualPath);
    if (inspected.executablePath) {
        return inspected.executablePath;
    }
    if (inspected.error) {
        throw new Error(inspected.error);
    }
    throw new Error('未找到可用的 GDB，请安装 gdb / arm-none-eabi-gdb / gdb-multiarch，或填写手动路径');
}

function ensureDirectory(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
}

function buildAskpassHelperScript(strategy) {
    const title = 'Entrance Tools';
    const message = 'Entrance Tools 需要管理员/root 权限以执行烧录或调试命令。请输入当前用户密码。';

    if (strategy.type === 'zenity') {
        return [
            '#!/bin/sh',
            `exec ${escapeShellArg(strategy.command)} --password --title ${escapeShellArg(title)} --text ${escapeShellArg(message)}`
        ].join('\n') + '\n';
    }

    if (strategy.type === 'kdialog') {
        return [
            '#!/bin/sh',
            `exec ${escapeShellArg(strategy.command)} --title ${escapeShellArg(title)} --password ${escapeShellArg(message)}`
        ].join('\n') + '\n';
    }

    return [
        '#!/bin/sh',
        `exec ${escapeShellArg(strategy.command)} <<'APPLESCRIPT'`,
        'display dialog "Entrance Tools 需要管理员/root 权限以执行烧录或调试命令。请输入当前用户密码。" with title "Entrance Tools" default answer "" with hidden answer buttons {"取消", "确定"} default button "确定" cancel button "取消"',
        'text returned of result',
        'APPLESCRIPT'
    ].join('\n') + '\n';
}

function ensureAskpassHelper(strategy) {
    const cacheKey = `${strategy.type}:${strategy.command}`;
    const cachedPath = askpassHelperCache.get(cacheKey);
    if (cachedPath && fs.existsSync(cachedPath)) {
        return cachedPath;
    }

    ensureDirectory(ASKPASS_DIR);
    const helperPath = path.join(ASKPASS_DIR, `askpass-${strategy.type}.sh`);
    fs.writeFileSync(helperPath, buildAskpassHelperScript(strategy), { mode: 0o700 });
    fs.chmodSync(helperPath, 0o700);
    askpassHelperCache.set(cacheKey, helperPath);
    return helperPath;
}

function getUnixAskpassStrategy() {
    if (process.platform === 'darwin') {
        const command = resolveExecutableFromPath('osascript');
        return command ? { type: 'osascript', command } : null;
    }

    const zenity = resolveExecutableFromPath('zenity');
    if (zenity) {
        return { type: 'zenity', command: zenity };
    }

    const kdialog = resolveExecutableFromPath('kdialog');
    if (kdialog) {
        return { type: 'kdialog', command: kdialog };
    }

    return null;
}

function getElevationInfo() {
    if (typeof process.getuid === 'function' && process.getuid() === 0) {
        return {
            available: true,
            alreadyElevated: true,
            method: 'already-elevated',
            label: 'already-elevated',
            note: '当前 Entrance 进程已经具备 root 权限，烧录/调试命令会直接以 root 身份执行。'
        };
    }

    if (process.platform === 'linux') {
        const pkexec = resolveExecutableFromPath('pkexec');
        if (pkexec) {
            return {
                available: true,
                alreadyElevated: false,
                method: 'pkexec',
                label: 'pkexec',
                command: pkexec,
                note: '启用后将通过 pkexec / Polkit 请求 root 权限。'
            };
        }

        const sudo = resolveExecutableFromPath('sudo');
        const askpass = sudo ? getUnixAskpassStrategy() : null;
        if (sudo && askpass) {
            return {
                available: true,
                alreadyElevated: false,
                method: 'sudo-askpass',
                label: 'sudo',
                command: sudo,
                askpass,
                note: `启用后将通过 sudo + ${askpass.type} 图形密码对话框请求 root 权限。`
            };
        }

        return {
            available: false,
            alreadyElevated: false,
            method: 'unsupported',
            label: '',
            reason: '当前 Linux 主机未检测到可用的提权方式。请安装 pkexec，或安装 zenity/kdialog 以配合 sudo 图形密码对话框。',
            note: '当前 Linux 主机未检测到可用的提权方式。请安装 pkexec，或安装 zenity/kdialog 以配合 sudo 图形密码对话框。'
        };
    }

    if (process.platform === 'darwin') {
        const sudo = resolveExecutableFromPath('sudo');
        const askpass = getUnixAskpassStrategy();
        if (sudo && askpass) {
            return {
                available: true,
                alreadyElevated: false,
                method: 'sudo-askpass',
                label: 'sudo',
                command: sudo,
                askpass,
                note: '启用后将通过 sudo + macOS 系统密码对话框请求管理员权限。'
            };
        }

        return {
            available: false,
            alreadyElevated: false,
            method: 'unsupported',
            label: '',
            reason: '当前 macOS 主机缺少 sudo 或 osascript，无法弹出管理员权限请求。',
            note: '当前 macOS 主机缺少 sudo 或 osascript，无法弹出管理员权限请求。'
        };
    }

    if (process.platform === 'win32') {
        const gsudo = resolveExecutableFromPath('gsudo');
        if (gsudo) {
            return {
                available: true,
                alreadyElevated: false,
                method: 'gsudo',
                label: 'gsudo',
                command: gsudo,
                note: '启用后将通过 gsudo / UAC 请求管理员权限。'
            };
        }

        const sudo = resolveExecutableFromPath('sudo');
        if (sudo) {
            return {
                available: true,
                alreadyElevated: false,
                method: 'windows-sudo',
                label: 'sudo',
                command: sudo,
                note: '启用后将通过 Windows sudo / UAC 请求管理员权限。'
            };
        }

        return {
            available: false,
            alreadyElevated: false,
            method: 'unsupported',
            label: '',
            reason: '当前 Windows 主机未检测到 gsudo 或 sudo，无法请求管理员权限。',
            note: '当前 Windows 主机未检测到 gsudo 或 sudo，无法请求管理员权限。'
        };
    }

    return {
        available: false,
        alreadyElevated: false,
        method: 'unsupported',
        label: '',
        reason: '当前平台暂不支持管理员/root 提权。',
        note: '当前平台暂不支持管理员/root 提权。'
    };
}

function getPublicElevationInfo() {
    const info = getElevationInfo();
    return {
        available: info.available,
        alreadyElevated: info.alreadyElevated,
        method: info.method,
        label: info.label,
        note: info.note || info.reason || ''
    };
}

function applyElevationToPlan(plan) {
    const info = getElevationInfo();
    if (info.alreadyElevated) {
        return {
            ...plan,
            notes: [
                ...plan.notes,
                '当前 Entrance 进程已经具备管理员/root 权限，已直接执行命令。'
            ],
            elevation: {
                requested: true,
                method: info.method,
                interactiveWindow: false
            }
        };
    }

    if (!info.available) {
        throw new Error(info.reason || '当前平台无法请求管理员/root 权限');
    }

    if (info.method === 'pkexec') {
        return {
            ...plan,
            executablePath: info.command,
            args: [plan.executablePath, ...plan.args],
            preview: buildCommandPreview(info.command, [plan.executablePath, ...plan.args]),
            notes: [
                ...plan.notes,
                '已启用 root 提权，请在系统认证对话框中确认。'
            ],
            elevation: {
                requested: true,
                method: info.method,
                interactiveWindow: false
            }
        };
    }

    if (info.method === 'sudo-askpass') {
        const helperPath = ensureAskpassHelper(info.askpass);
        return {
            ...plan,
            executablePath: info.command,
            args: ['-A', plan.executablePath, ...plan.args],
            env: Object.assign({}, plan.env || process.env, {
                SUDO_ASKPASS: helperPath
            }),
            preview: buildCommandPreview(info.command, ['-A', plan.executablePath, ...plan.args]),
            notes: [
                ...plan.notes,
                info.note || '已启用 sudo 管理员/root 权限请求。'
            ],
            elevation: {
                requested: true,
                method: info.method,
                interactiveWindow: false
            }
        };
    }

    return {
        ...plan,
        executablePath: info.command,
        args: [plan.executablePath, ...plan.args],
        preview: buildCommandPreview(info.command, [plan.executablePath, ...plan.args]),
        notes: [
            ...plan.notes,
            info.note || '已启用管理员权限请求，请在系统对话框中确认。',
            info.method === 'windows-sudo'
                ? '若系统 sudo 配置为新窗口模式，实时日志展示可能受限；如需更好的集成效果，建议优先安装 gsudo。'
                : ''
        ].filter(Boolean),
        elevation: {
            requested: true,
            method: info.method,
            interactiveWindow: true
        }
    };
}

function splitCliArgs(input, fieldName = '附加参数') {
    const source = normalizeString(input, fieldName, MAX_PATH_LENGTH, { trim: false });
    if (!source) return [];

    const result = [];
    let current = '';
    let quote = '';
    let escaping = false;

    for (const ch of source) {
        if (escaping) {
            current += ch;
            escaping = false;
            continue;
        }

        if (ch === '\\') {
            escaping = true;
            continue;
        }

        if (quote) {
            if (ch === quote) {
                quote = '';
            } else {
                current += ch;
            }
            continue;
        }

        if (ch === '"' || ch === '\'') {
            quote = ch;
            continue;
        }

        if (/\s/.test(ch)) {
            if (current) {
                result.push(current);
                current = '';
            }
            continue;
        }

        current += ch;
    }

    if (escaping || quote) {
        throw new Error('附加参数格式无效，请检查引号或转义符');
    }

    if (current) {
        result.push(current);
    }
    return result;
}

function normalizeExtraArgPosition(value = '') {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized || normalized === 'end' || normalized === 'append') {
        return 'end';
    }
    if (
        normalized === 'before_init'
        || normalized === 'before-init'
        || normalized === 'pre_init'
        || normalized === 'pre-init'
    ) {
        return 'before_init';
    }
    if (normalized === 'before_tail' || normalized === 'before-reset' || normalized === 'before_reset') {
        return 'before_tail';
    }
    throw new Error('附加参数插入位置无效');
}

function collectExtraArgBuckets(options = {}) {
    const buckets = {
        before_init: [],
        before_tail: [],
        end: []
    };
    const entries = Array.isArray(options.extraArgEntries) ? options.extraArgEntries : [];

    if (entries.length > 0) {
        entries.forEach((entry, index) => {
            if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
                throw new Error('附加参数格式无效');
            }

            const source = normalizeString(entry.value, '附加参数', MAX_PATH_LENGTH, { trim: false });
            if (!source.trim()) {
                return;
            }

            const position = normalizeExtraArgPosition(entry.position);
            buckets[position].push(...splitCliArgs(source));
        });
        return buckets;
    }

    buckets.end.push(...splitCliArgs(options.extraArgs));
    return buckets;
}

function escapeShellArg(arg) {
    const value = String(arg ?? '');
    if (!value) return '\'\'';
    if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(value)) {
        return value;
    }
    return `'${value.replace(/'/g, `'\\''`)}'`;
}

function buildCommandPreview(command, args) {
    return [command, ...args].map(escapeShellArg).join(' ');
}

function normalizeSingleLineString(value, fieldName, maxLength = MAX_TEXT_LENGTH, options = {}) {
    const normalized = normalizeString(value, fieldName, maxLength, options);
    if (/[\r\n]/.test(normalized)) {
        throw new Error(`${fieldName}不能包含换行`);
    }
    return normalized;
}

function quoteGdbPath(value) {
    const normalized = normalizeRequiredString(value, '文件路径', MAX_PATH_LENGTH);
    return `"${normalized.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function normalizeGdbRegisterName(value) {
    const normalized = normalizeRequiredString(value, '寄存器名', 64);
    const registerName = normalized.startsWith('$') ? normalized : `$${normalized}`;
    if (!/^\$[A-Za-z0-9_]+$/.test(registerName)) {
        throw new Error('寄存器名格式无效');
    }
    return registerName;
}

function getCommandValues(values = {}) {
    if (!values || typeof values !== 'object') {
        return {};
    }
    return values;
}

function normalizeDisplayPath(value) {
    return String(value || '').replace(/\\/g, '/');
}

function wrapTclValue(value) {
    return '{' + String(value).replace(/}/g, '\\}') + '}';
}

function uniqueOptions(items) {
    const seen = new Set();
    const result = [];

    for (const item of items) {
        const value = normalizeString(item && item.value, '选项值', 512);
        const label = normalizeString(item && item.label, '选项标签', 512);
        if (!value || seen.has(value)) continue;
        seen.add(value);
        result.push({ value, label: label || value });
    }

    return result;
}

function uniqueTargetCatalogOptions(items) {
    const seen = new Set();
    const result = [];

    for (const item of items) {
        const value = normalizeString(item && item.value, '目标名称', 256);
        const label = normalizeString(item && item.label, '目标标签', 256);
        const meta = normalizeString(item && item.meta, '目标元信息', 512);
        const keywords = normalizeString(item && item.keywords, '目标关键字', 1024);
        if (!value || seen.has(value)) continue;
        seen.add(value);
        result.push({
            value,
            label: label || value,
            meta,
            keywords
        });
    }

    return result;
}

function runCommandCapture(command, args, options = {}) {
    return new Promise((resolve, reject) => {
        let stdout = '';
        let stderr = '';
        let settled = false;
        let timedOut = false;

        const child = spawn(command, args, {
            cwd: options.cwd || process.cwd(),
            env: options.env || process.env,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true
        });

        const timeoutMs = options.timeoutMs || 0;
        const timer = timeoutMs
            ? setTimeout(() => {
                timedOut = true;
                try { child.kill('SIGTERM'); } catch {}
            }, timeoutMs)
            : null;

        child.stdout.on('data', (chunk) => {
            stdout += chunk.toString('utf8');
        });

        child.stderr.on('data', (chunk) => {
            stderr += chunk.toString('utf8');
        });

        child.on('error', (err) => {
            if (timer) clearTimeout(timer);
            if (settled) return;
            settled = true;
            reject(err);
        });

        child.on('close', (code, signal) => {
            if (timer) clearTimeout(timer);
            if (settled) return;
            settled = true;
            resolve({
                stdout,
                stderr,
                code: code ?? 0,
                signal: signal || null,
                timedOut
            });
        });
    });
}

function parseOpenOcdAdapters(output) {
    const options = [];
    for (const line of output.split(/\r?\n/)) {
        const match = line.match(/^\s*\d+:\s+(.+?)\s*$/);
        if (!match) continue;
        const name = match[1].trim();
        if (!name) continue;
        options.push({ value: name, label: name });
    }
    return uniqueOptions(options);
}

function parseTableLikeLines(output) {
    const lines = output
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean)
        .filter(line => !/^no available debug probes/i.test(line))
        .filter(line => !/^no debug probes were found/i.test(line))
        .filter(line => !/^the following debug probes were found/i.test(line))
        .filter(line => !/^found \d+ debug probes?/i.test(line))
        .filter(line => !/^warn\b/i.test(line))
        .filter(line => !/^error\b/i.test(line));

    return uniqueOptions(lines.map((line) => {
        if (line.includes('|')) {
            const parts = line.split('|').map(part => part.trim()).filter(Boolean);
            return {
                value: parts[0] || line,
                label: parts.join(' | ') || line
            };
        }

        const stripped = line.replace(/^\s*\d+:\s*/, '').trim();
        return {
            value: stripped || line,
            label: stripped || line
        };
    }));
}

function parseWarningLines(output) {
    return output
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean)
        .filter(line => /^(warn|error)\b/i.test(line));
}

function parsePyOcdPluginOptions(output) {
    const options = [];
    for (const line of output.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || /^Type\s+/i.test(trimmed) || /^-+$/.test(trimmed)) {
            continue;
        }

        const match = trimmed.match(/^Debug Probe\s+(\S+)\s+\S+\s+(.+)$/);
        if (!match) continue;

        const pluginName = match[1].trim();
        const description = match[2].trim();
        if (!pluginName) continue;

        options.push({
            value: `${pluginName}:`,
            label: `${description} (${pluginName}:)`
        });
    }

    return uniqueOptions(options);
}

function parseProbeRsListOptions(output) {
    const options = [];
    for (const rawLine of output.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) continue;
        if (/^(warn|error)\b/i.test(line)) continue;
        if (/^no debug probes were found/i.test(line)) continue;

        const indexedMatch = line.match(/^\[(\d+)\]:\s*(.+?)\s+--\s+([^()\s]+)\s*(?:\(([^)]+)\))?\s*$/);
        if (indexedMatch) {
            const probeId = indexedMatch[3].trim();
            const display = line.replace(/^\[(\d+)\]:\s*/, '').trim();
            options.push({
                value: probeId,
                label: display
            });
            continue;
        }

        const inlineMatch = line.match(/\b([0-9a-fA-F]{4}:[0-9a-fA-F]{4}(?::[^()\s]+)?)\b/);
        if (inlineMatch) {
            options.push({
                value: inlineMatch[1],
                label: line
            });
        }
    }

    return uniqueOptions(options);
}

function parseProbeRsChipList(output) {
    const chips = [];
    let currentFamily = '';
    let inVariants = false;

    for (const rawLine of output.split(/\r?\n/)) {
        const line = String(rawLine || '');
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (/^(warn|error)\b/i.test(trimmed)) continue;
        if (/^available chips:?$/i.test(trimmed)) continue;

        const indent = line.match(/^\s*/)?.[0].length || 0;
        if (indent === 0) {
            currentFamily = trimmed;
            inVariants = false;
            continue;
        }

        if (/^variants:?$/i.test(trimmed)) {
            inVariants = true;
            continue;
        }

        if (!inVariants || indent <= 4) {
            continue;
        }

        chips.push({
            value: trimmed,
            label: trimmed,
            meta: currentFamily,
            keywords: currentFamily
        });
    }

    return uniqueTargetCatalogOptions(chips);
}

function parsePyOcdTargetList(output) {
    const targets = [];
    const knownSources = new Set(['builtin', 'pack', 'cbuild-run']);

    for (const rawLine of output.split(/\r?\n/)) {
        const trimmed = rawLine.trim();
        if (!trimmed) continue;
        if (/^(name|vendor|part number|families|source)\b/i.test(trimmed)) continue;
        if (/^-{3,}$/.test(trimmed)) continue;
        if (/^(warn|error)\b/i.test(trimmed)) continue;

        const parts = trimmed.split(/\s{2,}/).map((part) => part.trim()).filter(Boolean);
        if (!parts.length) continue;

        const value = parts[0];
        const vendor = parts[1] || '';
        const partNumber = parts[2] || '';
        let families = '';
        let source = '';

        if (parts.length >= 5) {
            families = parts[3] || '';
            source = parts[4] || '';
        } else if (parts.length === 4) {
            if (knownSources.has(parts[3])) {
                source = parts[3];
            } else {
                families = parts[3];
            }
        }

        const metaParts = [vendor, partNumber, families].filter(Boolean);
        const keywordParts = [value, vendor, partNumber, families, source].filter(Boolean);

        targets.push({
            value,
            label: value,
            meta: metaParts.join(' | ') || source,
            keywords: keywordParts.join(' ')
        });
    }

    return uniqueTargetCatalogOptions(targets);
}

function getExecutableCacheKey(executablePath = '') {
    if (!executablePath) {
        return '';
    }

    try {
        const stats = fs.statSync(executablePath);
        return `${executablePath}:${stats.size}:${stats.mtimeMs}`;
    } catch {
        return executablePath;
    }
}

function isExistingDirectory(dirPath) {
    try {
        return fs.statSync(dirPath).isDirectory();
    } catch {
        return false;
    }
}

function uniqueStrings(items) {
    return Array.from(new Set(items.filter(Boolean)));
}

function escapeRegExp(value) {
    return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function resolveOpenOcdScriptsDir(executablePath = '') {
    const candidates = [];

    if (process.platform !== 'win32') {
        candidates.push(...DEFAULT_OPENOCD_SCRIPT_DIRS.map((dir) => ({ dir, source: 'system-default' })));
    }

    if (executablePath) {
        const resolvedExecutable = path.resolve(executablePath);
        const binDir = path.dirname(resolvedExecutable);
        OPENOCD_INSTALL_RELATIVE_SCRIPT_DIRS.forEach((segments) => {
            candidates.push({
                dir: path.resolve(binDir, ...segments),
                source: 'install-dir'
            });
        });
    }

    for (const candidate of candidates) {
        if (isExistingDirectory(candidate.dir)) {
            return {
                scriptsDir: fs.realpathSync(candidate.dir),
                source: candidate.source,
                error: ''
            };
        }
    }

    return {
        scriptsDir: '',
        source: '',
        error: '未找到 OpenOCD 配置目录，请检查系统默认目录或 OpenOCD 安装目录'
    };
}

function collectCfgFiles(rootDir, category) {
    const categoryDir = path.join(rootDir, category);
    if (!isExistingDirectory(categoryDir)) {
        return [];
    }

    const results = [];
    const stack = [categoryDir];

    while (stack.length > 0) {
        const currentDir = stack.pop();
        let entries = [];
        try {
            entries = fs.readdirSync(currentDir, { withFileTypes: true });
        } catch {
            continue;
        }

        for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);
            if (entry.isDirectory()) {
                stack.push(fullPath);
                continue;
            }

            if (!entry.isFile() || path.extname(entry.name).toLowerCase() !== '.cfg') {
                continue;
            }

            const relativePath = path.relative(rootDir, fullPath);
            results.push(normalizeDisplayPath(relativePath));
        }
    }

    return uniqueStrings(results).sort((a, b) => a.localeCompare(b));
}

function getOpenOcdConfigOptions(executablePath = '') {
    const resolved = resolveOpenOcdScriptsDir(executablePath);
    if (!resolved.scriptsDir) {
        return {
            scriptsDir: '',
            source: '',
            targetConfigs: [],
            interfaceConfigs: [],
            error: resolved.error
        };
    }

    return {
        scriptsDir: normalizeDisplayPath(resolved.scriptsDir),
        source: resolved.source,
        targetConfigs: collectCfgFiles(resolved.scriptsDir, 'target'),
        interfaceConfigs: collectCfgFiles(resolved.scriptsDir, 'interface'),
        error: ''
    };
}

function resolveOpenOcdInterfaceConfig(executablePath = '', probeSelection = '', explicitInterfaceConfig = '') {
    const interfaceConfig = normalizeString(explicitInterfaceConfig, '接口配置', MAX_PATH_LENGTH);
    if (interfaceConfig) {
        return interfaceConfig;
    }

    const adapterName = normalizeString(probeSelection, '烧录器', 256);
    if (!adapterName) {
        return '';
    }

    const directConfig = `interface/${adapterName}.cfg`;
    const resolved = resolveOpenOcdScriptsDir(executablePath);
    if (!resolved.scriptsDir) {
        return directConfig;
    }

    const interfaceConfigs = collectCfgFiles(resolved.scriptsDir, 'interface');
    if (interfaceConfigs.includes(directConfig)) {
        return directConfig;
    }

    const driverPattern = new RegExp(`^\\s*adapter driver\\s+${escapeRegExp(adapterName)}\\s*$`, 'mi');
    for (const relativePath of interfaceConfigs) {
        const fullPath = path.join(resolved.scriptsDir, relativePath);
        try {
            const content = fs.readFileSync(fullPath, 'utf8');
            if (driverPattern.test(content)) {
                return normalizeDisplayPath(relativePath);
            }
        } catch {}
    }

    return directConfig;
}

function normalizeOpenOcdTargetConfig(targetConfig = '') {
    const normalized = normalizeDisplayPath(normalizeRequiredString(targetConfig, '目标配置', MAX_PATH_LENGTH));
    return {
        value: OPENOCD_TARGET_ALIASES[normalized] || normalized,
        rewritten: Boolean(OPENOCD_TARGET_ALIASES[normalized]),
        originalValue: normalized
    };
}

function getOpenOcdEspUsbBridgeChipId(interfaceConfig = '', targetConfig = '') {
    const normalizedInterface = normalizeDisplayPath(interfaceConfig);
    const normalizedTarget = normalizeDisplayPath(targetConfig);
    const isEspUsbBridge = normalizedInterface === 'interface/esp_usb_bridge.cfg'
        || normalizedInterface.endsWith('/interface/esp_usb_bridge.cfg');
    if (!isEspUsbBridge) {
        return null;
    }
    return OPENOCD_ESP_USB_BRIDGE_CHIP_IDS[normalizedTarget] || null;
}

function normalizeProbeRsProbeSelection(value = '') {
    const normalized = normalizeString(value, '烧录器', 256);
    if (!normalized) {
        return '';
    }

    const indexedMatch = normalized.match(/^\[(\d+)\]:\s*(.+?)\s+--\s+([^()\s]+)\s*(?:\(([^)]+)\))?\s*$/);
    if (indexedMatch) {
        return indexedMatch[3].trim();
    }

    const inlineMatch = normalized.match(/\b([0-9a-fA-F]{4}:[0-9a-fA-F]{4}(?::[^()\s]+)?)\b/);
    if (inlineMatch) {
        return inlineMatch[1];
    }

    return normalized;
}

function isEspOpenOcdTarget(targetConfig = '') {
    return /^target\/esp32(?:s2|s3)?\.cfg$/i.test(normalizeDisplayPath(targetConfig));
}

function buildOpenOcdEspFlashCommand(firmwarePath, verify, resetAfterFlash, notes) {
    const normalizedPath = path.resolve(firmwarePath);
    const filename = path.basename(normalizedPath).toLowerCase();
    const ext = path.extname(filename);

    if (filename === 'flasher_args.json') {
        notes.push('已切换到 ESP-IDF 多镜像烧录模式，将按 flasher_args.json 烧录 bootloader、partition table 和 app。');
        return `program_esp_bins ${wrapTclValue(path.dirname(normalizedPath))} ${wrapTclValue(path.basename(normalizedPath))}${verify ? ' verify' : ''}${resetAfterFlash ? ' reset' : ''} exit`;
    }

    if (ext === '.bin') {
        notes.push('已切换到 ESP32 app bin 烧录模式，默认按应用分区偏移 0x10000 写入。若使用自定义分区，请改用 flasher_args.json。');
        return `program_esp ${wrapTclValue(normalizedPath)} 0x10000${verify ? ' verify' : ''}${resetAfterFlash ? ' reset' : ''} exit`;
    }

    throw new Error('ESP32 使用 OpenOCD 烧录时，请选择 app.bin 或 flasher_args.json；不要直接选择 ELF');
}

async function listProgrammers(tool, executablePath) {
    if (!executablePath) {
        return { programmers: [], listError: '', programmerSource: 'none' };
    }

    try {
        if (tool === 'openocd') {
            const result = await runCommandCapture(executablePath, ['-c', 'adapter list'], { timeoutMs: 4000 });
            const combined = `${result.stdout}\n${result.stderr}`;
            return {
                programmers: parseOpenOcdAdapters(combined),
                listError: '',
                programmerSource: 'adapters'
            };
        }

        if (tool === 'pyocd') {
            const probeResult = await runCommandCapture(executablePath, ['list', '--probes', '--no-header'], { timeoutMs: 5000 });
            const probeOutput = `${probeResult.stdout}\n${probeResult.stderr}`;
            const detected = parseTableLikeLines(probeOutput);

            if (detected.length > 0) {
                return {
                    programmers: detected,
                    listError: '',
                    programmerSource: 'detected'
                };
            }

            const pluginResult = await runCommandCapture(executablePath, ['list', '--plugins'], { timeoutMs: 5000 });
            const pluginOutput = `${pluginResult.stdout}\n${pluginResult.stderr}`;
            return {
                programmers: parsePyOcdPluginOptions(pluginOutput),
                listError: '未检测到已连接 probe，已回退显示 pyOCD debug-probe 插件前缀。',
                programmerSource: 'plugins'
            };
        }

        const result = await runCommandCapture(executablePath, ['list'], { timeoutMs: 5000 });
        const combined = `${result.stdout}\n${result.stderr}`;
        const detected = parseProbeRsListOptions(combined);
        const warnings = parseWarningLines(combined);

        if (detected.length > 0) {
            return {
                programmers: detected,
                listError: warnings[0] || '',
                programmerSource: 'detected'
            };
        }

        return {
            programmers: PROBE_RS_TEMPLATE_PROGRAMMERS,
            listError: warnings[0]
                ? `未检测到已连接 probe。${warnings[0]}`
                : '未检测到已连接 probe，可按 VID:PID 或 VID:PID:Serial 手动输入。',
            programmerSource: 'template'
        };
    } catch (err) {
        return {
            programmers: [],
            listError: err.message,
            programmerSource: 'error'
        };
    }
}

async function listTargetCatalog(tool, executablePath) {
    if (!executablePath || (tool !== 'probe-rs' && tool !== 'pyocd')) {
        return {
            targetCatalog: [],
            targetCatalogCount: 0,
            targetCatalogError: '',
            targetCatalogSource: 'none'
        };
    }

    const cacheKey = `${tool}:${getExecutableCacheKey(executablePath)}`;
    if (cacheKey && targetCatalogCache.has(cacheKey)) {
        const cached = targetCatalogCache.get(cacheKey);
        return {
            targetCatalog: cached.targetCatalog.map((item) => ({ ...item })),
            targetCatalogCount: cached.targetCatalogCount,
            targetCatalogError: '',
            targetCatalogSource: 'cache'
        };
    }

    try {
        const commandArgs = tool === 'probe-rs'
            ? ['chip', 'list']
            : ['list', '--targets', '--no-header'];
        const result = await runCommandCapture(executablePath, commandArgs, { timeoutMs: 5000 });
        if (result.timedOut) {
            return {
                targetCatalog: [],
                targetCatalogCount: 0,
                targetCatalogError: tool === 'probe-rs'
                    ? '读取 probe-rs 芯片目录超时'
                    : '读取 pyOCD 目标目录超时',
                targetCatalogSource: 'error'
            };
        }

        const combined = `${result.stdout}\n${result.stderr}`;
        const targetCatalog = tool === 'probe-rs'
            ? parseProbeRsChipList(result.stdout || combined)
            : parsePyOcdTargetList(result.stdout || combined);
        const warnings = parseWarningLines(combined);

        if (targetCatalog.length === 0) {
            return {
                targetCatalog: [],
                targetCatalogCount: 0,
                targetCatalogError: warnings[0]
                    || (result.code !== 0
                        ? (tool === 'probe-rs' ? '读取 probe-rs 芯片目录失败' : '读取 pyOCD 目标目录失败')
                        : (tool === 'probe-rs'
                            ? '未能从 probe-rs 输出中解析芯片目录'
                            : '未能从 pyOCD 输出中解析目标目录')),
                targetCatalogSource: result.code !== 0 ? 'error' : 'empty'
            };
        }

        const payload = {
            targetCatalog,
            targetCatalogCount: targetCatalog.length
        };
        if (cacheKey) {
            targetCatalogCache.set(cacheKey, payload);
        }

        return {
            ...payload,
            targetCatalogError: '',
            targetCatalogSource: 'catalog'
        };
    } catch (err) {
        return {
            targetCatalog: [],
            targetCatalogCount: 0,
            targetCatalogError: err.message,
            targetCatalogSource: 'error'
        };
    }
}

async function getToolingInfo(options = {}) {
    const tool = normalizeToolName(options.tool);
    const executable = inspectExecutable(tool, options.executablePath || '');
    const [listing, targetCatalogListing] = await Promise.all([
        listProgrammers(tool, executable.executablePath),
        listTargetCatalog(tool, executable.executablePath)
    ]);
    const configs = tool === 'openocd'
        ? getOpenOcdConfigOptions(executable.executablePath)
        : null;

    return {
        tool,
        label: TOOL_DEFS[tool].label,
        executablePath: executable.executablePath,
        foundInPath: executable.foundInPath,
        manualPathRequired: executable.manualPathRequired,
        manualPathProvided: executable.manualPathProvided,
        manualPathError: executable.error,
        programmers: listing.programmers,
        listError: listing.listError,
        programmerSource: listing.programmerSource,
        targetCatalog: targetCatalogListing.targetCatalog,
        targetCatalogCount: targetCatalogListing.targetCatalogCount,
        targetCatalogError: targetCatalogListing.targetCatalogError,
        targetCatalogSource: targetCatalogListing.targetCatalogSource,
        chips: tool === 'probe-rs' ? targetCatalogListing.targetCatalog : [],
        chipCount: tool === 'probe-rs' ? targetCatalogListing.targetCatalogCount : 0,
        chipListError: tool === 'probe-rs' ? targetCatalogListing.targetCatalogError : '',
        chipSource: tool === 'probe-rs' ? targetCatalogListing.targetCatalogSource : 'none',
        configs,
        notes: TOOL_DEFS[tool].notes,
        elevation: getPublicElevationInfo()
    };
}

function buildOpenOcdCommand(action, options, executablePath = '') {
    const firmwarePath = action === 'flash'
        ? normalizeRequiredString(options.firmwarePath, '固件路径', MAX_PATH_LENGTH)
        : '';
    const normalizedTarget = normalizeOpenOcdTargetConfig(options.targetConfig);
    const probeSelection = normalizeString(options.probeSelection, '烧录器', 256);
    const speed = normalizeOptionalInteger(options.speed, '速率', { min: 1, max: 500000 });
    const verify = normalizeBoolean(options.verify, true);
    const resetAfterFlash = normalizeBoolean(options.resetAfterFlash, true);
    const gdbPort = normalizeOptionalInteger(options.gdbPort, 'GDB 端口', { min: 1, max: 65535, fallback: 3333 });
    const telnetPort = normalizeOptionalInteger(options.telnetPort, 'Telnet 端口', { min: 1, max: 65535, fallback: 4444 });
    const args = [];
    const tailArgs = [];
    const notes = [];
    const extraArgBuckets = collectExtraArgBuckets(options);

    const resolvedInterfaceConfig = resolveOpenOcdInterfaceConfig(
        executablePath,
        probeSelection,
        options.interfaceConfig
    );
    if (!resolvedInterfaceConfig) {
        throw new Error('请填写烧录器或接口配置');
    }

    args.push('-f', resolvedInterfaceConfig);
    const espUsbBridgeChipId = getOpenOcdEspUsbBridgeChipId(resolvedInterfaceConfig, normalizedTarget.value);
    if (espUsbBridgeChipId !== null) {
        args.push('-c', `espusbjtag chip_id ${espUsbBridgeChipId}`);
        notes.push(`已为 ESP USB Bridge 自动设置 chip_id=${espUsbBridgeChipId}。`);
    }
    args.push('-f', normalizedTarget.value);
    if (normalizedTarget.rewritten) {
        notes.push(`已将 ${normalizedTarget.originalValue} 自动修正为 ${normalizedTarget.value}。`);
    }
    if (speed) {
        args.push('-c', `adapter speed ${speed}`);
    }

    if (action === 'flash') {
        args.push(...extraArgBuckets.before_init);
        args.push('-c', 'init');
        if (isEspOpenOcdTarget(normalizedTarget.value)) {
            tailArgs.push('-c', buildOpenOcdEspFlashCommand(firmwarePath, verify, resetAfterFlash, notes));
        } else {
            tailArgs.push('-c', `program ${wrapTclValue(firmwarePath)}${verify ? ' verify' : ''}${resetAfterFlash ? ' reset' : ''} exit`);
        }
    } else {
        args.push('-c', `gdb_port ${gdbPort}`);
        args.push('-c', `telnet_port ${telnetPort}`);
        args.push(...extraArgBuckets.before_init);
        args.push('-c', 'init');
        tailArgs.push('-c', 'reset halt');
        notes.push(`调试服务已准备，GDB 端口 ${gdbPort}，Telnet 端口 ${telnetPort}。`);
    }
    args.push(...extraArgBuckets.before_tail, ...tailArgs, ...extraArgBuckets.end);

    return {
        args,
        notes
    };
}

function buildPyOcdCommand(action, options) {
    const firmwarePath = action === 'flash'
        ? normalizeRequiredString(options.firmwarePath, '固件路径', MAX_PATH_LENGTH)
        : '';
    const target = normalizeRequiredString(options.target, '目标芯片', 256);
    const probeSelection = normalizeString(options.probeSelection, '烧录器', 256);
    const speed = normalizeString(options.speed, '速率', 64);
    const resetAfterFlash = normalizeBoolean(options.resetAfterFlash, true);
    const gdbPort = normalizeOptionalInteger(options.gdbPort, 'GDB 端口', { min: 1, max: 65535, fallback: 3333 });
    const telnetPort = normalizeOptionalInteger(options.telnetPort, 'Telnet 端口', { min: 1, max: 65535, fallback: 4444 });
    const elfPath = normalizeString(options.elfPath, 'ELF 路径', MAX_PATH_LENGTH);
    const args = [];
    const tailArgs = [];
    const notes = [];
    const extraArgBuckets = collectExtraArgBuckets(options);

    if (action === 'flash') {
        args.push('load', firmwarePath, '-t', target);
        args.push(...extraArgBuckets.before_init);
        if (probeSelection) {
            args.push('-u', probeSelection);
        }
        if (speed) {
            args.push('-f', speed);
        }
        if (!resetAfterFlash) {
            tailArgs.push('--no-reset');
        }
        notes.push('写后校验沿用 pyOCD 内置策略。');
    } else {
        args.push('gdbserver', '-t', target, '-p', String(gdbPort), '-T', String(telnetPort));
        args.push(...extraArgBuckets.before_init);
        if (probeSelection) {
            args.push('-u', probeSelection);
        }
        if (speed) {
            args.push('-f', speed);
        }
        if (elfPath) {
            args.push('--elf', elfPath);
        }
        tailArgs.push('--persist');
        notes.push(`调试服务已准备，GDB 端口 ${gdbPort}，Telnet 端口 ${telnetPort}。`);
    }
    args.push(...extraArgBuckets.before_tail, ...tailArgs, ...extraArgBuckets.end);

    return {
        args,
        notes
    };
}

function buildProbeRsCommand(action, options) {
    const firmwarePath = action === 'flash'
        ? normalizeRequiredString(options.firmwarePath, '固件路径', MAX_PATH_LENGTH)
        : '';
    const target = normalizeRequiredString(options.target, '目标芯片', 256);
    const probeSelection = normalizeProbeRsProbeSelection(options.probeSelection);
    const speed = normalizeString(options.speed, '速率', 64);
    const verify = normalizeBoolean(options.verify, true);
    const debugPort = normalizeOptionalInteger(options.gdbPort, '调试端口', { min: 1, max: 65535, fallback: 1337 });
    const elfPath = normalizeString(options.elfPath, 'ELF 路径', MAX_PATH_LENGTH);
    const args = [];
    const tailArgs = [];
    const notes = [];
    const extraArgBuckets = collectExtraArgBuckets(options);

    if (action === 'flash') {
        args.push('download', firmwarePath, '--chip', target);
        args.push(...extraArgBuckets.before_init);
        if (probeSelection) {
            args.push('--probe', probeSelection);
        }
        if (speed) {
            args.push('--speed', speed);
        }
        if (verify) {
            args.push('--verify');
        }
        notes.push('probe-rs 的烧录使用 download 子命令，支持 bin/hex/elf 等文件。');
    } else {
        args.push('gdb', '--gdb-connection-string', `127.0.0.1:${debugPort}`);
        args.push(...extraArgBuckets.before_init);
        if (probeSelection) {
            args.push('--probe', probeSelection);
        }
        if (target) {
            args.push('--chip', target);
        }
        if (speed) {
            args.push('--speed', speed);
        }
        if (elfPath) {
            tailArgs.push(elfPath);
        }
        notes.push(`GDB 调试服务已准备，监听端口 ${debugPort}。`);
    }
    args.push(...extraArgBuckets.before_tail, ...tailArgs, ...extraArgBuckets.end);

    return {
        args,
        notes
    };
}

function buildGdbCliCommandList(payload = {}) {
    const commandId = normalizeRequiredString(payload.commandId, 'GDB 命令', 64).toLowerCase();
    const values = getCommandValues(payload.values);
    const readArg = (name, fieldName, options = {}) => {
        const value = normalizeSingleLineString(values[name], fieldName, options.maxLength || MAX_TEXT_LENGTH, {
            trim: options.trim !== false
        });
        if (!value && options.required) {
            throw new Error(`${fieldName}不能为空`);
        }
        return value;
    };

    const arg1 = () => readArg('arg1', '参数 1', { required: true });
    const arg2 = () => readArg('arg2', '参数 2', { required: true });
    const arg3 = () => readArg('arg3', '参数 3', { required: true });

    switch (commandId) {
        case 'file':
            return [`file ${quoteGdbPath(readArg('arg1', 'ELF 路径', { required: true }))}`];
        case 'symbol-file':
            return [`symbol-file ${quoteGdbPath(readArg('arg1', '符号文件路径', { required: true }))}`];
        case 'target-extended-remote': {
            const hostOrTarget = readArg('arg1', '主机或 host:port', { required: true });
            const port = readArg('arg2', '端口', { required: false, maxLength: 16 });
            const target = port ? `${hostOrTarget}:${port}` : hostOrTarget;
            return [`target extended-remote ${target}`];
        }
        case 'disconnect':
            return ['disconnect'];
        case 'load':
            return ['load'];
        case 'compare-sections':
            return ['compare-sections'];
        case 'quit':
            return ['quit'];
        case 'continue':
            return ['continue'];
        case 'interrupt':
            return ['interrupt'];
        case 'step':
            return ['step'];
        case 'next':
            return ['next'];
        case 'finish':
            return ['finish'];
        case 'until':
            return [`until ${arg1()}`];
        case 'jump':
            return [`jump ${arg1()}`];
        case 'break':
            return [`break ${arg1()}`];
        case 'tbreak':
            return [`tbreak ${arg1()}`];
        case 'hbreak':
            return [`hbreak ${arg1()}`];
        case 'info-breakpoints':
            return ['info breakpoints'];
        case 'delete': {
            const breakpointId = readArg('arg1', '断点 ID', { required: false, maxLength: 64 });
            return [breakpointId ? `delete ${breakpointId}` : 'delete'];
        }
        case 'disable':
            return [`disable ${readArg('arg1', '断点 ID', { required: true, maxLength: 64 })}`];
        case 'enable':
            return [`enable ${readArg('arg1', '断点 ID', { required: true, maxLength: 64 })}`];
        case 'condition':
            return [`condition ${readArg('arg1', '断点 ID', { required: true, maxLength: 64 })} ${arg2()}`];
        case 'ignore': {
            const breakpointId = readArg('arg1', '断点 ID', { required: true, maxLength: 64 });
            const count = normalizeOptionalInteger(values.arg2, '忽略次数', { min: 0, max: Number.MAX_SAFE_INTEGER });
            if (count === null) {
                throw new Error('忽略次数不能为空');
            }
            return [`ignore ${breakpointId} ${count}`];
        }
        case 'watch':
            return [`watch ${arg1()}`];
        case 'rwatch':
            return [`rwatch ${arg1()}`];
        case 'awatch':
            return [`awatch ${arg1()}`];
        case 'backtrace':
            return ['backtrace'];
        case 'frame': {
            const frameIndex = normalizeOptionalInteger(values.arg1, '帧号', { min: 0, max: Number.MAX_SAFE_INTEGER });
            if (frameIndex === null) {
                throw new Error('帧号不能为空');
            }
            return [`frame ${frameIndex}`];
        }
        case 'up':
            return ['up'];
        case 'down':
            return ['down'];
        case 'info-frame':
            return ['info frame'];
        case 'info-args':
            return ['info args'];
        case 'info-locals':
            return ['info locals'];
        case 'print':
            return [`print ${arg1()}`];
        case 'print-hex':
            return [`p/x ${arg1()}`];
        case 'print-dec':
            return [`p/d ${arg1()}`];
        case 'print-bin':
            return [`p/t ${arg1()}`];
        case 'display':
            return [`display ${arg1()}`];
        case 'undisplay':
            return [`undisplay ${readArg('arg1', '显示项 ID', { required: true, maxLength: 64 })}`];
        case 'set-variable':
            return [`set variable ${readArg('arg1', '变量名', { required: true })}=${arg2()}`];
        case 'whatis':
            return [`whatis ${arg1()}`];
        case 'ptype':
            return [`ptype ${arg1()}`];
        case 'info-registers':
            return ['info registers'];
        case 'info-all-registers':
            return ['info all-registers'];
        case 'print-register':
            return [`print ${normalizeGdbRegisterName(readArg('arg1', '寄存器名', { required: true, maxLength: 64 }))}`];
        case 'set-register':
            return [
                `set ${normalizeGdbRegisterName(readArg('arg1', '寄存器名', { required: true, maxLength: 64 }))} = ${arg2()}`
            ];
        case 'examine-memory': {
            const count = normalizeOptionalInteger(values.arg1, '读取数量', { min: 1, max: 65535, fallback: 32 });
            const unit = readArg('arg2', '读取格式', { required: true, maxLength: 8 }).toLowerCase();
            const address = readArg('arg3', '地址', { required: true, maxLength: 128 });
            if (!['b', 'h', 'w', 'i'].includes(unit)) {
                throw new Error('读取格式仅支持 b / h / w / i');
            }
            const format = unit === 'i' ? 'i' : `${unit}x`;
            return [`x/${count}${format} ${address}`];
        }
        case 'set-memory':
            return [
                `set {${readArg('arg1', '内存类型', { required: true, maxLength: 64 })}}${readArg('arg2', '地址', {
                    required: true,
                    maxLength: 128
                })} = ${arg3()}`
            ];
        case 'dump-binary-memory':
            return [
                `dump binary memory ${quoteGdbPath(readArg('arg1', '导出文件', { required: true }))} ${readArg('arg2', '起始地址', {
                    required: true,
                    maxLength: 128
                })} ${readArg('arg3', '结束地址', { required: true, maxLength: 128 })}`
            ];
        case 'restore-binary':
            return [
                `restore ${quoteGdbPath(readArg('arg1', '导入文件', { required: true }))} binary ${readArg('arg2', '装载地址', {
                    required: true,
                    maxLength: 128
                })}`
            ];
        case 'disassemble': {
            const location = readArg('arg1', '位置', { required: false, maxLength: 256 });
            return [location ? `disassemble ${location}` : 'disassemble'];
        }
        case 'disassemble-mixed':
            return [`disassemble /m ${arg1()}`];
        case 'disassemble-raw':
            return [`disassemble /r ${arg1()}`];
        case 'list': {
            const location = readArg('arg1', '位置', { required: false, maxLength: 256 });
            return [location ? `list ${location}` : 'list'];
        }
        case 'monitor-raw':
            return [`monitor ${readArg('arg1', 'monitor 命令', { required: true, maxLength: MAX_PATH_LENGTH })}`];
        case 'pc-instructions':
            return ['x/8i $pc'];
        case 'run-to-cursor': {
            const location = readArg('arg1', '文件:行号', { required: true, maxLength: 256 });
            return [`tbreak ${location}`, 'continue'];
        }
        default:
            throw new Error('不支持的 GDB 命令');
    }
}

function buildGdbSessionPlan(payload = {}) {
    const executablePath = resolveGdbExecutableOrThrow(payload.gdbPath || '');
    const host = normalizeSingleLineString(payload.host || '127.0.0.1', '远端主机', 255);
    const port = normalizeOptionalInteger(payload.port, '远端端口', { min: 1, max: 65535, fallback: 3333 });
    const elfPath = normalizeString(payload.elfPath, 'ELF 路径', MAX_PATH_LENGTH);
    const symbolPath = normalizeString(payload.symbolPath, '符号文件路径', MAX_PATH_LENGTH) || elfPath;
    const autoFile = normalizeBoolean(payload.autoFile, true);
    const autoConnect = normalizeBoolean(payload.autoConnect, true);
    const useSymbolFile = normalizeBoolean(payload.useSymbolFile, false);
    const args = ['--quiet', '--nx'];
    const initialCommands = [
        'set confirm off',
        'set pagination off',
        'set height 0'
    ];
    const notes = [
        autoConnect
            ? `GDB CLI 已启动，并将自动连接目标 ${host}:${port}。`
            : 'GDB CLI 已启动，可稍后手动执行 target extended-remote。'
    ];

    if ((autoFile || useSymbolFile) && symbolPath) {
        initialCommands.push(`${useSymbolFile ? 'symbol-file' : 'file'} ${quoteGdbPath(symbolPath)}`);
    }

    if (autoConnect) {
        initialCommands.push(`target extended-remote ${host}:${port}`);
    }

    return {
        tool: 'gdb',
        action: 'cli',
        executablePath,
        args,
        notes,
        preview: buildCommandPreview(executablePath, args),
        env: process.env,
        initialCommands,
        elevation: {
            requested: false,
            method: 'none',
            interactiveWindow: false
        }
    };
}

function appendProbeRsCommonOptions(args, options = {}, config = {}) {
    const probeSelection = normalizeProbeRsProbeSelection(options.probeSelection);
    const target = normalizeString(options.target, '目标芯片', 256);
    const speed = normalizeString(options.speed, '速率', 64);
    const protocol = normalizeString(options.protocol, '协议', 16).toLowerCase();
    const connectUnderReset = normalizeBoolean(options.connectUnderReset, false);
    const includeCore = Boolean(config.includeCore);
    const core = includeCore
        ? normalizeOptionalInteger(options.core, 'Core', { min: 0, max: 255, fallback: 0 })
        : null;

    if (probeSelection) {
        args.push('--probe', probeSelection);
    }
    if (target) {
        args.push('--chip', target);
    }
    if (speed) {
        args.push('--speed', speed);
    }
    if (protocol) {
        if (protocol !== 'swd' && protocol !== 'jtag') {
            throw new Error('probe-rs 协议仅支持 swd 或 jtag');
        }
        args.push('--protocol', protocol);
    }
    if (connectUnderReset) {
        args.push('--connect-under-reset');
    }
    args.push('--non-interactive');

    if (includeCore && core !== null) {
        args.push('--core', String(core));
    }
}

function buildProbeRsNativePlan(payload = {}) {
    const tool = normalizeToolName(payload.tool);
    if (tool !== 'probe-rs') {
        throw new Error('probe-rs 原生命令仅在选择 probe-rs 调试器时可用');
    }

    const commandId = normalizeRequiredString(payload.commandId, 'probe-rs 命令', 64).toLowerCase();
    const values = getCommandValues(payload.values);
    const executablePath = resolveExecutableOrThrow(tool, payload.executablePath || '');
    const args = [];
    const notes = [];
    const readArg = (name, fieldName, options = {}) => {
        const value = normalizeSingleLineString(values[name], fieldName, options.maxLength || MAX_TEXT_LENGTH, {
            trim: options.trim !== false
        });
        if (!value && options.required) {
            throw new Error(`${fieldName}不能为空`);
        }
        return value;
    };

    switch (commandId) {
        case 'probe-list':
            args.push('list');
            notes.push('已执行 probe-rs list，用于探测当前已连接的 probe。');
            break;
        case 'probe-info':
            args.push('info');
            appendProbeRsCommonOptions(args, payload, { includeCore: false });
            notes.push('已执行 probe-rs info，用于查询当前 session 状态与目标识别信息。');
            break;
        case 'probe-reset':
            args.push('reset');
            appendProbeRsCommonOptions(args, payload, { includeCore: true });
            notes.push('已执行 probe-rs reset。');
            break;
        case 'probe-erase':
            args.push('erase');
            appendProbeRsCommonOptions(args, payload, { includeCore: false });
            notes.push('已执行 probe-rs erase（整片擦除）。');
            break;
        case 'probe-download': {
            const filePath = readArg('arg1', '下载文件路径', { required: true, maxLength: MAX_PATH_LENGTH });
            const binaryFormat = readArg('arg2', 'Binary 格式', { required: false, maxLength: 32 }).toLowerCase();
            const baseAddress = readArg('arg3', '基地址', { required: false, maxLength: 128 });
            const skip = readArg('arg4', '跳过字节数', { required: false, maxLength: 64 });

            args.push('download');
            appendProbeRsCommonOptions(args, payload, { includeCore: false });
            if (binaryFormat) {
                args.push('--binary-format', binaryFormat);
            }
            if (baseAddress) {
                args.push('--base-address', baseAddress);
            }
            if (skip) {
                args.push('--skip', skip);
            }
            if (normalizeBoolean(payload.verifyAfterLoad, false)) {
                args.push('--verify');
            }
            if (normalizeBoolean(payload.chipErase, false)) {
                args.push('--chip-erase');
            }
            args.push(filePath);
            notes.push('已执行 probe-rs download。');
            break;
        }
        case 'probe-verify': {
            const filePath = readArg('arg1', '校验文件路径', { required: true, maxLength: MAX_PATH_LENGTH });
            const binaryFormat = readArg('arg2', 'Binary 格式', { required: false, maxLength: 32 }).toLowerCase();
            const baseAddress = readArg('arg3', '基地址', { required: false, maxLength: 128 });
            const skip = readArg('arg4', '跳过字节数', { required: false, maxLength: 64 });

            args.push('verify');
            appendProbeRsCommonOptions(args, payload, { includeCore: false });
            if (binaryFormat) {
                args.push('--binary-format', binaryFormat);
            }
            if (baseAddress) {
                args.push('--base-address', baseAddress);
            }
            if (skip) {
                args.push('--skip', skip);
            }
            args.push(filePath);
            notes.push('已执行 probe-rs verify。');
            break;
        }
        case 'probe-read': {
            const width = readArg('arg1', '读取宽度', { required: true, maxLength: 8 }).toLowerCase();
            const address = readArg('arg2', '读取地址', { required: true, maxLength: 128 });
            const words = readArg('arg3', '读取数量', { required: true, maxLength: 64 });
            if (!['b8', 'b16', 'b32', 'b64'].includes(width)) {
                throw new Error('读取宽度仅支持 b8 / b16 / b32 / b64');
            }
            args.push('read');
            appendProbeRsCommonOptions(args, payload, { includeCore: true });
            args.push(width, address, words);
            notes.push('已执行 probe-rs read。');
            break;
        }
        case 'probe-write': {
            const width = readArg('arg1', '写入宽度', { required: true, maxLength: 8 }).toLowerCase();
            const address = readArg('arg2', '写入地址', { required: true, maxLength: 128 });
            const valuesText = readArg('arg3', '写入值', { required: true, maxLength: MAX_PATH_LENGTH, trim: false });
            const writeValues = splitCliArgs(valuesText);
            if (!['b8', 'b16', 'b32', 'b64'].includes(width)) {
                throw new Error('写入宽度仅支持 b8 / b16 / b32 / b64');
            }
            if (writeValues.length === 0) {
                throw new Error('至少需要一个写入值');
            }
            args.push('write');
            appendProbeRsCommonOptions(args, payload, { includeCore: true });
            args.push(width, address, ...writeValues);
            notes.push('已执行 probe-rs write。');
            break;
        }
        case 'probe-trace':
            args.push('trace');
            appendProbeRsCommonOptions(args, payload, { includeCore: true });
            args.push(readArg('arg1', 'Trace 地址', { required: true, maxLength: 128 }));
            notes.push('已执行 probe-rs trace。');
            break;
        case 'probe-attach':
            args.push('attach');
            appendProbeRsCommonOptions(args, payload, { includeCore: false });
            args.push(readArg('arg1', 'RTT ELF 路径', { required: true, maxLength: MAX_PATH_LENGTH }));
            notes.push('已执行 probe-rs attach（RTT/日志 attach）。');
            break;
        default:
            throw new Error('不支持的 probe-rs 原生命令');
    }

    return {
        tool,
        action: 'cli',
        executablePath,
        args,
        notes,
        preview: buildCommandPreview(executablePath, args),
        env: process.env,
        elevation: {
            requested: false,
            method: 'none',
            interactiveWindow: false
        }
    };
}

function buildExecutionPlan(payload = {}) {
    const action = normalizeRequiredString(payload.action, '操作类型', 32).toLowerCase();
    if (action !== 'flash' && action !== 'debug') {
        throw new Error('仅支持烧录和实时调试');
    }

    const tool = normalizeToolName(payload.tool);
    const executablePath = resolveExecutableOrThrow(tool, payload.executablePath || '');
    const options = payload.options && typeof payload.options === 'object' ? payload.options : {};
    const requestElevation = normalizeBoolean(payload.requestElevation, false);

    let built = null;
    if (tool === 'openocd') {
        built = buildOpenOcdCommand(action, options, executablePath);
    } else if (tool === 'pyocd') {
        built = buildPyOcdCommand(action, options);
    } else {
        built = buildProbeRsCommand(action, options);
    }

    let plan = {
        tool,
        action,
        executablePath,
        args: built.args,
        notes: built.notes,
        preview: buildCommandPreview(executablePath, built.args),
        env: process.env,
        elevation: {
            requested: false,
            method: 'none',
            interactiveWindow: false
        }
    };

    if (requestElevation) {
        plan = applyElevationToPlan(plan);
    }

    return plan;
}

function sendJson(ws, payload) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify(payload));
}

function createSessionId(prefix = 'flashdebug') {
    return `${prefix}_${typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : crypto.randomBytes(16).toString('hex')}`;
}

function sendInteractiveCommands(session, commands = []) {
    if (!session || !session.process || !session.process.stdin) {
        throw new Error('CLI 会话未启动');
    }

    const list = Array.isArray(commands) ? commands : [commands];
    const normalized = list
        .map(command => normalizeSingleLineString(command, 'CLI 命令', MAX_PATH_LENGTH, { trim: false }))
        .filter(Boolean);

    if (normalized.length === 0) {
        return;
    }

    const chunk = normalized.map(command => `${command}\n`).join('');
    sendJson(session.ws, {
        type: 'output',
        sessionId: session.id,
        action: session.action,
        sessionKind: session.kind,
        stream: 'stdin',
        data: normalized.map(command => `[stdin] ${command}\n`).join('')
    });

    try {
        session.process.stdin.write(chunk);
    } catch (err) {
        throw new Error(err.message || 'CLI 命令发送失败');
    }
}

function stopSession(session, reason = '用户停止') {
    if (!session || !session.process) return;

    sendJson(session.ws, {
        type: 'output',
        sessionId: session.id,
        action: session.action,
        sessionKind: session.kind,
        stream: 'system',
        data: `[system] ${reason}\n`
    });

    try {
        session.process.kill('SIGTERM');
    } catch {}

    setTimeout(() => {
        if (!activeSessions.has(session.id)) return;
        try {
            session.process.kill('SIGKILL');
        } catch {}
    }, PROCESS_KILL_TIMEOUT_MS);
}

function buildInteractiveSpawnSpec(plan = {}, interactive = false) {
    if (!interactive) {
        return {
            command: plan.executablePath,
            args: plan.args || [],
            note: ''
        };
    }

    if (process.platform === 'linux') {
        const scriptExecutable = resolveExecutableFromPath('script');
        if (scriptExecutable) {
            return {
                command: scriptExecutable,
                args: ['-q', '-e', '-f', '-E', 'never', '-c', buildCommandPreview(plan.executablePath, plan.args || []), '/dev/null'],
                note: 'CLI 会话已通过 script PTY 包装，以确保交互式 GDB 输出实时返回到消息框。'
            };
        }
    }

    return {
        command: plan.executablePath,
        args: plan.args || [],
        note: ''
    };
}

function launchProcessSession(options = {}) {
    const ws = options.ws;
    const sessionsByKind = options.sessionsByKind;
    const kind = normalizeRequiredString(options.kind, '会话类型', 32).toLowerCase();
    const plan = options.plan || {};
    const interactive = Boolean(options.interactive);
    const spawnSpec = buildInteractiveSpawnSpec(plan, interactive);

    const child = spawn(spawnSpec.command, spawnSpec.args, {
        cwd: process.cwd(),
        env: plan.env || process.env,
        stdio: interactive ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe'],
        windowsHide: !(plan.elevation && plan.elevation.interactiveWindow)
    });

    const session = {
        id: createSessionId(kind),
        ws,
        kind,
        process: child,
        action: plan.action || kind,
        tool: plan.tool || '',
        interactive
    };

    activeSessions.set(session.id, session);
    sessionsByKind.set(kind, session);

    sendJson(ws, {
        type: 'started',
        sessionId: session.id,
        sessionKind: kind,
        action: session.action,
        tool: plan.tool || '',
        pid: child.pid,
        command: plan.preview
    });

    for (const note of plan.notes || []) {
        sendJson(ws, {
            type: 'output',
            sessionId: session.id,
            sessionKind: kind,
            action: session.action,
            stream: 'system',
            data: `[system] ${note}\n`
        });
    }
    if (spawnSpec.note) {
        sendJson(ws, {
            type: 'output',
            sessionId: session.id,
            sessionKind: kind,
            action: session.action,
            stream: 'system',
            data: `[system] ${spawnSpec.note}\n`
        });
    }

    child.stdout.on('data', (chunk) => {
        sendJson(ws, {
            type: 'output',
            sessionId: session.id,
            sessionKind: kind,
            action: session.action,
            stream: 'stdout',
            data: chunk.toString('utf8')
        });
    });

    child.stderr.on('data', (chunk) => {
        sendJson(ws, {
            type: 'output',
            sessionId: session.id,
            sessionKind: kind,
            action: session.action,
            stream: 'stderr',
            data: chunk.toString('utf8')
        });
    });

    child.on('error', (err) => {
        sendJson(ws, {
            type: 'error',
            sessionId: session.id,
            sessionKind: kind,
            action: session.action,
            message: err.message
        });
    });

    child.on('close', (code, signal) => {
        sendJson(ws, {
            type: 'exit',
            sessionId: session.id,
            sessionKind: kind,
            action: session.action,
            exitCode: code ?? 0,
            signal: signal || null
        });
        activeSessions.delete(session.id);
        const currentSession = sessionsByKind.get(kind);
        if (currentSession && currentSession.id === session.id) {
            sessionsByKind.delete(kind);
        }
    });

    if (interactive && Array.isArray(plan.initialCommands) && plan.initialCommands.length > 0) {
        sendInteractiveCommands(session, plan.initialCommands);
    }

    return session;
}

function init(server, wsPath = '/flashdebug') {
    flashDebugPath = wsPath;
    flashDebugWss = new WebSocket.Server({
        noServer: true,
        perMessageDeflate: false
    });

    flashDebugWss.on('connection', (ws, req) => {
        const sessionsByKind = new Map();
        const getSession = (kind) => sessionsByKind.get(kind) || null;
        const stopKind = (kind, reason = '用户停止') => {
            const session = getSession(kind);
            if (session) {
                stopSession(session, reason);
            }
        };
        const stopAllKinds = (reason = '连接已关闭') => {
            Array.from(sessionsByKind.values()).forEach((session) => {
                stopSession(session, reason);
            });
        };

        ws.on('message', (message) => {
            let payload = null;
            try {
                payload = JSON.parse(message.toString());

                if (payload.type === 'stop') {
                    const sessionKind = normalizeString(payload.sessionKind, '会话类型', 32).toLowerCase();
                    if (sessionKind) {
                        stopKind(sessionKind);
                    } else {
                        stopAllKinds('用户停止');
                    }
                    return;
                }

                if (payload.type === 'start') {
                    const plan = buildExecutionPlan(payload);
                    stopKind('flash', plan.action === 'flash' ? '新的操作已接管当前会话' : '新的调试服务已接管当前烧录会话');
                    stopKind('debug', plan.action === 'debug' ? '新的操作已接管当前会话' : '新的烧录会话已接管当前调试服务');
                    launchProcessSession({
                        ws,
                        sessionsByKind,
                        kind: plan.action,
                        plan,
                        interactive: false
                    });
                    return;
                }

                if (payload.type === 'cli-start') {
                    stopKind('cli', '新的 CLI 会话已接管当前会话');
                    const plan = buildGdbSessionPlan(payload);
                    launchProcessSession({
                        ws,
                        sessionsByKind,
                        kind: 'cli',
                        plan,
                        interactive: true
                    });
                    return;
                }

                if (payload.type === 'cli-command') {
                    const session = getSession('cli');
                    if (!session) {
                        throw new Error('CLI 会话尚未启动');
                    }
                    sendInteractiveCommands(session, buildGdbCliCommandList(payload));
                    return;
                }

                if (payload.type === 'native-start') {
                    stopKind('native', '新的 probe-rs 原生命令已接管当前会话');
                    const plan = buildProbeRsNativePlan(payload);
                    launchProcessSession({
                        ws,
                        sessionsByKind,
                        kind: 'native',
                        plan,
                        interactive: false
                    });
                    return;
                }

                sendJson(ws, { type: 'error', message: '不支持的操作类型' });
            } catch (err) {
                const sessionKind = payload && payload.sessionKind
                    ? normalizeString(payload.sessionKind, '会话类型', 32).toLowerCase()
                    : null;
                const action = payload && payload.action
                    ? normalizeString(payload.action, '操作类型', 32).toLowerCase()
                    : null;
                sendJson(ws, {
                    type: 'error',
                    sessionKind,
                    action,
                    message: err.message
                });
            }
        });

        ws.on('close', () => {
            stopAllKinds('连接已关闭');
        });

        ws.on('error', () => {});
    });

    return { available: true, wss: flashDebugWss, path: wsPath };
}

function handleUpgrade(request, socket, head) {
    if (flashDebugWss) {
        flashDebugWss.handleUpgrade(request, socket, head, (ws) => {
            flashDebugWss.emit('connection', ws, request);
        });
    }
}

function closeAll() {
    for (const session of activeSessions.values()) {
        stopSession(session, '服务正在关闭');
    }
    activeSessions.clear();
}

module.exports = {
    TOOL_NAMES,
    init,
    handleUpgrade,
    closeAll,
    getToolingInfo
};
