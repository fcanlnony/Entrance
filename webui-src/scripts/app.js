
    (function() {
        'use strict';

        const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';

        function normalizeAbsoluteUrl(value, fallback, protocolPattern) {
            const raw = String(value || '').trim();
            if (!raw) {
                return fallback;
            }
            try {
                const parsed = new URL(raw);
                if (protocolPattern && !protocolPattern.test(parsed.protocol)) {
                    return fallback;
                }
                return parsed.toString().replace(/\/$/, '');
            } catch {
                return fallback;
            }
        }

        const runtimeParams = new URLSearchParams(location.search);
        const Config = {
            API: normalizeAbsoluteUrl(runtimeParams.get('apiBase'), location.origin, /^https?:$/i),
            WS_BASE: normalizeAbsoluteUrl(runtimeParams.get('wsBase'), `${wsProtocol}//${location.host}`, /^wss?:$/i),
            DESKTOP_MODE: runtimeParams.get('desktopMode') === '1',
            AUTH_PROXY: String(runtimeParams.get('authProxy') || '').trim().toLowerCase()
        };

        function usesInjectedDesktopAuth() {
            return Config.DESKTOP_MODE && Config.AUTH_PROXY === 'header';
        }

        const DEFAULT_LOGIN_KEEP_VALUE = '7d';

        const State = {
            loggedIn: false,
            isAdmin: false,
            isNologin: false,
            username: '',
            token: '',
            language: 'en',
            appVersion: '0.1.9',
            projectHomepage: 'https://github.com/fcanlnony/Entrance',
            authSecretFingerprint: '',
            defaultLoginKeepSeconds: 604800,
            desktopVersion: '',
            desktopProjectHomepage: 'https://github.com/EntranceToolBox/Entrance-Desktop',
            showDesktopClientInfo: false,
            hosts: [],
            editingHostIndex: null,
            sshConnected: false,
            sftpConnected: false,
            sftpSession: null,
            currentPath: '/',
            selectedFiles: [],
            filesTransferred: 0,
            theme: 'light',
            colorScheme: 'default',
            // 导航历史
            navHistory: [],
            navIndex: -1
        };

        const Storage = {
            getTheme() { return localStorage.getItem('theme') || 'light'; },
            setTheme(t) { localStorage.setItem('theme', t); },
            getColorScheme() { return localStorage.getItem('colorScheme') || 'default'; },
            setColorScheme(s) { localStorage.setItem('colorScheme', s); },
            getLanguage() { return localStorage.getItem('language') || 'en'; },
            setLanguage(language) { localStorage.setItem('language', language); },
            getToken() { return usesInjectedDesktopAuth() ? '' : (localStorage.getItem('authToken') || ''); },
            setToken(t) {
                if (usesInjectedDesktopAuth()) return;
                localStorage.setItem('authToken', t);
            },
            clearToken() { localStorage.removeItem('authToken'); },
            getAuthSecretFingerprint() { return localStorage.getItem('authSecretFingerprint') || ''; },
            setAuthSecretFingerprint(fingerprint) { localStorage.setItem('authSecretFingerprint', fingerprint); },
            clearAuthSecretFingerprint() { localStorage.removeItem('authSecretFingerprint'); },
            getLoginKeepValue() { return localStorage.getItem('loginKeepValue') || DEFAULT_LOGIN_KEEP_VALUE; },
            setLoginKeepValue(value) { localStorage.setItem('loginKeepValue', value); }
        };

        function applyPublicAppInfo(data = {}) {
            if (!data || typeof data !== 'object') return;
            State.appVersion = data.version || State.appVersion;
            State.projectHomepage = data.projectHomepage || State.projectHomepage;
            State.showDesktopClientInfo = data.desktopNoLogin === true;
            State.desktopVersion = data.desktopVersion || '';
            State.desktopProjectHomepage = data.desktopProjectHomepage || State.desktopProjectHomepage;
            State.authSecretFingerprint = data.authSecretFingerprint || State.authSecretFingerprint;
            if (Number.isFinite(Number(data.defaultLoginKeepSeconds)) && Number(data.defaultLoginKeepSeconds) >= 0) {
                State.defaultLoginKeepSeconds = Number(data.defaultLoginKeepSeconds);
            }
            if (window.About && typeof window.About.render === 'function') {
                try { window.About.render(); } catch {}
            }
        }

        const I18n = {
            observer: null,
            observing: false,
            applying: false,
            nativeConfirm: window.confirm.bind(window),
            nativeAlert: window.alert.bind(window),
            EXACT: {
                zh: {},
                en: {
                    '切换主题': 'Toggle theme',
                    '请使用账户登录': 'Please sign in with your account',
                    '正在恢复登录状态...': 'Restoring your session...',
                    '正在验证本地保存的登录态，请稍候。': 'Checking the saved local session. Please wait.',
                    '正在启动工作台...': 'Starting the workspace...',
                    '先载入界面，再分阶段连接服务模块。': 'Rendering the interface first, then loading service modules in stages.',
                    '正在准备界面...': 'Preparing the interface...',
                    '正在渲染工作台...': 'Rendering the workspace...',
                    '正在初始化终端模块...': 'Initializing terminal modules...',
                    '正在初始化串口与远程桌面模块...': 'Initializing serial and remote desktop modules...',
                    '正在同步本机终端能力...': 'Syncing local shell capabilities...',
                    '正在加载主机列表...': 'Loading saved hosts...',
                    '正在加载安全设置...': 'Loading security settings...',
                    '启动完成': 'Startup complete',
                    '用户名': 'Username',
                    '密码': 'Password',
                    '登录': 'Sign in',
                    '关于': 'About',
                    'SSH 终端': 'SSH Terminal',
                    'SFTP 管理': 'SFTP Manager',
                    'VNC 远程': 'VNC Remote',
                    'Web 终端': 'Web Terminal',
                    '串口终端': 'Serial Terminal',
                    '烧录调试': 'Flash & Debug',
                    '设置': 'Settings',
                    '收起': 'Collapse',
                    '退出': 'Log out',
                    '主机地址': 'Host',
                    '端口': 'Port',
                    '认证方式': 'Authentication',
                    '私钥': 'Private key',
                    '私钥口令（可选）': 'Key passphrase (optional)',
                    '私钥口令': 'Key passphrase',
                    '取消编辑': 'Cancel edit',
                    '保存主机': 'Save host',
                    '更新主机': 'Update host',
                    '已保存的主机': 'Saved Hosts',
                    '终端 - 未连接': 'Terminal - Disconnected',
                    '未连接': 'Disconnected',
                    '内存:': 'Memory:',
                    '展开图表': 'Expand charts',
                    '清除数据': 'Clear data',
                    '进程:': 'Processes:',
                    '运行:': 'Running:',
                    '负载:': 'Load:',
                    '展开进程': 'Expand processes',
                    '进程列表 (TOP)': 'Process List (TOP)',
                    '排序:': 'Sort:',
                    '内存%': 'Memory%',
                    '时间': 'Time',
                    '显示:': 'Show:',
                    '刷新': 'Refresh',
                    '运行时间': 'Uptime',
                    '用户数': 'Users',
                    '负载均值': 'Load Avg',
                    '任务': 'Tasks',
                    'CPU使用': 'CPU Usage',
                    '内存': 'Memory',
                    '操作': 'Action',
                    '连接SSH后自动获取进程信息': 'Process information loads automatically after SSH connects',
                    '容器:': 'Containers:',
                    '展开 Docker': 'Expand Docker',
                    '总计': 'Total',
                    '详细': 'Details',
                    '连接 SSH 后自动获取容器信息': 'Container information loads automatically after SSH connects',
                    '连接 SSH 后自动获取 Docker Stats': 'Docker stats load automatically after SSH connects',
                    '终端服务不可用': 'Terminal service unavailable',
                    '当前服务器平台暂不支持终端功能': 'The current server platform does not support terminal mode yet',
                    '目标主机': 'Target host',
                    'Windows 用户名': 'Windows username',
                    'Windows 登录密码': 'Windows sign-in password',
                    '未启动': 'Stopped',
                    '启动': 'Start',
                    '停止': 'Stop',
                    'Web 终端 - 未启动': 'Web Terminal - Stopped',
                    '清屏': 'Clear',
                    '连接': 'Connect',
                    '断开': 'Disconnect',
                    '远程文件': 'Remote Files',
                    '新建': 'New Folder',
                    '下载': 'Download',
                    '后退': 'Back',
                    '前进': 'Forward',
                    '上级目录': 'Up',
                    '跳转': 'Go',
                    '名称': 'Name',
                    '(Ctrl+点击多选)': '(Ctrl+Click for multi-select)',
                    '大小': 'Size',
                    '修改时间': 'Modified',
                    '请先连接服务器': 'Connect to a server first',
                    '拖拽文件到此处，或点击下方按钮上传': 'Drag files here, or use the buttons below to upload',
                    '上传文件': 'Upload Files',
                    '上传文件夹': 'Upload Folder',
                    '上传中...': 'Uploading...',
                    'VNC 远程桌面': 'VNC Remote Desktop',
                    'VNC 主机': 'VNC Host',
                    'VNC 密码（可选）': 'VNC password (optional)',
                    '只读模式': 'View-only mode',
                    '缩放适应': 'Scale to fit',
                    '请连接到 VNC 服务器': 'Connect to a VNC server',
                    '内网白名单': 'Private Network Allowlist',
                    '返回设置': 'Back to Settings',
                    '仅允许私有网段（如 10.0.0.0/8、192.168.0.0/16）用于 SSH/SFTP/VNC 连接。修改后立即生效。': 'Only private CIDR ranges such as 10.0.0.0/8 or 192.168.0.0/16 are allowed for SSH/SFTP/VNC. Changes take effect immediately.',
                    '新增网段 (CIDR)': 'Add Network (CIDR)',
                    '添加': 'Add',
                    '当前白名单': 'Current Allowlist',
                    '波特率': 'Baud Rate',
                    '数据位': 'Data Bits',
                    '停止位': 'Stop Bits',
                    '校验位': 'Parity',
                    '无': 'None',
                    '偶校验': 'Even',
                    '奇校验': 'Odd',
                    '流控制': 'Flow Control',
                    '硬件': 'Hardware',
                    '连接串口': 'Connect Serial',
                    '模拟数据演示': 'Demo Data',
                    '演示': 'Demo',
                    '波形显示': 'Waveform',
                    '波形': 'Waveform',
                    '统计': 'Statistics',
                    '统计图': 'Statistics',
                    '全屏': 'Fullscreen',
                    '浏览器不支持 Web Serial API': 'This browser does not support the Web Serial API',
                    '请使用 Chrome 89+ 或 Edge 89+ 浏览器，并确保使用 HTTPS 或 localhost 访问。': 'Use Chrome 89+ or Edge 89+, and access the app over HTTPS or localhost.',
                    '串口终端 - 未连接': 'Serial Terminal - Disconnected',
                    '自动滚动': 'Auto scroll',
                    'HEX显示': 'HEX view',
                    '发送数据': 'Send Data',
                    '输入要发送的数据...': 'Enter data to send...',
                    '文本': 'Text',
                    '发送': 'Send',
                    'GUI 封装 OpenOCD、pyOCD、probe-rs，复用串口页统一风格与工作流。': 'A GUI wrapper for OpenOCD, pyOCD, and probe-rs, using the same visual language and workflow as the serial page.',
                    '烧录': 'Flash',
                    '实时调试': 'Live Debug',
                    '正在检测 PATH...': 'Checking PATH...',
                    '检测': 'Detect',
                    '路径': 'Path',
                    '手动路径': 'Manual Path',
                    '当 PATH 未命中时，在这里填写工具绝对路径': 'When PATH detection fails, enter the absolute executable path here',
                    '仅允许填写与当前工具同名的可执行文件，例如 `openocd`、`pyocd`、`probe-rs`。': 'Only executables matching the selected tool are allowed, for example `openocd`, `pyocd`, or `probe-rs`.',
                    '该功能需要管理员权限，当前账户只能查看界面，不能启动本机烧录或调试会话。': 'This feature requires admin permissions. The current account can view the UI but cannot start local flash or debug sessions.',
                    '烧录任务': 'Flash Job',
                    '选择烧录器、固件路径、速率和验证选项，然后由 GUI 生成对应 CLI。': 'Choose a probe, firmware path, speed, and verification options, then let the GUI generate the CLI command.',
                    '空闲': 'Idle',
                    '烧录器': 'Probe',
                    '自动检测 / 留空手填': 'Auto-detect / leave blank to type manually',
                    '优先从所选工具列举可用烧录器；无结果时可直接在右侧输入。': 'Available probes are listed from the selected tool first. If none are found, type one manually on the right.',
                    '烧录器标识 / 配置': 'Probe Identifier / Config',
                    '例如 cmsis-dap、st-link、UID 或 probe 选择串': 'For example: cmsis-dap, st-link, a UID, or a probe selector',
                    '例如 cmsis-dap、st-link': 'For example: cmsis-dap or st-link',
                    '目标芯片 / 目标配置': 'Target Chip / Target Config',
                    '例如 target/stm32f4x.cfg 或 stm32f103rc': 'For example: target/stm32f4x.cfg or stm32f103rc',
                    '例如 target/stm32f4x.cfg': 'For example: target/stm32f4x.cfg',
                    '接口配置': 'Interface Config',
                    '可选，留空时使用 interface/<烧录器>.cfg': 'Optional. Leave empty to use interface/<probe>.cfg',
                    '波特率 / 速率': 'Baud Rate / Speed',
                    '例如 4000、1000000、10m': 'For example: 4000, 1000000, or 10m',
                    '例如 4000': 'For example: 4000',
                    '固件路径': 'Firmware Path',
                    '输入固件在当前主机上的绝对路径': 'Enter the firmware absolute path on the current host',
                    '选择文件': 'Choose File',
                    '选择本地文件后会上传到当前 Entrance 主机的临时目录，并自动回填路径。': 'Selecting a local file uploads it to a temporary path on the current Entrance host and fills the path automatically.',
                    '附加参数': 'Extra Arguments',
                    '可选，补充板卡专用 CLI 参数': 'Optional extra CLI parameters for the target board',
                    '请求管理员/root 权限': 'Request admin/root privileges',
                    '写后校验': 'Verify after write',
                    '烧录后复位': 'Reset after flash',
                    '正在检测管理员/root 提权方式...': 'Checking admin/root elevation options...',
                    '不同工具的校验参数并不完全一致；未显式支持时会沿用各自默认策略。': 'Verification arguments differ between tools. When no explicit option is supported, each tool falls back to its default behavior.',
                    '清空日志': 'Clear Log',
                    '开始烧录': 'Start Flash',
                    '烧录消息框': 'Flash Log',
                    'CLI 命令与实时输出': 'CLI commands and live output',
                    '启动 GDB 或 DAP 调试后端，并持续输出 GUI 封装后的命令与日志。': 'Start a GDB or DAP backend and continuously stream the wrapped GUI commands and logs.',
                    '烧录器 / 调试器': 'Probe / Debugger',
                    '支持自动列举的工具会填充下拉；否则请手动输入 UID 或适配器名。': 'Tools that support enumeration populate the dropdown; otherwise enter a UID or adapter name manually.',
                    '调试端口': 'Debug Port',
                    'Telnet 端口': 'Telnet Port',
                    'ELF / 符号文件': 'ELF / Symbols',
                    '可选，为 pyOCD 传入 ELF 文件': 'Optional. Pass an ELF file to pyOCD',
                    '启动调试': 'Start Debug',
                    '调试消息框': 'Debug Log',
                    'CLI 操作': 'CLI Actions',
                    '在调试服务启动后，通过 GDB CLI 与 tool-specific CLI 执行调试命令，并保留原始输出。': 'After the debug service starts, run commands through GDB CLI and tool-specific CLI while keeping the raw output.',
                    'GDB 路径': 'GDB Path',
                    '留空自动探测 arm-none-eabi-gdb / gdb-multiarch / gdb': 'Leave empty to auto-detect arm-none-eabi-gdb / gdb-multiarch / gdb',
                    'CLI 会话会优先自动探测常见 GDB；若你使用交叉 GDB，可手动填写绝对路径。': 'CLI sessions auto-detect common GDB binaries first. If you use a cross GDB, enter its absolute path manually.',
                    '远端主机': 'Remote Host',
                    '远端端口': 'Remote Port',
                    '启动 CLI 会话时可自动执行 file 或 symbol-file': 'Automatically run file or symbol-file when the CLI session starts',
                    '若烧录任务已选择文件，CLI ELF 默认会优先沿用该路径；也可在这里单独上传 ELF / 符号文件。': 'If a file is already selected for flashing, the CLI ELF path defaults to it. You can also upload a separate ELF / symbols file here.',
                    '启动后自动载入 file': 'Auto-run file on start',
                    '改用 symbol-file': 'Use symbol-file instead',
                    '启动后自动连接 target extended-remote': 'Auto-connect target extended-remote on start',
                    '该卡片会把发送的 CLI 命令和 stdout/stderr 原样写入下方消息框；OpenOCD / pyOCD 独占 monitor 区只在对应 debugger 下显示。': 'This card writes the CLI commands and stdout/stderr to the log below. OpenOCD / pyOCD monitor panels only appear for their matching debugger.',
                    '停止 CLI': 'Stop CLI',
                    '启动 CLI': 'Start CLI',
                    'GDB 常用快捷命令': 'Common GDB Shortcuts',
                    '第一版优先覆盖会话、运行控制、断点、调用栈、寄存器和常用反汇编命令。': 'The first version covers session control, execution control, breakpoints, call stacks, registers, and common disassembly commands.',
                    'GDB 命令构造器': 'GDB Command Builder',
                    '按命令模板填写参数，生成并执行 GDB CLI；支持 run to cursor、monitor 透传、断点/观察点、内存、寄存器等命令。': 'Fill in command templates to generate and execute GDB CLI commands, including run to cursor, monitor passthrough, breakpoints/watchpoints, memory, and register commands.',
                    '命令模板': 'Command Template',
                    '参数 1': 'Argument 1',
                    '参数 2': 'Argument 2',
                    '参数 3': 'Argument 3',
                    '参数 4': 'Argument 4',
                    '执行 GDB 命令': 'Run GDB Command',
                    '以下命令会通过 `monitor ...` 透传到当前 OpenOCD 调试后端。': 'These commands are passed through to the current OpenOCD backend via `monitor ...`.',
                    'monitor 原始命令': 'Raw monitor command',
                    '例如 mdw 0x08000000 或 mww 0x20000000 0x12345678': 'For example: mdw 0x08000000 or mww 0x20000000 0x12345678',
                    '执行 monitor': 'Run monitor',
                    '以下命令会通过 `monitor ...` 透传到当前 pyOCD GDB server。': 'These commands are passed through to the current pyOCD GDB server via `monitor ...`.',
                    '例如 status 或 reg': 'For example: status or reg',
                    'probe-rs 原生命令': 'Native probe-rs Commands',
                    '这里只执行 `probe-rs` 自身的 CLI 子命令；适合 probe 枚举、info/reset、download/verify/erase、read/write/trace/attach RTT。执行时会把原始 stdout/stderr 写入消息框。': 'This section runs native `probe-rs` CLI subcommands only. It is suitable for probe listing, info/reset, download/verify/erase, read/write/trace/attach RTT, and writes raw stdout/stderr to the log.',
                    'probe-rs 命令模板': 'probe-rs Command Template',
                    '协议': 'Protocol',
                    '自动 / 默认': 'Auto / Default',
                    '命令参数 1': 'Command Arg 1',
                    '命令参数 2': 'Command Arg 2',
                    '命令参数 3': 'Command Arg 3',
                    '命令参数 4': 'Command Arg 4',
                    '停止 probe-rs': 'Stop probe-rs',
                    '执行 probe-rs': 'Run probe-rs',
                    'CLI 消息框': 'CLI Log',
                    'GDB / probe-rs 原始输出': 'Raw GDB / probe-rs output',
                    '修改密码': 'Change Password',
                    '当前账户：': 'Current account:',
                    '桌面应用不允许修改密码': 'Password changes are disabled in the desktop app',
                    '登录保持': 'Session Keepalive',
                    '默认保持 7 天，支持预设或自定义输入，例如 7d、14d、1m、12h、never': 'Keep the session for 7 days by default. Presets and custom values such as 7d, 14d, 1m, 12h, and never are supported.',
                    '免登录模式下不会使用登录保持时间': 'Session keepalive is not used in no-login mode.',
                    '预设': 'Preset',
                    '自定义': 'Custom',
                    '时长表达式': 'Duration expression',
                    '保存登录保持时间': 'Save session keepalive',
                    '当前登录保持时间：': 'Current session keepalive: ',
                    '请输入登录保持时间': 'Enter a session keepalive duration',
                    '登录保持时间格式无效，示例：7d、14d、1m、12h、never': 'Invalid session keepalive format. Examples: 7d, 14d, 1m, 12h, never.',
                    '登录保持时间过长，请控制在 10 年以内': 'The session keepalive is too long. Keep it within 10 years.',
                    '登录保持时间已保存，当前免登录模式不会使用该设置': 'The session keepalive has been saved. It is not used in no-login mode.',
                    '登录保持时间已保存，将在下次登录时生效': 'The session keepalive has been saved and will take effect on the next sign-in.',
                    '登录保持时间已更新': 'Session keepalive updated',
                    '登录保持时间更新失败': 'Failed to update the session keepalive',
                    '新密码': 'New password',
                    '输入新密码': 'Enter a new password',
                    '确认密码': 'Confirm password',
                    '再次输入新密码': 'Re-enter the new password',
                    '管理 SSH、SFTP、VNC 可访问的内网网段。点击后进入白名单页进行新增或删除。': 'Manage private CIDR ranges allowed for SSH, SFTP, and VNC. Click to open the allowlist page and add or remove entries.',
                    '进入管理': 'Manage',
                    '配色方案': 'Color Scheme',
                    '选择 Material You Design 风格的强调色方案': 'Choose a Material You inspired accent color scheme',
                    '语言': 'Language',
                    '选择界面语言，默认英文': 'Choose the interface language. English is the default.',
                    '新建文件夹': 'New Folder',
                    '文件夹名称': 'Folder name',
                    '新文件夹': 'New folder',
                    '取消': 'Cancel',
                    '创建': 'Create',
                    '终止进程': 'Terminate Process',
                    '进程信息': 'Process Info',
                    '用户:': 'User:',
                    '命令:': 'Command:',
                    '选择信号': 'Choose Signal',
                    '优雅终止，允许进程清理': 'Gracefully terminate and allow cleanup',
                    '强制终止，立即杀死进程': 'Force kill immediately',
                    '中断信号，类似 Ctrl+C': 'Interrupt, similar to Ctrl+C',
                    '挂起信号，常用于重载配置': 'Hangup, often used to reload configuration',
                    '暂停进程': 'Pause process',
                    '继续已暂停的进程': 'Resume paused process',
                    '发送信号': 'Send Signal',
                    '版本号': 'Version',
                    '项目信息': 'Project',
                    '桌面客户端版本': 'Desktop Version',
                    '未设置': 'Not set',
                    '桌面客户端项目主页': 'Desktop Project Homepage',
                    '欢迎提交issue和pr': 'Issues and PRs are welcome',
                    '关闭': 'Close',
                    '默认方案': 'Default',
                    '中性石墨': 'Neutral Graphite',
                    '樱花粉': 'Sakura Pink',
                    '柔和花瓣': 'Soft Petals',
                    '海洋蓝': 'Ocean Blue',
                    '清澈潮汐': 'Clear Tide',
                    '森林绿': 'Forest Green',
                    '苔藓林地': 'Moss Grove',
                    '暮光紫': 'Twilight Violet',
                    '柔雾暮色': 'Soft Dusk',
                    '琥珀橙': 'Amber Orange',
                    '温暖日落': 'Warm Sunset',
                    '当前': 'Current',
                    '简体中文': 'Simplified Chinese',
                    '默认界面语言': 'Default UI language',
                    '简体中文界面': 'Simplified Chinese interface',
                    '英文界面翻译': 'Translate the interface to English',
                    '密码登录需要提供密码': 'Password authentication requires a password',
                    '密钥登录需要提供私钥': 'Key authentication requires a private key',
                    '私钥格式无效，仅支持 PEM/OpenSSH 私钥': 'Invalid private key format. Only PEM/OpenSSH private keys are supported.',
                    '主机未保存私钥，请先补充': 'No private key is saved for this host. Add one first.',
                    '主机未保存密码，请先补充': 'No password is saved for this host. Add one first.',
                    '目标地址校验失败': 'Target validation failed',
                    '目标主机解析到内网地址，但未在内网白名单中放行': 'The target host resolved to a private network address, but it is not allowed by the private network allowlist',
                    '目标主机解析到内网地址，但未在内网白名单中放行。请先到 设置 -> 内网白名单 放行对应网段。': 'The target host resolved to a private network address, but it is not allowed by the private network allowlist. Go to Settings -> Private Network Allowlist and allow the matching CIDR range first.',
                    '仅管理员可管理内网白名单': 'Only administrators can manage the private network allowlist',
                    '当前用户不可用': 'Current user is unavailable',
                    '请输入新密码': 'Enter a new password',
                    '两次输入的密码不一致': 'The two passwords do not match',
                    '密码修改成功': 'Password updated successfully',
                    '密码修改失败': 'Password update failed',
                    '请输入用户名和密码': 'Enter both username and password',
                    '登录失败': 'Sign-in failed',
                    '已退出登录': 'Signed out',
                    '正在连接桌面会话...': 'Connecting desktop session...',
                    '正在验证桌面包装器注入的本地会话。': 'Validating the local session injected by the desktop wrapper.',
                    '桌面会话初始化失败': 'Desktop session initialization failed',
                    '未能建立受保护的桌面免登录会话，请重新启动桌面应用。': 'Unable to establish the protected desktop no-login session. Restart the desktop app.',
                    '桌面免登录由桌面包装器托管，不能在页面内退出': 'Desktop no-login is managed by the wrapper and cannot be signed out from the page.',
                    '登录已过期，请重新登录': 'The session expired. Please sign in again.',
                    '请先连接 SSH': 'Connect SSH first',
                    'WebSocket 连接失败': 'WebSocket connection failed',
                    '输入连接信息后点击 SSH 按钮连接服务器': 'Enter the connection details, then click SSH to connect to the server',
                    '连接已断开': 'Disconnected',
                    'SSH 连接已断开': 'SSH disconnected',
                    '串口终端 - 已连接': 'Serial Terminal - Connected',
                    '填写本机 SSH 凭据后点击 "连接" 按钮开启终端': 'Enter local SSH credentials, then click "Connect" to start the terminal',
                    '点击 "启动" 按钮开启终端': 'Click "Start" to launch the terminal',
                    '点击 "连接串口" 按钮选择串口设备': 'Click "Connect Serial" to choose a serial device',
                    '当前平台不允许访问串口': 'Serial access is not available on the current platform',
                    '波形数据: Sin, Cos, Sin3Hz, ADC, Temp': 'Waveform data: Sin, Cos, Sin3Hz, ADC, Temp',
                    '统计数据: stats:[a:x, b:x, c:x, d:x] 格式': 'Statistics data: stats:[a:x, b:x, c:x, d:x] format',
                    '点击 "波形" 或 "统计" 按钮查看实时图表': 'Click "Waveform" or "Statistics" to view real-time charts',
                    '数据过快，已丢弃部分内容': 'Data arrived too fast. Some content was dropped.',
                    '正在上传文件...': 'Uploading file...',
                    '文件上传失败': 'File upload failed',
                    'Web 终端 - 本机 SSH': 'Web Terminal - Local SSH',
                    '目标为本机 OpenSSH Server，用于提供 Windows 终端 PTY 语义': 'The target is the local OpenSSH Server, which provides PTY semantics for the Windows terminal',
                    'SSH 连接失败，请确认 OpenSSH Server 已启用并允许本机登录': 'SSH connection failed. Make sure OpenSSH Server is enabled and allows local sign-in.',
                    'Windows 下通过 OpenSSH Server 为 Web 终端提供 PTY/ConPTY 语义。': 'On Windows, OpenSSH Server provides PTY/ConPTY semantics for the web terminal.',
                    '已连接': 'Connected',
                    '无进程数据': 'No process data',
                    '未连接到SSH': 'SSH is not connected',
                    '进程信号已发送': 'Process signal sent',
                    '操作失败': 'Operation failed',
                    'Docker 不可用': 'Docker unavailable',
                    '暂无运行中的容器': 'No running containers',
                    '未检测到正在运行的容器': 'No running containers detected',
                    '请选择一个容器': 'Select a container',
                    '请从左侧选择容器': 'Select a container from the left',
                    '已用': 'used',
                    '无限制': 'unlimited',
                    '总流量': 'total traffic',
                    '容器叠加': 'containers combined',
                    '列表错误': 'List error',
                    '文件夹创建成功': 'Folder created successfully',
                    '删除成功': 'Deleted successfully',
                    '请先选择要下载的文件': 'Select files to download first',
                    '请选择有效的文件': 'Select valid files',
                    '下载失败': 'Download failed',
                    '下载完成': 'Download complete',
                    '空目录': 'Empty directory',
                    '暂无保存的主机': 'No saved hosts',
                    '密钥登录': 'Key authentication',
                    '密码登录': 'Password authentication',
                    '编辑': 'Edit',
                    '加载主机列表失败': 'Failed to load host list',
                    '主机已保存': 'Host saved',
                    '保存失败': 'Save failed',
                    '主机已更新': 'Host updated',
                    '更新失败': 'Update failed',
                    '主机已删除': 'Host deleted',
                    '删除失败': 'Delete failed',
                    '加载白名单失败': 'Failed to load allowlist',
                    '白名单已更新': 'Allowlist updated',
                    '请输入网段': 'Enter a network',
                    '暂无白名单': 'Allowlist is empty',
                    '私有网段': 'Private network',
                    '内存 %': 'Memory %',
                    '磁盘读 KB/s': 'Disk Read KB/s',
                    '磁盘写 KB/s': 'Disk Write KB/s',
                    '当前环境不支持 Web Serial': 'The current environment does not support Web Serial',
                    '请使用支持 Web Serial 的桌面应用或 Chromium 内核浏览器': 'Use the desktop app or a Chromium-based browser with Web Serial support',
                    '请先断开当前连接': 'Disconnect the current connection first',
                    '演示模式已启动': 'Demo mode started',
                    '串口已连接': 'Serial connected',
                    '未选择串口设备': 'No serial device selected',
                    '未知错误': 'Unknown error',
                    '串口权限被拒绝，请在权限弹窗中允许串口访问。': 'Serial access was denied. Allow the port in the permission dialog.',
                    '当前用户可能没有串口设备权限，请将用户加入 dialout/uucp 组并重新登录。': 'The current user may not have permission to access serial devices. Add the user to the dialout/uucp group and sign in again.',
                    '串口被占用或无权限访问，请检查设备占用和用户组权限。': 'The serial port is busy or access is denied. Check whether the device is in use and verify group permissions.',
                    '演示模式已停止': 'Demo mode stopped',
                    '串口已断开': 'Serial disconnected',
                    '演示模式': 'Demo Mode',
                    '串口终端 - 演示模式': 'Serial Terminal - Demo Mode',
                    '烧录器 Adapter': 'Adapter',
                    '来自 OpenOCD 的 adapter list，通常映射到 interface/<adapter>.cfg。': 'Taken from the OpenOCD adapter list, usually mapped to interface/<adapter>.cfg.',
                    '目标配置': 'Target Config',
                    '支持从 OpenOCD 的 target 目录中搜索并选择 .cfg。': 'Supports searching and selecting .cfg files from the OpenOCD target directory.',
                    '适配器速率 (kHz)': 'Adapter Speed (kHz)',
                    '支持从 OpenOCD 的 interface 目录中搜索并选择 .cfg。': 'Supports searching and selecting .cfg files from the OpenOCD interface directory.',
                    'OpenOCD 会按 GUI 选项追加 verify/reset/exit 指令。': 'OpenOCD appends verify/reset/exit commands according to the GUI options.',
                    '优先自动列出已连接 probe，也可手动填写 UID 或部分 UID。': 'Connected probes are listed automatically first, or you can enter a UID or partial UID manually.',
                    '例如 cmsisdap:12345678 或部分 UID': 'For example: cmsisdap:12345678 or a partial UID',
                    '目标芯片': 'Target Chip',
                    '例如 stm32f103rc': 'For example: stm32f103rc',
                    '请输入 pyOCD 支持的目标芯片名称。': 'Enter a pyOCD target name.',
                    '调试频率 (Hz)': 'Debug Frequency (Hz)',
                    '例如 1000000、10m': 'For example: 1000000 or 10m',
                    'pyOCD 的写后校验沿用自身默认烧录策略。': 'pyOCD uses its default verification behavior after flashing.',
                    'Probe 选择': 'Probe Selector',
                    '优先自动列出当前 probe，也可手动填写 probe 选择串。': 'The current probe is listed automatically first, or you can enter a probe selector manually.',
                    '例如 0483:3748 或 0483:3748:SERIAL': 'For example: 0483:3748 or 0483:3748:SERIAL',
                    '请输入 probe-rs 支持的芯片名称。': 'Enter a chip name supported by probe-rs.',
                    '例如 STM32F103C8': 'For example: STM32F103C8',
                    '调试速率 (kHz)': 'Debug Speed (kHz)',
                    'probe-rs 的写后校验沿用当前 CLI 默认行为。': 'probe-rs uses the current CLI default verification behavior.',
                    '载入 ELF，适合在启动 GDB CLI 后绑定当前目标程序。': 'Load an ELF file, typically after starting the GDB CLI for the current target program.',
                    'ELF 路径': 'ELF path',
                    '例如 /tmp/app.elf': 'For example: /tmp/app.elf',
                    '当前 Entrance 进程已经具备 root 权限，烧录/调试命令会直接以 root 身份执行。': 'The current Entrance process already has root privileges, so flash/debug commands will run directly as root.',
                    '启用后将通过 pkexec / Polkit 请求 root 权限。': 'When enabled, root privileges will be requested through pkexec / Polkit.',
                    '当前 Linux 主机未检测到可用的提权方式。请安装 pkexec，或安装 zenity/kdialog 以配合 sudo 图形密码对话框。': 'No usable elevation method was detected on the current Linux host. Install pkexec, or install zenity/kdialog for a sudo graphical password dialog.',
                    '启用后将通过 sudo + macOS 系统密码对话框请求管理员权限。': 'When enabled, administrator privileges will be requested through the macOS system password dialog with sudo.',
                    '当前 macOS 主机缺少 sudo 或 osascript，无法弹出管理员权限请求。': 'The current macOS host is missing sudo or osascript, so it cannot show an administrator privilege prompt.',
                    '启用后将通过 gsudo / UAC 请求管理员权限。': 'When enabled, administrator privileges will be requested through gsudo / UAC.',
                    '启用后将通过 Windows sudo / UAC 请求管理员权限。': 'When enabled, administrator privileges will be requested through Windows sudo / UAC.',
                    '当前 Windows 主机未检测到 gsudo 或 sudo，无法请求管理员权限。': 'The current Windows host did not detect gsudo or sudo, so it cannot request administrator privileges.',
                    '当前平台暂不支持管理员/root 提权。': 'Admin/root elevation is not supported on the current platform.',
                    '未找到 OpenOCD 配置目录，请检查系统默认目录或 OpenOCD 安装目录': 'OpenOCD config directory was not found. Check the system default directory or the OpenOCD installation directory.',
                    'ESP32 使用 OpenOCD 烧录时，请选择 app.bin 或 flasher_args.json；不要直接选择 ELF': 'When flashing ESP32 with OpenOCD, choose app.bin or flasher_args.json instead of selecting an ELF directly.',
                    '请填写烧录器或接口配置': 'Enter a probe or interface config',
                    'CLI 会话已通过 script PTY 包装，以确保交互式 GDB 输出实时返回到消息框。': 'The CLI session is wrapped with a script PTY so interactive GDB output can stream back to the log in real time.',
                    'OpenOCD 会优先匹配 interface/<adapter>.cfg；若不存在，则按 adapter driver 自动反查接口配置。': 'OpenOCD prefers matching interface/<adapter>.cfg first; if it does not exist, it falls back to resolving the interface config from the adapter driver.',
                    '若板卡需要自定义接口文件或脚本目录，可在附加参数中补充。': 'If the board needs a custom interface file or script directory, add it in the extra arguments.',
                    'pyOCD 会优先列出当前已连接的 probe；未检测到时可手动填写 UID。': 'pyOCD lists currently connected probes first. If none are detected, enter the UID manually.',
                    '写后校验沿用 pyOCD 内置烧录策略。': 'Verification after flashing follows the built-in pyOCD behavior.',
                    'probe-rs 的实时调试使用 GDB server 模式，请用支持 GDB Remote 的调试器连接。': 'probe-rs live debugging uses GDB server mode. Connect with a debugger that supports GDB Remote.',
                    '若本机 CLI 版本参数存在差异，可在附加参数中补充。': 'If the local CLI version uses different arguments, add them in the extra arguments.',
                    '模板: VID:PID': 'Template: VID:PID',
                    '模板: VID:PID:Serial': 'Template: VID:PID:Serial',
                    '不支持的工具类型': 'Unsupported tool type',
                    '工具路径': 'Tool path',
                    '手动路径不存在': 'Manual path does not exist',
                    '手动路径不是可执行文件': 'Manual path is not an executable file',
                    '手动路径不可执行': 'Manual path is not executable',
                    '手动路径与所选工具不匹配': 'Manual path does not match the selected tool',
                    'GDB 手动路径不存在': 'Manual GDB path does not exist',
                    'GDB 手动路径不是可执行文件': 'Manual GDB path is not an executable file',
                    'GDB 手动路径不可执行': 'Manual GDB path is not executable',
                    'GDB 手动路径与 gdb / arm-none-eabi-gdb / gdb-multiarch 不匹配': 'Manual GDB path does not match gdb / arm-none-eabi-gdb / gdb-multiarch',
                    '未找到可用的 GDB，请安装 gdb / arm-none-eabi-gdb / gdb-multiarch，或填写手动路径': 'No usable GDB was found. Install gdb / arm-none-eabi-gdb / gdb-multiarch, or enter a manual path.',
                    '当前 Entrance 进程已经具备管理员/root 权限，已直接执行命令。': 'The current Entrance process already has admin/root privileges, so the command was executed directly.',
                    '当前平台无法请求管理员/root 权限': 'The current platform cannot request admin/root privileges',
                    '已启用 root 提权，请在系统认证对话框中确认。': 'Root elevation is enabled. Confirm it in the system authentication dialog.',
                    '已启用 sudo 管理员/root 权限请求。': 'sudo admin/root privilege request is enabled.',
                    '已启用管理员权限请求，请在系统对话框中确认。': 'Administrator privilege request is enabled. Confirm it in the system dialog.',
                    '若系统 sudo 配置为新窗口模式，实时日志展示可能受限；如需更好的集成效果，建议优先安装 gsudo。': 'If sudo is configured to open a new window, real-time log streaming may be limited. For better integration, prefer installing gsudo.',
                    '附加参数格式无效，请检查引号或转义符': 'Extra argument format is invalid. Check quotes or escape characters.',
                    '寄存器名格式无效': 'Register name format is invalid',
                    '选项值': 'Option value',
                    '选项标签': 'Option label',
                    '目标名称': 'Target name',
                    '目标标签': 'Target label',
                    '目标元信息': 'Target metadata',
                    '目标关键字': 'Target keywords',
                    '已切换到 ESP-IDF 多镜像烧录模式，将按 flasher_args.json 烧录 bootloader、partition table 和 app。': 'Switched to ESP-IDF multi-image flash mode. bootloader, partition table, and app will be flashed according to flasher_args.json.',
                    '已切换到 ESP32 app bin 烧录模式，默认按应用分区偏移 0x10000 写入。若使用自定义分区，请改用 flasher_args.json。': 'Switched to ESP32 app bin flash mode. The file will be written to the default app partition offset 0x10000. If you use a custom partition layout, use flasher_args.json instead.',
                    '未检测到已连接 probe，已回退显示 pyOCD debug-probe 插件前缀。': 'No connected probe was detected. Fell back to showing pyOCD debug-probe plugin prefixes.',
                    '未检测到已连接 probe，可按 VID:PID 或 VID:PID:Serial 手动输入。': 'No connected probe was detected. You can enter VID:PID or VID:PID:Serial manually.',
                    '读取 probe-rs 芯片目录超时': 'Timed out while reading the probe-rs chip catalog',
                    '读取 pyOCD 目标目录超时': 'Timed out while reading the pyOCD target catalog',
                    '读取 probe-rs 芯片目录失败': 'Failed to read the probe-rs chip catalog',
                    '读取 pyOCD 目标目录失败': 'Failed to read the pyOCD target catalog',
                    '未能从 probe-rs 输出中解析芯片目录': 'Could not parse the chip catalog from probe-rs output',
                    '未能从 pyOCD 输出中解析目标目录': 'Could not parse the target catalog from pyOCD output',
                    '速率': 'Speed',
                    'GDB 端口': 'GDB port',
                    '写后校验沿用 pyOCD 内置策略。': 'Post-write verification follows the built-in pyOCD strategy.',
                    'probe-rs 的烧录使用 download 子命令，支持 bin/hex/elf 等文件。': 'probe-rs flashing uses the download subcommand and supports bin/hex/elf files.',
                    'GDB 命令': 'GDB command',
                    '主机或 host:port': 'Host or host:port',
                    '忽略次数不能为空': 'Ignore count cannot be empty',
                    '帧号': 'Frame index',
                    '帧号不能为空': 'Frame index cannot be empty',
                    '显示项 ID': 'Display item ID',
                    '读取数量': 'Read count',
                    '读取格式': 'Read format',
                    '读取格式仅支持 b / h / w / i': 'Read format only supports b / h / w / i',
                    '内存类型': 'Memory type',
                    '不支持的 GDB 命令': 'Unsupported GDB command',
                    'probe-rs 协议仅支持 swd 或 jtag': 'probe-rs protocol only supports swd or jtag',
                    'probe-rs 原生命令仅在选择 probe-rs 调试器时可用': 'Native probe-rs commands are only available when the probe-rs debugger is selected',
                    'probe-rs 命令': 'probe-rs command',
                    '已执行 probe-rs list，用于探测当前已连接的 probe。': 'Executed probe-rs list to detect currently connected probes.',
                    '已执行 probe-rs info，用于查询当前 session 状态与目标识别信息。': 'Executed probe-rs info to query current session state and target identification information.',
                    '已执行 probe-rs reset。': 'Executed probe-rs reset.',
                    '已执行 probe-rs erase（整片擦除）。': 'Executed probe-rs erase (full chip erase).',
                    '下载文件路径': 'Download file path',
                    '跳过字节数': 'Skip bytes',
                    '已执行 probe-rs download。': 'Executed probe-rs download.',
                    '校验文件路径': 'Verify file path',
                    '已执行 probe-rs verify。': 'Executed probe-rs verify.',
                    '读取宽度': 'Read width',
                    '读取地址': 'Read address',
                    '读取宽度仅支持 b8 / b16 / b32 / b64': 'Read width only supports b8 / b16 / b32 / b64',
                    '已执行 probe-rs read。': 'Executed probe-rs read.',
                    '写入宽度': 'Write width',
                    '写入地址': 'Write address',
                    '写入宽度仅支持 b8 / b16 / b32 / b64': 'Write width only supports b8 / b16 / b32 / b64',
                    '至少需要一个写入值': 'At least one value to write is required',
                    '已执行 probe-rs write。': 'Executed probe-rs write.',
                    '已执行 probe-rs trace。': 'Executed probe-rs trace.',
                    'RTT ELF 路径': 'RTT ELF path',
                    '已执行 probe-rs attach（RTT/日志 attach）。': 'Executed probe-rs attach (RTT/log attach).',
                    '不支持的 probe-rs 原生命令': 'Unsupported native probe-rs command',
                    '操作类型': 'Action type',
                    '仅支持烧录和实时调试': 'Only flash and live debug are supported',
                    'CLI 会话未启动': 'CLI session is not started',
                    'CLI 命令': 'CLI command',
                    'CLI 命令发送失败': 'Failed to send the CLI command',
                    '会话类型': 'Session type',
                    'CLI 会话尚未启动': 'CLI session has not started yet',
                    '不支持的操作类型': 'Unsupported action type',
                    '服务正在关闭': 'Service is shutting down',
                    '用户停止': 'Stopped by user',
                    '连接已关闭': 'Connection closed',
                    '新的操作已接管当前会话': 'A new action has taken over the current session',
                    '新的调试服务已接管当前烧录会话': 'A new debug service has taken over the current flash session',
                    '新的烧录会话已接管当前调试服务': 'A new flash session has taken over the current debug service',
                    '新的 CLI 会话已接管当前会话': 'A new CLI session has taken over the current session',
                    '新的 probe-rs 原生命令已接管当前会话': 'A new native probe-rs command has taken over the current session',
                    '烧录调试连接已关闭': 'Flash/debug connection closed',
                    'Shell 不在 PATH 中或不可执行': 'The shell is not in PATH or is not executable',
                    '未找到可用的 PATH Shell': 'No usable shell was found in PATH',
                    '仅管理员可使用本机 SSH 终端': 'Only administrators can use the local SSH terminal',
                    '当前平台不支持本机 SSH 终端模式': 'The current platform does not support local SSH terminal mode',
                    '本机 SSH 终端仅允许连接 localhost 或 127.0.0.1': 'The local SSH terminal only allows connections to localhost or 127.0.0.1',
                    '远程主机未安装 Docker': 'Docker is not installed on the remote host',
                    '无效的 PID': 'Invalid PID',
                    '只载入符号文件，不替换当前 executable。': 'Load symbol information only without replacing the current executable.',
                    '符号文件路径': 'Symbol file path',
                    '连接到当前实时调试服务暴露的 GDB Remote 端口。': 'Connect to the GDB remote port exposed by the current live debug service.',
                    '主机': 'Host',
                    '例如 3333 或 1337': 'For example: 3333 or 1337',
                    '断开当前 remote target 连接。': 'Disconnect the current remote target.',
                    '向目标装载当前 file/symbol-file 关联的 ELF。': 'Load the ELF referenced by the current file/symbol-file into the target.',
                    '对比 ELF 与目标端的 section 内容。': 'Compare section contents between the ELF and the target.',
                    '退出当前 GDB CLI 会话。': 'Exit the current GDB CLI session.',
                    '继续运行目标程序。': 'Continue the target program.',
                    '中断当前程序执行。': 'Interrupt the current program.',
                    '单步进入。': 'Step into.',
                    '单步越过。': 'Step over.',
                    '运行到当前函数返回。': 'Run until the current function returns.',
                    '运行到指定位置后停止。': 'Run until the specified location, then stop.',
                    '位置': 'Location',
                    '例如 main.c:128 或 func': 'For example: main.c:128 or func',
                    '跳转到指定源码位置或 `*0x...` 地址。': 'Jump to a source location or a `*0x...` address.',
                    '跳转位置': 'Jump location',
                    '例如 main.c:256 或 *0x08000100': 'For example: main.c:256 or *0x08000100',
                    '支持函数名或 文件:行号。': 'Supports function names or file:line syntax.',
                    '断点位置': 'Breakpoint location',
                    '例如 foo 或 main.c:42': 'For example: foo or main.c:42',
                    '一次性断点，命中后自动删除。': 'One-shot breakpoint, automatically removed after it is hit.',
                    '临时断点位置': 'Temporary breakpoint location',
                    '例如 main.c:88': 'For example: main.c:88',
                    '硬件断点；受硬件资源数量限制。': 'Hardware breakpoint; limited by available hardware resources.',
                    '硬件断点位置': 'Hardware breakpoint location',
                    '列出当前全部断点/观察点。': 'List all current breakpoints and watchpoints.',
                    '留空等价于 `delete`，会删除全部断点。': 'Leave empty to run `delete` and remove all breakpoints.',
                    '断点 ID': 'Breakpoint ID',
                    '留空则删除全部断点': 'Leave empty to delete all breakpoints',
                    '禁用指定断点。': 'Disable a breakpoint.',
                    '启用指定断点。': 'Enable a breakpoint.',
                    '为断点附加条件表达式。': 'Attach a conditional expression to a breakpoint.',
                    '条件表达式': 'Conditional expression',
                    '例如 counter > 10': 'For example: counter > 10',
                    '让指定断点先忽略前 N 次命中。': 'Ignore the first N hits for a breakpoint.',
                    '忽略次数': 'Ignore count',
                    '例如 5': 'For example: 5',
                    '写观察点。': 'Write watchpoint.',
                    '表达式': 'Expression',
                    '例如 some_var': 'For example: some_var',
                    '读观察点。': 'Read watchpoint.',
                    '读写观察点。': 'Read/write watchpoint.',
                    '输出当前调用栈。': 'Print the current call stack.',
                    '切换到指定栈帧。': 'Switch to a stack frame.',
                    '栈帧号': 'Frame number',
                    '例如 0': 'For example: 0',
                    '移动到上一个栈帧。': 'Move to the previous stack frame.',
                    '移动到下一个栈帧。': 'Move to the next stack frame.',
                    '显示当前栈帧详细信息。': 'Show details for the current stack frame.',
                    '显示当前函数参数。': 'Show current function arguments.',
                    '显示当前函数局部变量。': 'Show current local variables.',
                    '按默认格式打印表达式。': 'Print an expression with the default format.',
                    '例如 var': 'For example: var',
                    '按十六进制打印表达式。': 'Print an expression in hexadecimal.',
                    '按十进制打印表达式。': 'Print an expression in decimal.',
                    '按二进制打印表达式。': 'Print an expression in binary.',
                    '例如 flags': 'For example: flags',
                    '持续显示表达式。': 'Continuously display an expression.',
                    '取消指定 display 项。': 'Remove a display entry.',
                    '变量名': 'Variable name',
                    '值': 'Value',
                    '直接修改变量值。': 'Modify a variable value directly.',
                    '例如 123': 'For example: 123',
                    '查看表达式的类型名。': 'Show an expression type name.',
                    '显示表达式/类型的完整类型定义。': 'Show the full type definition for an expression or type.',
                    '表达式或类型': 'Expression or type',
                    '例如 foo': 'For example: foo',
                    '显示核心寄存器。': 'Show core registers.',
                    '显示全部寄存器。': 'Show all registers.',
                    '快速打印单个寄存器值。': 'Print a single register value quickly.',
                    '寄存器名': 'Register name',
                    '例如 pc、sp、lr、xpsr': 'For example: pc, sp, lr, xpsr',
                    '修改 PC / SP 等寄存器。': 'Modify registers such as PC or SP.',
                    '例如 pc 或 sp': 'For example: pc or sp',
                    '例如 0x08000000': 'For example: 0x08000000',
                    '格式填写 b/h/w/i；例如 32 + b + 0x20000000 对应 x/32bx。': 'Use b/h/w/i for the format. For example, 32 + b + 0x20000000 becomes x/32bx.',
                    '数量': 'Count',
                    '例如 32': 'For example: 32',
                    '格式': 'Format',
                    'b / h / w / i': 'b / h / w / i',
                    '地址': 'Address',
                    '例如 0x20000000': 'For example: 0x20000000',
                    '可用于向 RAM 或寄存器映射地址写值。': 'Useful for writing values to RAM or memory-mapped registers.',
                    '类型': 'Type',
                    '例如 uint32_t': 'For example: uint32_t',
                    '例如 0x12345678': 'For example: 0x12345678',
                    '把目标内存导出为 binary。': 'Export target memory to a binary file.',
                    '导出文件': 'Output file',
                    '例如 /tmp/ram.bin': 'For example: /tmp/ram.bin',
                    '起始地址': 'Start address',
                    '结束地址': 'End address',
                    '例如 0x20000100': 'For example: 0x20000100',
                    '从 binary 文件恢复到目标内存。': 'Restore target memory from a binary file.',
                    '导入文件': 'Input file',
                    '装载地址': 'Load address',
                    '留空时反汇编当前上下文。': 'Disassemble the current context when left empty.',
                    '可选，例如 main': 'Optional, for example: main',
                    '混合源码与汇编。': 'Mix source and assembly.',
                    '附带原始机器码。': 'Include raw machine code.',
                    '留空时显示当前位置源码。': 'Show source at the current location when left empty.',
                    '可选，例如 main.c:128': 'Optional, for example: main.c:128',
                    'OpenOCD / pyOCD 专用透传；probe-rs 下不会显示独占快捷区。': 'OpenOCD / pyOCD passthrough only; the dedicated shortcut area is hidden when probe-rs is selected.',
                    'monitor 命令': 'Monitor command',
                    '例如 reset halt': 'For example: reset halt',
                    '查看当前 PC 附近 8 条指令。': 'Show the 8 instructions near the current PC.',
                    '内部会执行 `tbreak <file>:<line>` 再 `continue`。': 'Internally runs `tbreak <file>:<line>` and then `continue`.',
                    '文件:行号': 'File:line',
                    '例如 main.c:200': 'For example: main.c:200',
                    '枚举当前已连接 probe。': 'List currently connected probes.',
                    '查询 probe 与 target 状态，等价 session state query / target info。': 'Query probe and target state, similar to session state query / target info.',
                    '复位目标，可配合 Under Reset 连接。': 'Reset the target and optionally combine it with Under Reset attach.',
                    '整片擦除。': 'Erase the entire chip.',
                    '下载 ELF / BIN / HEX；可结合 Verify Flash 与 Chip Erase。': 'Download ELF / BIN / HEX, optionally using Verify Flash and Chip Erase.',
                    '文件路径': 'File path',
                    '例如 /tmp/app.elf 或 /tmp/app.bin': 'For example: /tmp/app.elf or /tmp/app.bin',
                    'Binary 格式': 'Binary format',
                    '可选，例如 bin / elf / hex': 'Optional, for example: bin / elf / hex',
                    '基地址': 'Base address',
                    'bin 时可填，例如 0x08000000': 'Optional for bin, for example: 0x08000000',
                    '跳过字节': 'Skip bytes',
                    '可选，例如 0': 'Optional, for example: 0',
                    '对比文件与目标 flash 内容。': 'Compare the file with flash contents on the target.',
                    '读取 RAM / 外设内存；宽度支持 b8 / b16 / b32 / b64。': 'Read RAM or peripheral memory; widths include b8 / b16 / b32 / b64.',
                    '宽度': 'Width',
                    '例如 b32': 'For example: b32',
                    '写 RAM / 外设内存；多个值用空格分隔。': 'Write RAM or peripheral memory; separate multiple values with spaces.',
                    '写入值': 'Values to write',
                    '例如 0x1 0x2 0x3': 'For example: 0x1 0x2 0x3',
                    '持续 trace 指定内存位置。': 'Continuously trace the specified memory location.',
                    'Trace 地址': 'Trace address',
                    'RTT / defmt 日志 attach；需要 ELF 路径。': 'Attach RTT / defmt logging; requires an ELF path.',
                    'pyOCD 目标': 'pyOCD targets',
                    'pyOCD 目标目录': 'pyOCD Target Catalog',
                    'probe-rs 芯片': 'probe-rs chips',
                    'probe-rs 芯片目录': 'probe-rs Chip Catalog',
                    'OpenOCD target 配置': 'OpenOCD target config',
                    'OpenOCD interface 配置': 'OpenOCD interface config',
                    '输入关键字搜索 OpenOCD target 配置。': 'Type keywords to search OpenOCD target configs.',
                    '未找到匹配的 OpenOCD target 配置，可继续手动输入。': 'No matching OpenOCD target config found. You can keep typing manually.',
                    '输入关键字搜索 OpenOCD interface 配置。': 'Type keywords to search OpenOCD interface configs.',
                    '未找到匹配的 OpenOCD interface 配置，可继续手动输入。': 'No matching OpenOCD interface config found. You can keep typing manually.',
                    '未找到匹配项，可继续手动输入 pyOCD 目标名。': 'No match found. You can keep typing a pyOCD target name manually.',
                    '未找到匹配项，可继续手动输入芯片名。': 'No match found. You can keep typing a chip name manually.',
                    '当前值': 'current value',
                    '当前显示 probe-rs 选择模板，可按帮助格式手动补全。': 'Showing probe-rs selector templates. Complete them manually using the documented format.',
                    '当前未检测到候选项，可直接手动输入。': 'No candidates detected right now. You can type manually.',
                    '当前平台暂未检测到可用的管理员/root 提权方式。': 'No available admin/root elevation method was detected on the current platform.',
                    '自动列出 adapter / 留空手填': 'List adapters automatically / leave blank to type manually',
                    '自动列出 probe / 留空手填': 'List probes automatically / leave blank to type manually',
                    '仅管理员可启动本机烧录调试': 'Only administrators can start local flash/debug sessions',
                    '检测失败': 'Detection failed',
                    '系统默认目录': 'System default directory',
                    'OpenOCD 安装目录': 'OpenOCD installation directory',
                    '固件文件': 'firmware file',
                    'ELF 文件': 'ELF file',
                    '当前固件路径：': 'Current firmware path:',
                    '仅管理员可使用烧录调试功能': 'Only administrators can use flash/debug features',
                    '请先停止当前烧录 / CLI / probe-rs 原生命令任务': 'Stop the current flash / CLI / native probe-rs task first',
                    '请先启动 GDB CLI 会话': 'Start a GDB CLI session first',
                    '请选择 probe-rs 调试器后再执行原生命令': 'Select a probe-rs debugger before running native commands',
                    'probe-rs 原生命令执行前，请先停止当前烧录 / 调试 / CLI 会话': 'Stop the current flash / debug / CLI session before running native probe-rs commands',
                    '烧录调试 WebSocket 连接失败': 'Flash/debug WebSocket connection failed',
                    'GDB CLI 会话已启动': 'GDB CLI session started',
                    'probe-rs 原生命令已启动': 'Native probe-rs command started',
                    '烧录任务已启动': 'Flash task started',
                    '调试任务已启动': 'Debug task started',
                    'GDB CLI 会话已结束': 'GDB CLI session ended',
                    'probe-rs 原生命令已结束': 'Native probe-rs command ended',
                    '烧录任务已结束': 'Flash task ended',
                    '调试任务已结束': 'Debug task ended',
                    'CLI / probe-rs 运行中': 'CLI / probe-rs running',
                    'GDB CLI 运行中': 'GDB CLI running',
                    'probe-rs 运行中': 'probe-rs running',
                    '请先停止当前任务': 'Stop the current task first',
                    '当前主机未检测到可用的管理员/root 提权方式': 'No available admin/root elevation method was detected on the current host',
                    '当前平台无可选 Shell': 'No shell is available on the current platform',
                    'SSH 到': 'SSH to',
                    'Windows 下通过 SSH 连接本机，借助 OpenSSH Server 获取真正的终端语义。': 'On Windows, the local terminal connects back to the same machine over SSH so OpenSSH Server can provide real terminal semantics.',
                    '请先在系统中启用 OpenSSH Server，再使用本机账号登录。': 'Enable OpenSSH Server on the system first, then sign in with a local account.',
                    '无法检查终端服务状态': 'Unable to check terminal service status',
                    '权限不足': 'Permission denied',
                    '终端已启动': 'Terminal started',
                    '终端已退出': 'Terminal exited',
                    'SSH 端口范围必须是 1-65535': 'SSH port must be within 1-65535',
                    '请输入 Windows 用户名': 'Enter a Windows username',
                    '本机 SSH 终端已断开': 'Local SSH terminal disconnected',
                    '本机 SSH 连接失败': 'Local SSH connection failed',
                    '终端已停止': 'Terminal stopped',
                    '运行中': 'Running',
                    'VNC 连接意外断开': 'VNC connection closed unexpectedly',
                    'VNC 已断开': 'VNC disconnected',
                    '请输入 VNC 主机地址': 'Enter a VNC host address',
                    'VNC 模块未加载，请刷新页面': 'The VNC module is not loaded. Refresh the page.',
                    '请输入主机地址和用户名': 'Enter both host and username',
                    '删除': 'Delete',
                    '终端': 'Terminal',
                    '无进程数据': 'No process data',
                    '未连接到SSH': 'Not connected to SSH',
                    '进程信号已发送': 'Process signal sent',
                    '操作失败': 'Operation failed',
                    'Docker 不可用': 'Docker unavailable',
                    '暂无运行中的容器': 'No running containers',
                    '未检测到正在运行的容器': 'No running containers were detected',
                    '请选择一个容器': 'Select a container',
                    '请从左侧选择容器': 'Select a container from the left',
                    '无限制': 'Unlimited',
                    '容器叠加': 'containers aggregated',
                    '总流量': 'Total traffic',
                    '已用': 'used',
                    '文件夹创建成功': 'Folder created successfully',
                    '请先选择要下载的文件': 'Select files to download first',
                    '请选择有效的文件': 'Select a valid file',
                    '下载完成': 'Download completed',
                    '空目录': 'Empty folder',
                    '暂无保存的主机': 'No saved hosts yet',
                    '加载主机列表失败': 'Failed to load host list',
                    '密钥登录': 'Key authentication',
                    '暂无白名单': 'No allowlist entries',
                    '私有网段': 'Private network range',
                    '演示模式': 'Demo mode',
                    '串口终端 - 演示模式': 'Serial Terminal - Demo Mode',
                    '串口终端 - 已连接': 'Serial Terminal - Connected',
                    '固件文件': 'Firmware file',
                    'ELF 文件': 'ELF file',
                    'VNC 库加载失败，请刷新页面重试': 'The VNC library failed to load. Refresh the page and try again.',
                    'VNC 服务器需要密码': 'The VNC server requires a password',
                    '密码错误': 'Incorrect password'
                }
            },
            PATTERNS: {
                zh: [],
                en: [
                    [/^已连接到 (.+)$/u, 'Connected to $1'],
                    [/^已连接: (.+)$/u, 'Connected: $1'],
                    [/^SFTP 已连接到 (.+)$/u, 'SFTP connected to $1'],
                    [/^VNC 已连接到 (.+)$/u, 'VNC connected to $1'],
                    [/^容器: (.+)$/u, 'Container: $1'],
                    [/^总计 · (\d+) 个容器$/u, 'Total · $1 containers'],
                    [/^已选 (\d+) 项$/u, '$1 selected'],
                    [/^失败: (.+)$/u, (_match, message) => `Failed: ${I18n.auto(message)}`],
                    [/^下载失败: (.+)$/u, (_match, message) => `Download failed: ${I18n.auto(message)}`],
                    [/^保存失败: (.+)$/u, (_match, message) => `Save failed: ${I18n.auto(message)}`],
                    [/^更新失败: (.+)$/u, (_match, message) => `Update failed: ${I18n.auto(message)}`],
                    [/^认证失败: (.+)$/u, (_match, message) => `Authentication failed: ${I18n.auto(message)}`],
                    [/^加载白名单失败: (.+)$/u, (_match, message) => `Failed to load allowlist: ${I18n.auto(message)}`],
                    [/^密码修改失败: (.+)$/u, (_match, message) => `Password update failed: ${I18n.auto(message)}`],
                    [/^登录失败: (.+)$/u, (_match, message) => `Sign-in failed: ${I18n.auto(message)}`],
                    [/^登录保持时间更新失败: (.+)$/u, (_match, message) => `Session keepalive update failed: ${I18n.auto(message)}`],
                    [/^连接失败: (.+)$/u, (_match, message) => `Connection failed: ${I18n.auto(message)}`],
                    [/^当前登录保持时间：(.+)$/u, 'Current session keepalive: $1'],
                    [/^列表错误: (.+)$/u, (_match, message) => `List error: ${I18n.auto(message)}`],
                    [/^例如\s*(.+)$/u, (_match, example) => `For example: ${String(example || '').replace(/、/gu, ', ').replace(/\s*或\s*/gu, ' or ').trim()}`],
                    [/^正在下载: (.+)$/u, 'Downloading: $1'],
                    [/^正在打包 (\d+) 个项目\.\.\.$/u, 'Packaging $1 items...'],
                    [/^正在发送 (.+) 到 PID (\d+)\.\.\.$/u, 'Sending $1 to PID $2...'],
                    [/^(.+) 连接失败$/u, (_match, label) => `${I18n.auto(label)} connection failed`],
                    [/^(.+) 连接被拦截：(.+)$/u, (_match, label, message) => `${I18n.auto(label)} connection blocked: ${I18n.auto(message)}`],
                    [/^(.+) 目标地址校验失败: (.+)$/u, (_match, label, message) => `${I18n.auto(label)} target validation failed: ${I18n.auto(message)}`],
                    [/^(.+) 目标地址校验失败$/u, '$1 target validation failed'],
                    [/^已上传 (.+)$/u, 'Uploaded $1'],
                    [/^正在上传 (.+) \((.+)\)\.\.\.$/u, 'Uploading $1 ($2)...'],
                    [/^已上传 (.+) \((.+)\)，当前路径：(.+)$/u, 'Uploaded $1 ($2), current path: $3'],
                    [/^当前固件路径：(.+)$/u, 'Current firmware path: $1'],
                    [/^当前 CLI ELF \/ 符号文件路径：(.+)$/u, 'Current CLI ELF / symbols path: $1'],
                    [/^当前未单独设置 CLI ELF，默认将沿用烧录文件路径：(.+)$/u, 'No separate CLI ELF is set. The flash file path will be used by default: $1'],
                    [/^(.+?) 未检测到已连接 probe，已回退显示 pyOCD debug-probe 插件前缀。$/u, (_match, prefix) => `${I18n.auto(prefix)} No connected probe was detected. Fell back to showing pyOCD debug-probe plugin prefixes.`],
                    [/^(.+?) 未检测到已连接 probe，可按 VID:PID 或 VID:PID:Serial 手动输入。$/u, (_match, prefix) => `${I18n.auto(prefix)} No connected probe was detected. You can enter VID:PID or VID:PID:Serial manually.`],
                    [/^(.+?) 当前显示 (\d+) 个 pyOCD 插件前缀，选择后可在右侧继续补充 UID。$/u, (_match, prefix, count) => `${I18n.auto(prefix)} Showing ${count} pyOCD probe prefixes. After selecting one, you can continue entering the UID on the right.`],
                    [/^(.+?) 当前显示 probe-rs 选择模板，可按帮助格式手动补全。$/u, (_match, prefix) => `${I18n.auto(prefix)} Showing probe-rs selector templates. Complete them manually using the help format.`],
                    [/^(.+?) 当前检测到 (\d+) 个候选项。$/u, (_match, prefix, count) => `${I18n.auto(prefix)} ${count} candidates detected.`],
                    [/^(.+?) 当前未检测到候选项，可直接手动输入。$/u, (_match, prefix) => `${I18n.auto(prefix)} No candidates detected right now. You can type manually.`],
                    [/^当前显示 (\d+) 个 pyOCD 插件前缀，选择后可在右侧继续补充 UID。$/u, 'Showing $1 pyOCD probe prefixes. After selecting one, you can continue entering the UID on the right.'],
                    [/^当前检测到 (\d+) 个候选项。$/u, '$1 candidates detected.'],
                    [/^正在检测 (.+) \.\.\.$/u, 'Checking $1...'],
                    [/^SSH 到 (.+)$/u, 'SSH to $1'],
                    [/^当前服务器: (.+)$/u, 'Current server: $1'],
                    [/^PATH: (.+)$/u, 'PATH: $1'],
                    [/^自定义: (.+)$/u, 'Custom: $1'],
                    [/^(.+) 未在 PATH 中找到，请填写手动路径$/u, '$1 was not found in PATH. Enter the path manually.'],
                    [/^未载入 (.+)：(.+)$/u, (_match, label, message) => `${I18n.auto(label)} not loaded: ${I18n.auto(message)}`],
                    [/^(.+)尚未载入，可直接手动输入。$/u, (_match, label) => `${I18n.auto(label)} is not loaded yet. You can type it manually.`],
                    [/^正在等待 (.+)，期间仍可直接手动输入。$/u, (_match, label) => `Waiting for ${I18n.auto(label)}. You can still type it manually.`],
                    [/^输入关键字搜索 (.+)。$/u, (_match, label) => `Type keywords to search ${I18n.auto(label)}.`],
                    [/^未找到匹配项，可继续手动输入 (.+)。$/u, (_match, label) => `No match found. You can keep entering ${I18n.auto(label)} manually.`],
                    [/^已载入 (\d+) 个(.+)，输入时支持前缀、片段和模糊搜索。$/u, (_match, count, label) => `Loaded ${count} ${I18n.auto(String(label || '').trim())}. Prefix, substring, and fuzzy search are supported when typing.`],
                    [/^已载入 (\d+) 个 target 配置，来源：(.+) (.+)；输入时支持前缀、片段和模糊搜索。$/u, (_match, count, sourceLabel, dir) => `Loaded ${count} target configs from ${I18n.auto(sourceLabel)} ${dir}. Prefix, substring, and fuzzy search are supported when typing.`],
                    [/^已载入 (\d+) 个 interface 配置，来源：(.+) (.+)；输入时支持前缀、片段和模糊搜索。$/u, (_match, count, sourceLabel, dir) => `Loaded ${count} interface configs from ${I18n.auto(sourceLabel)} ${dir}. Prefix, substring, and fuzzy search are supported when typing.`],
                    [/^删除 "(.+)"\?$/u, 'Delete "$1"?'],
                    [/^正在连接 (.+)\.\.\.$/u, 'Connecting to $1...'],
                    [/^错误: (.+)$/u, (_match, message) => `Error: ${I18n.auto(message)}`],
                    [/^读取错误: (.+)$/u, (_match, message) => `Read error: ${I18n.auto(message)}`],
                    [/^串口已连接 \((.+)\)$/u, 'Serial connected ($1)'],
                    [/^建议: (.+)$/u, (_match, message) => `Suggestion: ${I18n.auto(message)}`],
                    [/^终端已退出 \(code: (.+)\)$/u, 'Terminal exited (code: $1)'],
                    [/^Shell 进程错误: (.+)$/u, (_match, message) => `Shell process error: ${I18n.auto(message)}`],
                    [/^启动 shell 失败: (.+)$/u, (_match, message) => `Failed to start shell: ${I18n.auto(message)}`],
                    [/^发送信号失败: (.+)$/u, (_match, message) => `Failed to send signal: ${I18n.auto(message)}`],
                    [/^已发送 (.+) 到 PID (\d+)$/u, 'Sent $1 to PID $2'],
                    [/^上传了 (\d+) 个文件$/u, 'Uploaded $1 files'],
                    [/^终端 - (.+)$/u, 'Terminal - $1'],
                    [/^Web 终端 - (.+)$/u, 'Web Terminal - $1'],
                    [/^串口终端 - (.+)$/u, 'Serial Terminal - $1'],
                    [/^总计 (\d+) 个，运行中 (\d+) 个$/u, '$1 total, $2 running'],
                    [/^(\d+) 个容器叠加$/u, 'Aggregated across $1 containers'],
                    [/^(.+)格式无效$/u, (_match, field) => `Invalid ${I18n.auto(field)} format`],
                    [/^(.+)长度超过限制$/u, (_match, field) => `${I18n.auto(field)} exceeds the length limit`],
                    [/^(.+)不能为空$/u, (_match, field) => `${I18n.auto(field)} cannot be empty`],
                    [/^(.+)必须是整数$/u, (_match, field) => `${I18n.auto(field)} must be an integer`],
                    [/^(.+)范围无效$/u, (_match, field) => `Invalid range for ${I18n.auto(field)}`],
                    [/^(.+)不能包含换行$/u, (_match, field) => `${I18n.auto(field)} cannot contain newlines`],
                    [/^启用后将通过 sudo \+ (.+) 图形密码对话框请求 root 权限。$/u, 'When enabled, root privileges will be requested through sudo + $1 graphical password dialog.'],
                    [/^已为 ESP USB Bridge 自动设置 chip_id=(.+)。$/u, 'Automatically set chip_id=$1 for ESP USB Bridge.'],
                    [/^已将 (.+) 自动修正为 (.+)。$/u, 'Automatically normalized $1 to $2.'],
                    [/^调试服务已准备，GDB 端口 (\d+)，Telnet 端口 (\d+)。$/u, 'Debug service is ready. GDB port $1, Telnet port $2.'],
                    [/^GDB 调试服务已准备，监听端口 (\d+)。$/u, 'GDB debug service is ready and listening on port $1.'],
                    [/^GDB CLI 已启动，并将自动连接目标 (.+):(\d+)。$/u, 'GDB CLI started and will automatically connect to target $1:$2.'],
                    [/^GDB CLI 已启动，可稍后手动执行 target extended-remote。$/u, 'GDB CLI started. You can run target extended-remote manually later.']
                ]
            },
            init() {
                State.language = Storage.getLanguage() === 'zh' ? 'zh' : 'en';
                window.confirm = (message) => this.nativeConfirm(this.auto(message));
                window.alert = (message) => this.nativeAlert(this.auto(message));
                if (!this.observer) {
                    this.observer = new MutationObserver((mutations) => {
                        if (this.applying) return;
                        mutations.forEach((mutation) => {
                            if (mutation.type === 'childList') {
                                mutation.addedNodes.forEach((node) => this.applyTree(node, true));
                            } else if (mutation.type === 'characterData') {
                                this.applyTextNode(mutation.target, true);
                            } else if (mutation.type === 'attributes') {
                                this.applyElementAttributes(mutation.target, true, [mutation.attributeName]);
                            }
                        });
                    });
                }
                this.refresh();
            },
            setLanguage(language) {
                const next = language === 'en' ? 'en' : 'zh';
                if (State.language === next) return;
                State.language = next;
                Storage.setLanguage(next);
                this.refresh();
            },
            startObserver() {
                if (!this.observer || this.observing) return;
                this.observer.observe(document.body, {
                    subtree: true,
                    childList: true,
                    characterData: true,
                    attributes: true,
                    attributeFilter: ['placeholder', 'title', 'aria-label']
                });
                this.observing = true;
            },
            stopObserver() {
                if (!this.observer || !this.observing) return;
                this.observer.disconnect();
                this.observing = false;
            },
            refresh(root = document.body) {
                const shouldResumeObserver = Boolean(this.observer);
                this.stopObserver();
                try {
                    document.documentElement.lang = State.language === 'en' ? 'en' : 'zh-CN';
                    this.applyTree(root, false);
                    if (typeof Theme !== 'undefined' && document.getElementById('colorSchemeGrid')) {
                        Theme.renderSchemeGrid();
                    }
                    if (typeof Settings !== 'undefined' && document.getElementById('languageGrid')) {
                        Settings.renderLanguageGrid();
                    }
                } finally {
                    if (shouldResumeObserver) {
                        this.startObserver();
                    }
                }
            },
            apply(root = document.body) {
                document.documentElement.lang = State.language === 'en' ? 'en' : 'zh-CN';
                this.applyTree(root, false);
            },
            applyTree(node, refreshSource = false) {
                if (!node) return;
                this.applying = true;
                try {
                    this._applyTree(node, refreshSource);
                } finally {
                    this.applying = false;
                }
            },
            _applyTree(node, refreshSource = false) {
                if (!node) return;
                if (node.nodeType === Node.TEXT_NODE) {
                    this.applyTextNode(node, refreshSource);
                    return;
                }
                if (node.nodeType !== Node.ELEMENT_NODE) return;
                if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(node.tagName)) return;
                this.applyElementAttributes(node, refreshSource);
                node.childNodes.forEach((child) => this._applyTree(child, refreshSource));
            },
            applyTextNode(node, refreshSource = false) {
                if (!node || node.nodeType !== Node.TEXT_NODE || !node.parentElement) return;
                if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(node.parentElement.tagName)) return;
                const raw = node.textContent || '';
                if (!raw.trim()) return;
                if (refreshSource || !Object.prototype.hasOwnProperty.call(node, '__i18nSource')) {
                    node.__i18nSource = raw;
                }
                const source = node.__i18nSource || raw;
                const leading = source.match(/^\s*/u)?.[0] || '';
                const trailing = source.match(/\s*$/u)?.[0] || '';
                const core = source.trim();
                const translated = this.auto(core);
                if (translated === core && raw === `${leading}${translated}${trailing}`) return;
                node.textContent = `${leading}${translated}${trailing}`;
            },
            applyElementAttributes(element, refreshSource = false, attrs = ['placeholder', 'title', 'aria-label']) {
                if (!element || element.nodeType !== Node.ELEMENT_NODE) return;
                attrs.forEach((attr) => {
                    if (!element.hasAttribute(attr)) return;
                    const sourceKey = this.getSourceKey(attr);
                    const current = element.getAttribute(attr) || '';
                    if (refreshSource || !element.dataset[sourceKey]) {
                        element.dataset[sourceKey] = current;
                    }
                    const source = element.dataset[sourceKey] || current;
                    const translated = this.auto(source);
                    if (current !== translated) {
                        element.setAttribute(attr, translated);
                    }
                });
            },
            getSourceKey(attr) {
                return `i18n${attr.replace(/(^|-)([a-z])/g, (_, _dash, letter) => letter.toUpperCase())}Source`;
            },
            autoLine(value) {
                const text = String(value ?? '');
                if (State.language !== 'en' || !text) return text;
                const prefixed = text.match(/^(\s*\[[^\]]+\]\s*)(.*)$/u);
                if (prefixed) {
                    return `${prefixed[1]}${this.auto(prefixed[2])}`;
                }
                return this.auto(text);
            },
            autoMultiline(value) {
                const text = String(value ?? '');
                if (State.language !== 'en' || !text) return text;
                return text
                    .split(/(\r?\n)/u)
                    .map((part) => (/^\r?\n$/u.test(part) ? part : this.autoLine(part)))
                    .join('');
            },
            auto(value) {
                const text = String(value ?? '');
                if (State.language !== 'en' || !text) return text;
                const exact = this.EXACT.en[text];
                if (exact) return exact;
                for (const [pattern, replacement] of this.PATTERNS.en) {
                    const match = text.match(pattern);
                    if (match) {
                        return typeof replacement === 'function'
                            ? replacement(...match)
                            : text.replace(pattern, replacement);
                    }
                }
                return text;
            }
        };

        window.I18n = I18n;

        function buildIconTextHtml(iconClass, text) {
            return `<i class="fas ${escapeHtml(iconClass)}"></i><span>${escapeHtml(I18n.auto(text))}</span>`;
        }

        function buildInlineIconTextHtml(iconClass, text) {
            return `<i class="fas ${escapeHtml(iconClass)}"></i> ${escapeHtml(I18n.auto(text))}`;
        }

        function buildEmptyStateHtml(iconClass, text, className = 'empty') {
            const icon = iconClass ? `<i class="fas ${escapeHtml(iconClass)}"></i>` : '';
            const content = className === 'empty'
                ? `<p>${escapeHtml(I18n.auto(text))}</p>`
                : escapeHtml(I18n.auto(text));
            return `<div class="${escapeHtml(className)}">${icon}${content}</div>`;
        }

        function buildTablePlaceholderHtml(text, colspan = 10) {
            return `<tr><td colspan="${colspan}" style="text-align:center;color:var(--color-text-3);padding:20px">${escapeHtml(I18n.auto(text))}</td></tr>`;
        }

        function setI18nTextValue(element, source) {
            if (!element) return;
            const text = String(source ?? '');
            const shouldResumeObserver = Boolean(I18n.observer && I18n.observing);
            I18n.stopObserver();
            try {
                element.textContent = text;
                const node = element.firstChild;
                if (node && element.childNodes.length === 1 && node.nodeType === Node.TEXT_NODE) {
                    node.__i18nSource = text;
                }
                I18n.applyTree(element, false);
            } finally {
                if (shouldResumeObserver) {
                    I18n.startObserver();
                }
            }
        }

        function setI18nAttributeValue(element, attr, source) {
            if (!element) return;
            const text = String(source ?? '');
            const shouldResumeObserver = Boolean(I18n.observer && I18n.observing);
            I18n.stopObserver();
            try {
                const sourceKey = I18n.getSourceKey(attr);
                element.dataset[sourceKey] = text;
                element.setAttribute(attr, text);
                I18n.applyElementAttributes(element, false, [attr]);
            } finally {
                if (shouldResumeObserver) {
                    I18n.startObserver();
                }
            }
        }

        function buildWsUrl(path) {
            const url = new URL(path, Config.WS_BASE);
            if (State.token) {
                url.searchParams.set('token', State.token);
            }
            return url.toString();
        }

        async function apiFetch(url, options = {}) {
            const headers = { ...(options.headers || {}) };
            if (State.token) {
                headers.Authorization = `Bearer ${State.token}`;
            }
            const res = await fetch(url, { ...options, headers });
            if (res.status === 401) {
                Auth.handleUnauthorized();
            }
            return res;
        }

        const AUTH_TYPE_PASSWORD = 'password';
        const AUTH_TYPE_KEY = 'key';

        function escapeHtml(value) {
            return String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function normalizeAuthType(authType, privateKey = '') {
            const lowered = String(authType || '').trim().toLowerCase();
            if (lowered === AUTH_TYPE_KEY || lowered === 'privatekey' || lowered === 'private_key') {
                return AUTH_TYPE_KEY;
            }
            if (lowered === AUTH_TYPE_PASSWORD || lowered === 'pass') {
                return AUTH_TYPE_PASSWORD;
            }
            return privateKey ? AUTH_TYPE_KEY : AUTH_TYPE_PASSWORD;
        }

        function isValidPrivateKey(privateKey) {
            return /^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+-----END [A-Z0-9 ]*PRIVATE KEY-----$/.test(privateKey);
        }

        function updateAuthFields(prefix, authType) {
            const normalized = normalizeAuthType(authType);
            const passwordGroup = document.getElementById(`${prefix}PasswordGroup`);
            const keyPanel = document.getElementById(`${prefix}KeyPanel`);
            if (passwordGroup) {
                passwordGroup.style.display = normalized === AUTH_TYPE_KEY ? 'none' : '';
            }
            if (keyPanel) {
                keyPanel.classList.toggle('active', normalized === AUTH_TYPE_KEY);
            }
        }

        function readCredentialForm(prefix, options = {}) {
            const requireCredential = options.requireCredential !== false;
            const authTypeRaw = document.getElementById(`${prefix}AuthType`)?.value || AUTH_TYPE_PASSWORD;
            const password = document.getElementById(`${prefix}Pass`)?.value || '';
            const privateKey = (document.getElementById(`${prefix}PrivateKey`)?.value || '')
                .replace(/\r\n/g, '\n')
                .trim();
            const passphrase = document.getElementById(`${prefix}Passphrase`)?.value || '';
            const authType = normalizeAuthType(authTypeRaw, privateKey);
            if (!requireCredential && authType === AUTH_TYPE_PASSWORD && !password) {
                return {};
            }

            if (authType === AUTH_TYPE_KEY) {
                if (!privateKey) {
                    throw new Error('密钥登录需要提供私钥');
                }
                if (!isValidPrivateKey(privateKey)) {
                    throw new Error('私钥格式无效，仅支持 PEM/OpenSSH 私钥');
                }
                const payload = { authType: AUTH_TYPE_KEY, privateKey };
                if (passphrase) {
                    payload.passphrase = passphrase;
                }
                return payload;
            }

            if (!password && requireCredential) {
                throw new Error('密码登录需要提供密码');
            }

            const payload = { authType: AUTH_TYPE_PASSWORD };
            if (password) {
                payload.password = password;
            }
            return payload;
        }

        function getHostCredentialPayload(host, options = {}) {
            const requireCredential = options.requireCredential !== false;
            const privateKey = String(host.privateKey || '').replace(/\r\n/g, '\n').trim();
            const password = host.pass || host.password || '';
            const passphrase = host.passphrase || '';
            const authType = normalizeAuthType(host.authType, privateKey);
            const hasCredential = Boolean(password || privateKey);

            if (!requireCredential && !hasCredential) {
                return {};
            }

            if (authType === AUTH_TYPE_KEY) {
                if (!privateKey) {
                    throw new Error('主机未保存私钥，请先补充');
                }
                return passphrase
                    ? { authType: AUTH_TYPE_KEY, privateKey, passphrase }
                    : { authType: AUTH_TYPE_KEY, privateKey };
            }

            if (!password && requireCredential) {
                throw new Error('主机未保存密码，请先补充');
            }

            return password
                ? { authType: AUTH_TYPE_PASSWORD, password }
                : { authType: AUTH_TYPE_PASSWORD };
        }

        function fillCredentialForm(prefix, host) {
            const privateKey = host.privateKey || '';
            const authType = normalizeAuthType(host.authType, privateKey);
            const authTypeEl = document.getElementById(`${prefix}AuthType`);
            if (authTypeEl) {
                authTypeEl.value = authType;
            }
            const passEl = document.getElementById(`${prefix}Pass`);
            if (passEl) {
                passEl.value = host.pass || host.password || '';
            }
            const privateKeyEl = document.getElementById(`${prefix}PrivateKey`);
            if (privateKeyEl) {
                privateKeyEl.value = privateKey;
            }
            const passphraseEl = document.getElementById(`${prefix}Passphrase`);
            if (passphraseEl) {
                passphraseEl.value = host.passphrase || '';
            }
            updateAuthFields(prefix, authType);
        }

        function fillSshHostForm(host) {
            document.getElementById('sshHost').value = host.host || '';
            document.getElementById('sshPort').value = host.port || 22;
            document.getElementById('sshUser').value = host.user || '';
            fillCredentialForm('ssh', host);
        }

        function isPrivateNetworkBlockedError(error, code = '') {
            const normalizedCode = String(code || '').trim().toLowerCase();
            if (normalizedCode === 'private_network_not_whitelisted') {
                return true;
            }
            const normalizedError = String(error || '').trim().toLowerCase();
            return normalizedError.includes('内网白名单')
                || normalizedError.includes('私有网络地址未在白名单')
                || normalizedError.includes('内网地址')
                || normalizedError.includes('private network');
        }

        function formatConnectionError(serviceLabel, error, code = '') {
            const normalized = String(error || `${serviceLabel} 连接失败`).trim().replace(/[。\s]+$/u, '');
            if (!isPrivateNetworkBlockedError(normalized, code)) {
                return normalized || `${serviceLabel} 连接失败`;
            }
            if (normalized.includes('设置') && normalized.includes('内网白名单')) {
                return `${serviceLabel} 连接被拦截：${normalized}`;
            }
            return `${serviceLabel} 连接被拦截：${normalized}。请先到 设置 -> 内网白名单 放行对应网段。`;
        }

        async function validateTargetForConnection(serviceLabel, host) {
            try {
                const res = await apiFetch(`${Config.API}/api/security/validate-target?host=${encodeURIComponent(host)}`);
                if (res.ok) {
                    return { ok: true };
                }
                const data = await res.json().catch(() => ({}));
                return {
                    ok: false,
                    error: formatConnectionError(serviceLabel, data.error || '目标地址校验失败', data.code),
                    code: data.code || ''
                };
            } catch (err) {
                return {
                    ok: false,
                    error: `${serviceLabel} 目标地址校验失败: ${err.message}`,
                    code: ''
                };
            }
        }

        function updateSaveHostButton() {
            const btn = document.getElementById('saveHostBtn');
            const cancelBtn = document.getElementById('cancelEditHostBtn');
            if (!btn) return;
            const editing = State.editingHostIndex !== null;
            btn.innerHTML = editing
                ? `<i class="fas fa-save"></i> ${escapeHtml(I18n.auto('更新主机'))}`
                : `<i class="fas fa-plus"></i> ${escapeHtml(I18n.auto('保存主机'))}`;
            if (cancelBtn) cancelBtn.style.display = editing ? '' : 'none';
        }

        function setEditingHostIndex(index) {
            State.editingHostIndex = Number.isInteger(index) ? index : null;
            updateSaveHostButton();
        }

        function getCssVar(name) {
            return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        }

        // 主题
        const Theme = {
            COLOR_SCHEMES: {
                default:  { label: '默认方案', tone: '中性石墨' },
                sakura:   { label: '樱花粉',   tone: '柔和花瓣' },
                ocean:    { label: '海洋蓝',   tone: '清澈潮汐' },
                forest:   { label: '森林绿',   tone: '苔藓林地' },
                twilight: { label: '暮光紫',   tone: '柔雾暮色' },
                amber:    { label: '琥珀橙',   tone: '温暖日落' }
            },
            init() {
                State.theme = Storage.getTheme();
                State.colorScheme = Storage.getColorScheme();
                this.apply();
                this.applyColorScheme(State.colorScheme);
                const themeToggle = document.getElementById('themeToggle');
                if (themeToggle) {
                    themeToggle.addEventListener('click', () => this.toggle());
                }
            },
            apply() {
                document.documentElement.setAttribute('data-theme', State.theme);
                const icon = document.querySelector('#themeToggle i');
                if (icon) {
                    icon.className = State.theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
                }
                [
                    ['Terminal_', Terminal_],
                    ['LocalShell', LocalShell],
                    ['Serial', Serial]
                ].forEach(([name, module]) => {
                    try {
                        module.applyTheme();
                    } catch (error) {
                        console.error(`[Theme] ${name}.applyTheme() failed:`, error);
                    }
                });
            },
            applyColorScheme(scheme, persist = false) {
                const key = this.COLOR_SCHEMES[scheme] ? scheme : 'default';
                State.colorScheme = key;
                document.documentElement.setAttribute('data-color-scheme', key);
                if (persist) Storage.setColorScheme(key);
                this.syncSchemeSelection();
                this.apply();
            },
            getSchemePreviewColors(scheme) {
                const probe = document.createElement('div');
                probe.setAttribute('data-theme', State.theme);
                if (scheme !== 'default') {
                    probe.setAttribute('data-color-scheme', scheme);
                }
                probe.style.cssText = 'position:absolute;left:-9999px;top:-9999px;visibility:hidden;pointer-events:none;';
                document.body.appendChild(probe);
                const style = getComputedStyle(probe);
                const preview = [
                    style.getPropertyValue('--color-accent-light').trim(),
                    style.getPropertyValue('--color-accent').trim(),
                    style.getPropertyValue('--color-accent-hover').trim()
                ].filter(Boolean);
                probe.remove();
                return preview.length ? preview : ['#cbd5e1', '#6b7280', '#374151'];
            },
            renderSchemeGrid() {
                const grid = document.getElementById('colorSchemeGrid');
                if (!grid) return;
                grid.innerHTML = Object.entries(this.COLOR_SCHEMES).map(([key, s]) => {
                    const active = key === State.colorScheme;
                    const swatches = this.getSchemePreviewColors(key)
                        .map(c => `<span class="scheme-swatch" style="background:${escapeHtml(c)}"></span>`)
                        .join('');
                    return `<button type="button" class="scheme-card${active ? ' active' : ''}" data-scheme="${escapeHtml(key)}" aria-pressed="${active}">
                        <div class="scheme-preview">${swatches}</div>
                        <div class="scheme-meta">
                            <div><div class="scheme-name">${escapeHtml(s.label)}</div><div class="scheme-tone">${escapeHtml(s.tone)}</div></div>
                            ${active ? `<span class="scheme-badge">${escapeHtml(I18n.auto('当前'))}</span>` : ''}
                        </div>
                    </button>`;
                }).join('');
                grid.querySelectorAll('.scheme-card').forEach(card => {
                    card.addEventListener('click', () => this.applyColorScheme(card.dataset.scheme, true));
                });
                I18n.applyTree(grid, true);
            },
            syncSchemeSelection() {
                const grid = document.getElementById('colorSchemeGrid');
                if (!grid) return;
                grid.querySelectorAll('.scheme-card').forEach(card => {
                    const active = card.dataset.scheme === State.colorScheme;
                    card.classList.toggle('active', active);
                    card.setAttribute('aria-pressed', String(active));
                    const meta = card.querySelector('.scheme-meta');
                    const badge = meta ? meta.querySelector('.scheme-badge') : null;
                    if (active && !badge && meta) {
                        const nextBadge = document.createElement('span');
                        nextBadge.className = 'scheme-badge';
                        nextBadge.textContent = I18n.auto('当前');
                        meta.appendChild(nextBadge);
                    }
                    if (!active && badge) {
                        badge.remove();
                    }
                });
            },
            toggle() {
                State.theme = State.theme === 'dark' ? 'light' : 'dark';
                Storage.setTheme(State.theme);
                this.apply();
                this.renderSchemeGrid();
            },
            getTerminalTheme() {
                return {
                    background: getCssVar('--terminal-screen-bg'),
                    foreground: getCssVar('--terminal-screen-text'),
                    cursor: getCssVar('--terminal-screen-cursor'),
                    selection: getCssVar('--terminal-screen-selection'),
                    black: getCssVar('--terminal-screen-black'),
                    red: getCssVar('--terminal-screen-red'),
                    green: getCssVar('--terminal-screen-green'),
                    yellow: getCssVar('--terminal-screen-yellow'),
                    blue: getCssVar('--terminal-screen-blue'),
                    magenta: getCssVar('--terminal-screen-magenta'),
                    cyan: getCssVar('--terminal-screen-cyan'),
                    white: getCssVar('--terminal-screen-white')
                };
            },
            getTerminalWelcomeColors() {
                return State.theme === 'light'
                    ? { frame: '90', title: '30;1' }
                    : { frame: '37', title: '97' };
            }
        };

        const Settings = {
            LANGUAGE_OPTIONS: [
                { key: 'en', code: 'EN', label: 'English', tone: '默认界面语言' },
                { key: 'zh', code: 'ZH', label: '简体中文', tone: '简体中文界面' }
            ],
            LOGIN_KEEP_PRESETS: ['7d', '14d', '1m', 'never'],
            init() {
                document.getElementById('settingsChangePasswordBtn').addEventListener('click', () => this.changePassword());
                document.getElementById('settingsSaveLoginKeepBtn').addEventListener('click', () => this.saveLoginKeep());
                document.getElementById('settingsOpenPrivateNetworksBtn').addEventListener('click', () => this.openPrivateNetworks());
                document.getElementById('securityBackToSettingsBtn').addEventListener('click', () => UI.switchView('settings'));
                document.getElementById('settingsLoginKeepPreset').addEventListener('change', (event) => this.handleLoginKeepPresetChange(event.target.value));
                document.getElementById('settingsLoginKeepInput').addEventListener('input', () => this.syncLoginKeepPresetFromInput());
                document.getElementById('settingsLoginKeepInput').addEventListener('keypress', (event) => {
                    if (event.key === 'Enter') this.saveLoginKeep();
                });
                ['settingsNewPassword', 'settingsConfirmPassword'].forEach(id => {
                    document.getElementById(id).addEventListener('keypress', e => {
                        if (e.key === 'Enter') this.changePassword();
                    });
                });
            },
            parseLoginKeepValue(value) {
                const raw = String(value || '').trim().toLowerCase();
                if (!raw) {
                    throw new Error('请输入登录保持时间');
                }
                if (raw === 'never') {
                    return { seconds: 0, display: 'never' };
                }
                const match = raw.match(/^(\d+)\s*([a-z\u4e00-\u9fa5]+)$/iu);
                if (!match) {
                    throw new Error('登录保持时间格式无效，示例：7d、14d、1m、12h、never');
                }
                const amount = Number(match[1]);
                const unit = match[2];
                const unitMap = {
                    s: { seconds: 1, display: 's' },
                    sec: { seconds: 1, display: 's' },
                    secs: { seconds: 1, display: 's' },
                    second: { seconds: 1, display: 's' },
                    seconds: { seconds: 1, display: 's' },
                    秒: { seconds: 1, display: 's' },
                    min: { seconds: 60, display: 'min' },
                    mins: { seconds: 60, display: 'min' },
                    minute: { seconds: 60, display: 'min' },
                    minutes: { seconds: 60, display: 'min' },
                    分: { seconds: 60, display: 'min' },
                    分钟: { seconds: 60, display: 'min' },
                    h: { seconds: 3600, display: 'h' },
                    hr: { seconds: 3600, display: 'h' },
                    hrs: { seconds: 3600, display: 'h' },
                    hour: { seconds: 3600, display: 'h' },
                    hours: { seconds: 3600, display: 'h' },
                    小时: { seconds: 3600, display: 'h' },
                    d: { seconds: 86400, display: 'd' },
                    day: { seconds: 86400, display: 'd' },
                    days: { seconds: 86400, display: 'd' },
                    天: { seconds: 86400, display: 'd' },
                    w: { seconds: 604800, display: 'w' },
                    week: { seconds: 604800, display: 'w' },
                    weeks: { seconds: 604800, display: 'w' },
                    周: { seconds: 604800, display: 'w' },
                    m: { seconds: 2592000, display: 'm' },
                    mo: { seconds: 2592000, display: 'm' },
                    mon: { seconds: 2592000, display: 'm' },
                    month: { seconds: 2592000, display: 'm' },
                    months: { seconds: 2592000, display: 'm' },
                    月: { seconds: 2592000, display: 'm' },
                    y: { seconds: 31536000, display: 'y' },
                    yr: { seconds: 31536000, display: 'y' },
                    year: { seconds: 31536000, display: 'y' },
                    years: { seconds: 31536000, display: 'y' },
                    年: { seconds: 31536000, display: 'y' }
                };
                const mapped = unitMap[unit];
                if (!mapped || !Number.isFinite(amount) || amount <= 0) {
                    throw new Error('登录保持时间格式无效，示例：7d、14d、1m、12h、never');
                }
                const seconds = amount * mapped.seconds;
                if (!Number.isFinite(seconds) || seconds > 315360000) {
                    throw new Error('登录保持时间过长，请控制在 10 年以内');
                }
                return {
                    seconds,
                    display: `${amount}${mapped.display}`
                };
            },
            getSavedLoginKeepDisplay() {
                const saved = Storage.getLoginKeepValue();
                try {
                    return this.parseLoginKeepValue(saved).display;
                } catch {
                    Storage.setLoginKeepValue(DEFAULT_LOGIN_KEEP_VALUE);
                    return DEFAULT_LOGIN_KEEP_VALUE;
                }
            },
            renderLoginKeepStatus(display) {
                document.getElementById('settingsLoginKeepStatus').textContent = `${I18n.auto('当前登录保持时间：')}${display}`;
            },
            syncLoginKeepPresetFromInput() {
                const inputEl = document.getElementById('settingsLoginKeepInput');
                const presetEl = document.getElementById('settingsLoginKeepPreset');
                const rawValue = inputEl.value.trim();
                if (!rawValue) {
                    presetEl.value = 'custom';
                    this.renderLoginKeepStatus(this.getSavedLoginKeepDisplay());
                    return;
                }
                try {
                    const parsed = this.parseLoginKeepValue(rawValue);
                    presetEl.value = this.LOGIN_KEEP_PRESETS.includes(parsed.display) ? parsed.display : 'custom';
                    this.renderLoginKeepStatus(parsed.display);
                } catch {
                    presetEl.value = 'custom';
                    this.renderLoginKeepStatus(this.getSavedLoginKeepDisplay());
                }
            },
            handleLoginKeepPresetChange(value) {
                const inputEl = document.getElementById('settingsLoginKeepInput');
                if (value !== 'custom') {
                    inputEl.value = value;
                }
                this.syncLoginKeepPresetFromInput();
            },
            renderLoginKeepControls() {
                const display = this.getSavedLoginKeepDisplay();
                document.getElementById('settingsLoginKeepInput').value = display;
                document.getElementById('settingsLoginKeepPreset').value = this.LOGIN_KEEP_PRESETS.includes(display) ? display : 'custom';
                this.renderLoginKeepStatus(display);
            },
            renderLanguageGrid() {
                const grid = document.getElementById('languageGrid');
                if (!grid) return;
                grid.innerHTML = this.LANGUAGE_OPTIONS.map((option) => {
                    const active = option.key === State.language;
                    return `<button type="button" class="language-card${active ? ' active' : ''}" data-language="${escapeHtml(option.key)}" aria-pressed="${active}">
                        <div class="scheme-meta">
                            <span class="language-code">${escapeHtml(option.code)}</span>
                            ${active ? `<span class="scheme-badge">${escapeHtml(I18n.auto('当前'))}</span>` : ''}
                        </div>
                        <div>
                            <div class="scheme-name">${escapeHtml(option.label)}</div>
                            <div class="scheme-tone">${escapeHtml(option.tone)}</div>
                        </div>
                    </button>`;
                }).join('');
                grid.querySelectorAll('.language-card').forEach((card) => {
                    card.addEventListener('click', () => I18n.setLanguage(card.dataset.language));
                });
                I18n.applyTree(grid, true);
            },
            render() {
                document.getElementById('settingsCurrentUser').textContent = State.username || '--';
                document.getElementById('settingsNologinNotice').style.display = State.isNologin ? 'flex' : 'none';
                document.getElementById('settingsLoginKeepNologinNotice').style.display = State.isNologin ? 'flex' : 'none';
                document.getElementById('settingsPasswordForm').style.display = State.isNologin ? 'none' : '';
                document.getElementById('settingsPrivateNetworkSection').style.display = State.isAdmin ? '' : 'none';
                this.renderLoginKeepControls();
                Theme.renderSchemeGrid();
                this.renderLanguageGrid();
            },
            reset() {
                document.getElementById('settingsNewPassword').value = '';
                document.getElementById('settingsConfirmPassword').value = '';
                document.getElementById('settingsChangePasswordBtn').disabled = false;
                document.getElementById('settingsSaveLoginKeepBtn').disabled = false;
                document.getElementById('settingsCurrentUser').textContent = '--';
                document.getElementById('settingsNologinNotice').style.display = 'none';
                document.getElementById('settingsLoginKeepNologinNotice').style.display = 'none';
                document.getElementById('settingsPasswordForm').style.display = '';
                document.getElementById('settingsPrivateNetworkSection').style.display = 'none';
                this.renderLoginKeepControls();
            },
            openPrivateNetworks() {
                if (!State.isAdmin) {
                    Toast.error('仅管理员可管理内网白名单');
                    return;
                }
                Security.load();
                UI.switchView('security');
            },
            async changePassword() {
                if (State.isNologin) { Toast.info('桌面应用不允许修改密码'); return; }
                if (!State.username) { Toast.error('当前用户不可用'); return; }
                const pwd = document.getElementById('settingsNewPassword').value;
                const confirm = document.getElementById('settingsConfirmPassword').value;
                if (!pwd) { Toast.error('请输入新密码'); return; }
                if (pwd !== confirm) { Toast.error('两次输入的密码不一致'); return; }
                const btn = document.getElementById('settingsChangePasswordBtn');
                btn.disabled = true;
                try {
                    const res = await apiFetch(`${Config.API}/api/users/${encodeURIComponent(State.username)}/password`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: pwd })
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        document.getElementById('settingsNewPassword').value = '';
                        document.getElementById('settingsConfirmPassword').value = '';
                        Toast.success(data.message || '密码修改成功');
                    } else {
                        Toast.error(data.error || '密码修改失败');
                    }
                } catch (err) {
                    Toast.error(`密码修改失败: ${err.message}`);
                } finally {
                    btn.disabled = false;
                }
            },
            async saveLoginKeep() {
                let parsed = null;
                try {
                    parsed = this.parseLoginKeepValue(document.getElementById('settingsLoginKeepInput').value);
                } catch (err) {
                    Toast.error(err.message);
                    return;
                }

                Storage.setLoginKeepValue(parsed.display);
                this.renderLoginKeepControls();

                if (!State.loggedIn || State.isNologin) {
                    Toast.success(State.isNologin ? '登录保持时间已保存，当前免登录模式不会使用该设置' : '登录保持时间已保存，将在下次登录时生效');
                    return;
                }

                const btn = document.getElementById('settingsSaveLoginKeepBtn');
                btn.disabled = true;
                try {
                    const res = await apiFetch(`${Config.API}/api/auth/session`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ keepSeconds: parsed.seconds })
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        Auth.setSession(data);
                        Toast.success('登录保持时间已更新');
                    } else {
                        Toast.error(data.error || '登录保持时间更新失败');
                    }
                } catch (err) {
                    Toast.error(`登录保持时间更新失败: ${err.message}`);
                } finally {
                    btn.disabled = false;
                }
            }
        };

        const Toast = {
            show(msg, type = 'info') {
                const translated = I18n.auto(msg);
                const el = document.createElement('div');
                el.className = `toast ${type}`;
                el.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i><span>${escapeHtml(translated)}</span>`;
                document.getElementById('toasts').appendChild(el);
                setTimeout(() => { el.style.animation = 'slideIn .3s reverse'; setTimeout(() => el.remove(), 300); }, 3500);
            },
            success(m) { this.show(m, 'success'); },
            error(m) { this.show(m, 'error'); },
            info(m) { this.show(m, 'info'); }
        };

        const About = {
            init() {
                this.render();
            },
            async load() {
                try {
                    const res = await fetch(`${Config.API}/api/app-info`);
                    if (!res.ok) {
                        return;
                    }
                    const data = await res.json();
                    applyPublicAppInfo(data);
                    this.render();
                } catch {}
            },
            render() {
                document.getElementById('aboutVersionValue').textContent = State.appVersion;

                const projectLink = document.getElementById('aboutProjectHomepageLink');
                projectLink.href = State.projectHomepage;
                projectLink.textContent = State.projectHomepage;

                const desktopVersionItem = document.getElementById('aboutDesktopVersionItem');
                const desktopHomepageItem = document.getElementById('aboutDesktopHomepageItem');
                if (!State.showDesktopClientInfo) {
                    desktopVersionItem.style.display = 'none';
                    desktopHomepageItem.style.display = 'none';
                    return;
                }

                document.getElementById('aboutDesktopVersionValue').textContent = State.desktopVersion || '未设置';

                const desktopHomepageLink = document.getElementById('aboutDesktopHomepageLink');
                desktopHomepageLink.href = State.desktopProjectHomepage;
                desktopHomepageLink.textContent = State.desktopProjectHomepage;

                desktopVersionItem.style.display = '';
                desktopHomepageItem.style.display = '';
            }
        };

        window.About = About;

        const Auth = {
            getToken() {
                return State.token || Storage.getToken();
            },
            init() {
                document.getElementById('loginBtn').addEventListener('click', () => this.login());
                document.getElementById('loginPass').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') this.login();
                });
                document.getElementById('logoutBtn').addEventListener('click', () => this.logout());

                this._bootstrap();
            },
            async _bootstrap() {
                if (usesInjectedDesktopAuth()) {
                    this.showLoading('正在连接桌面会话...', '正在验证桌面包装器注入的本地会话。');
                    this.verify({ expectNoLogin: true });
                    return;
                }

                let publicInfo = null;
                try {
                    const res = await fetch(`${Config.API}/api/auth/nologin`);
                    if (res.ok) {
                        const data = await res.json();
                        applyPublicAppInfo(data);
                        publicInfo = data;
                        if (data && data.nologin) {
                            State.isNologin = true;
                            this.setSession(data);
                            UI.showDashboard({ showBootOverlay: false });
                            return;
                        }
                    }
                } catch {}

                const savedToken = Storage.getToken();
                if (savedToken) {
                    const savedFingerprint = Storage.getAuthSecretFingerprint();
                    const currentFingerprint = (publicInfo && publicInfo.authSecretFingerprint) || State.authSecretFingerprint;
                    if (savedFingerprint && currentFingerprint && savedFingerprint !== currentFingerprint) {
                        this.clearSession();
                        this.showLogin();
                        return;
                    }
                    State.token = savedToken;
                    this.showLoading('正在恢复登录状态...', '正在验证本地保存的登录态，请稍候。');
                    this.verify();
                } else {
                    this.showLogin();
                }
            },
            async login() {
                const username = document.getElementById('loginUser').value.trim();
                const password = document.getElementById('loginPass').value;
                let keepSeconds = 0;
                try {
                    keepSeconds = Settings.parseLoginKeepValue(Storage.getLoginKeepValue()).seconds;
                } catch {
                    Storage.setLoginKeepValue(DEFAULT_LOGIN_KEEP_VALUE);
                    keepSeconds = Settings.parseLoginKeepValue(DEFAULT_LOGIN_KEEP_VALUE).seconds;
                }
                if (!username || !password) {
                    this.showError('请输入用户名和密码');
                    return;
                }
                this.showError('');
                try {
                    const res = await fetch(`${Config.API}/api/auth/login`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password, keepSeconds })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        this.setSession(data);
                        document.getElementById('loginPass').value = '';
                        this.showLoading('正在启动工作台...', '先载入界面，再分阶段连接服务模块。');
                        UI.showDashboard();
                    } else {
                        this.showError(data.error || '登录失败');
                    }
                } catch (err) {
                    this.showError(`登录失败: ${err.message}`);
                }
            },
            async verify(options = {}) {
                const expectNoLogin = options.expectNoLogin === true;
                try {
                    const res = await apiFetch(`${Config.API}/api/auth/verify`, { method: 'POST' });
                    if (res.ok) {
                        const data = await res.json();
                        this.setSession({ token: State.token, nologin: expectNoLogin || data.nologin === true, ...data });
                        this.showLoading('正在启动工作台...', '先载入界面，再分阶段连接服务模块。');
                        UI.showDashboard();
                        return;
                    }
                } catch {}
                this.clearSession();
                if (expectNoLogin) {
                    this.showLoading('桌面会话初始化失败', '未能建立受保护的桌面免登录会话，请重新启动桌面应用。');
                    return;
                }
                this.showLogin();
            },
            setSession(session = {}) {
                const { token, username, role, keepSeconds, nologin } = session;
                if (token) {
                    State.token = token;
                    Storage.setToken(token);
                }
                applyPublicAppInfo(session);
                State.loggedIn = true;
                State.isNologin = Boolean(nologin);
                State.username = username || State.username;
                State.isAdmin = role === 'admin';
                if (State.authSecretFingerprint) {
                    Storage.setAuthSecretFingerprint(State.authSecretFingerprint);
                }
                if (Number.isFinite(Number(keepSeconds))) {
                    Storage.setLoginKeepValue(Number(keepSeconds) === 0 ? 'never' : Storage.getLoginKeepValue());
                }
            },
            clearSession() {
                State.loggedIn = false;
                State.isAdmin = false;
                State.isNologin = false;
                State.username = '';
                State.token = '';
                State.hosts = [];
                State.navHistory = [];
                State.navIndex = -1;
                State.selectedFiles = [];
                State.authSecretFingerprint = '';
                setEditingHostIndex(null);
                Settings.reset();
                Storage.clearToken();
                Storage.clearAuthSecretFingerprint();
                UI.resetConnections();
                UI.hideDashboard();
            },
            logout() {
                if (usesInjectedDesktopAuth()) {
                    Toast.info('桌面免登录由桌面包装器托管，不能在页面内退出');
                    return;
                }
                this.clearSession();
                this.showLogin();
                Toast.info('已退出登录');
            },
            handleUnauthorized() {
                if (State.loggedIn) {
                    Toast.error('登录已过期，请重新登录');
                }
                this.clearSession();
                if (usesInjectedDesktopAuth()) {
                    this.showLoading('桌面会话初始化失败', '未能建立受保护的桌面免登录会话，请重新启动桌面应用。');
                    return;
                }
                this.showLogin();
            },
            showLogin() {
                document.getElementById('authOverlay').classList.remove('hidden');
                document.getElementById('authLoginPanel').classList.remove('hidden');
                document.getElementById('authLoadingPanel').classList.add('hidden');
                document.getElementById('loginPass').value = '';
                this.updateLoadingProgress(0, '正在准备界面...');
                this.showError('');
                document.getElementById('loginUser').focus();
            },
            showLoading(title = '正在恢复登录状态...', sub = '正在验证本地保存的登录态，请稍候。') {
                document.getElementById('authOverlay').classList.remove('hidden');
                document.getElementById('authLoginPanel').classList.add('hidden');
                document.getElementById('authLoadingPanel').classList.remove('hidden');
                const titleEl = document.getElementById('authLoadingTitle');
                const subEl = document.getElementById('authLoadingSub');
                if (titleEl) {
                    titleEl.textContent = I18n.auto(title);
                }
                if (subEl) {
                    subEl.textContent = I18n.auto(sub);
                }
                this.updateLoadingProgress(0, '正在准备界面...');
                this.showError('');
            },
            updateLoadingProgress(progress = 0, stage = '') {
                const safeProgress = Math.max(0, Math.min(1, Number(progress) || 0));
                const fill = document.getElementById('authProgressFill');
                const value = document.getElementById('authProgressValue');
                const label = document.getElementById('authProgressStage');
                if (fill) {
                    const totalLength = fill._progressPathLength || fill.getTotalLength();
                    const filledLength = totalLength * safeProgress;
                    fill._progressPathLength = totalLength;
                    fill.style.opacity = safeProgress > 0 ? '1' : '0';
                    fill.style.strokeDasharray = `${filledLength} ${totalLength}`;
                    fill.style.strokeDashoffset = '0';
                }
                if (value) {
                    value.textContent = `${Math.round(safeProgress * 100)}%`;
                }
                if (label && stage) {
                    label.textContent = I18n.auto(stage);
                }
            },
            hideLogin() {
                document.getElementById('authOverlay').classList.add('hidden');
                document.getElementById('authLoginPanel').classList.remove('hidden');
                document.getElementById('authLoadingPanel').classList.add('hidden');
                this.showError('');
            },
            showError(msg) {
                document.getElementById('authError').textContent = msg ? I18n.auto(msg) : '';
            }
        };

        window.Auth = Auth;

        // 终端
        const Terminal_ = {
            term: null, fit: null, ws: null, host: null,
            // System stats monitoring
            statsActive: false,      // 是否正在采集数据
            chartExpanded: false,    // 图表是否展开
            statsVisualizer: null,
            lastCpuStat: null,
            // TOP panel
            topActive: false,        // TOP是否正在采集
            topExpanded: false,      // TOP面板是否展开
            topProcesses: [],        // 进程列表
            topSortField: 'cpu',     // 排序字段
            topSortDesc: true,       // 降序
            // Docker stats panel
            dockerStatsActive: false,
            dockerExpanded: false,
            dockerMode: 'total',
            dockerContainers: [],
            dockerSelectedId: null,
            dockerAvailable: null,
            dockerError: '',
            init() {
                this.term = new Terminal({
                    theme: Theme.getTerminalTheme(),
                    fontFamily: 'Consolas, Monaco, monospace',
                    fontSize: 14, cursorBlink: true
                });
                this.fit = new FitAddon.FitAddon();
                this.term.loadAddon(this.fit);
                this.term.open(document.getElementById('terminal'));
                this.doFit();
                this.welcome();
                window.addEventListener('resize', () => this.doFit());
                this.term.onData(data => {
                    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                        this.ws.send(JSON.stringify({ type: 'data', data }));
                    }
                });
                this.term.onResize(({ cols, rows }) => {
                    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                        this.ws.send(JSON.stringify({ type: 'resize', cols, rows }));
                    }
                });
            },
            applyTheme() {
                if (!this.term) return;
                this.term.setOption('theme', Theme.getTerminalTheme());
                this.doFit();
                if (!State.sshConnected) {
                    this.term.clear();
                    this.welcome();
                }
            },
            doFit() { try { this.fit.fit(); } catch {} },
            welcome() {
                const colors = Theme.getTerminalWelcomeColors();
                this.term.writeln('');
                this.term.writeln(`\x1b[${colors.frame}m  ╔══════════════════════════════════════════╗\x1b[0m`);
                this.term.writeln(`\x1b[${colors.frame}m  ║\x1b[0m          \x1b[${colors.title}mEntrance Tools\x1b[0m                  \x1b[${colors.frame}m║\x1b[0m`);
                this.term.writeln(`\x1b[${colors.frame}m  ╚══════════════════════════════════════════╝\x1b[0m`);
                this.term.writeln('');
                this.term.writeln(`\x1b[90m  ${I18n.auto('输入连接信息后点击 SSH 按钮连接服务器')}\x1b[0m`);
                this.term.writeln('');
            },
            async connect(host, port, user, authPayload = {}) {
                if (this.ws) this.ws.close();
                this.term.clear();
                this.term.writeln(`\x1b[33m${I18n.auto(`正在连接 ${user}@${host}:${port}...`)}\x1b[0m\n`);
                const targetCheck = await validateTargetForConnection('SSH', host);
                if (!targetCheck.ok) {
                    this.term.writeln(`\x1b[31m${I18n.auto(targetCheck.error)}\x1b[0m`);
                    Toast.error(targetCheck.error);
                    return;
                }
                this.ws = new WebSocket(buildWsUrl('/ssh'));
                this.ws.onopen = () => {
                    this.ws.send(JSON.stringify({
                        type: 'connect',
                        host,
                        port: +port,
                        username: user,
                        ...authPayload
                    }));
                };
                this.ws.onmessage = (e) => {
                    const msg = JSON.parse(e.data);
                    switch (msg.type) {
                        case 'connected':
                            State.sshConnected = true;
                            this.host = host;
                            this.updateStatus(true);
                            Toast.success(`已连接到 ${host}`);
                            this.doFit();
                            // 自动开始采集系统数据
                            this.startStats();
                            // 自动开始采集TOP数据
                            this.startTop();
                            // 自动开始采集Docker Stats
                            this.startDockerStats();
                            break;
                        case 'data': this.term.write(msg.data); break;
                        case 'stats': this.handleStats(msg.data); break;
                        case 'top': this.handleTop(msg.data); break;
                        case 'dockerStats': this.handleDockerStats(msg.data); break;
                        case 'killResult': this.handleKillResult(msg.data); break;
                        case 'error':
                            {
                                const message = formatConnectionError('SSH', msg.message, msg.code);
                                this.term.writeln(`\x1b[31m${I18n.auto(`错误: ${message}`)}\x1b[0m`);
                                Toast.error(message);
                            }
                            break;
                        case 'disconnected':
                            State.sshConnected = false;
                            this.host = null;
                            this.stopStats();
                            this.stopTop();
                            this.stopDockerStats();
                            this.updateStatus(false);
                            this.term.writeln(`\n\x1b[33m${I18n.auto('连接已断开')}\x1b[0m`);
                            Toast.info('SSH 连接已断开');
                            break;
                    }
                };
                this.ws.onerror = () => {
                    this.term.writeln(`\x1b[31m${I18n.auto('连接失败，请确保后端服务正在运行')}\x1b[0m`);
                    Toast.error('WebSocket 连接失败');
                };
                this.ws.onclose = () => {
                    if (State.sshConnected) {
                        State.sshConnected = false;
                        this.stopStats();
                        this.stopTop();
                        this.stopDockerStats();
                        this.updateStatus(false);
                    }
                };
            },
            updateStatus(connected) {
                const status = document.getElementById('termStatus');
                const title = document.getElementById('termTitle');
                if (connected) {
                    status.className = 'terminal-status connected';
                    status.innerHTML = buildIconTextHtml('fa-circle', '已连接');
                    title.textContent = I18n.auto(`终端 - ${this.host}`);
                } else {
                    status.className = 'terminal-status disconnected';
                    status.innerHTML = buildIconTextHtml('fa-circle', '未连接');
                    title.textContent = I18n.auto('终端 - 未连接');
                }
            },
            // Start stats collection (called on SSH connect)
            startStats() {
                if (this.statsActive) return;

                // Initialize visualizer if needed
                if (!this.statsVisualizer) {
                    this.statsVisualizer = new SysStatsVisualizer('sysStatsCanvas');
                }
                this.statsActive = true;

                // Start stats collection on server
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ type: 'startStats' }));
                }
            },
            // Toggle chart expansion (show/hide waveform)
            toggleStats() {
                if (!State.sshConnected) {
                    Toast.error('请先连接 SSH');
                    return;
                }
                const container = document.getElementById('sysStatsContainer');

                this.chartExpanded = !this.chartExpanded;
                if (this.chartExpanded) {
                    container.classList.add('active');
                } else {
                    container.classList.remove('active');
                }
            },
            // Stop stats collection (called on SSH disconnect)
            stopStats() {
                const container = document.getElementById('sysStatsContainer');

                this.statsActive = false;
                this.chartExpanded = false;
                this.lastCpuStat = null;
                container.classList.remove('active');

                // Reset display values
                document.getElementById('statCpuValue').textContent = '--%';
                document.getElementById('statMemValue').textContent = '--%';
                document.getElementById('statDiskValue').textContent = '-- KB/s';

                // Stop stats collection on server
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ type: 'stopStats' }));
                }
            },
            // Clear stats data
            clearStats() {
                if (this.statsVisualizer) {
                    this.statsVisualizer.clear();
                }
                this.lastCpuStat = null;
            },
            // Handle stats data from server
            handleStats(data) {
                if (!this.statsVisualizer) return;

                const currentTime = Date.now();

                // Parse CPU stats
                let cpuPercent = 0;
                if (data.stat) {
                    const cpuStat = this.statsVisualizer.parseCpuStat(data.stat.split('\n'));
                    if (cpuStat && this.lastCpuStat) {
                        const totalDelta = cpuStat.total - this.lastCpuStat.total;
                        const busyDelta = cpuStat.busy - this.lastCpuStat.busy;
                        if (totalDelta > 0) {
                            cpuPercent = (busyDelta / totalDelta) * 100;
                        }
                    }
                    this.lastCpuStat = cpuStat;
                }

                // Parse memory stats
                let memPercent = 0;
                if (data.meminfo) {
                    const mem = this.statsVisualizer.parseMemInfo(data.meminfo.split('\n'));
                    if (mem !== null) {
                        memPercent = parseFloat(mem);
                    }
                }

                // Parse disk stats
                let diskRead = 0, diskWrite = 0;
                if (data.diskstats) {
                    const disk = this.statsVisualizer.parseDiskStats(data.diskstats.split('\n'), currentTime);
                    if (disk) {
                        diskRead = disk.read;
                        diskWrite = disk.write;
                    }
                }

                // Update display values (always, for the hint bar)
                if (this.lastCpuStat) {
                    document.getElementById('statCpuValue').textContent = cpuPercent.toFixed(1) + '%';
                    document.getElementById('statMemValue').textContent = memPercent.toFixed(1) + '%';
                    document.getElementById('statDiskValue').textContent = (diskRead + diskWrite).toFixed(1) + ' KB/s';

                    // Push data to chart
                    this.statsVisualizer.pushData(cpuPercent, memPercent, diskRead, diskWrite);
                }
            },
            // Start TOP data collection
            startTop() {
                if (this.topActive) return;
                this.topActive = true;
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ type: 'startTop' }));
                }
            },
            // Stop TOP data collection
            stopTop() {
                const container = document.getElementById('topPanelContainer');
                this.topActive = false;
                this.topExpanded = false;
                this.topProcesses = [];
                container.classList.remove('active');
                // Reset hint values
                document.getElementById('topProcsValue').textContent = '--';
                document.getElementById('topRunningValue').textContent = '--';
                document.getElementById('topLoadValue').textContent = '--';
                // Reset summary
                document.getElementById('topUptime').textContent = '--';
                document.getElementById('topUsers').textContent = '--';
                document.getElementById('topLoadAvg').textContent = '--';
                document.getElementById('topTasks').textContent = '--';
                document.getElementById('topCpuUsage').textContent = '--';
                document.getElementById('topMemUsage').textContent = '--';
                // Clear table
                document.getElementById('topTableBody').innerHTML = buildTablePlaceholderHtml('连接SSH后自动获取进程信息');
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ type: 'stopTop' }));
                }
            },
            // Toggle TOP panel expansion
            toggleTop() {
                if (!State.sshConnected) {
                    Toast.error('请先连接 SSH');
                    return;
                }
                const container = document.getElementById('topPanelContainer');
                this.topExpanded = !this.topExpanded;
                container.classList.toggle('active', this.topExpanded);
            },
            // Refresh TOP data manually
            refreshTop() {
                if (this.ws && this.ws.readyState === WebSocket.OPEN && State.sshConnected) {
                    this.ws.send(JSON.stringify({ type: 'refreshTop' }));
                }
            },
            // Handle TOP data from server
            handleTop(data) {
                // Parse uptime info
                if (data.uptime) {
                    this.parseUptime(data.uptime);
                }
                // Parse process list (ps aux output)
                if (data.ps) {
                    this.parseProcessList(data.ps);
                    this.renderTopTable();
                }
            },
            // Parse uptime output
            parseUptime(uptimeStr) {
                // Example: " 10:15:03 up 5 days, 12:30,  2 users,  load average: 0.15, 0.10, 0.05"
                const lines = uptimeStr.trim().split('\n');
                const line = lines[0];

                // Extract uptime
                const uptimeMatch = line.match(/up\s+(.+?),\s+\d+\s+user/);
                if (uptimeMatch) {
                    document.getElementById('topUptime').textContent = uptimeMatch[1].trim();
                }

                // Extract users
                const usersMatch = line.match(/(\d+)\s+user/);
                if (usersMatch) {
                    document.getElementById('topUsers').textContent = usersMatch[1];
                }

                // Extract load average
                const loadMatch = line.match(/load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)/);
                if (loadMatch) {
                    document.getElementById('topLoadAvg').textContent = `${loadMatch[1]}, ${loadMatch[2]}, ${loadMatch[3]}`;
                    document.getElementById('topLoadValue').textContent = loadMatch[1];
                }
            },
            // Parse ps aux output
            parseProcessList(psStr) {
                const lines = psStr.trim().split('\n');
                if (lines.length < 2) return;

                // Skip header line
                const processes = [];
                let totalProcs = 0;
                let runningProcs = 0;

                for (let i = 1; i < lines.length; i++) {
                    const line = lines[i].trim();
                    if (!line) continue;

                    // ps aux format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                    const parts = line.split(/\s+/);
                    if (parts.length < 11) continue;

                    const proc = {
                        user: parts[0],
                        pid: parseInt(parts[1]),
                        cpu: parseFloat(parts[2]),
                        mem: parseFloat(parts[3]),
                        vsz: parseInt(parts[4]),
                        rss: parseInt(parts[5]),
                        tty: parts[6],
                        stat: parts[7],
                        start: parts[8],
                        time: parts[9],
                        cmd: parts.slice(10).join(' ')
                    };

                    processes.push(proc);
                    totalProcs++;
                    if (proc.stat.startsWith('R')) runningProcs++;
                }

                this.topProcesses = processes;

                // Update hint bar
                document.getElementById('topProcsValue').textContent = totalProcs;
                document.getElementById('topRunningValue').textContent = runningProcs;

                // Update summary
                document.getElementById('topTasks').textContent = I18n.auto(`总计 ${totalProcs} 个，运行中 ${runningProcs} 个`);

                // Calculate total CPU/MEM
                const totalCpu = processes.reduce((sum, p) => sum + p.cpu, 0);
                const totalMem = processes.reduce((sum, p) => sum + p.mem, 0);
                document.getElementById('topCpuUsage').textContent = totalCpu.toFixed(1) + '%';
                document.getElementById('topMemUsage').textContent = totalMem.toFixed(1) + '%';
            },
            // Render TOP table
            renderTopTable() {
                const tbody = document.getElementById('topTableBody');
                const sortBy = document.getElementById('topSortBy').value;
                const showCount = parseInt(document.getElementById('topShowCount').value);

                // Sort processes
                let sorted = [...this.topProcesses];
                sorted.sort((a, b) => {
                    let va, vb;
                    switch (sortBy) {
                        case 'cpu': va = a.cpu; vb = b.cpu; break;
                        case 'mem': va = a.mem; vb = b.mem; break;
                        case 'pid': va = a.pid; vb = b.pid; break;
                        case 'time': va = a.time; vb = b.time; break;
                        default: va = a.cpu; vb = b.cpu;
                    }
                    return this.topSortDesc ? vb - va : va - vb;
                });

                // Limit to showCount
                sorted = sorted.slice(0, showCount);

                // Render rows
                if (sorted.length === 0) {
                    tbody.innerHTML = buildTablePlaceholderHtml('无进程数据');
                    return;
                }

                const escapeHtml = (str) => str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

                tbody.innerHTML = sorted.map(p => {
                    const cpuBarWidth = Math.min(p.cpu, 100);
                    const memBarWidth = Math.min(p.mem, 100);
                    const escapedCmd = escapeHtml(p.cmd);
                    return `<tr>
                        <td class="col-pid">${p.pid}</td>
                        <td class="col-user">${escapeHtml(p.user)}</td>
                        <td class="col-cpu"><span class="top-cpu-bar" style="width:${cpuBarWidth}px"></span>${p.cpu.toFixed(1)}</td>
                        <td class="col-mem"><span class="top-mem-bar" style="width:${memBarWidth}px"></span>${p.mem.toFixed(1)}</td>
                        <td class="col-vsz">${this.formatSize(p.vsz * 1024)}</td>
                        <td class="col-rss">${this.formatSize(p.rss * 1024)}</td>
                        <td class="col-stat">${p.stat}</td>
                        <td class="col-time">${p.time}</td>
                        <td class="col-cmd" title="${escapedCmd}">${escapedCmd}</td>
                        <td class="col-action"><button class="top-kill-btn" onclick="Terminal_.showKillModal(${p.pid}, '${escapeHtml(p.user)}', '${escapedCmd.replace(/'/g, "\\'")}')"><i class="fas fa-times"></i></button></td>
                    </tr>`;
                }).join('');
            },
            // Show kill process modal
            showKillModal(pid, user, cmd) {
                document.getElementById('killPid').value = pid;
                document.getElementById('killPidDisplay').textContent = pid;
                document.getElementById('killUserDisplay').textContent = user;
                document.getElementById('killCmdDisplay').textContent = cmd;
                document.getElementById('killCmdDisplay').title = cmd;
                // Reset to default signal
                document.querySelector('input[name="killSignal"][value="15"]').checked = true;
                document.getElementById('killModal').classList.add('active');
            },
            // Kill process with selected signal
            killProcess() {
                const pid = document.getElementById('killPid').value;
                const signal = document.querySelector('input[name="killSignal"]:checked').value;
                const signalNames = { '1': 'SIGHUP', '2': 'SIGINT', '9': 'SIGKILL', '15': 'SIGTERM', '18': 'SIGCONT', '19': 'SIGSTOP' };

                if (this.ws && this.ws.readyState === WebSocket.OPEN && State.sshConnected) {
                    this.ws.send(JSON.stringify({ type: 'kill', pid: parseInt(pid), signal: parseInt(signal) }));
                    Toast.info(`正在发送 ${signalNames[signal]} 到 PID ${pid}...`);
                    document.getElementById('killModal').classList.remove('active');
                } else {
                    Toast.error('未连接到SSH');
                }
            },
            // Handle kill result from server
            handleKillResult(data) {
                if (data.success) {
                    Toast.success(data.message || `进程信号已发送`);
                    // Refresh process list
                    this.refreshTop();
                } else {
                    Toast.error(data.message || '操作失败');
                }
            },
            // ---- Docker Stats ----
            startDockerStats() {
                if (this.dockerStatsActive) return;
                this.dockerStatsActive = true;
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ type: 'startDockerStats' }));
                }
            },
            stopDockerStats() {
                const container = document.getElementById('dockerPanelContainer');
                const body = document.getElementById('dockerPanelBody');
                this.dockerStatsActive = false;
                this.dockerExpanded = false;
                this.dockerMode = 'total';
                this.dockerContainers = [];
                this.dockerSelectedId = null;
                this.dockerAvailable = null;
                this.dockerError = '';
                container.classList.remove('active');
                body.classList.remove('single-mode');
                document.getElementById('dockerContainerCountValue').textContent = '--';
                document.getElementById('dockerCpuHintValue').textContent = '--';
                document.getElementById('dockerMemHintValue').textContent = '--';
                document.getElementById('dockerPanelStatus').textContent = I18n.auto('连接 SSH 后自动获取容器信息');
                document.getElementById('dockerContainerList').innerHTML = '';
                document.getElementById('dockerMetricsGrid').innerHTML = buildEmptyStateHtml('', '连接 SSH 后自动获取 Docker Stats', 'docker-panel-empty');
                document.querySelectorAll('#dockerModeSwitch .docker-mode-tag').forEach(btn => {
                    btn.classList.toggle('active', btn.dataset.mode === 'total');
                });
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ type: 'stopDockerStats' }));
                }
            },
            toggleDockerPanel() {
                if (!State.sshConnected) { Toast.error('请先连接 SSH'); return; }
                const container = document.getElementById('dockerPanelContainer');
                this.dockerExpanded = !this.dockerExpanded;
                container.classList.toggle('active', this.dockerExpanded);
            },
            refreshDockerStats() {
                if (this.ws && this.ws.readyState === WebSocket.OPEN && State.sshConnected) {
                    this.ws.send(JSON.stringify({ type: 'refreshDockerStats' }));
                }
            },
            setDockerMode(mode) {
                if (this.dockerMode === mode) return;
                this.dockerMode = mode;
                if (mode === 'single' && !this.dockerSelectedId && this.dockerContainers.length) {
                    this.dockerSelectedId = this.dockerContainers[0].id;
                }
                this.renderDockerPanel();
            },
            selectDockerContainer(id) {
                this.dockerSelectedId = id;
                this.renderDockerPanel();
            },
            handleDockerStats(data) {
                this.dockerAvailable = data && data.available !== false;
                this.dockerError = (data && data.error) ? data.error : '';
                const containers = this.dockerAvailable && Array.isArray(data.containers)
                    ? data.containers.map(c => this._normalizeContainer(c)).filter(Boolean)
                    : [];
                containers.sort((a, b) => b.cpuPercent - a.cpuPercent || b.memPercent - a.memPercent);
                this.dockerContainers = containers;
                if (!containers.some(c => c.id === this.dockerSelectedId)) {
                    this.dockerSelectedId = containers.length ? containers[0].id : null;
                }
                const totals = this._dockerAggregate(containers);
                document.getElementById('dockerContainerCountValue').textContent = this.dockerAvailable ? String(containers.length) : '--';
                document.getElementById('dockerCpuHintValue').textContent = this.dockerAvailable ? totals.cpuPercent.toFixed(1) + '%' : '--';
                document.getElementById('dockerMemHintValue').textContent = this.dockerAvailable ? totals.memPercent.toFixed(1) + '%' : '--';
                this.renderDockerPanel();
            },
            renderDockerPanel() {
                const body = document.getElementById('dockerPanelBody');
                const list = document.getElementById('dockerContainerList');
                const metrics = document.getElementById('dockerMetricsGrid');
                const status = document.getElementById('dockerPanelStatus');
                const isSingle = this.dockerMode === 'single';
                body.classList.toggle('single-mode', isSingle);
                document.querySelectorAll('#dockerModeSwitch .docker-mode-tag').forEach(btn => {
                    btn.classList.toggle('active', btn.dataset.mode === this.dockerMode);
                });
                if (this.dockerAvailable === null) {
                    status.textContent = I18n.auto('连接 SSH 后自动获取容器信息');
                    list.innerHTML = '';
                    metrics.innerHTML = buildEmptyStateHtml('', '连接 SSH 后自动获取 Docker Stats', 'docker-panel-empty');
                    return;
                }
                if (!this.dockerAvailable) {
                    const errMsg = this.dockerError || 'Docker 不可用';
                    status.textContent = I18n.auto(errMsg);
                    list.innerHTML = '';
                    metrics.innerHTML = buildEmptyStateHtml('', errMsg, 'docker-panel-empty');
                    return;
                }
                if (!this.dockerContainers.length) {
                    status.textContent = I18n.auto('暂无运行中的容器');
                    list.innerHTML = '';
                    metrics.innerHTML = buildEmptyStateHtml('', '未检测到正在运行的容器', 'docker-panel-empty');
                    return;
                }
                // Render container list (single mode)
                if (isSingle) {
                    list.innerHTML = this.dockerContainers.map(c => {
                        const active = c.id === this.dockerSelectedId ? ' active' : '';
                        return `<button type="button" class="docker-container-item${active}" data-container-id="${escapeHtml(c.id)}">
                            <span class="docker-container-name" title="${escapeHtml(c.name)}">${escapeHtml(c.name)}</span>
                            <span class="docker-container-meta">CPU ${c.cpuPercent.toFixed(1)}% · MEM ${c.memPercent.toFixed(1)}%</span>
                        </button>`;
                    }).join('');
                } else {
                    list.innerHTML = '';
                }
                const totals = this._dockerAggregate(this.dockerContainers);
                const selected = isSingle ? this.dockerContainers.find(c => c.id === this.dockerSelectedId) : null;
                if (isSingle && !selected) {
                    status.textContent = I18n.auto('请选择一个容器');
                    metrics.innerHTML = buildEmptyStateHtml('', '请从左侧选择容器', 'docker-panel-empty');
                    return;
                }
                const scope = selected || totals;
                const badge = isSingle ? '详细' : '总计';
                status.textContent = I18n.auto(isSingle ? `容器: ${selected.name}` : `总计 · ${this.dockerContainers.length} 个容器`);
                // Build metric cards
                const netTotal = scope.netIn + scope.netOut;
                const blockTotal = scope.blockRead + scope.blockWrite;
                const allNetTotal = totals.netIn + totals.netOut;
                const allBlockTotal = totals.blockRead + totals.blockWrite;
                const netPct = isSingle ? (allNetTotal > 0 ? Math.min(netTotal / allNetTotal * 100, 100) : 0) : (netTotal > 0 ? 100 : 0);
                const blockPct = isSingle ? (allBlockTotal > 0 ? Math.min(blockTotal / allBlockTotal * 100, 100) : 0) : (blockTotal > 0 ? 100 : 0);
                const cards = [
                    { label: 'CPU', color: '#4b5563', pct: Math.min(scope.cpuPercent, 100), text: scope.cpuPercent.toFixed(1) + '%', sub: badge, detail: isSingle ? scope.name : `${this.dockerContainers.length} ${I18n.auto('容器叠加')}` },
                    { label: 'MEM', color: '#107c10', pct: Math.min(scope.memPercent, 100), text: scope.memPercent.toFixed(1) + '%', sub: `${this.formatSize(scope.memUsed)} ${I18n.auto('已用')}`, detail: `${this.formatSize(scope.memUsed)} / ${scope.memLimit > 0 ? this.formatSize(scope.memLimit) : I18n.auto('无限制')}` },
                    { label: 'NET I/O', color: '#ff8c00', pct: netPct, text: this.formatSize(netTotal), sub: isSingle ? `${netPct.toFixed(1)}%` : I18n.auto('总流量'), detail: `IN ${this.formatSize(scope.netIn)} / OUT ${this.formatSize(scope.netOut)}` },
                    { label: 'BLOCK I/O', color: '#d83b01', pct: blockPct, text: this.formatSize(blockTotal), sub: isSingle ? `${blockPct.toFixed(1)}%` : I18n.auto('总流量'), detail: `R ${this.formatSize(scope.blockRead)} / W ${this.formatSize(scope.blockWrite)}` }
                ];
                metrics.innerHTML = cards.map(c => this._renderRingCard(c, badge)).join('');
            },
            _renderRingCard(m, badge) {
                const r = 40, circ = 2 * Math.PI * r;
                const pct = Math.max(0, Math.min(m.pct, 100));
                const off = circ * (1 - pct / 100);
                return `<div class="docker-metric-card">
                    <div class="docker-metric-head">
                        <span class="docker-metric-title">${escapeHtml(m.label)}</span>
                        <span class="docker-metric-mode">${escapeHtml(badge)}</span>
                    </div>
                    <div class="docker-ring-wrap">
                        <div class="docker-ring" style="--ring-color:${m.color}">
                            <svg viewBox="0 0 110 110">
                                <circle class="docker-ring-track" cx="55" cy="55" r="${r}"></circle>
                                <circle class="docker-ring-progress" cx="55" cy="55" r="${r}" style="stroke-dasharray:${circ.toFixed(2)};stroke-dashoffset:${off.toFixed(2)}"></circle>
                            </svg>
                            <div class="docker-ring-center">
                                <strong>${escapeHtml(m.text)}</strong>
                                <span>${escapeHtml(m.sub)}</span>
                            </div>
                        </div>
                    </div>
                    <div class="docker-metric-detail">${escapeHtml(m.detail)}</div>
                </div>`;
            },
            _normalizeContainer(item) {
                const id = String(item.ID || item.Container || item.Name || '').trim();
                if (!id) return null;
                const name = String(item.Name || item.Container || id).trim();
                const pairOf = (v) => { const p = String(v || '').split('/'); return [this._parseBytes(p[0]), this._parseBytes(p[1])]; };
                const [memUsed, memLimit] = pairOf(item.MemUsage);
                const [netIn, netOut] = pairOf(item.NetIO);
                const [blockRead, blockWrite] = pairOf(item.BlockIO);
                return {
                    id, name,
                    cpuPercent: parseFloat(String(item.CPUPerc || '0').replace('%', '')) || 0,
                    memPercent: parseFloat(String(item.MemPerc || '0').replace('%', '')) || 0,
                    memUsed, memLimit, netIn, netOut, blockRead, blockWrite,
                    pids: parseInt(item.PIDs, 10) || 0
                };
            },
            _dockerAggregate(containers) {
                return containers.reduce((a, c) => {
                    a.cpuPercent += c.cpuPercent; a.memPercent += c.memPercent;
                    a.memUsed += c.memUsed; a.memLimit += c.memLimit;
                    a.netIn += c.netIn; a.netOut += c.netOut;
                    a.blockRead += c.blockRead; a.blockWrite += c.blockWrite;
                    a.pids += c.pids;
                    return a;
                }, { cpuPercent: 0, memPercent: 0, memUsed: 0, memLimit: 0, netIn: 0, netOut: 0, blockRead: 0, blockWrite: 0, pids: 0 });
            },
            _parseBytes(v) {
                const s = String(v || '').trim();
                if (!s || s === '--') return 0;
                const m = s.replace(/,/g, '').match(/^([\d.]+)\s*([A-Za-z]*)/);
                if (!m) return parseFloat(s) || 0;
                const n = parseFloat(m[1]);
                const u = (m[2] || 'B').toUpperCase();
                const mul = { B:1, K:1e3, KB:1e3, MB:1e6, GB:1e9, TB:1e12, KIB:1024, MIB:1048576, GIB:1073741824, TIB:1099511627776 };
                return n * (mul[u] || 1);
            },
            // Format bytes to human readable
            formatSize(bytes) {
                if (bytes < 1024) return bytes + ' B';
                if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' K';
                if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' M';
                return (bytes / 1024 / 1024 / 1024).toFixed(1) + ' G';
            }
        };
        window.Terminal_ = Terminal_;

        // SFTP
        const SFTP = {
            async connect(host, port, user, authPayload = {}) {
                const targetCheck = await validateTargetForConnection('SFTP', host);
                if (!targetCheck.ok) {
                    Toast.error(targetCheck.error);
                    return;
                }
                try {
                    const payload = { host, port: +port, username: user, ...authPayload };
                    const res = await apiFetch(`${Config.API}/api/sftp/connect`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    if (res.ok) {
                        State.sftpConnected = true;
                        State.sftpSession = data.sessionId;
                        // 重置导航历史
                        State.navHistory = [];
                        State.navIndex = -1;
                        this.updateStatus(true, host);
                        Toast.success(`SFTP 已连接到 ${host}`);
                        await this.getHome();
                        await this.navigate(State.currentPath);
                        this.enableBtns(true);
                    } else {
                        Toast.error(formatConnectionError('SFTP', data.error || '连接失败', data.code));
                    }
                } catch (e) {
                    Toast.error('连接失败: ' + e.message);
                }
            },
            async disconnect() {
                if (!State.sftpSession) return;
                try { await apiFetch(`${Config.API}/api/sftp/disconnect/${State.sftpSession}`, { method: 'POST' }); } catch {}
                State.sftpConnected = false;
                State.sftpSession = null;
                State.currentPath = '/';
                State.navHistory = [];
                State.navIndex = -1;
                this.updateStatus(false);
                this.enableBtns(false);
                this.updateNavBtns();
                this.renderFiles([]);
                Toast.info('SFTP 已断开');
            },
            async getHome() {
                if (!State.sftpSession) return;
                try {
                    const res = await apiFetch(`${Config.API}/api/sftp/home/${State.sftpSession}`);
                    const data = await res.json();
                    if (res.ok) {
                        State.currentPath = data.path;
                        document.getElementById('remotePath').value = data.path;
                    }
                } catch {}
            },
            // 导航到路径（添加到历史）
            async navigate(path, addToHistory = true) {
                if (!State.sftpSession) return;
                try {
                    const res = await apiFetch(`${Config.API}/api/sftp/list/${State.sftpSession}?path=${encodeURIComponent(path)}`);
                    const data = await res.json();
                    if (res.ok) {
                        State.currentPath = data.path;
                        document.getElementById('remotePath').value = data.path;
                        State.selectedFiles = [];
                        this.renderFiles(data.files);
                        // 添加到历史
                        if (addToHistory) {
                            // 如果不在历史末尾，截断后面的
                            if (State.navIndex < State.navHistory.length - 1) {
                                State.navHistory = State.navHistory.slice(0, State.navIndex + 1);
                            }
                            State.navHistory.push(data.path);
                            State.navIndex = State.navHistory.length - 1;
                        }
                        this.updateNavBtns();
                    } else {
                        Toast.error(data.error);
                    }
                } catch (e) {
                    Toast.error('列表错误: ' + e.message);
                }
            },
            // 后退
            goBack() {
                if (State.navIndex > 0) {
                    State.navIndex--;
                    this.navigate(State.navHistory[State.navIndex], false);
                }
            },
            // 前进
            goForward() {
                if (State.navIndex < State.navHistory.length - 1) {
                    State.navIndex++;
                    this.navigate(State.navHistory[State.navIndex], false);
                }
            },
            // 上级目录
            goUp() {
                const parts = State.currentPath.split('/').filter(p => p);
                parts.pop();
                const parentPath = '/' + parts.join('/');
                this.navigate(parentPath);
            },
            // 更新导航按钮状态
            updateNavBtns() {
                document.getElementById('navBackBtn').disabled = State.navIndex <= 0;
                document.getElementById('navForwardBtn').disabled = State.navIndex >= State.navHistory.length - 1;
            },
            // 更新选中计数
            updateSelectionCount() {
                const count = State.selectedFiles.filter(f => f.name !== '..').length;
                const el = document.getElementById('selectedCount');
                el.textContent = count > 0 ? I18n.auto(`已选 ${count} 项`) : '';
            },
            async list(path) {
                await this.navigate(path);
            },
            async mkdir(name) {
                if (!State.sftpSession) return;
                const p = State.currentPath === '/' ? `/${name}` : `${State.currentPath}/${name}`;
                try {
                    const res = await apiFetch(`${Config.API}/api/sftp/mkdir/${State.sftpSession}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ path: p })
                    });
                    if (res.ok) {
                        Toast.success('文件夹创建成功');
                        await this.list(State.currentPath);
                    } else {
                        const d = await res.json();
                        Toast.error(d.error);
                    }
                } catch (e) {
                    Toast.error(e.message);
                }
            },
            async delete_() {
                if (!State.sftpSession || State.selectedFiles.length === 0) return;
                const f = State.selectedFiles[0];
                const p = State.currentPath === '/' ? `/${f.name}` : `${State.currentPath}/${f.name}`;
                try {
                    const res = await apiFetch(`${Config.API}/api/sftp/delete/${State.sftpSession}?path=${encodeURIComponent(p)}&type=${f.type}`, { method: 'DELETE' });
                    if (res.ok) {
                        Toast.success('删除成功');
                        State.selectedFiles = [];
                        await this.list(State.currentPath);
                    } else {
                        const d = await res.json();
                        Toast.error(d.error);
                    }
                } catch (e) {
                    Toast.error(e.message);
                }
            },
            async upload(files) {
                if (!State.sftpSession || files.length === 0) return;
                const form = new FormData();
                const paths = [];
                for (const f of files) {
                    form.append('files', f);
                    paths.push(f.webkitRelativePath || f.name);
                }
                form.append('remotePath', State.currentPath);
                form.append('paths', JSON.stringify(paths));
                this.showProgress(true);
                try {
                    const res = await apiFetch(`${Config.API}/api/sftp/upload/${State.sftpSession}`, { method: 'POST', body: form });
                    const data = await res.json();
                    if (res.ok) {
                        State.filesTransferred += data.results.length;
                        const statFiles = document.getElementById('statFiles');
                        if (statFiles) {
                            statFiles.textContent = State.filesTransferred;
                        }
                        Toast.success(data.message);
                        if (data.errors.length > 0) data.errors.forEach(e => Toast.error(`失败: ${e.file}`));
                        await this.list(State.currentPath);
                    } else {
                        Toast.error(data.error);
                    }
                } catch (e) {
                    Toast.error(e.message);
                } finally {
                    this.showProgress(false);
                }
            },
            showProgress(show) {
                const el = document.getElementById('uploadProgress');
                document.getElementById('progressFill').style.width = show ? '100%' : '0';
                el.classList.toggle('active', show);
            },
            updateStatus(connected, host = '') {
                const el = document.getElementById('sftpStatus');
                const txt = document.getElementById('sftpStatusText');
                const disconnBtn = document.getElementById('sftpDisconnectBtn');
                const connBtn = document.getElementById('sftpConnectBtn');
                if (connected) {
                    el.classList.remove('disconnected'); el.classList.add('connected');
                    txt.textContent = I18n.auto(`已连接到 ${host}`);
                    disconnBtn.style.display = 'inline-flex'; connBtn.disabled = true;
                } else {
                    el.classList.remove('connected'); el.classList.add('disconnected');
                    txt.textContent = I18n.auto('未连接');
                    disconnBtn.style.display = 'none'; connBtn.disabled = false;
                }
            },
            async download() {
                if (!State.sftpSession || State.selectedFiles.length === 0) {
                    Toast.error('请先选择要下载的文件');
                    return;
                }
                // 过滤掉 ".."
                const files = State.selectedFiles.filter(f => f.name !== '..');
                if (files.length === 0) {
                    Toast.error('请选择有效的文件');
                    return;
                }
                // 单个普通文件直接下载
                if (files.length === 1 && files[0].type !== 'folder') {
                    const f = files[0];
                    const filePath = State.currentPath === '/' ? `/${f.name}` : `${State.currentPath}/${f.name}`;
                    try {
                        const res = await apiFetch(`${Config.API}/api/sftp/download/${State.sftpSession}?path=${encodeURIComponent(filePath)}`);
                        if (res.ok) {
                            const blob = await res.blob();
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = f.name;
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                            URL.revokeObjectURL(url);
                            Toast.success(`正在下载: ${f.name}`);
                        } else {
                            const data = await res.json();
                            Toast.error(data.error || '下载失败');
                        }
                    } catch (e) {
                        Toast.error('下载失败: ' + e.message);
                    }
                } else {
                    // 多文件或文件夹，打包下载
                    Toast.info(`正在打包 ${files.length} 个项目...`);
                    try {
                        const res = await apiFetch(`${Config.API}/api/sftp/download-zip/${State.sftpSession}`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ files, basePath: State.currentPath })
                        });
                        if (res.ok) {
                            const blob = await res.blob();
                            const zipName = files.length === 1 ? `${files[0].name}.zip` : `download_${Date.now()}.zip`;
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = zipName;
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                            URL.revokeObjectURL(url);
                            Toast.success('下载完成');
                        } else {
                            const data = await res.json();
                            Toast.error(data.error || '下载失败');
                        }
                    } catch (e) {
                        Toast.error('下载失败: ' + e.message);
                    }
                }
            },
            enableBtns(enabled) {
                document.getElementById('sftpRefreshBtn').disabled = !enabled;
                document.getElementById('sftpMkdirBtn').disabled = !enabled;
                document.getElementById('sftpDownloadBtn').disabled = !enabled;
                document.getElementById('sftpDeleteBtn').disabled = !enabled;
                document.getElementById('uploadFilesBtn').disabled = !enabled;
                document.getElementById('uploadFolderBtn').disabled = !enabled;
            },
            renderFiles(files) {
                const el = document.getElementById('fileList');
                if (!files || files.length === 0) {
                    el.innerHTML = State.sftpConnected
                        ? buildEmptyStateHtml('fa-folder-open', '空目录')
                        : buildEmptyStateHtml('fa-plug', '请先连接服务器');
                    return;
                }
                const items = State.currentPath !== '/' ? [{ name: '..', type: 'folder', size: '', modified: '' }, ...files] : files;
                el.innerHTML = items.map(f => `
                    <div class="file-item" data-name="${f.name}" data-type="${f.type}">
                        <i class="fas ${this.getIcon(f)}"></i>
                        <span class="file-name">${f.name}</span>
                        <span class="file-size">${this.formatSize(f.size)}</span>
                        <span class="file-modified">${this.formatDate(f.modified)}</span>
                    </div>
                `).join('');
                el.querySelectorAll('.file-item').forEach(item => {
                    item.addEventListener('click', e => {
                        if (!e.ctrlKey && !e.shiftKey) el.querySelectorAll('.file-item').forEach(i => i.classList.remove('selected'));
                        item.classList.toggle('selected');
                        State.selectedFiles = [...el.querySelectorAll('.file-item.selected')].map(i => ({ name: i.dataset.name, type: i.dataset.type }));
                        this.updateSelectionCount();
                    });
                    item.addEventListener('dblclick', () => {
                        if (item.dataset.type === 'folder') {
                            let newPath;
                            if (item.dataset.name === '..') {
                                this.goUp();
                            } else {
                                newPath = State.currentPath === '/' ? `/${item.dataset.name}` : `${State.currentPath}/${item.dataset.name}`;
                                this.navigate(newPath);
                            }
                        }
                    });
                });
            },
            getIcon(f) {
                if (f.type === 'folder') return 'fa-folder';
                const ext = f.name.split('.').pop().toLowerCase();
                const map = { js: 'fa-file-code', ts: 'fa-file-code', py: 'fa-file-code', html: 'fa-file-code', css: 'fa-file-code', json: 'fa-file-code', png: 'fa-file-image', jpg: 'fa-file-image', jpeg: 'fa-file-image', gif: 'fa-file-image', zip: 'fa-file-archive', tar: 'fa-file-archive', gz: 'fa-file-archive' };
                return map[ext] || 'fa-file';
            },
            formatSize(b) {
                if (!b) return '-';
                const u = ['B', 'KB', 'MB', 'GB'];
                let i = 0, s = b;
                while (s >= 1024 && i < u.length - 1) { s /= 1024; i++; }
                return `${s.toFixed(1)} ${u[i]}`;
            },
            formatDate(d) {
                if (!d) return '-';
                const dt = new Date(d);
                return `${dt.toLocaleDateString()} ${dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
            }
        };

        // 主机管理（服务端存储）
        const Hosts = {
            getUserId() {
                return State.username;
            },
            findMatchingIndex(host) {
                return State.hosts.findIndex(h =>
                    h.host === host.host && h.user === host.user && `${h.port || 22}` === `${host.port || 22}`
                );
            },
            startEdit(index) {
                const host = State.hosts[index];
                if (!host) return;
                UI.switchView('ssh');
                fillSshHostForm(host);
                setEditingHostIndex(index);
                document.getElementById('sshHost').focus();
            },
            async load() {
                const userId = this.getUserId();
                if (!userId) return;
                try {
                    const res = await apiFetch(`${Config.API}/api/userdata/${userId}/hosts`);
                    const data = await res.json().catch(() => []);
                    if (!res.ok) {
                        State.hosts = [];
                        setEditingHostIndex(null);
                        this.render();
                        Toast.error(data.error || '加载主机列表失败');
                        return;
                    }
                    State.hosts = Array.isArray(data) ? data : [];
                    if (State.editingHostIndex !== null && State.editingHostIndex >= State.hosts.length) {
                        setEditingHostIndex(null);
                    }
                    this.render();
                } catch (e) {
                    console.error('加载主机列表失败:', e);
                    State.hosts = [];
                    setEditingHostIndex(null);
                    this.render();
                }
            },
            async add(h) {
                const userId = this.getUserId();
                if (!userId) return;
                try {
                    const res = await apiFetch(`${Config.API}/api/userdata/${userId}/hosts`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(h)
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        Toast.success(data.message || '主机已保存');
                        setEditingHostIndex(null);
                        await this.load();
                    } else {
                        Toast.error(data.error || '保存失败');
                    }
                } catch (e) {
                    Toast.error('保存失败: ' + e.message);
                }
            },
            async update(index, h) {
                const userId = this.getUserId();
                if (!userId) return;
                try {
                    const res = await apiFetch(`${Config.API}/api/userdata/${userId}/hosts/${index}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(h)
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        Toast.success(data.message || '主机已更新');
                        setEditingHostIndex(null);
                        await this.load();
                    } else {
                        Toast.error(data.error || '更新失败');
                    }
                } catch (e) {
                    Toast.error('更新失败: ' + e.message);
                }
            },
            async save(h) {
                if (State.editingHostIndex !== null) {
                    await this.update(State.editingHostIndex, h);
                    return;
                }
                const existingIndex = this.findMatchingIndex(h);
                if (existingIndex >= 0) {
                    await this.update(existingIndex, h);
                    return;
                }
                await this.add(h);
            },
            async remove(i) {
                const userId = this.getUserId();
                if (!userId) return;
                try {
                    const res = await apiFetch(`${Config.API}/api/userdata/${userId}/hosts/${i}`, { method: 'DELETE' });
                    if (res.ok) {
                        if (State.editingHostIndex === i) {
                            setEditingHostIndex(null);
                        } else if (State.editingHostIndex !== null && State.editingHostIndex > i) {
                            State.editingHostIndex -= 1;
                            updateSaveHostButton();
                        }
                        Toast.info('主机已删除');
                        await this.load();
                    }
                } catch (e) {
                    Toast.error('删除失败');
                }
            },
            render() {
                const el = document.getElementById('hostsGrid');
                if (!Array.isArray(State.hosts) || State.hosts.length === 0) {
                    el.innerHTML = buildEmptyStateHtml('fa-server', '暂无保存的主机');
                    return;
                }
                el.innerHTML = State.hosts.map((h, i) => {
                    const authType = normalizeAuthType(h.authType, h.privateKey || '');
                    const authLabel = I18n.auto(authType === AUTH_TYPE_KEY ? '密钥登录' : '密码登录');
                    const hostText = escapeHtml(h.host || '');
                    const userText = escapeHtml(h.user || '');
                    const portText = escapeHtml(h.port || 22);
                    return `
                    <div class="host-card ${Terminal_.host === h.host ? 'connected' : ''}" data-index="${i}">
                        <button class="host-delete" data-index="${i}"><i class="fas fa-times"></i></button>
                        <div class="host-card-content">
                            <div class="host-info"><i class="fas fa-server"></i><span class="host-ip">${hostText}</span></div>
                            <div class="host-details">${userText}@${hostText}:${portText}</div>
                            <span class="host-auth-tag">${authLabel}</span>
                            <div class="host-actions">
                                <button class="btn btn-sm btn-secondary host-edit-btn" data-index="${i}"><i class="fas fa-pen"></i> 编辑</button>
                                <button class="btn btn-sm ssh-btn" data-index="${i}"><i class="fas fa-terminal"></i> SSH</button>
                                <button class="btn btn-sm btn-secondary sftp-btn" data-index="${i}"><i class="fas fa-folder"></i> SFTP</button>
                            </div>
                        </div>
                    </div>
                `;
                }).join('');
                el.querySelectorAll('.host-delete').forEach(btn => btn.addEventListener('click', e => { e.stopPropagation(); this.remove(+btn.dataset.index); }));
                el.querySelectorAll('.host-edit-btn').forEach(btn => btn.addEventListener('click', e => {
                    e.stopPropagation();
                    this.startEdit(+btn.dataset.index);
                }));
                el.querySelectorAll('.ssh-btn').forEach(btn => btn.addEventListener('click', e => {
                    e.stopPropagation();
                    const index = +btn.dataset.index;
                    const h = State.hosts[index];
                    try {
                        const authPayload = getHostCredentialPayload(h);
                        Terminal_.connect(h.host, h.port, h.user, authPayload);
                    } catch (err) {
                        Toast.error(err.message);
                        this.startEdit(index);
                    }
                }));
                el.querySelectorAll('.sftp-btn').forEach(btn => btn.addEventListener('click', e => {
                    e.stopPropagation();
                    const h = State.hosts[+btn.dataset.index];
                    UI.switchView('sftp');
                    document.getElementById('sftpHost').value = h.host || '';
                    document.getElementById('sftpPort').value = h.port || 22;
                    document.getElementById('sftpUser').value = h.user || '';
                    fillCredentialForm('sftp', h);
                    try {
                        const authPayload = getHostCredentialPayload(h);
                        SFTP.connect(h.host, h.port, h.user, authPayload);
                    } catch (err) {
                        Toast.error(err.message);
                    }
                }));
            }
        };

        const Security = {
            networks: [],
            async load() {
                if (!State.isAdmin) return;
                try {
                    const res = await apiFetch(`${Config.API}/api/security/private-networks`);
                    if (!res.ok) {
                        const data = await res.json().catch(() => ({}));
                        Toast.error(data.error || '加载白名单失败');
                        return;
                    }
                    const data = await res.json();
                    this.networks = Array.isArray(data.networks) ? data.networks : [];
                    this.render();
                } catch (e) {
                    Toast.error('加载白名单失败: ' + e.message);
                }
            },
            async update(networks) {
                try {
                    const res = await apiFetch(`${Config.API}/api/security/private-networks`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ networks })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        this.networks = data.networks || networks;
                        this.render();
                        Toast.success('白名单已更新');
                    } else {
                        Toast.error(data.error || '更新失败');
                    }
                } catch (e) {
                    Toast.error('更新失败: ' + e.message);
                }
            },
            async add() {
                const input = document.getElementById('privateNetInput');
                const value = input.value.trim();
                if (!value) {
                    Toast.error('请输入网段');
                    return;
                }
                const next = [...new Set([...this.networks, value])];
                input.value = '';
                await this.update(next);
            },
            async remove(index) {
                const next = this.networks.filter((_, i) => i !== index);
                await this.update(next);
            },
            render() {
                const el = document.getElementById('privateNetList');
                if (!el) return;
                if (!this.networks.length) {
                    el.innerHTML = buildEmptyStateHtml('fa-network-wired', '暂无白名单');
                    return;
                }
                el.innerHTML = this.networks.map((net, i) => `
                    <div class="host-card" data-index="${i}">
                        <button class="host-delete" data-index="${i}"><i class="fas fa-times"></i></button>
                        <div class="host-card-content">
                            <div class="host-info"><i class="fas fa-network-wired"></i><span class="host-ip">${net}</span></div>
                            <div class="host-details">${escapeHtml(I18n.auto('私有网段'))}</div>
                        </div>
                    </div>
                `).join('');
                el.querySelectorAll('.host-delete').forEach(btn => btn.addEventListener('click', e => {
                    e.stopPropagation();
                    this.remove(+btn.dataset.index);
                }));
            }
        };

        // Waveform Visualizer - ES6 Class for oscilloscope-like visualization
        class WaveformVisualizer {
            constructor(canvasId, legendId, options = {}) {
                this.canvas = document.getElementById(canvasId);
                this.legendEl = document.getElementById(legendId);
                this.ctx = this.canvas.getContext('2d');

                // Configuration
                this.windowSize = options.windowSize || 200;
                this.paused = false;
                this.datasets = new Map(); // Map<string, { data: number[], color: string, latestValue: number }>
                this.chart = null;
                this.frameId = null;
                this.pendingUpdates = false;

                // Color palette for auto-assignment
                this.colorPalette = [
                    '#4b5563', '#107c10', '#e81123', '#ff8c00',
                    '#7c3aed', '#6b7280', '#059669', '#c2410c',
                    '#be185d', '#0f766e', '#8b5cf6', '#57534e'
                ];
                this.colorIndex = 0;

                this._initChart();
            }

            _initChart() {
                const isDark = document.documentElement.getAttribute('data-theme') !== 'light';

                this.chart = new Chart(this.ctx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: []
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: false, // Disable animation for performance
                        interaction: {
                            intersect: false,
                            mode: 'index'
                        },
                        plugins: {
                            legend: {
                                display: false // We use custom legend
                            },
                            tooltip: {
                                enabled: true,
                                backgroundColor: isDark ? 'rgba(32,32,32,0.9)' : 'rgba(255,255,255,0.9)',
                                titleColor: isDark ? '#fff' : '#1a1a1a',
                                bodyColor: isDark ? '#a0a0a0' : '#666',
                                borderColor: isDark ? '#3a3a3a' : '#d0d0d0',
                                borderWidth: 1
                            }
                        },
                        scales: {
                            x: {
                                display: true,
                                grid: {
                                    color: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
                                    drawBorder: false
                                },
                                ticks: {
                                    color: isDark ? '#6a6a6a' : '#999',
                                    maxTicksLimit: 10,
                                    font: { size: 10 }
                                }
                            },
                            y: {
                                display: true,
                                grid: {
                                    color: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
                                    drawBorder: false
                                },
                                ticks: {
                                    color: isDark ? '#6a6a6a' : '#999',
                                    font: { size: 10 }
                                }
                            }
                        },
                        elements: {
                            point: {
                                radius: 0 // Hide points for performance
                            },
                            line: {
                                tension: 0.2,
                                borderWidth: 2
                            }
                        }
                    }
                });

                // Generate initial labels
                this._updateLabels();
            }

            _updateLabels() {
                const labels = [];
                for (let i = 0; i < this.windowSize; i++) {
                    labels.push(i.toString());
                }
                this.chart.data.labels = labels;
            }

            _getNextColor() {
                const color = this.colorPalette[this.colorIndex % this.colorPalette.length];
                this.colorIndex++;
                return color;
            }

            _ensureDataset(key) {
                if (!this.datasets.has(key)) {
                    const color = this._getNextColor();
                    const data = new Array(this.windowSize).fill(null);
                    this.datasets.set(key, { data, color, latestValue: 0 });

                    // Add to chart
                    this.chart.data.datasets.push({
                        label: key,
                        data: [...data],
                        borderColor: color,
                        backgroundColor: color + '20',
                        fill: false
                    });

                    this._updateLegend();
                }
                return this.datasets.get(key);
            }

            _updateLegend() {
                if (!this.legendEl) return;

                let html = '';
                this.datasets.forEach((dataset, key) => {
                    const valueStr = dataset.latestValue !== null ? dataset.latestValue.toFixed(2) : '-';
                    html += `
                        <div class="waveform-legend-item">
                            <div class="waveform-legend-color" style="background:${dataset.color}"></div>
                            <span class="waveform-legend-label">${key}</span>
                            <span class="waveform-legend-value">${valueStr}</span>
                        </div>
                    `;
                });
                this.legendEl.innerHTML = html;
            }

            pushData(key, value) {
                if (this.paused) return;

                const numValue = parseFloat(value);
                if (isNaN(numValue)) return;

                const dataset = this._ensureDataset(key);
                dataset.data.push(numValue);
                dataset.latestValue = numValue;

                // Maintain sliding window
                while (dataset.data.length > this.windowSize) {
                    dataset.data.shift();
                }

                // Pad with nulls if needed
                while (dataset.data.length < this.windowSize) {
                    dataset.data.unshift(null);
                }

                this.pendingUpdates = true;
                this._scheduleRender();
            }

            _scheduleRender() {
                if (this.frameId) return;

                this.frameId = requestAnimationFrame(() => {
                    this.frameId = null;
                    if (this.pendingUpdates) {
                        this._render();
                        this.pendingUpdates = false;
                    }
                });
            }

            _render() {
                // Update chart datasets
                let idx = 0;
                this.datasets.forEach((dataset, key) => {
                    if (this.chart.data.datasets[idx]) {
                        this.chart.data.datasets[idx].data = [...dataset.data];
                    }
                    idx++;
                });

                this.chart.update('none'); // Update without animation
                this._updateLegend();
            }

            setWindowSize(size) {
                this.windowSize = Math.max(50, Math.min(1000, size));
                this._updateLabels();

                // Resize all datasets
                this.datasets.forEach((dataset) => {
                    while (dataset.data.length > this.windowSize) {
                        dataset.data.shift();
                    }
                    while (dataset.data.length < this.windowSize) {
                        dataset.data.unshift(null);
                    }
                });

                this._render();
            }

            pause() {
                this.paused = true;
            }

            resume() {
                this.paused = false;
            }

            togglePause() {
                this.paused = !this.paused;
                return this.paused;
            }

            clear() {
                this.datasets.clear();
                this.chart.data.datasets = [];
                this.colorIndex = 0;
                this._updateLegend();
                this.chart.update('none');
            }

            destroy() {
                if (this.frameId) {
                    cancelAnimationFrame(this.frameId);
                }
                if (this.chart) {
                    this.chart.destroy();
                }
            }
        }

        // StatChart Visualizer - Bar chart for statistics data
        // Format: var:[a:2, b:3, c:5, d:6] or multiple: var1:[a:4, b:6], var2:[a:6, b:3]
        class StatChartVisualizer {
            constructor(canvasId) {
                this.canvas = document.getElementById(canvasId);
                this.ctx = this.canvas.getContext('2d');
                this.chart = null;
                this.datasets = new Map(); // Map<varName, Map<subKey, value>>
                this.frameId = null;
                this.pendingUpdates = false;

                // Color palette for sub-variables (a, b, c, d, etc.)
                this.colorPalette = [
                    '#4b5563', '#107c10', '#e81123', '#ff8c00',
                    '#7c3aed', '#6b7280', '#059669', '#c2410c',
                    '#be185d', '#0f766e', '#8b5cf6', '#57534e',
                    '#a21caf', '#6366f1', '#047857', '#a16207'
                ];
                this.subKeyColors = new Map(); // Map<subKey, color>
                this.colorIndex = 0;

                this._initChart();
            }

            _initChart() {
                const isDark = document.documentElement.getAttribute('data-theme') !== 'light';

                this.chart = new Chart(this.ctx, {
                    type: 'bar',
                    data: {
                        labels: [], // Variable names (var1, var2, ...)
                        datasets: [] // Each dataset is a sub-key (a, b, c, d, ...)
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: { duration: 300 },
                        interaction: {
                            intersect: false,
                            mode: 'index'
                        },
                        plugins: {
                            legend: {
                                display: true,
                                position: 'top',
                                labels: {
                                    color: isDark ? '#a0a0a0' : '#666',
                                    font: { size: 11 },
                                    boxWidth: 12,
                                    padding: 8
                                }
                            },
                            tooltip: {
                                enabled: true,
                                backgroundColor: isDark ? 'rgba(32,32,32,0.9)' : 'rgba(255,255,255,0.9)',
                                titleColor: isDark ? '#fff' : '#1a1a1a',
                                bodyColor: isDark ? '#a0a0a0' : '#666',
                                borderColor: isDark ? '#3a3a3a' : '#d0d0d0',
                                borderWidth: 1
                            }
                        },
                        scales: {
                            x: {
                                display: true,
                                grid: {
                                    color: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
                                    drawBorder: false
                                },
                                ticks: {
                                    color: isDark ? '#a0a0a0' : '#666',
                                    font: { size: 11 }
                                }
                            },
                            y: {
                                display: true,
                                beginAtZero: true,
                                grid: {
                                    color: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
                                    drawBorder: false
                                },
                                ticks: {
                                    color: isDark ? '#a0a0a0' : '#666',
                                    font: { size: 11 }
                                }
                            }
                        }
                    }
                });
            }

            _getColorForSubKey(subKey) {
                if (!this.subKeyColors.has(subKey)) {
                    const color = this.colorPalette[this.colorIndex % this.colorPalette.length];
                    this.subKeyColors.set(subKey, color);
                    this.colorIndex++;
                }
                return this.subKeyColors.get(subKey);
            }

            // Parse format: var:[a:2, b:3, c:5] or var1:[a:4, b:6], var2:[a:6, b:3]
            parseStatLine(line) {
                const results = [];
                // Match pattern: varName:[key:value, key:value, ...]
                const regex = /([A-Za-z_][A-Za-z0-9_]*):\s*\[([^\]]+)\]/g;
                let match;

                while ((match = regex.exec(line)) !== null) {
                    const varName = match[1];
                    const content = match[2];
                    const pairs = {};

                    // Parse key:value pairs inside brackets
                    const pairRegex = /([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(-?\d+\.?\d*)/g;
                    let pairMatch;
                    while ((pairMatch = pairRegex.exec(content)) !== null) {
                        pairs[pairMatch[1]] = parseFloat(pairMatch[2]);
                    }

                    if (Object.keys(pairs).length > 0) {
                        results.push({ varName, pairs });
                    }
                }

                return results.length > 0 ? results : null;
            }

            pushData(varName, pairs) {
                if (!this.datasets.has(varName)) {
                    this.datasets.set(varName, new Map());
                }
                const varData = this.datasets.get(varName);

                for (const [subKey, value] of Object.entries(pairs)) {
                    varData.set(subKey, value);
                }

                this.pendingUpdates = true;
                this._scheduleRender();
            }

            _scheduleRender() {
                if (this.frameId) return;

                this.frameId = requestAnimationFrame(() => {
                    this.frameId = null;
                    if (this.pendingUpdates) {
                        this._render();
                        this.pendingUpdates = false;
                    }
                });
            }

            _render() {
                // Collect all unique sub-keys across all variables
                const allSubKeys = new Set();
                this.datasets.forEach((varData) => {
                    varData.forEach((_, subKey) => allSubKeys.add(subKey));
                });

                // Sort sub-keys for consistent ordering
                const sortedSubKeys = Array.from(allSubKeys).sort();

                // Variable names as labels
                const varNames = Array.from(this.datasets.keys());

                // Build datasets (one per sub-key)
                const chartDatasets = sortedSubKeys.map(subKey => {
                    const color = this._getColorForSubKey(subKey);
                    const data = varNames.map(varName => {
                        const varData = this.datasets.get(varName);
                        return varData.has(subKey) ? varData.get(subKey) : 0;
                    });

                    return {
                        label: subKey,
                        data: data,
                        backgroundColor: color + 'CC',
                        borderColor: color,
                        borderWidth: 1
                    };
                });

                this.chart.data.labels = varNames;
                this.chart.data.datasets = chartDatasets;
                this.chart.update('none');
            }

            clear() {
                this.datasets.clear();
                this.subKeyColors.clear();
                this.colorIndex = 0;
                this.chart.data.labels = [];
                this.chart.data.datasets = [];
                this.chart.update('none');
            }

            destroy() {
                if (this.frameId) {
                    cancelAnimationFrame(this.frameId);
                }
                if (this.chart) {
                    this.chart.destroy();
                }
            }
        }

        // System Stats Visualizer - Line chart for CPU, Memory, Disk I/O
        class SysStatsVisualizer {
            constructor(canvasId) {
                this.canvas = document.getElementById(canvasId);
                this.ctx = this.canvas.getContext('2d');
                this.chart = null;
                this.maxDataPoints = 60; // 60 data points (about 1 minute at 1s interval)
                this.cpuData = [];
                this.memData = [];
                this.diskReadData = [];
                this.diskWriteData = [];
                this.labels = [];
                this.lastDiskStats = null;
                this.lastDiskTime = null;
                this._initChart();
            }

            _initChart() {
                const isDark = document.documentElement.getAttribute('data-theme') !== 'light';

                this.chart = new Chart(this.ctx, {
                    type: 'line',
                    data: {
                        labels: this.labels,
                        datasets: [
                            {
                                label: 'CPU %',
                                data: this.cpuData,
                                borderColor: '#4b5563',
                                backgroundColor: 'rgba(75, 85, 99, 0.12)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.3,
                                pointRadius: 0
                            },
                            {
                                label: '内存 %',
                                data: this.memData,
                                borderColor: '#107c10',
                                backgroundColor: 'rgba(16, 124, 16, 0.1)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.3,
                                pointRadius: 0
                            },
                            {
                                label: '磁盘读 KB/s',
                                data: this.diskReadData,
                                borderColor: '#ff8c00',
                                backgroundColor: 'rgba(255, 140, 0, 0.1)',
                                borderWidth: 2,
                                fill: false,
                                tension: 0.3,
                                pointRadius: 0,
                                yAxisID: 'y1'
                            },
                            {
                                label: '磁盘写 KB/s',
                                data: this.diskWriteData,
                                borderColor: '#e81123',
                                backgroundColor: 'rgba(232, 17, 35, 0.1)',
                                borderWidth: 2,
                                fill: false,
                                tension: 0.3,
                                pointRadius: 0,
                                yAxisID: 'y1'
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: { duration: 0 },
                        interaction: {
                            intersect: false,
                            mode: 'index'
                        },
                        plugins: {
                            legend: {
                                display: true,
                                position: 'top',
                                labels: {
                                    color: isDark ? '#a0a0a0' : '#666',
                                    font: { size: 11 },
                                    boxWidth: 12,
                                    padding: 8
                                }
                            },
                            tooltip: {
                                enabled: true,
                                backgroundColor: isDark ? 'rgba(32,32,32,0.9)' : 'rgba(255,255,255,0.9)',
                                titleColor: isDark ? '#fff' : '#1a1a1a',
                                bodyColor: isDark ? '#a0a0a0' : '#666',
                                borderColor: isDark ? '#3a3a3a' : '#d0d0d0',
                                borderWidth: 1
                            }
                        },
                        scales: {
                            x: {
                                display: false
                            },
                            y: {
                                display: true,
                                position: 'left',
                                min: 0,
                                max: 100,
                                grid: {
                                    color: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
                                    drawBorder: false
                                },
                                ticks: {
                                    color: isDark ? '#a0a0a0' : '#666',
                                    font: { size: 10 },
                                    callback: (value) => value + '%'
                                }
                            },
                            y1: {
                                display: true,
                                position: 'right',
                                min: 0,
                                grid: {
                                    drawOnChartArea: false
                                },
                                ticks: {
                                    color: isDark ? '#a0a0a0' : '#666',
                                    font: { size: 10 },
                                    callback: (value) => value.toFixed(0) + ' KB/s'
                                }
                            }
                        }
                    }
                });
            }

            // Parse /proc/loadavg output: "0.00 0.01 0.05 1/234 12345"
            parseLoadAvg(line) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 3) {
                    // 1-minute load average, normalize to percentage (rough estimate based on CPU count)
                    return parseFloat(parts[0]);
                }
                return null;
            }

            // Parse /proc/meminfo output
            parseMemInfo(lines) {
                const info = {};
                for (const line of lines) {
                    const match = line.match(/^(\w+):\s+(\d+)/);
                    if (match) {
                        info[match[1]] = parseInt(match[2]);
                    }
                }
                if (info.MemTotal && info.MemAvailable !== undefined) {
                    const used = info.MemTotal - info.MemAvailable;
                    return (used / info.MemTotal * 100).toFixed(1);
                }
                return null;
            }

            // Parse /proc/diskstats output
            parseDiskStats(lines, currentTime) {
                let totalReadSectors = 0;
                let totalWriteSectors = 0;

                for (const line of lines) {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length >= 14) {
                        const deviceName = parts[2];
                        // Only count major block devices (sda, vda, nvme0n1, etc.), not partitions
                        if (/^(sd[a-z]|vd[a-z]|nvme\d+n\d+|xvd[a-z])$/.test(deviceName)) {
                            totalReadSectors += parseInt(parts[5]) || 0;  // sectors read
                            totalWriteSectors += parseInt(parts[9]) || 0; // sectors written
                        }
                    }
                }

                if (this.lastDiskStats && this.lastDiskTime) {
                    const timeDelta = (currentTime - this.lastDiskTime) / 1000; // seconds
                    const readDelta = totalReadSectors - this.lastDiskStats.read;
                    const writeDelta = totalWriteSectors - this.lastDiskStats.write;
                    // Each sector is 512 bytes
                    const readKBps = (readDelta * 512 / 1024 / timeDelta).toFixed(1);
                    const writeKBps = (writeDelta * 512 / 1024 / timeDelta).toFixed(1);

                    this.lastDiskStats = { read: totalReadSectors, write: totalWriteSectors };
                    this.lastDiskTime = currentTime;

                    return { read: parseFloat(readKBps), write: parseFloat(writeKBps) };
                }

                this.lastDiskStats = { read: totalReadSectors, write: totalWriteSectors };
                this.lastDiskTime = currentTime;
                return null;
            }

            // Parse /proc/stat for CPU usage
            parseCpuStat(lines) {
                for (const line of lines) {
                    if (line.startsWith('cpu ')) {
                        const parts = line.split(/\s+/).slice(1).map(Number);
                        // user, nice, system, idle, iowait, irq, softirq, steal
                        const [user, nice, system, idle, iowait = 0, irq = 0, softirq = 0, steal = 0] = parts;
                        const total = user + nice + system + idle + iowait + irq + softirq + steal;
                        const busy = user + nice + system + irq + softirq + steal;
                        return { total, busy };
                    }
                }
                return null;
            }

            pushData(cpu, mem, diskRead, diskWrite) {
                const now = new Date();
                const timeLabel = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

                this.cpuData.push(cpu);
                this.memData.push(mem);
                this.diskReadData.push(diskRead);
                this.diskWriteData.push(diskWrite);
                this.labels.push(timeLabel);

                // Keep only last N data points
                if (this.cpuData.length > this.maxDataPoints) {
                    this.cpuData.shift();
                    this.memData.shift();
                    this.diskReadData.shift();
                    this.diskWriteData.shift();
                    this.labels.shift();
                }

                this.chart.update('none');
            }

            clear() {
                this.cpuData.length = 0;
                this.memData.length = 0;
                this.diskReadData.length = 0;
                this.diskWriteData.length = 0;
                this.labels.length = 0;
                this.lastDiskStats = null;
                this.lastDiskTime = null;
                document.getElementById('statCpuValue').textContent = '--%';
                document.getElementById('statMemValue').textContent = '--%';
                document.getElementById('statDiskValue').textContent = '-- KB/s';
                this.chart.update('none');
            }

            destroy() {
                if (this.chart) {
                    this.chart.destroy();
                }
            }
        }

        // 串口终端 (WebSerial API)
        const Serial = {
            port: null,
            reader: null,
            writer: null,
            term: null,
            fit: null,
            connected: false,
            readLoop: null,
            platformDenied: false,
            pendingCR: false,
            // Waveform visualization
            waveformVisualizer: null,
            waveformActive: false,
            // Stat chart visualization
            statChartVisualizer: null,
            statChartActive: false,
            lineBuffer: '', // Buffer for line-based parsing
            // Demo mode
            demoMode: false,
            demoInterval: null,
            demoTime: 0,
            chunkQueue: [],
            queuedSize: 0,
            queueScheduled: false,
            lastDropNotice: 0,

            init() {
                // 检查浏览器支持
                if (!('serial' in navigator)) {
                    this.platformDenied = true;
                    document.getElementById('serialNotSupported').style.display = 'block';
                    document.getElementById('serialNotSupported').innerHTML =
                        '<p style="color:var(--color-warning);margin-bottom:8px"><i class="fas fa-exclamation-triangle"></i> 当前环境不支持 Web Serial</p>' +
                        '<p style="color:var(--color-text-2);font-size:12px">请使用支持 Web Serial 的桌面应用或 Chromium 内核浏览器</p>';
                    document.getElementById('serialConnectBtn').disabled = true;
                    return;
                }

                // 初始化终端
                this.term = new Terminal({
                    theme: Theme.getTerminalTheme(),
                    fontFamily: 'Consolas, Monaco, monospace',
                    fontSize: 14, cursorBlink: true,
                    convertEol: true
                });
                this.fit = new FitAddon.FitAddon();
                this.term.loadAddon(this.fit);
                this.term.open(document.getElementById('serialTerminal'));
                this.doFit();
                this.welcome();

                window.addEventListener('resize', () => this.doFit());

                // 终端输入处理
                this.term.onData(data => {
                    if (this.connected && this.writer) {
                        this.write(data);
                    }
                });

                // 绑定事件
                document.getElementById('serialConnectBtn').addEventListener('click', () => this.connect());
                document.getElementById('serialDisconnectBtn').addEventListener('click', () => this.disconnect());
                document.getElementById('serialClearBtn').addEventListener('click', () => { this.term.clear(); this.welcome(); });
                document.getElementById('serialSendBtn').addEventListener('click', () => this.sendData());
                document.getElementById('serialSendInput').addEventListener('keypress', e => { if (e.key === 'Enter') this.sendData(); });

                // Waveform event handlers
                document.getElementById('serialWaveformBtn').addEventListener('click', () => this.toggleWaveform());
                document.getElementById('waveformPauseBtn').addEventListener('click', () => this.toggleWaveformPause());
                document.getElementById('waveformClearBtn').addEventListener('click', () => this.clearWaveform());
                document.getElementById('waveformWindowSize').addEventListener('change', (e) => {
                    if (this.waveformVisualizer) {
                        this.waveformVisualizer.setWindowSize(parseInt(e.target.value));
                    }
                });

                // Stat chart event handlers
                document.getElementById('serialStatChartBtn').addEventListener('click', () => this.toggleStatChart());
                document.getElementById('statChartClearBtn').addEventListener('click', () => this.clearStatChart());

                // Demo mode button
                document.getElementById('serialDemoBtn').addEventListener('click', () => this.startDemo());
            },

            applyTheme() {
                if (!this.term) return;
                this.term.setOption('theme', Theme.getTerminalTheme());
                this.doFit();
                if (!this.connected && !this.demoMode) {
                    this.term.clear();
                    this.welcome();
                }
            },

            // Start demo mode - simulates waveform data without real serial port
            startDemo() {
                if (this.connected || this.demoMode) {
                    Toast.info('请先断开当前连接');
                    return;
                }

                this.demoMode = true;
                this.connected = true;
                this.demoTime = 0;
                this.updateStatus(true, true);
                this.term.clear();
                this.term.writeln(`\x1b[32m${I18n.auto('演示模式已启动')} (Demo data)\x1b[0m`);
                this.term.writeln(`\x1b[90m${I18n.auto('波形数据: Sin, Cos, Sin3Hz, ADC, Temp')}\x1b[0m`);
                this.term.writeln(`\x1b[90m${I18n.auto('统计数据: stats:[a:x, b:x, c:x, d:x] 格式')}\x1b[0m`);
                this.term.writeln(`\x1b[90m${I18n.auto('点击 "波形" 或 "统计" 按钮查看实时图表')}\x1b[0m\n`);

                // Auto-enable waveform view
                if (!this.waveformActive) {
                    this.toggleWaveform();
                }

                Toast.success('演示模式已启动');

                // Start generating demo data at 50Hz
                this.demoInterval = setInterval(() => {
                    const t = this.demoTime;

                    // Generate waveform data
                    const sin = Math.sin(2 * Math.PI * 1.0 * t).toFixed(3);
                    const cos = Math.cos(2 * Math.PI * 1.0 * t).toFixed(3);
                    const sin3 = (0.5 * Math.sin(2 * Math.PI * 3.0 * t)).toFixed(3);
                    const adcBase = 2048 + 1800 * Math.sin(2 * Math.PI * 0.5 * t);
                    const adc = Math.floor(Math.max(0, Math.min(4095, adcBase + (Math.random() - 0.5) * 100)));
                    const temp = (25 + 5 * Math.sin(2 * Math.PI * 0.1 * t) + (Math.random() - 0.5) * 0.4).toFixed(2);

                    // Process as if received from serial
                    const lines = [
                        `Sin:${sin}`,
                        `Cos:${cos}`,
                        `Sin3Hz:${sin3}`,
                        `ADC:${adc}`,
                        `Temp:${temp}`
                    ];

                    lines.forEach(line => {
                        const waveformDataArray = this.parseWaveformLine(line);
                        if (waveformDataArray && this.waveformActive && this.waveformVisualizer) {
                            waveformDataArray.forEach(data => {
                                this.waveformVisualizer.pushData(data.key, data.value);
                            });
                        }
                    });

                    // Generate stat chart data every 500ms (every 25 frames)
                    if (Math.floor(this.demoTime * 50) % 25 === 0) {
                        const a = Math.floor(Math.random() * 10 + 1);
                        const b = Math.floor(Math.random() * 10 + 1);
                        const c = Math.floor(Math.random() * 10 + 1);
                        const d = Math.floor(Math.random() * 10 + 1);
                        const statLine = `stats:[a:${a}, b:${b}, c:${c}, d:${d}]`;

                        // Parse and display stat chart data
                        if (this.statChartActive && this.statChartVisualizer) {
                            const statData = this.statChartVisualizer.parseStatLine(statLine);
                            if (statData) {
                                statData.forEach(item => {
                                    this.statChartVisualizer.pushData(item.varName, item.pairs);
                                });
                            }
                        }
                    }

                    this.demoTime += 0.02; // 50Hz = 20ms interval
                }, 20);
            },

            // Toggle waveform visualization
            toggleWaveform() {
                const container = document.getElementById('waveformContainer');
                const btn = document.getElementById('serialWaveformBtn');

                this.waveformActive = !this.waveformActive;
                container.classList.toggle('active', this.waveformActive);
                btn.classList.toggle('btn-secondary', !this.waveformActive);
                btn.classList.toggle('btn-success', this.waveformActive);

                if (this.waveformActive && !this.waveformVisualizer) {
                    // Initialize waveform visualizer on first activation
                    const windowSize = parseInt(document.getElementById('waveformWindowSize').value) || 200;
                    this.waveformVisualizer = new WaveformVisualizer('waveformCanvas', 'waveformLegend', { windowSize });
                }
            },

            // Toggle pause for waveform
            toggleWaveformPause() {
                if (!this.waveformVisualizer) return;
                const paused = this.waveformVisualizer.togglePause();
                const btn = document.getElementById('waveformPauseBtn');
                btn.innerHTML = paused ? '<i class="fas fa-play"></i>' : '<i class="fas fa-pause"></i>';
            },

            // Clear waveform data
            clearWaveform() {
                if (this.waveformVisualizer) {
                    this.waveformVisualizer.clear();
                }
            },

            // Toggle stat chart visualization
            toggleStatChart() {
                const container = document.getElementById('statChartContainer');
                const btn = document.getElementById('serialStatChartBtn');

                this.statChartActive = !this.statChartActive;
                container.classList.toggle('active', this.statChartActive);
                btn.classList.toggle('btn-secondary', !this.statChartActive);
                btn.classList.toggle('btn-success', this.statChartActive);

                if (this.statChartActive && !this.statChartVisualizer) {
                    this.statChartVisualizer = new StatChartVisualizer('statChartCanvas');
                }
            },

            // Clear stat chart data
            clearStatChart() {
                if (this.statChartVisualizer) {
                    this.statChartVisualizer.clear();
                }
            },

            // Check if line matches stat chart format (var:[a:2, b:3])
            isStatChartFormat(line) {
                return /[A-Za-z_][A-Za-z0-9_]*:\s*\[[^\]]+\]/.test(line);
            },

            // Parse data line for waveform format (Variable:Value)
            // Supports both single value and comma-separated multiple values
            parseWaveformLine(line) {
                // Match format: VariableName:NumericValue
                // Examples:
                //   Single: ADC1:1024, Temp:25.5, Sin:-0.5
                //   Multiple: a:2, b:4, temp:25.5
                const trimmedLine = line.trim();

                // Try to parse as comma-separated values first
                const pairs = trimmedLine.split(',').map(pair => pair.trim());
                const results = [];

                for (const pair of pairs) {
                    const match = pair.match(/^([A-Za-z_][A-Za-z0-9_]*):(-?\d+\.?\d*)$/);
                    if (match) {
                        results.push({ key: match[1], value: parseFloat(match[2]) });
                    }
                }

                return results.length > 0 ? results : null;
            },

            doFit() {
                try { this.fit.fit(); } catch {}
            },

            welcome() {
                const colors = Theme.getTerminalWelcomeColors();
                this.term.writeln('');
                this.term.writeln(`\x1b[${colors.frame}m  ╔══════════════════════════════════════════╗\x1b[0m`);
                this.term.writeln(`\x1b[${colors.frame}m  ║\x1b[0m    \x1b[${colors.title}mSerial Terminal (WebSerial)\x1b[0m          \x1b[${colors.frame}m║\x1b[0m`);
                this.term.writeln(`\x1b[${colors.frame}m  ╚══════════════════════════════════════════╝\x1b[0m`);
                this.term.writeln('');
                this.term.writeln(`\x1b[90m  ${I18n.auto('点击 "连接串口" 按钮选择串口设备')}\x1b[0m`);
                this.term.writeln('');
            },

            async connect() {
                try {
                    if (this.platformDenied) {
                        Toast.error('当前平台不允许访问串口');
                        return;
                    }
                    // 请求串口
                    this.port = await navigator.serial.requestPort();

                    // 获取配置
                    const baudRate = parseInt(document.getElementById('serialBaudRate').value);
                    const dataBits = parseInt(document.getElementById('serialDataBits').value);
                    const stopBits = parseInt(document.getElementById('serialStopBits').value);
                    const parity = document.getElementById('serialParity').value;
                    const flowControl = document.getElementById('serialFlowControl').value;

                    // 打开串口
                    await this.port.open({
                        baudRate,
                        dataBits,
                        stopBits,
                        parity,
                        flowControl,
                        bufferSize: 262144
                    });

                    this.connected = true;
                    this.pendingCR = false;
                    this.chunkQueue = [];
                    this.queuedSize = 0;
                    this.queueScheduled = false;
                    this.updateStatus(true);
                    this.term.clear();
                    this.term.writeln(`\x1b[32m${I18n.auto(`串口已连接 (${baudRate} bps)`)}\x1b[0m\n`);

                    // 设置读写
                    const textDecoder = new TextDecoderStream();
                    const readableStreamClosed = this.port.readable.pipeTo(textDecoder.writable);
                    this.reader = textDecoder.readable.getReader();
                    readableStreamClosed.catch(() => {});

                    const textEncoder = new TextEncoderStream();
                    const writableStreamClosed = textEncoder.readable.pipeTo(this.port.writable);
                    this.writer = textEncoder.writable.getWriter();
                    writableStreamClosed.catch(() => {});

                    // 开始读取
                    this.readLoop = this.startReading();

                    Toast.success('串口已连接');
                } catch (e) {
                    if (e.name === 'NotFoundError') {
                        Toast.info('未选择串口设备');
                        this.term.writeln(`\x1b[33m${I18n.auto('未选择串口设备')}\x1b[0m`);
                        return;
                    }

                    const message = String((e && e.message) || e || '未知错误');
                    const lowerMessage = message.toLowerCase();
                    let hint = '';

                    if (e.name === 'SecurityError') {
                        hint = '串口权限被拒绝，请在权限弹窗中允许串口访问。';
                    } else if (
                        lowerMessage.includes('permission') ||
                        lowerMessage.includes('denied') ||
                        lowerMessage.includes('access')
                    ) {
                        hint = '当前用户可能没有串口设备权限，请将用户加入 dialout/uucp 组并重新登录。';
                    } else if (
                        lowerMessage.includes('failed to open serial port') ||
                        lowerMessage.includes('could not open port')
                    ) {
                        hint = '串口被占用或无权限访问，请检查设备占用和用户组权限。';
                    }

                    Toast.error(hint ? `连接失败: ${hint}` : `连接失败: ${message}`);
                    this.term.writeln(`\x1b[31m${I18n.auto(`连接失败: ${e.name || 'Error'}: ${message}`)}\x1b[0m`);
                    if (hint) {
                        this.term.writeln(`\x1b[33m${I18n.auto(`建议: ${hint}`)}\x1b[0m`);
                    }
                }
            },

            normalizeIncoming(chunk) {
                let data = String(chunk || '');
                if (!data) return '';

                if (this.pendingCR) {
                    if (data.startsWith('\n')) {
                        data = data.slice(1);
                    }
                    this.pendingCR = false;
                }

                data = data.replace(/\r\n/g, '\n');
                if (data.endsWith('\r')) {
                    this.pendingCR = true;
                    data = data.slice(0, -1);
                }
                data = data.replace(/\r/g, '\n');
                return data;
            },

            appendIncoming(chunk) {
                const data = this.normalizeIncoming(chunk);
                if (!data) return;
                this.lineBuffer += data;
            },

            scheduleQueue() {
                if (this.queueScheduled) return;
                this.queueScheduled = true;
                setTimeout(() => {
                    this.queueScheduled = false;
                    this.flushQueue();
                }, 0);
            },

            flushQueue() {
                if (!this.connected) return;
                if (this.chunkQueue.length === 0) return;

                const chunks = this.chunkQueue.splice(0);
                this.queuedSize = 0;
                const data = chunks.join('');
                if (data) {
                    this.handleIncoming(data);
                }
            },

            handleIncoming(data) {
                const showHex = () => document.getElementById('serialShowHex').checked;
                const autoScroll = () => document.getElementById('serialAutoScroll').checked;
                const needsLineParsing = showHex() || this.waveformActive || this.statChartActive;

                if (!needsLineParsing) {
                    const normalized = this.normalizeIncoming(data);
                    if (normalized) {
                        this.term.write(normalized);
                        if (autoScroll()) {
                            this.term.scrollToBottom();
                        }
                    }
                    return;
                }

                this.appendIncoming(data);

                let newlineIdx;
                while ((newlineIdx = this.lineBuffer.indexOf('\n')) !== -1) {
                    const line = this.lineBuffer.substring(0, newlineIdx).replace(/\r$/, '');
                    this.lineBuffer = this.lineBuffer.substring(newlineIdx + 1);

                    const isStatData = this.isStatChartFormat(line);
                    if (isStatData && this.statChartActive && this.statChartVisualizer) {
                        const statData = this.statChartVisualizer.parseStatLine(line);
                        if (statData) {
                            statData.forEach(item => {
                                this.statChartVisualizer.pushData(item.varName, item.pairs);
                            });
                        }
                    }

                    if (!isStatData) {
                        const waveformDataArray = this.parseWaveformLine(line);
                        if (waveformDataArray && this.waveformActive && this.waveformVisualizer) {
                            waveformDataArray.forEach(dataPoint => {
                                this.waveformVisualizer.pushData(dataPoint.key, dataPoint.value);
                            });
                        }
                    }

                    if (showHex()) {
                        const hex = Array.from(new TextEncoder().encode(line + '\n'))
                            .map(b => b.toString(16).padStart(2, '0').toUpperCase())
                            .join(' ');
                        this.term.write(`\x1b[33m${hex}\x1b[0m `);
                    } else {
                        this.term.writeln(line);
                    }
                }

                if (this.lineBuffer.length > 256) {
                    if (showHex()) {
                        const hex = Array.from(new TextEncoder().encode(this.lineBuffer))
                            .map(b => b.toString(16).padStart(2, '0').toUpperCase())
                            .join(' ');
                        this.term.write(`\x1b[33m${hex}\x1b[0m `);
                    } else {
                        this.term.write(this.lineBuffer);
                    }
                    this.lineBuffer = '';
                }

                if (autoScroll()) {
                    this.term.scrollToBottom();
                }
            },

            async startReading() {
                try {
                    while (this.connected) {
                        const { value, done } = await this.reader.read();
                        if (done) break;
                        if (value) {
                            this.chunkQueue.push(value);
                            this.queuedSize += value.length;
                            if (this.queuedSize > 1024 * 1024) {
                                const now = Date.now();
                                if (now - this.lastDropNotice > 2000) {
                                    this.term.writeln(`\n\x1b[33m${I18n.auto('数据过快，已丢弃部分内容')}\x1b[0m`);
                                    this.lastDropNotice = now;
                                }
                                this.chunkQueue = [];
                                this.queuedSize = 0;
                                this.lineBuffer = '';
                                this.pendingCR = false;
                            }
                            this.scheduleQueue();
                        }
                    }
                } catch (e) {
                    if (this.connected) {
                        this.term.writeln(`\n\x1b[31m${I18n.auto(`读取错误: ${e.message}`)}\x1b[0m`);
                        this.disconnect();
                    }
                }
            },

            async write(data) {
                if (this.writer) {
                    try {
                        await this.writer.write(data);
                    } catch (e) {
                        console.error('写入错误:', e);
                    }
                }
            },

            async sendData() {
                if (!this.connected) return;

                let data = document.getElementById('serialSendInput').value;
                const mode = document.getElementById('serialSendMode').value;
                const lineEnding = document.getElementById('serialLineEnding').value;

                if (!data) return;

                if (mode === 'hex') {
                    // HEX 模式：将空格分隔的十六进制字符串转换为字节
                    const hexBytes = data.replace(/\s/g, '').match(/.{1,2}/g);
                    if (hexBytes) {
                        const bytes = hexBytes.map(h => parseInt(h, 16));
                        const uint8 = new Uint8Array(bytes);
                        await this.writer.write(new TextDecoder().decode(uint8));
                    }
                } else {
                    // 文本模式
                    data += lineEnding.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
                    await this.write(data);
                }

                document.getElementById('serialSendInput').value = '';
            },

            async disconnect() {
                this.connected = false;
                this.lineBuffer = ''; // Clear the line buffer

                // Stop demo mode if active
                if (this.demoMode) {
                    if (this.demoInterval) {
                        clearInterval(this.demoInterval);
                        this.demoInterval = null;
                    }
                    this.demoMode = false;
                    this.updateStatus(false);
                    this.term.writeln(`\n\x1b[33m${I18n.auto('演示模式已停止')}\x1b[0m`);
                    Toast.info('演示模式已停止');
                    return;
                }

                try {
                    if (this.reader) {
                        await this.reader.cancel();
                        this.reader = null;
                    }
                    if (this.writer) {
                        await this.writer.close();
                        this.writer = null;
                    }
                    if (this.port) {
                        await this.port.close();
                        this.port = null;
                    }
                } catch (e) {
                    console.error('断开错误:', e);
                }

                this.updateStatus(false);
                this.term.writeln(`\n\x1b[33m${I18n.auto('串口已断开')}\x1b[0m`);
                Toast.info('串口已断开');
            },

            updateStatus(connected, isDemo = false) {
                const status = document.getElementById('serialStatus');
                const text = document.getElementById('serialStatusText');
                const disconnBtn = document.getElementById('serialDisconnectBtn');
                const connBtn = document.getElementById('serialConnectBtn');
                const demoBtn = document.getElementById('serialDemoBtn');
                const sendBtn = document.getElementById('serialSendBtn');
                const title = document.getElementById('serialTermTitle');

                if (connected) {
                    status.classList.remove('disconnected');
                    status.classList.add('connected');
                    text.textContent = I18n.auto(isDemo ? '演示模式' : '已连接');
                    disconnBtn.style.display = 'inline-flex';
                    connBtn.disabled = true;
                    demoBtn.disabled = true;
                    sendBtn.disabled = isDemo; // Disable send in demo mode
                    title.textContent = I18n.auto(isDemo ? '串口终端 - 演示模式' : '串口终端 - 已连接');
                } else {
                    status.classList.remove('connected');
                    status.classList.add('disconnected');
                    text.textContent = I18n.auto('未连接');
                    disconnBtn.style.display = 'none';
                    connBtn.disabled = false;
                    demoBtn.disabled = false;
                    sendBtn.disabled = true;
                    title.textContent = I18n.auto('串口终端 - 未连接');
                }
            }
        };

        const FlashDebug = {
            initialized: false,
            ws: null,
            wsReadyPromise: null,
            currentTool: 'openocd',
            currentMode: 'flash',
            manualPathForced: false,
            tooling: null,
            autocompleteCatalogs: {},
            autocompleteUi: {
                activeInputId: '',
                activeIndex: -1,
                results: [],
                closeTimer: null,
                lastQuery: ''
            },
            running: {
                flash: false,
                debug: false,
                cli: false,
                native: false
            },
            presets: {
                openocd: {
                    probeLabel: '烧录器 Adapter',
                    probeHint: '来自 OpenOCD 的 adapter list，通常映射到 interface/<adapter>.cfg。',
                    probePlaceholder: '例如 cmsis-dap、st-link',
                    targetLabel: '目标配置',
                    targetPlaceholder: '例如 target/stm32f4x.cfg',
                    targetHint: '支持从 OpenOCD 的 target 目录中搜索并选择 .cfg。',
                    speedLabel: '适配器速率 (kHz)',
                    speedPlaceholder: '例如 4000',
                    showInterface: true,
                    interfacePlaceholder: '可选，留空时使用 interface/<烧录器>.cfg',
                    interfaceHint: '支持从 OpenOCD 的 interface 目录中搜索并选择 .cfg。',
                    debugPortLabel: 'GDB 端口',
                    defaultDebugPort: 3333,
                    showTelnet: true,
                    defaultTelnetPort: 4444,
                    showElf: false,
                    verifyHint: 'OpenOCD 会按 GUI 选项追加 verify/reset/exit 指令。'
                },
                pyocd: {
                    probeLabel: 'Probe UID',
                    probeHint: '优先自动列出已连接 probe，也可手动填写 UID 或部分 UID。',
                    probePlaceholder: '例如 cmsisdap:12345678 或部分 UID',
                    targetLabel: '目标芯片',
                    targetPlaceholder: '例如 stm32f103rc',
                    targetHint: '请输入 pyOCD 支持的目标芯片名称。',
                    speedLabel: '调试频率 (Hz)',
                    speedPlaceholder: '例如 1000000、10m',
                    showInterface: false,
                    interfacePlaceholder: '',
                    interfaceHint: '',
                    debugPortLabel: 'GDB 端口',
                    defaultDebugPort: 3333,
                    showTelnet: true,
                    defaultTelnetPort: 4444,
                    showElf: true,
                    verifyHint: 'pyOCD 的写后校验沿用自身默认烧录策略。'
                },
                'probe-rs': {
                    probeLabel: 'Probe 选择',
                    probeHint: '优先自动列出当前 probe，也可手动填写 probe 选择串。',
                    probePlaceholder: '例如 0483:3748 或 0483:3748:SERIAL',
                    targetLabel: '目标芯片',
                    targetPlaceholder: '例如 STM32F103C8',
                    targetHint: '请输入 probe-rs 支持的芯片名称。',
                    speedLabel: '调试速率 (kHz)',
                    speedPlaceholder: '例如 4000',
                    showInterface: false,
                    interfacePlaceholder: '',
                    interfaceHint: '',
                    debugPortLabel: 'GDB 端口',
                    defaultDebugPort: 1337,
                    showTelnet: false,
                    defaultTelnetPort: '',
                    showElf: false,
                    verifyHint: 'probe-rs 的写后校验沿用当前 CLI 默认行为。'
                }
            },
            gdbCommandSpecs: {
                'file': {
                    label: 'file <elf-path>',
                    hint: '载入 ELF，适合在启动 GDB CLI 后绑定当前目标程序。',
                    fields: [{ key: 'arg1', label: 'ELF 路径', placeholder: '例如 /tmp/app.elf' }]
                },
                'symbol-file': {
                    label: 'symbol-file <elf-path>',
                    hint: '只载入符号文件，不替换当前 executable。',
                    fields: [{ key: 'arg1', label: '符号文件路径', placeholder: '例如 /tmp/app.elf' }]
                },
                'target-extended-remote': {
                    label: 'target extended-remote <host:port>',
                    hint: '连接到当前实时调试服务暴露的 GDB Remote 端口。',
                    fields: [
                        { key: 'arg1', label: '主机', placeholder: '例如 127.0.0.1' },
                        { key: 'arg2', label: '端口', placeholder: '例如 3333 或 1337' }
                    ]
                },
                'disconnect': { label: 'disconnect', hint: '断开当前 remote target 连接。', fields: [] },
                'load': { label: 'load', hint: '向目标装载当前 file/symbol-file 关联的 ELF。', fields: [] },
                'compare-sections': { label: 'compare-sections', hint: '对比 ELF 与目标端的 section 内容。', fields: [] },
                'quit': { label: 'quit', hint: '退出当前 GDB CLI 会话。', fields: [] },
                'continue': { label: 'continue', hint: '继续运行目标程序。', fields: [] },
                'interrupt': { label: 'interrupt', hint: '中断当前程序执行。', fields: [] },
                'step': { label: 'step', hint: '单步进入。', fields: [] },
                'next': { label: 'next', hint: '单步越过。', fields: [] },
                'finish': { label: 'finish', hint: '运行到当前函数返回。', fields: [] },
                'until': {
                    label: 'until <location>',
                    hint: '运行到指定位置后停止。',
                    fields: [{ key: 'arg1', label: '位置', placeholder: '例如 main.c:128 或 func' }]
                },
                'jump': {
                    label: 'jump <location>',
                    hint: '跳转到指定源码位置或 `*0x...` 地址。',
                    fields: [{ key: 'arg1', label: '跳转位置', placeholder: '例如 main.c:256 或 *0x08000100' }]
                },
                'break': {
                    label: 'break <function|file:line>',
                    hint: '支持函数名或 文件:行号。',
                    fields: [{ key: 'arg1', label: '断点位置', placeholder: '例如 foo 或 main.c:42' }]
                },
                'tbreak': {
                    label: 'tbreak <location>',
                    hint: '一次性断点，命中后自动删除。',
                    fields: [{ key: 'arg1', label: '临时断点位置', placeholder: '例如 main.c:88' }]
                },
                'hbreak': {
                    label: 'hbreak <location>',
                    hint: '硬件断点；受硬件资源数量限制。',
                    fields: [{ key: 'arg1', label: '硬件断点位置', placeholder: '例如 main.c:88' }]
                },
                'info-breakpoints': { label: 'info breakpoints', hint: '列出当前全部断点/观察点。', fields: [] },
                'delete': {
                    label: 'delete [breakpoint-id]',
                    hint: '留空等价于 `delete`，会删除全部断点。',
                    fields: [{ key: 'arg1', label: '断点 ID', placeholder: '留空则删除全部断点' }]
                },
                'disable': {
                    label: 'disable <breakpoint-id>',
                    hint: '禁用指定断点。',
                    fields: [{ key: 'arg1', label: '断点 ID', placeholder: '例如 3' }]
                },
                'enable': {
                    label: 'enable <breakpoint-id>',
                    hint: '启用指定断点。',
                    fields: [{ key: 'arg1', label: '断点 ID', placeholder: '例如 3' }]
                },
                'condition': {
                    label: 'condition <id> <expr>',
                    hint: '为断点附加条件表达式。',
                    fields: [
                        { key: 'arg1', label: '断点 ID', placeholder: '例如 3' },
                        { key: 'arg2', label: '条件表达式', placeholder: '例如 counter > 10' }
                    ]
                },
                'ignore': {
                    label: 'ignore <id> <count>',
                    hint: '让指定断点先忽略前 N 次命中。',
                    fields: [
                        { key: 'arg1', label: '断点 ID', placeholder: '例如 3' },
                        { key: 'arg2', label: '忽略次数', placeholder: '例如 5' }
                    ]
                },
                'watch': { label: 'watch <expr>', hint: '写观察点。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 some_var' }] },
                'rwatch': { label: 'rwatch <expr>', hint: '读观察点。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 some_var' }] },
                'awatch': { label: 'awatch <expr>', hint: '读写观察点。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 some_var' }] },
                'backtrace': { label: 'backtrace', hint: '输出当前调用栈。', fields: [] },
                'frame': { label: 'frame <n>', hint: '切换到指定栈帧。', fields: [{ key: 'arg1', label: '栈帧号', placeholder: '例如 0' }] },
                'up': { label: 'up', hint: '移动到上一个栈帧。', fields: [] },
                'down': { label: 'down', hint: '移动到下一个栈帧。', fields: [] },
                'info-frame': { label: 'info frame', hint: '显示当前栈帧详细信息。', fields: [] },
                'info-args': { label: 'info args', hint: '显示当前函数参数。', fields: [] },
                'info-locals': { label: 'info locals', hint: '显示当前函数局部变量。', fields: [] },
                'print': { label: 'print <expr>', hint: '按默认格式打印表达式。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 var' }] },
                'print-hex': { label: 'p/x <expr>', hint: '按十六进制打印表达式。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 var' }] },
                'print-dec': { label: 'p/d <expr>', hint: '按十进制打印表达式。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 var' }] },
                'print-bin': { label: 'p/t <expr>', hint: '按二进制打印表达式。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 flags' }] },
                'display': { label: 'display <expr>', hint: '持续显示表达式。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 var' }] },
                'undisplay': { label: 'undisplay <id>', hint: '取消指定 display 项。', fields: [{ key: 'arg1', label: 'Display ID', placeholder: '例如 1' }] },
                'set-variable': {
                    label: 'set variable <var>=<value>',
                    hint: '直接修改变量值。',
                    fields: [
                        { key: 'arg1', label: '变量名', placeholder: '例如 counter' },
                        { key: 'arg2', label: '值', placeholder: '例如 123' }
                    ]
                },
                'whatis': { label: 'whatis <expr>', hint: '查看表达式的类型名。', fields: [{ key: 'arg1', label: '表达式', placeholder: '例如 foo' }] },
                'ptype': { label: 'ptype <expr>', hint: '显示表达式/类型的完整类型定义。', fields: [{ key: 'arg1', label: '表达式或类型', placeholder: '例如 foo' }] },
                'info-registers': { label: 'info registers', hint: '显示核心寄存器。', fields: [] },
                'info-all-registers': { label: 'info all-registers', hint: '显示全部寄存器。', fields: [] },
                'print-register': {
                    label: 'print $pc/$sp/$lr/$xpsr',
                    hint: '快速打印单个寄存器值。',
                    fields: [{ key: 'arg1', label: '寄存器名', placeholder: '例如 pc、sp、lr、xpsr' }]
                },
                'set-register': {
                    label: 'set $reg = <value>',
                    hint: '修改 PC / SP 等寄存器。',
                    fields: [
                        { key: 'arg1', label: '寄存器名', placeholder: '例如 pc 或 sp' },
                        { key: 'arg2', label: '值', placeholder: '例如 0x08000000' }
                    ]
                },
                'examine-memory': {
                    label: 'x/<count>{b|h|w|i[x]} <address>',
                    hint: '格式填写 b/h/w/i；例如 32 + b + 0x20000000 对应 x/32bx。',
                    fields: [
                        { key: 'arg1', label: '数量', placeholder: '例如 32' },
                        { key: 'arg2', label: '格式', placeholder: 'b / h / w / i' },
                        { key: 'arg3', label: '地址', placeholder: '例如 0x20000000' }
                    ]
                },
                'set-memory': {
                    label: 'set {<type>}<address> = <value>',
                    hint: '可用于向 RAM 或寄存器映射地址写值。',
                    fields: [
                        { key: 'arg1', label: '类型', placeholder: '例如 uint32_t' },
                        { key: 'arg2', label: '地址', placeholder: '例如 0x20000000' },
                        { key: 'arg3', label: '值', placeholder: '例如 0x12345678' }
                    ]
                },
                'dump-binary-memory': {
                    label: 'dump binary memory <file> <start> <end>',
                    hint: '把目标内存导出为 binary。',
                    fields: [
                        { key: 'arg1', label: '导出文件', placeholder: '例如 /tmp/ram.bin' },
                        { key: 'arg2', label: '起始地址', placeholder: '例如 0x20000000' },
                        { key: 'arg3', label: '结束地址', placeholder: '例如 0x20000100' }
                    ]
                },
                'restore-binary': {
                    label: 'restore <file> binary <address>',
                    hint: '从 binary 文件恢复到目标内存。',
                    fields: [
                        { key: 'arg1', label: '导入文件', placeholder: '例如 /tmp/ram.bin' },
                        { key: 'arg2', label: '装载地址', placeholder: '例如 0x20000000' }
                    ]
                },
                'disassemble': { label: 'disassemble [location]', hint: '留空时反汇编当前上下文。', fields: [{ key: 'arg1', label: '位置', placeholder: '可选，例如 main' }] },
                'disassemble-mixed': { label: 'disassemble /m <location>', hint: '混合源码与汇编。', fields: [{ key: 'arg1', label: '位置', placeholder: '例如 main' }] },
                'disassemble-raw': { label: 'disassemble /r <location>', hint: '附带原始机器码。', fields: [{ key: 'arg1', label: '位置', placeholder: '例如 main' }] },
                'list': { label: 'list [location]', hint: '留空时显示当前位置源码。', fields: [{ key: 'arg1', label: '位置', placeholder: '可选，例如 main.c:128' }] },
                'monitor-raw': { label: 'monitor <raw-command>', hint: 'OpenOCD / pyOCD 专用透传；probe-rs 下不会显示独占快捷区。', fields: [{ key: 'arg1', label: 'monitor 命令', placeholder: '例如 reset halt' }] },
                'pc-instructions': { label: 'x/8i $pc', hint: '查看当前 PC 附近 8 条指令。', fields: [] },
                'run-to-cursor': { label: 'Run To Cursor', hint: '内部会执行 `tbreak <file>:<line>` 再 `continue`。', fields: [{ key: 'arg1', label: '文件:行号', placeholder: '例如 main.c:200' }] }
            },
            probeRsCommandSpecs: {
                'probe-list': { label: 'probe-rs list', hint: '枚举当前已连接 probe。', fields: [] },
                'probe-info': { label: 'probe-rs info', hint: '查询 probe 与 target 状态，等价 session state query / target info。', fields: [] },
                'probe-reset': { label: 'probe-rs reset', hint: '复位目标，可配合 Under Reset 连接。', fields: [] },
                'probe-erase': { label: 'probe-rs erase', hint: '整片擦除。', fields: [] },
                'probe-download': {
                    label: 'probe-rs download',
                    hint: '下载 ELF / BIN / HEX；可结合 Verify Flash 与 Chip Erase。',
                    fields: [
                        { key: 'arg1', label: '文件路径', placeholder: '例如 /tmp/app.elf 或 /tmp/app.bin' },
                        { key: 'arg2', label: 'Binary 格式', placeholder: '可选，例如 bin / elf / hex' },
                        { key: 'arg3', label: '基地址', placeholder: 'bin 时可填，例如 0x08000000' },
                        { key: 'arg4', label: '跳过字节', placeholder: '可选，例如 0' }
                    ]
                },
                'probe-verify': {
                    label: 'probe-rs verify',
                    hint: '对比文件与目标 flash 内容。',
                    fields: [
                        { key: 'arg1', label: '文件路径', placeholder: '例如 /tmp/app.elf' },
                        { key: 'arg2', label: 'Binary 格式', placeholder: '可选，例如 bin / elf / hex' },
                        { key: 'arg3', label: '基地址', placeholder: 'bin 时可填，例如 0x08000000' },
                        { key: 'arg4', label: '跳过字节', placeholder: '可选，例如 0' }
                    ]
                },
                'probe-read': {
                    label: 'probe-rs read',
                    hint: '读取 RAM / 外设内存；宽度支持 b8 / b16 / b32 / b64。',
                    fields: [
                        { key: 'arg1', label: '宽度', placeholder: '例如 b32' },
                        { key: 'arg2', label: '地址', placeholder: '例如 0x20000000' },
                        { key: 'arg3', label: '数量', placeholder: '例如 4' }
                    ]
                },
                'probe-write': {
                    label: 'probe-rs write',
                    hint: '写 RAM / 外设内存；多个值用空格分隔。',
                    fields: [
                        { key: 'arg1', label: '宽度', placeholder: '例如 b32' },
                        { key: 'arg2', label: '地址', placeholder: '例如 0x20000000' },
                        { key: 'arg3', label: '写入值', placeholder: '例如 0x1 0x2 0x3' }
                    ]
                },
                'probe-trace': {
                    label: 'probe-rs trace',
                    hint: '持续 trace 指定内存位置。',
                    fields: [{ key: 'arg1', label: 'Trace 地址', placeholder: '例如 0x20000000' }]
                },
                'probe-attach': {
                    label: 'probe-rs attach',
                    hint: 'RTT / defmt 日志 attach；需要 ELF 路径。',
                    fields: [{ key: 'arg1', label: 'ELF 路径', placeholder: '例如 /tmp/app.elf' }]
                }
            },

            init() {
                if (this.initialized) return;
                this.initialized = true;

                this.currentTool = document.getElementById('flashDebugToolSelector').value || 'openocd';
                this.currentMode = 'flash';

                document.querySelectorAll('#flashDebugModeTags .feature-tag').forEach((btn) => {
                    btn.addEventListener('click', () => this.applyMode(btn.dataset.mode));
                });

                document.getElementById('flashDebugToolSelector').addEventListener('change', () => {
                    this.currentTool = document.getElementById('flashDebugToolSelector').value;
                    this.manualPathForced = false;
                    document.getElementById('flashDebugManualPath').value = '';
                    this.closeAutocompleteSuggestions();
                    this.updateManualPathVisibility();
                    this.applyToolPreset();
                    this.refreshTooling(true);
                });

                document.getElementById('flashDebugRefreshBtn').addEventListener('click', () => this.refreshTooling());
                document.getElementById('flashDebugManualBtn').addEventListener('click', () => this.toggleManualPath());
                document.getElementById('flashDebugManualPath').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') this.refreshTooling();
                });
                document.getElementById('flashDebugManualPath').addEventListener('blur', () => {
                    if (this.manualPathForced || document.getElementById('flashDebugManualPath').value.trim()) {
                        this.refreshTooling(true);
                    }
                });

                document.getElementById('flashProbeSelect').addEventListener('change', () => {
                    document.getElementById('flashProbeInput').value = document.getElementById('flashProbeSelect').value;
                });
                document.getElementById('debugProbeSelect').addEventListener('change', () => {
                    document.getElementById('debugProbeInput').value = document.getElementById('debugProbeSelect').value;
                });
                this.getAutocompleteInputIds().forEach((inputId) => this.bindAutocompleteInput(inputId));
                document.getElementById('flashFirmwareSelectBtn').addEventListener('click', () => this.pickFirmwareFile());
                document.getElementById('cliElfSelectBtn').addEventListener('click', () => this.pickCliElfFile());
                document.getElementById('flashFirmwarePath').addEventListener('input', () => {
                    this.syncFirmwareUploadHint();
                    this.syncCliDefaults();
                });
                document.getElementById('flashFirmwarePath').addEventListener('change', () => this.syncCliDefaults());
                document.getElementById('flashFirmwareFilePicker').addEventListener('change', (e) => {
                    const file = e.target.files && e.target.files[0];
                    if (file) {
                        this.uploadFirmwareFile(file);
                    }
                    e.target.value = '';
                });
                document.getElementById('cliElfFilePicker').addEventListener('change', (e) => {
                    const file = e.target.files && e.target.files[0];
                    if (file) {
                        this.uploadFileToPathInput(file, {
                            pathInputId: 'cliElfPath',
                            placeholder: '启动 CLI 会话时可自动执行 file 或 symbol-file',
                            onPending: (meta) => this.syncCliElfHint(meta),
                            onSuccess: (data) => {
                                this.setCliElfManualState(true);
                                this.syncCliElfHint(data);
                            },
                            onError: () => this.syncCliElfHint()
                        });
                    }
                    e.target.value = '';
                });

                document.getElementById('flashStartBtn').addEventListener('click', () => this.startAction('flash'));
                document.getElementById('flashStopBtn').addEventListener('click', () => this.stopAction('flash'));
                document.getElementById('flashClearLogBtn').addEventListener('click', () => this.clearLog('flash'));

                document.getElementById('debugStartBtn').addEventListener('click', () => this.startAction('debug'));
                document.getElementById('debugStopBtn').addEventListener('click', () => this.stopAction('debug'));
                document.getElementById('debugClearLogBtn').addEventListener('click', () => this.clearLog('debug'));
                document.getElementById('cliStartBtn').addEventListener('click', () => this.startCliSession());
                document.getElementById('cliStopBtn').addEventListener('click', () => this.stopAction('cli'));
                document.getElementById('cliClearLogBtn').addEventListener('click', () => this.clearLog('cli'));
                document.getElementById('probeRsStopBtn').addEventListener('click', () => this.stopAction('native'));
                document.getElementById('cliExecuteBtn').addEventListener('click', () => this.executeCliCommand());
                document.getElementById('openocdMonitorExecuteBtn').addEventListener('click', () => {
                    this.executeCliCommand('monitor-raw', { arg1: document.getElementById('openocdMonitorRaw').value.trim() });
                });
                document.getElementById('pyocdMonitorExecuteBtn').addEventListener('click', () => {
                    this.executeCliCommand('monitor-raw', { arg1: document.getElementById('pyocdMonitorRaw').value.trim() });
                });
                document.getElementById('probeRsExecuteBtn').addEventListener('click', () => this.executeProbeRsCommand());
                document.getElementById('cliCommandSelect').addEventListener('change', () => this.updateCliCommandForm());
                document.getElementById('probeRsCommandSelect').addEventListener('change', () => this.updateProbeRsCommandForm());
                document.getElementById('debugPortInput').addEventListener('change', () => this.syncCliDefaults());
                document.getElementById('debugElfPath').addEventListener('change', () => this.syncCliDefaults());
                document.getElementById('debugElfPath').addEventListener('input', () => this.syncCliDefaults());
                document.getElementById('cliElfPath').addEventListener('input', (e) => {
                    if (e.isTrusted) {
                        this.setCliElfManualState(Boolean(e.target.value.trim()));
                    }
                    this.syncCliElfHint();
                });
                document.getElementById('cliElfPath').addEventListener('change', (e) => {
                    if (e.isTrusted) {
                        this.setCliElfManualState(Boolean(e.target.value.trim()));
                        if (!e.target.value.trim()) {
                            this.syncCliDefaults();
                            return;
                        }
                    }
                    this.syncCliElfHint();
                });

                document.querySelectorAll('[data-gdb-command]').forEach((btn) => {
                    btn.addEventListener('click', () => this.executeCliCommand(btn.dataset.gdbCommand));
                });
                document.querySelectorAll('#openocdCliGroup [data-monitor-command], #pyocdCliGroup [data-monitor-command]').forEach((btn) => {
                    btn.addEventListener('click', () => this.executeCliCommand('monitor-raw', { arg1: btn.dataset.monitorCommand || '' }));
                });
                document.querySelectorAll('[data-probe-rs-command]').forEach((btn) => {
                    btn.addEventListener('click', () => this.executeProbeRsCommand(btn.dataset.probeRsCommand));
                });
                document.getElementById('flashRequestElevation').addEventListener('change', (e) => {
                    document.getElementById('debugRequestElevation').checked = e.target.checked;
                });
                document.getElementById('debugRequestElevation').addEventListener('change', (e) => {
                    document.getElementById('flashRequestElevation').checked = e.target.checked;
                });

                this.populateCliCommandSelectors();
                this.applyToolPreset();
                this.applyMode(this.currentMode);
                this.applyAccessState();
                this.syncFirmwareUploadHint();
                this.syncCliDefaults();
                this.updateCliCommandForm();
                this.updateProbeRsCommandForm();
                this.refreshTooling(true);
            },

            isBusy() {
                return this.running.flash || this.running.debug || this.running.cli || this.running.native;
            },

            getAutocompleteInputIds() {
                return [
                    'flashTargetInput',
                    'debugTargetInput',
                    'flashInterfaceConfigInput',
                    'debugInterfaceConfigInput'
                ];
            },

            supportsTargetAutocomplete() {
                return this.currentTool === 'probe-rs' || this.currentTool === 'pyocd';
            },

            getTargetCatalogLabel() {
                return this.currentTool === 'pyocd' ? 'pyOCD 目标目录' : 'probe-rs 芯片目录';
            },

            getAutocompleteSuggestionPanel(inputId) {
                return document.getElementById(`${inputId}Suggestions`);
            },

            getAutocompleteConfig(inputId) {
                return this.autocompleteCatalogs[inputId] || null;
            },

            isAutocompleteEnabledForInput(inputId) {
                const config = this.getAutocompleteConfig(inputId);
                return Boolean(config && config.enabled);
            },

            hasEnabledAutocomplete() {
                return this.getAutocompleteInputIds().some((inputId) => this.isAutocompleteEnabledForInput(inputId));
            },

            clearAutocompleteCloseTimer() {
                if (this.autocompleteUi.closeTimer) {
                    clearTimeout(this.autocompleteUi.closeTimer);
                    this.autocompleteUi.closeTimer = null;
                }
            },

            scheduleAutocompleteSuggestionsClose() {
                this.clearAutocompleteCloseTimer();
                this.autocompleteUi.closeTimer = setTimeout(() => {
                    this.closeAutocompleteSuggestions();
                }, 120);
            },

            closeAutocompleteSuggestions() {
                this.clearAutocompleteCloseTimer();
                this.autocompleteUi.activeInputId = '';
                this.autocompleteUi.activeIndex = -1;
                this.autocompleteUi.results = [];
                this.autocompleteUi.lastQuery = '';
                this.getAutocompleteInputIds().forEach((inputId) => {
                    const panel = this.getAutocompleteSuggestionPanel(inputId);
                    if (!panel) return;
                    panel.innerHTML = '';
                    panel.classList.add('flashdebug-hidden');
                });
            },

            bindAutocompleteInput(inputId) {
                const input = document.getElementById(inputId);
                const panel = this.getAutocompleteSuggestionPanel(inputId);
                if (!input || !panel) return;

                input.addEventListener('input', () => this.updateAutocompleteSuggestions(inputId));
                input.addEventListener('focus', () => this.updateAutocompleteSuggestions(inputId));
                input.addEventListener('keydown', (event) => this.handleAutocompleteKeydown(inputId, event));
                input.addEventListener('blur', () => this.scheduleAutocompleteSuggestionsClose());
                panel.addEventListener('mousedown', (event) => event.preventDefault());
            },

            normalizeAutocompleteItems(items = []) {
                return (Array.isArray(items) ? items : [])
                    .map((item) => {
                        const value = String(item && item.value ? item.value : '').trim();
                        const label = String(item && item.label ? item.label : value).trim();
                        const meta = String(item && (item.meta || item.family) ? (item.meta || item.family) : '').trim();
                        const keywords = String(item && item.keywords ? item.keywords : '').trim();
                        if (!value) return null;
                        return {
                            value,
                            label: label || value,
                            meta,
                            keywords,
                            normalizedValue: value.toLowerCase(),
                            normalizedLabel: label.toLowerCase(),
                            normalizedMeta: meta.toLowerCase(),
                            normalizedKeywords: keywords.toLowerCase()
                        };
                    })
                    .filter(Boolean);
            },

            buildConfigAutocompleteItems(values = [], kindLabel) {
                return (Array.isArray(values) ? values : [])
                    .map((value) => String(value || '').trim())
                    .filter(Boolean)
                    .map((value) => {
                        const basename = value.split('/').pop() || value;
                        const stem = basename.replace(/\.cfg$/i, '');
                        return {
                            value,
                            label: value,
                            meta: kindLabel,
                            keywords: [value, basename, stem].filter(Boolean).join(' ')
                        };
                    });
            },

            setAutocompleteCatalog(inputId, items = [], options = {}) {
                this.autocompleteCatalogs[inputId] = {
                    enabled: options.enabled !== false,
                    label: String(options.label || '').trim(),
                    emptyQueryMessage: String(options.emptyQueryMessage || '').trim(),
                    emptyCatalogMessage: String(options.emptyCatalogMessage || '').trim(),
                    noResultsMessage: String(options.noResultsMessage || '').trim(),
                    items: this.normalizeAutocompleteItems(items)
                };

                const activeElement = document.activeElement;
                if (activeElement && activeElement.id === inputId) {
                    this.updateAutocompleteSuggestions(inputId);
                } else if (this.autocompleteUi.activeInputId === inputId && !this.isAutocompleteEnabledForInput(inputId)) {
                    this.closeAutocompleteSuggestions();
                }
            },

            syncAutocompleteCatalogs(configs = null, targetCatalog = []) {
                const targetInputs = ['flashTargetInput', 'debugTargetInput'];
                const interfaceInputs = ['flashInterfaceConfigInput', 'debugInterfaceConfigInput'];

                if (this.currentTool === 'openocd') {
                    const targetItems = this.buildConfigAutocompleteItems(configs && configs.targetConfigs, 'OpenOCD target 配置');
                    const interfaceItems = this.buildConfigAutocompleteItems(configs && configs.interfaceConfigs, 'OpenOCD interface 配置');
                    const targetEmptyCatalogMessage = configs && configs.error
                        ? `未载入 OpenOCD target 配置：${configs.error}`
                        : '正在等待 OpenOCD target 配置目录，期间仍可直接手动输入。';
                    const interfaceEmptyCatalogMessage = configs && configs.error
                        ? `未载入 OpenOCD interface 配置：${configs.error}`
                        : '正在等待 OpenOCD interface 配置目录，期间仍可直接手动输入。';

                    targetInputs.forEach((inputId) => {
                        this.setAutocompleteCatalog(inputId, targetItems, {
                            enabled: true,
                            label: 'OpenOCD target 配置',
                            emptyQueryMessage: '输入关键字搜索 OpenOCD target 配置。',
                            emptyCatalogMessage: targetEmptyCatalogMessage,
                            noResultsMessage: '未找到匹配的 OpenOCD target 配置，可继续手动输入。'
                        });
                    });
                    interfaceInputs.forEach((inputId) => {
                        this.setAutocompleteCatalog(inputId, interfaceItems, {
                            enabled: true,
                            label: 'OpenOCD interface 配置',
                            emptyQueryMessage: '输入关键字搜索 OpenOCD interface 配置。',
                            emptyCatalogMessage: interfaceEmptyCatalogMessage,
                            noResultsMessage: '未找到匹配的 OpenOCD interface 配置，可继续手动输入。'
                        });
                    });
                    return;
                }

                if (this.supportsTargetAutocomplete()) {
                    const label = this.getTargetCatalogLabel();
                    const noResultsMessage = this.currentTool === 'pyocd'
                        ? '未找到匹配项，可继续手动输入 pyOCD 目标名。'
                        : '未找到匹配项，可继续手动输入芯片名。';
                    const emptyCatalogMessage = this.tooling && (this.tooling.targetCatalogError || this.tooling.chipListError)
                        ? `未载入 ${label}：${this.tooling.targetCatalogError || this.tooling.chipListError}`
                        : `正在等待 ${label}，期间仍可直接手动输入。`;

                    targetInputs.forEach((inputId) => {
                        this.setAutocompleteCatalog(inputId, targetCatalog, {
                            enabled: true,
                            label,
                            emptyQueryMessage: `输入关键字搜索 ${label}。`,
                            emptyCatalogMessage,
                            noResultsMessage
                        });
                    });
                    interfaceInputs.forEach((inputId) => {
                        this.setAutocompleteCatalog(inputId, [], {
                            enabled: false,
                            label: 'OpenOCD interface 配置'
                        });
                    });
                    return;
                }

                this.getAutocompleteInputIds().forEach((inputId) => {
                    this.setAutocompleteCatalog(inputId, [], { enabled: false });
                });
            },

            normalizeAutocompleteSearch(value) {
                return String(value || '').trim().toLowerCase();
            },

            fuzzyAutocompleteMatch(query, text) {
                if (!query || !text) return null;

                let queryIndex = 0;
                let start = -1;
                let previousMatch = -1;
                let gaps = 0;

                for (let index = 0; index < text.length && queryIndex < query.length; index += 1) {
                    if (text[index] !== query[queryIndex]) continue;
                    if (start === -1) {
                        start = index;
                    } else {
                        gaps += index - previousMatch - 1;
                    }
                    previousMatch = index;
                    queryIndex += 1;
                }

                if (queryIndex !== query.length) {
                    return null;
                }

                return { start, gaps };
            },

            scoreAutocompleteItem(query, item) {
                if (!query || !item) return -1;

                const value = item.normalizedValue || '';
                const label = item.normalizedLabel || value;
                const meta = item.normalizedMeta || '';
                const keywords = item.normalizedKeywords || '';

                if (value === query) {
                    return 10000 - value.length;
                }
                if (label === query) {
                    return 9800 - label.length;
                }
                if (value.startsWith(query)) {
                    return 9000 - value.length;
                }
                if (label.startsWith(query)) {
                    return 8800 - label.length;
                }

                const valueIndex = value.indexOf(query);
                if (valueIndex !== -1) {
                    return 8000 - (valueIndex * 10) - value.length;
                }
                const labelIndex = label.indexOf(query);
                if (labelIndex !== -1) {
                    return 7800 - (labelIndex * 10) - label.length;
                }

                if (meta) {
                    if (meta.startsWith(query)) {
                        return 7000 - meta.length;
                    }

                    const metaIndex = meta.indexOf(query);
                    if (metaIndex !== -1) {
                        return 6500 - (metaIndex * 10) - meta.length;
                    }
                }
                if (keywords) {
                    const keywordIndex = keywords.indexOf(query);
                    if (keywordIndex !== -1) {
                        return 6200 - (keywordIndex * 10) - keywords.length;
                    }
                }

                const fuzzyValue = this.fuzzyAutocompleteMatch(query, value);
                if (fuzzyValue) {
                    return 5000 - (fuzzyValue.gaps * 4) - fuzzyValue.start;
                }

                const fuzzyMeta = this.fuzzyAutocompleteMatch(query, meta);
                if (fuzzyMeta) {
                    return 4000 - (fuzzyMeta.gaps * 4) - fuzzyMeta.start;
                }

                return -1;
            },

            searchAutocompleteCatalog(inputId, query, limit = 24) {
                const normalizedQuery = this.normalizeAutocompleteSearch(query);
                const config = this.getAutocompleteConfig(inputId);
                if (!normalizedQuery || !config) {
                    return [];
                }

                const results = [];
                config.items.forEach((item) => {
                    const score = this.scoreAutocompleteItem(normalizedQuery, item);
                    if (score < 0) return;
                    results.push({ item, score });
                });

                results.sort((left, right) => {
                    if (right.score !== left.score) {
                        return right.score - left.score;
                    }
                    return left.item.label.localeCompare(right.item.label);
                });

                return results.slice(0, limit);
            },

            renderAutocompleteSuggestions(inputId, results = [], message = '') {
                const panel = this.getAutocompleteSuggestionPanel(inputId);
                const config = this.getAutocompleteConfig(inputId);
                if (!panel || !config) return;

                panel.innerHTML = '';
                panel.classList.remove('flashdebug-hidden');

                if (!results.length) {
                    const empty = document.createElement('div');
                    empty.className = 'flashdebug-suggestion-empty';
                    empty.textContent = message || config.noResultsMessage || `未找到匹配项，可继续手动输入 ${config.label || '当前值'}。`;
                    panel.appendChild(empty);
                    return;
                }

                results.forEach((result, index) => {
                    const button = document.createElement('button');
                    button.type = 'button';
                    button.className = 'flashdebug-suggestion';
                    if (index === this.autocompleteUi.activeIndex) {
                        button.classList.add('active');
                    }

                    const primary = document.createElement('span');
                    primary.className = 'flashdebug-suggestion-primary';
                    primary.textContent = result.item.label;
                    button.appendChild(primary);

                    const meta = document.createElement('span');
                    meta.className = 'flashdebug-suggestion-meta';
                    meta.textContent = result.item.meta || config.label;
                    button.appendChild(meta);

                    button.addEventListener('mousedown', (event) => {
                        event.preventDefault();
                        this.acceptAutocompleteSuggestion(inputId, result.item.value);
                    });
                    panel.appendChild(button);
                });

                const activeButton = panel.querySelector('.flashdebug-suggestion.active');
                if (activeButton) {
                    activeButton.scrollIntoView({ block: 'nearest' });
                }
            },

            updateAutocompleteSuggestions(inputId) {
                const input = document.getElementById(inputId);
                const config = this.getAutocompleteConfig(inputId);
                if (!input || !config || !config.enabled) {
                    this.closeAutocompleteSuggestions();
                    return;
                }

                this.clearAutocompleteCloseTimer();

                const query = input.value.trim();
                if (!config.items.length) {
                    this.autocompleteUi.activeInputId = inputId;
                    this.autocompleteUi.activeIndex = -1;
                    this.autocompleteUi.results = [];
                    this.autocompleteUi.lastQuery = query;
                    this.renderAutocompleteSuggestions(
                        inputId,
                        [],
                        config.emptyCatalogMessage || config.emptyQueryMessage || `正在等待 ${config.label}，期间仍可直接手动输入。`
                    );
                    return;
                }

                if (!query) {
                    this.autocompleteUi.activeInputId = inputId;
                    this.autocompleteUi.activeIndex = -1;
                    this.autocompleteUi.results = [];
                    this.autocompleteUi.lastQuery = '';
                    this.renderAutocompleteSuggestions(inputId, [], config.emptyQueryMessage || `输入关键字搜索 ${config.label}。`);
                    return;
                }

                const results = this.searchAutocompleteCatalog(inputId, query);
                const sameInput = this.autocompleteUi.activeInputId === inputId;
                const sameQuery = this.autocompleteUi.lastQuery === query;
                this.autocompleteUi.activeInputId = inputId;
                this.autocompleteUi.results = results;
                this.autocompleteUi.lastQuery = query;
                if (results.length > 0) {
                    this.autocompleteUi.activeIndex = sameInput && sameQuery
                        ? Math.min(Math.max(this.autocompleteUi.activeIndex, 0), results.length - 1)
                        : 0;
                } else {
                    this.autocompleteUi.activeIndex = -1;
                }

                this.renderAutocompleteSuggestions(inputId, results, config.noResultsMessage);
            },

            moveAutocompleteSelection(inputId, delta) {
                if (this.autocompleteUi.activeInputId !== inputId || !this.autocompleteUi.results.length) {
                    this.updateAutocompleteSuggestions(inputId);
                }
                if (!this.autocompleteUi.results.length) return;

                const total = this.autocompleteUi.results.length;
                const current = this.autocompleteUi.activeIndex;
                const nextIndex = current < 0
                    ? (delta > 0 ? 0 : total - 1)
                    : (current + delta + total) % total;
                this.autocompleteUi.activeIndex = nextIndex;
                this.renderAutocompleteSuggestions(inputId, this.autocompleteUi.results);
            },

            acceptAutocompleteSuggestion(inputId, value) {
                const input = document.getElementById(inputId);
                if (!input) return;

                input.value = value || '';
                input.focus();
                input.dispatchEvent(new Event('change', { bubbles: true }));
                this.closeAutocompleteSuggestions();
            },

            handleAutocompleteKeydown(inputId, event) {
                if (!this.isAutocompleteEnabledForInput(inputId)) return;

                if (event.key === 'ArrowDown') {
                    event.preventDefault();
                    this.moveAutocompleteSelection(inputId, 1);
                    return;
                }

                if (event.key === 'ArrowUp') {
                    event.preventDefault();
                    this.moveAutocompleteSelection(inputId, -1);
                    return;
                }

                if (event.key === 'Enter') {
                    if (this.autocompleteUi.activeInputId === inputId
                        && this.autocompleteUi.activeIndex >= 0
                        && this.autocompleteUi.results[this.autocompleteUi.activeIndex]) {
                        event.preventDefault();
                        this.acceptAutocompleteSuggestion(
                            inputId,
                            this.autocompleteUi.results[this.autocompleteUi.activeIndex].item.value
                        );
                    }
                    return;
                }

                if (event.key === 'Escape') {
                    event.preventDefault();
                    this.closeAutocompleteSuggestions();
                }
            },

            populateCliCommandSelectors() {
                const cliSelect = document.getElementById('cliCommandSelect');
                const probeRsSelect = document.getElementById('probeRsCommandSelect');

                cliSelect.innerHTML = '';
                Object.entries(this.gdbCommandSpecs).forEach(([commandId, spec]) => {
                    const option = document.createElement('option');
                    option.value = commandId;
                    option.textContent = spec.label;
                    cliSelect.appendChild(option);
                });

                probeRsSelect.innerHTML = '';
                Object.entries(this.probeRsCommandSpecs).forEach(([commandId, spec]) => {
                    const option = document.createElement('option');
                    option.value = commandId;
                    option.textContent = spec.label;
                    probeRsSelect.appendChild(option);
                });
            },

            setDynamicField(labelId, inputId, field) {
                const label = document.getElementById(labelId);
                const input = document.getElementById(inputId);
                if (!label || !input) return;

                const group = input.closest('.input-group');
                if (!field) {
                    group.classList.add('flashdebug-hidden');
                    input.value = '';
                    setI18nAttributeValue(input, 'placeholder', '');
                    return;
                }

                group.classList.remove('flashdebug-hidden');
                setI18nTextValue(label, field.label || '');
                setI18nAttributeValue(input, 'placeholder', field.placeholder || '');
            },

            updateCliCommandForm() {
                const select = document.getElementById('cliCommandSelect');
                const spec = this.gdbCommandSpecs[select.value] || this.gdbCommandSpecs.file;
                const fields = spec.fields || [];

                this.setDynamicField('cliCommandArg1Label', 'cliCommandArg1', fields[0] || null);
                this.setDynamicField('cliCommandArg2Label', 'cliCommandArg2', fields[1] || null);
                this.setDynamicField('cliCommandArg3Label', 'cliCommandArg3', fields[2] || null);
                this.setDynamicField('cliCommandArg4Label', 'cliCommandArg4', fields[3] || null);
                setI18nTextValue(document.getElementById('cliCommandHint'), spec.hint || '');
            },

            updateProbeRsCommandForm() {
                const select = document.getElementById('probeRsCommandSelect');
                const spec = this.probeRsCommandSpecs[select.value] || this.probeRsCommandSpecs['probe-list'];
                const fields = spec.fields || [];

                this.setDynamicField('probeRsArg1Label', 'probeRsArg1', fields[0] || null);
                this.setDynamicField('probeRsArg2Label', 'probeRsArg2', fields[1] || null);
                this.setDynamicField('probeRsArg3Label', 'probeRsArg3', fields[2] || null);
                this.setDynamicField('probeRsArg4Label', 'probeRsArg4', fields[3] || null);
                setI18nTextValue(document.getElementById('probeRsCommandHint'), spec.hint || '');
            },

            syncCliToolPanels() {
                document.getElementById('openocdCliGroup').classList.toggle('flashdebug-hidden', this.currentTool !== 'openocd');
                document.getElementById('pyocdCliGroup').classList.toggle('flashdebug-hidden', this.currentTool !== 'pyocd');
                document.getElementById('probeRsCliGroup').classList.toggle('flashdebug-hidden', this.currentTool !== 'probe-rs');

                const commandSelect = document.getElementById('cliCommandSelect');
                const monitorOption = commandSelect.querySelector('option[value="monitor-raw"]');
                if (monitorOption) {
                    monitorOption.hidden = this.currentTool === 'probe-rs';
                }
                if (this.currentTool === 'probe-rs' && commandSelect.value === 'monitor-raw') {
                    commandSelect.value = 'continue';
                    this.updateCliCommandForm();
                }
            },

            getPreferredCliElfPath() {
                const flashFirmwarePath = document.getElementById('flashFirmwarePath').value.trim();
                const debugElfPath = document.getElementById('debugElfPath').value.trim();
                return flashFirmwarePath || debugElfPath || '';
            },

            getResolvedCliElfPath() {
                return document.getElementById('cliElfPath').value.trim() || this.getPreferredCliElfPath();
            },

            setCliElfAutoValue(value) {
                const cliElfPath = document.getElementById('cliElfPath');
                if (!cliElfPath) return;
                cliElfPath.value = value || '';
                cliElfPath.dataset.userEdited = 'false';
                cliElfPath.dataset.autoValue = value || '';
            },

            setCliElfManualState(isManual) {
                const cliElfPath = document.getElementById('cliElfPath');
                if (!cliElfPath) return;
                cliElfPath.dataset.userEdited = isManual ? 'true' : 'false';
                if (!isManual) {
                    cliElfPath.dataset.autoValue = cliElfPath.value.trim();
                }
            },

            syncCliDefaults(force = false) {
                const cliPortInput = document.getElementById('cliPortInput');
                const cliElfPath = document.getElementById('cliElfPath');
                const debugPortInput = document.getElementById('debugPortInput');
                const preferredCliElfPath = this.getPreferredCliElfPath();
                const currentCliElfPath = cliElfPath.value.trim();
                const autoCliElfPath = cliElfPath.dataset.autoValue || '';
                const cliElfManuallyEdited = cliElfPath.dataset.userEdited === 'true';

                if (force || !cliPortInput.value.trim()) {
                    cliPortInput.value = debugPortInput.value || cliPortInput.value;
                }
                if ((force || !currentCliElfPath || (!cliElfManuallyEdited && currentCliElfPath === autoCliElfPath))
                    && preferredCliElfPath
                    && currentCliElfPath !== preferredCliElfPath) {
                    this.setCliElfAutoValue(preferredCliElfPath);
                }
                this.syncCliElfHint();
            },

            applyMode(mode) {
                this.currentMode = mode === 'debug' ? 'debug' : 'flash';
                document.querySelectorAll('#flashDebugModeTags .feature-tag').forEach((btn) => {
                    btn.classList.toggle('active', btn.dataset.mode === this.currentMode);
                });
                document.getElementById('flashDebugFlashCard').classList.toggle('active', this.currentMode === 'flash');
                document.getElementById('flashDebugDebugCard').classList.toggle('active', this.currentMode === 'debug');
                document.getElementById('flashDebugCliCard').classList.toggle('active', this.currentMode === 'debug');
                this.closeAutocompleteSuggestions();
            },

            applyAccessState() {
                if (!this.initialized) return;
                document.getElementById('flashDebugAccessNote').style.display = State.isAdmin ? 'none' : 'block';
                this.syncControls();
            },

            syncControls() {
                if (!this.initialized) return;

                const locked = !State.isAdmin;
                const anyActive = this.isBusy();
                const serviceBusy = this.running.flash || this.running.debug || this.running.cli || this.running.native;
                const cliSessionBusy = this.running.flash || this.running.cli || this.running.native;
                const cliCommandLocked = locked || !this.running.cli || this.running.native;
                const probeRsNativeLocked = locked
                    || this.currentTool !== 'probe-rs'
                    || this.running.flash
                    || this.running.debug
                    || this.running.cli
                    || this.running.native;

                const toolingIds = [
                    'flashDebugToolSelector',
                    'flashDebugRefreshBtn',
                    'flashDebugManualBtn',
                    'flashDebugManualPath'
                ];
                const flashIds = [
                    'flashProbeSelect',
                    'flashProbeInput',
                    'flashTargetInput',
                    'flashInterfaceConfigInput',
                    'flashSpeedInput',
                    'flashFirmwarePath',
                    'flashFirmwareSelectBtn',
                    'flashExtraArgs',
                    'flashRequestElevation',
                    'flashVerify',
                    'flashReset'
                ];
                const debugIds = [
                    'debugProbeSelect',
                    'debugProbeInput',
                    'debugTargetInput',
                    'debugInterfaceConfigInput',
                    'debugSpeedInput',
                    'debugPortInput',
                    'debugTelnetPortInput',
                    'debugElfPath',
                    'debugExtraArgs',
                    'debugRequestElevation'
                ];
                const cliSessionIds = [
                    'cliGdbPath',
                    'cliHostInput',
                    'cliPortInput',
                    'cliElfPath',
                    'cliElfSelectBtn',
                    'cliAutoFile',
                    'cliUseSymbolFile',
                    'cliAutoConnect'
                ];
                const cliCommandIds = [
                    'cliCommandSelect',
                    'cliCommandArg1',
                    'cliCommandArg2',
                    'cliCommandArg3',
                    'cliCommandArg4',
                    'cliExecuteBtn',
                    'openocdMonitorRaw',
                    'openocdMonitorExecuteBtn',
                    'pyocdMonitorRaw',
                    'pyocdMonitorExecuteBtn'
                ];
                const probeRsIds = [
                    'probeRsCommandSelect',
                    'probeRsProtocol',
                    'probeRsCore',
                    'probeRsArg1',
                    'probeRsArg2',
                    'probeRsArg3',
                    'probeRsArg4',
                    'probeRsUnderReset',
                    'probeRsVerifyAfterLoad',
                    'probeRsChipErase',
                    'probeRsExecuteBtn'
                ];

                toolingIds.forEach((id) => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.disabled = locked || anyActive;
                    }
                });
                flashIds.forEach((id) => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.disabled = locked || serviceBusy;
                    }
                });
                debugIds.forEach((id) => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.disabled = locked || serviceBusy;
                    }
                });
                cliSessionIds.forEach((id) => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.disabled = locked || cliSessionBusy;
                    }
                });
                cliCommandIds.forEach((id) => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.disabled = cliCommandLocked;
                    }
                });
                probeRsIds.forEach((id) => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.disabled = probeRsNativeLocked;
                    }
                });

                document.getElementById('flashStartBtn').disabled = locked || serviceBusy;
                document.getElementById('debugStartBtn').disabled = locked || serviceBusy;
                document.getElementById('flashStopBtn').disabled = locked || !this.running.flash;
                document.getElementById('debugStopBtn').disabled = locked || !this.running.debug;
                document.getElementById('cliStartBtn').disabled = locked || cliSessionBusy;
                document.getElementById('cliStopBtn').disabled = locked || !this.running.cli;
                document.getElementById('cliClearLogBtn').disabled = locked;
                document.getElementById('probeRsStopBtn').disabled = locked || !this.running.native;
                document.querySelectorAll('[data-gdb-command]').forEach((btn) => {
                    btn.disabled = cliCommandLocked;
                });
                document.querySelectorAll('#openocdCliGroup [data-monitor-command], #pyocdCliGroup [data-monitor-command]').forEach((btn) => {
                    btn.disabled = cliCommandLocked;
                });
                document.querySelectorAll('[data-probe-rs-command]').forEach((btn) => {
                    btn.disabled = probeRsNativeLocked;
                });
                if (locked || anyActive || !this.hasEnabledAutocomplete()) {
                    this.closeAutocompleteSuggestions();
                }
                this.syncElevationUi();
            },

            applyToolPreset() {
                const preset = this.presets[this.currentTool] || this.presets.openocd;

                setI18nTextValue(document.getElementById('flashProbeLabel'), preset.probeLabel);
                setI18nTextValue(document.getElementById('debugProbeLabel'), preset.probeLabel);
                setI18nTextValue(document.getElementById('flashTargetLabel'), preset.targetLabel);
                setI18nTextValue(document.getElementById('debugTargetLabel'), preset.targetLabel);
                setI18nTextValue(document.getElementById('flashSpeedLabel'), preset.speedLabel);
                setI18nTextValue(document.getElementById('debugSpeedLabel'), preset.speedLabel);
                setI18nTextValue(document.getElementById('debugPortLabel'), preset.debugPortLabel);
                setI18nAttributeValue(document.getElementById('flashProbeInput'), 'placeholder', preset.probePlaceholder || '');
                setI18nAttributeValue(document.getElementById('debugProbeInput'), 'placeholder', preset.probePlaceholder || '');
                setI18nAttributeValue(document.getElementById('flashTargetInput'), 'placeholder', preset.targetPlaceholder || '');
                setI18nAttributeValue(document.getElementById('debugTargetInput'), 'placeholder', preset.targetPlaceholder || '');
                setI18nAttributeValue(document.getElementById('flashSpeedInput'), 'placeholder', preset.speedPlaceholder || '');
                setI18nAttributeValue(document.getElementById('debugSpeedInput'), 'placeholder', preset.speedPlaceholder || '');
                setI18nAttributeValue(document.getElementById('flashInterfaceConfigInput'), 'placeholder', preset.interfacePlaceholder || '');
                setI18nAttributeValue(document.getElementById('debugInterfaceConfigInput'), 'placeholder', preset.interfacePlaceholder || '');

                document.getElementById('flashInterfaceGroup').classList.toggle('flashdebug-hidden', !preset.showInterface);
                document.getElementById('debugInterfaceGroup').classList.toggle('flashdebug-hidden', !preset.showInterface);
                document.getElementById('debugTelnetGroup').classList.toggle('flashdebug-hidden', !preset.showTelnet);
                document.getElementById('debugElfGroup').classList.toggle('flashdebug-hidden', !preset.showElf);
                this.setConfigInputMode(this.currentTool === 'openocd');
                this.closeAutocompleteSuggestions();

                document.getElementById('debugPortInput').value = String(preset.defaultDebugPort || 3333);
                if (preset.showTelnet) {
                    document.getElementById('debugTelnetPortInput').value = String(preset.defaultTelnetPort || 4444);
                }

                this.syncCliDefaults(true);
                this.syncCliToolPanels();
                this.syncHints();
            },

            syncHints() {
                const preset = this.presets[this.currentTool] || this.presets.openocd;
                const count = this.tooling && Array.isArray(this.tooling.programmers) ? this.tooling.programmers.length : 0;
                const programmerSource = this.tooling && this.tooling.programmerSource;
                let listExtra = '';

                if (this.tooling && this.tooling.listError) {
                    listExtra = ` ${this.tooling.listError}`;
                } else if (count > 0 && programmerSource === 'plugins') {
                    listExtra = ` 当前显示 ${count} 个 pyOCD 插件前缀，选择后可在右侧继续补充 UID。`;
                } else if (count > 0 && programmerSource === 'template') {
                    listExtra = ' 当前显示 probe-rs 选择模板，可按帮助格式手动补全。';
                } else if (count > 0) {
                    listExtra = ` 当前检测到 ${count} 个候选项。`;
                } else {
                    listExtra = ' 当前未检测到候选项，可直接手动输入。';
                }

                setI18nTextValue(document.getElementById('flashProbeHint'), `${preset.probeHint}${listExtra}`);
                setI18nTextValue(document.getElementById('debugProbeHint'), `${preset.probeHint}${listExtra}`);
                setI18nTextValue(document.getElementById('flashVerifyHint'), preset.verifyHint);
                this.syncConfigHints();
                this.syncElevationUi();
            },

            getElevationInfo() {
                return this.tooling && this.tooling.elevation ? this.tooling.elevation : null;
            },

            getElevationCheckbox(action) {
                return document.getElementById(action === 'flash' ? 'flashRequestElevation' : 'debugRequestElevation');
            },

            syncElevationUi() {
                const info = this.getElevationInfo();
                const locked = !State.isAdmin;
                const busy = this.isBusy();
                const supported = Boolean(info && info.available);
                const note = info
                    ? (info.note || '')
                    : '正在检测管理员/root 提权方式...';

                ['flash', 'debug'].forEach((action) => {
                    const checkbox = this.getElevationCheckbox(action);
                    const hint = document.getElementById(action === 'flash' ? 'flashPrivilegeHint' : 'debugPrivilegeHint');
                    if (!checkbox || !hint) return;

                    if (!supported) {
                        checkbox.checked = false;
                    }

                    checkbox.disabled = locked || busy || !supported;
                    setI18nTextValue(hint, note || '当前平台暂未检测到可用的管理员/root 提权方式。');
                });
            },

            setConfigInputMode(enabled) {
                this.getAutocompleteInputIds().forEach((id) => {
                    const input = document.getElementById(id);
                    if (input) {
                        input.removeAttribute('list');
                    }
                });
            },

            populateConfigOptions(configs = null) {
                const targetCatalog = this.tooling && Array.isArray(this.tooling.targetCatalog)
                    ? this.tooling.targetCatalog
                    : (this.tooling && Array.isArray(this.tooling.chips) ? this.tooling.chips : []);
                this.syncAutocompleteCatalogs(configs, targetCatalog);
                this.syncConfigHints();
            },

            syncConfigHints() {
                const preset = this.presets[this.currentTool] || this.presets.openocd;
                const configs = this.tooling && this.tooling.configs;
                let targetHint = preset.targetHint || '';
                let interfaceHint = preset.interfaceHint || '';

                if (this.currentTool === 'openocd') {
                    if (configs && !configs.error && configs.scriptsDir) {
                        const sourceLabel = configs.source === 'system-default' ? '系统默认目录' : 'OpenOCD 安装目录';
                        targetHint = `已载入 ${configs.targetConfigs.length || 0} 个 target 配置，来源：${sourceLabel} ${configs.scriptsDir}；输入时支持前缀、片段和模糊搜索。`;
                        interfaceHint = `已载入 ${configs.interfaceConfigs.length || 0} 个 interface 配置，来源：${sourceLabel} ${configs.scriptsDir}；输入时支持前缀、片段和模糊搜索。`;
                    } else if (configs && configs.error) {
                        targetHint = configs.error;
                        interfaceHint = configs.error;
                    }
                } else if (this.supportsTargetAutocomplete()) {
                    const targetCatalogCount = this.tooling && typeof this.tooling.targetCatalogCount === 'number'
                        ? this.tooling.targetCatalogCount
                        : (this.tooling && Array.isArray(this.tooling.targetCatalog) ? this.tooling.targetCatalog.length : 0);
                    const targetCatalogError = this.tooling && (this.tooling.targetCatalogError || this.tooling.chipListError);

                    if (targetCatalogCount > 0) {
                        targetHint = `已载入 ${targetCatalogCount} 个${this.currentTool === 'pyocd' ? ' pyOCD 目标' : ' probe-rs 芯片'}，输入时支持前缀、片段和模糊搜索。`;
                    } else if (targetCatalogError) {
                        targetHint = `未载入 ${this.getTargetCatalogLabel()}：${targetCatalogError}`;
                    } else {
                        targetHint = `${this.getTargetCatalogLabel()}尚未载入，可直接手动输入。`;
                    }
                }

                setI18nTextValue(document.getElementById('flashTargetConfigHint'), targetHint);
                setI18nTextValue(document.getElementById('debugTargetConfigHint'), targetHint);
                setI18nTextValue(document.getElementById('flashInterfaceConfigHint'), interfaceHint);
                setI18nTextValue(document.getElementById('debugInterfaceConfigHint'), interfaceHint);
            },

            updateManualPathVisibility() {
                const row = document.getElementById('flashDebugManualPathRow');
                const inputValue = document.getElementById('flashDebugManualPath').value.trim();
                const required = this.tooling && this.tooling.manualPathRequired;
                row.style.display = this.manualPathForced || required || Boolean(inputValue) ? 'flex' : 'none';
            },

            toggleManualPath() {
                const required = this.tooling && this.tooling.manualPathRequired;
                if (required && !document.getElementById('flashDebugManualPath').value.trim()) {
                    this.manualPathForced = true;
                } else {
                    this.manualPathForced = !this.manualPathForced;
                }

                if (!this.manualPathForced && this.tooling && this.tooling.foundInPath) {
                    document.getElementById('flashDebugManualPath').value = '';
                }

                this.updateManualPathVisibility();
                if (!this.manualPathForced) {
                    this.refreshTooling(true);
                }
            },

            setPathBadge(state, text) {
                const badge = document.getElementById('flashDebugPathBadge');
                const iconMap = {
                    ok: 'fa-circle-check',
                    warn: 'fa-triangle-exclamation',
                    error: 'fa-circle-xmark'
                };
                badge.className = `flashdebug-path-badge ${state}`;
                badge.innerHTML = `<i class="fas ${iconMap[state] || 'fa-magnifying-glass'}"></i><span></span>`;
                setI18nTextValue(badge.querySelector('span'), text);
            },

            populateProgrammers(programmers = []) {
                const placeholder = this.currentTool === 'openocd'
                    ? '自动列出 adapter / 留空手填'
                    : '自动列出 probe / 留空手填';

                ['flashProbeSelect', 'debugProbeSelect'].forEach((id) => {
                    const select = document.getElementById(id);
                    select.innerHTML = '';
                    const baseOption = document.createElement('option');
                    baseOption.value = '';
                    setI18nTextValue(baseOption, placeholder);
                    select.appendChild(baseOption);

                    programmers.forEach((item) => {
                        const option = document.createElement('option');
                        option.value = item.value;
                        option.textContent = item.label;
                        select.appendChild(option);
                    });
                });
            },

            async refreshTooling(silent = false) {
                if (!this.initialized) return;
                if (!State.isAdmin) {
                    this.setPathBadge('warn', '仅管理员可启动本机烧录调试');
                    this.tooling = null;
                    this.syncAutocompleteCatalogs(null, []);
                    this.populateProgrammers([]);
                    this.populateConfigOptions(null);
                    this.syncHints();
                    return;
                }

                const manualPath = document.getElementById('flashDebugManualPath').value.trim();
                this.setPathBadge('warn', `正在检测 ${this.currentTool} ...`);

                try {
                    const url = new URL(`${Config.API}/api/flashdebug/tooling`);
                    url.searchParams.set('tool', this.currentTool);
                    if (manualPath) {
                        url.searchParams.set('path', manualPath);
                    }

                    const res = await apiFetch(url.toString());
                    const data = await res.json().catch(() => ({}));
                    if (!res.ok) {
                        throw new Error(data.error || '检测失败');
                    }

                    this.tooling = data;
                    if (data.manualPathProvided && data.executablePath) {
                        document.getElementById('flashDebugManualPath').value = data.executablePath;
                    }

                    if (data.executablePath) {
                        const label = data.foundInPath ? `PATH: ${data.executablePath}` : `自定义: ${data.executablePath}`;
                        this.setPathBadge('ok', label);
                    } else if (data.manualPathError) {
                        this.setPathBadge('error', data.manualPathError);
                    } else {
                        this.setPathBadge('warn', `${data.label || this.currentTool} 未在 PATH 中找到，请填写手动路径`);
                    }

                    this.populateProgrammers(data.programmers || []);
                    this.populateConfigOptions(data.configs || null);
                    this.manualPathForced = this.manualPathForced || Boolean(data.manualPathRequired);
                    this.updateManualPathVisibility();
                    this.syncHints();
                    this.syncControls();
                    if (!silent && data.configs && data.configs.error) {
                        Toast.info(data.configs.error);
                    }
                } catch (err) {
                    this.tooling = null;
                    this.syncAutocompleteCatalogs(null, []);
                    this.populateProgrammers([]);
                    this.populateConfigOptions(null);
                    this.setPathBadge('error', err.message);
                    this.syncHints();
                    this.syncControls();
                    if (!silent) {
                        Toast.error(err.message);
                    }
                }
            },

            pickFirmwareFile() {
                if (!State.isAdmin || this.isBusy()) return;
                document.getElementById('flashFirmwareFilePicker').click();
            },

            pickCliElfFile() {
                if (!State.isAdmin || this.running.flash || this.running.cli || this.running.native) return;
                document.getElementById('cliElfFilePicker').click();
            },

            formatUploadSize(bytes) {
                const size = Number(bytes || 0);
                if (!size) return '-';
                const units = ['B', 'KB', 'MB', 'GB'];
                let value = size;
                let unitIndex = 0;
                while (value >= 1024 && unitIndex < units.length - 1) {
                    value /= 1024;
                    unitIndex += 1;
                }
                return `${value.toFixed(1)} ${units[unitIndex]}`;
            },

            syncFirmwareUploadHint(meta = null) {
                const hint = document.getElementById('flashFirmwareUploadHint');
                const pathValue = document.getElementById('flashFirmwarePath').value.trim();
                if (meta && meta.uploading) {
                    const sizeText = this.formatUploadSize(meta.size);
                    setI18nTextValue(hint, `正在上传 ${meta.originalName || '固件文件'} (${sizeText})...`);
                    return;
                }
                if (meta && pathValue) {
                    const sizeText = this.formatUploadSize(meta.size);
                    setI18nTextValue(hint, `已上传 ${meta.originalName || '固件文件'} (${sizeText})，当前路径：${pathValue}`);
                    return;
                }
                if (pathValue) {
                    setI18nTextValue(hint, `当前固件路径：${pathValue}`);
                    return;
                }
                setI18nTextValue(hint, '选择本地文件后会上传到当前 Entrance 主机的临时目录，并自动回填路径。');
            },

            syncCliElfHint(meta = null) {
                const hint = document.getElementById('cliElfHint');
                const cliPath = document.getElementById('cliElfPath').value.trim();
                const flashPath = document.getElementById('flashFirmwarePath').value.trim();

                if (meta && meta.uploading) {
                    const sizeText = this.formatUploadSize(meta.size);
                    setI18nTextValue(hint, `正在上传 ${meta.originalName || 'ELF 文件'} (${sizeText})...`);
                    return;
                }
                if (meta && cliPath) {
                    const sizeText = this.formatUploadSize(meta.size);
                    setI18nTextValue(hint, `已上传 ${meta.originalName || 'ELF 文件'} (${sizeText})，当前路径：${cliPath}`);
                    return;
                }
                if (cliPath) {
                    setI18nTextValue(hint, `当前 CLI ELF / 符号文件路径：${cliPath}`);
                    return;
                }
                if (flashPath) {
                    setI18nTextValue(hint, `当前未单独设置 CLI ELF，默认将沿用烧录文件路径：${flashPath}`);
                    return;
                }
                setI18nTextValue(hint, '若烧录任务已选择文件，CLI ELF 默认会优先沿用该路径；也可在这里单独上传 ELF / 符号文件。');
            },

            async uploadFileToPathInput(file, config = {}) {
                if (!file) return;

                const form = new FormData();
                form.append('file', file);
                const pathInput = document.getElementById(config.pathInputId);
                if (!pathInput) return;

                try {
                    setI18nAttributeValue(pathInput, 'placeholder', '正在上传文件...');
                    if (typeof config.onPending === 'function') {
                        config.onPending({
                            originalName: file.name,
                            size: file.size,
                            uploading: true
                        });
                    }
                    const res = await apiFetch(`${Config.API}/api/flashdebug/upload`, {
                        method: 'POST',
                        body: form
                    });
                    const data = await res.json().catch(() => ({}));
                    if (!res.ok) {
                        throw new Error(data.error || '文件上传失败');
                    }
                    pathInput.value = data.path || '';
                    pathInput.dispatchEvent(new Event('input', { bubbles: true }));
                    pathInput.dispatchEvent(new Event('change', { bubbles: true }));
                    if (typeof config.onSuccess === 'function') {
                        config.onSuccess(data);
                    }
                    Toast.success(`已上传 ${data.originalName || file.name}`);
                } catch (err) {
                    if (typeof config.onError === 'function') {
                        config.onError();
                    }
                    Toast.error(err.message);
                } finally {
                    setI18nAttributeValue(pathInput, 'placeholder', config.placeholder || '');
                }
            },

            async uploadFirmwareFile(file) {
                return this.uploadFileToPathInput(file, {
                    pathInputId: 'flashFirmwarePath',
                    placeholder: '输入固件在当前主机上的绝对路径',
                    onPending: (meta) => this.syncFirmwareUploadHint(meta),
                    onSuccess: (data) => this.syncFirmwareUploadHint(data),
                    onError: () => this.syncFirmwareUploadHint()
                });
            },

            getExecutablePathForRequest() {
                return document.getElementById('flashDebugManualPath').value.trim();
            },

            getProbeValue(prefix) {
                const manualValue = document.getElementById(`${prefix}ProbeInput`).value.trim();
                if (manualValue) return manualValue;
                return document.getElementById(`${prefix}ProbeSelect`).value;
            },

            shouldRequestElevation(action) {
                const checkbox = this.getElevationCheckbox(action);
                return Boolean(checkbox && checkbox.checked);
            },

            collectFlashOptions() {
                const tool = this.currentTool;
                const options = {
                    probeSelection: this.getProbeValue('flash'),
                    speed: document.getElementById('flashSpeedInput').value.trim(),
                    firmwarePath: document.getElementById('flashFirmwarePath').value.trim(),
                    verify: document.getElementById('flashVerify').checked,
                    resetAfterFlash: document.getElementById('flashReset').checked,
                    extraArgs: document.getElementById('flashExtraArgs').value.trim()
                };

                if (tool === 'openocd') {
                    options.targetConfig = document.getElementById('flashTargetInput').value.trim();
                    options.interfaceConfig = document.getElementById('flashInterfaceConfigInput').value.trim();
                } else {
                    options.target = document.getElementById('flashTargetInput').value.trim();
                }

                return options;
            },

            collectDebugOptions() {
                const tool = this.currentTool;
                const options = {
                    probeSelection: this.getProbeValue('debug'),
                    speed: document.getElementById('debugSpeedInput').value.trim(),
                    gdbPort: document.getElementById('debugPortInput').value.trim(),
                    telnetPort: document.getElementById('debugTelnetPortInput').value.trim(),
                    elfPath: document.getElementById('debugElfPath').value.trim(),
                    extraArgs: document.getElementById('debugExtraArgs').value.trim()
                };

                if (tool === 'openocd') {
                    options.targetConfig = document.getElementById('debugTargetInput').value.trim();
                    options.interfaceConfig = document.getElementById('debugInterfaceConfigInput').value.trim();
                } else {
                    options.target = document.getElementById('debugTargetInput').value.trim();
                }

                return options;
            },

            collectCliSessionOptions() {
                return {
                    gdbPath: document.getElementById('cliGdbPath').value.trim(),
                    host: document.getElementById('cliHostInput').value.trim() || '127.0.0.1',
                    port: document.getElementById('cliPortInput').value.trim(),
                    elfPath: this.getResolvedCliElfPath(),
                    autoFile: document.getElementById('cliAutoFile').checked,
                    useSymbolFile: document.getElementById('cliUseSymbolFile').checked,
                    autoConnect: document.getElementById('cliAutoConnect').checked
                };
            },

            collectDynamicArgs(prefix) {
                return {
                    arg1: document.getElementById(`${prefix}Arg1`).value.trim(),
                    arg2: document.getElementById(`${prefix}Arg2`).value.trim(),
                    arg3: document.getElementById(`${prefix}Arg3`).value.trim(),
                    arg4: document.getElementById(`${prefix}Arg4`).value.trim()
                };
            },

            getDefaultCliValues(commandId) {
                const defaults = {};
                if (commandId === 'file' || commandId === 'symbol-file') {
                    defaults.arg1 = this.getResolvedCliElfPath();
                } else if (commandId === 'target-extended-remote') {
                    defaults.arg1 = document.getElementById('cliHostInput').value.trim() || '127.0.0.1';
                    defaults.arg2 = document.getElementById('cliPortInput').value.trim();
                }
                return defaults;
            },

            async startCliSession() {
                if (!State.isAdmin) {
                    Toast.error('仅管理员可使用烧录调试功能');
                    return;
                }
                if (this.running.flash || this.running.cli || this.running.native) {
                    Toast.info('请先停止当前烧录 / CLI / probe-rs 原生命令任务');
                    return;
                }

                try {
                    await this.ensureSocket();
                    const payload = Object.assign({ type: 'cli-start' }, this.collectCliSessionOptions());
                    this.appendLog('cli', '\n[gui] 启动 GDB CLI 会话\n');
                    this.ws.send(JSON.stringify(payload));
                } catch (err) {
                    this.appendLog('cli', `[error] ${err.message}\n`);
                    Toast.error(err.message);
                }
            },

            async executeCliCommand(commandId = null, overrideValues = null) {
                if (!State.isAdmin) {
                    Toast.error('仅管理员可使用烧录调试功能');
                    return;
                }
                if (!this.running.cli) {
                    Toast.info('请先启动 GDB CLI 会话');
                    return;
                }

                const selectedCommand = commandId || document.getElementById('cliCommandSelect').value;
                const selectedFromBuilder = document.getElementById('cliCommandSelect').value;
                const values = Object.assign({}, this.getDefaultCliValues(selectedCommand));
                if (!commandId || selectedCommand === selectedFromBuilder) {
                    Object.entries(this.collectDynamicArgs('cliCommand')).forEach(([key, value]) => {
                        if (value) {
                            values[key] = value;
                        }
                    });
                }
                Object.entries(overrideValues || {}).forEach(([key, value]) => {
                    if (value !== undefined) {
                        values[key] = value;
                    }
                });

                try {
                    await this.ensureSocket();
                    this.ws.send(JSON.stringify({
                        type: 'cli-command',
                        sessionKind: 'cli',
                        commandId: selectedCommand,
                        values
                    }));
                } catch (err) {
                    this.appendLog('cli', `[error] ${err.message}\n`);
                    Toast.error(err.message);
                }
            },

            getProbeRsNativeContext() {
                return {
                    type: 'native-start',
                    tool: this.currentTool,
                    executablePath: this.getExecutablePathForRequest(),
                    probeSelection: this.getProbeValue('debug'),
                    target: document.getElementById('debugTargetInput').value.trim(),
                    speed: document.getElementById('debugSpeedInput').value.trim(),
                    protocol: document.getElementById('probeRsProtocol').value,
                    core: document.getElementById('probeRsCore').value.trim(),
                    connectUnderReset: document.getElementById('probeRsUnderReset').checked,
                    verifyAfterLoad: document.getElementById('probeRsVerifyAfterLoad').checked,
                    chipErase: document.getElementById('probeRsChipErase').checked
                };
            },

            async executeProbeRsCommand(commandId = null) {
                if (!State.isAdmin) {
                    Toast.error('仅管理员可使用烧录调试功能');
                    return;
                }
                if (this.currentTool !== 'probe-rs') {
                    Toast.info('请选择 probe-rs 调试器后再执行原生命令');
                    return;
                }
                if (this.running.flash || this.running.debug || this.running.cli || this.running.native) {
                    Toast.info('probe-rs 原生命令执行前，请先停止当前烧录 / 调试 / CLI 会话');
                    return;
                }

                const selectedCommand = commandId || document.getElementById('probeRsCommandSelect').value;
                const payload = Object.assign({}, this.getProbeRsNativeContext(), {
                    sessionKind: 'native',
                    commandId: selectedCommand,
                    values: this.collectDynamicArgs('probeRs')
                });

                try {
                    await this.ensureSocket();
                    this.appendLog('cli', `\n[gui] 执行 probe-rs 原生命令: ${selectedCommand}\n`);
                    this.ws.send(JSON.stringify(payload));
                } catch (err) {
                    this.appendLog('cli', `[error] ${err.message}\n`);
                    Toast.error(err.message);
                }
            },

            async ensureSocket() {
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    return;
                }
                if (this.wsReadyPromise) {
                    return this.wsReadyPromise;
                }

                this.wsReadyPromise = new Promise((resolve, reject) => {
                    let settled = false;
                    this.ws = new WebSocket(buildWsUrl('/flashdebug'));

                    this.ws.onopen = () => {
                        settled = true;
                        this.wsReadyPromise = null;
                        resolve();
                    };

                    this.ws.onmessage = (event) => {
                        this.handleSocketMessage(event);
                    };

                    this.ws.onerror = () => {
                        if (!settled) {
                            settled = true;
                            this.wsReadyPromise = null;
                            reject(new Error('烧录调试 WebSocket 连接失败'));
                        }
                        Toast.error('烧录调试 WebSocket 连接失败');
                    };

                    this.ws.onclose = () => {
                        this.ws = null;
                        this.running.flash = false;
                        this.running.debug = false;
                        this.running.cli = false;
                        this.running.native = false;
                        this.updateStatusBadge('flash');
                        this.updateStatusBadge('debug');
                        this.updateStatusBadge('cli');
                        this.syncControls();
                        if (!settled) {
                            settled = true;
                            this.wsReadyPromise = null;
                            reject(new Error('烧录调试连接已关闭'));
                        }
                    };
                });

                return this.wsReadyPromise;
            },

            handleSocketMessage(event) {
                try {
                    const msg = JSON.parse(event.data);
                    const logAction = msg.action === 'cli' || msg.sessionKind === 'cli' || msg.sessionKind === 'native'
                        ? 'cli'
                        : (msg.action || this.currentMode);
                    switch (msg.type) {
                        case 'started': {
                            if (msg.sessionKind === 'cli') {
                                this.running.cli = true;
                            } else if (msg.sessionKind === 'native') {
                                this.running.native = true;
                            } else if (msg.action === 'flash' || msg.action === 'debug') {
                                this.running[msg.action] = true;
                            }
                            this.updateStatusBadge('flash');
                            this.updateStatusBadge('debug');
                            this.updateStatusBadge('cli');
                            this.syncControls();
                            this.appendLog(logAction, `\n[gui] ${msg.command}\n`);
                            if (msg.sessionKind === 'cli') {
                                Toast.success('GDB CLI 会话已启动');
                            } else if (msg.sessionKind === 'native') {
                                Toast.success('probe-rs 原生命令已启动');
                            } else {
                                Toast.success(msg.action === 'flash' ? '烧录任务已启动' : '调试任务已启动');
                            }
                            break;
                        }
                        case 'output':
                            this.appendLog(logAction, msg.data || '');
                            break;
                        case 'exit':
                            if (msg.sessionKind === 'cli') {
                                this.running.cli = false;
                            } else if (msg.sessionKind === 'native') {
                                this.running.native = false;
                            } else if (msg.action === 'flash' || msg.action === 'debug') {
                                this.running[msg.action] = false;
                            }
                            this.updateStatusBadge('flash');
                            this.updateStatusBadge('debug');
                            this.updateStatusBadge('cli');
                            this.syncControls();
                            this.appendLog(
                                logAction,
                                `\n[exit] code=${msg.exitCode}${msg.signal ? ` signal=${msg.signal}` : ''}\n`
                            );
                            if (msg.sessionKind === 'cli') {
                                Toast.info('GDB CLI 会话已结束');
                            } else if (msg.sessionKind === 'native') {
                                Toast.info('probe-rs 原生命令已结束');
                            } else {
                                Toast.info(msg.action === 'flash' ? '烧录任务已结束' : '调试任务已结束');
                            }
                            break;
                        case 'error':
                            if (msg.action === 'flash' || msg.action === 'debug') {
                                this.running[msg.action] = false;
                            }
                            this.updateStatusBadge('flash');
                            this.updateStatusBadge('debug');
                            this.updateStatusBadge('cli');
                            this.syncControls();
                            this.appendLog(logAction, `[error] ${msg.message}\n`);
                            Toast.error(msg.message);
                            break;
                    }
                } catch (err) {
                    console.error('[FlashDebug] 消息解析错误:', err);
                }
            },

            updateStatusBadge(action) {
                const badgeIdMap = {
                    flash: 'flashStatusBadge',
                    debug: 'debugStatusBadge',
                    cli: 'cliStatusBadge'
                };
                const badge = document.getElementById(badgeIdMap[action] || 'debugStatusBadge');
                if (!badge) return;

                if (action === 'cli') {
                    const cliRunning = this.running.cli;
                    const nativeRunning = this.running.native;
                    badge.classList.toggle('running', cliRunning || nativeRunning);
                    if (cliRunning && nativeRunning) {
                        badge.innerHTML = buildInlineIconTextHtml('fa-circle-notch fa-spin', 'CLI / probe-rs 运行中');
                    } else if (cliRunning) {
                        badge.innerHTML = buildInlineIconTextHtml('fa-circle-notch fa-spin', 'GDB CLI 运行中');
                    } else if (nativeRunning) {
                        badge.innerHTML = buildInlineIconTextHtml('fa-circle-notch fa-spin', 'probe-rs 运行中');
                    } else {
                        badge.innerHTML = buildInlineIconTextHtml('fa-circle', '空闲');
                    }
                    return;
                }

                const running = this.running[action];
                badge.classList.toggle('running', running);
                badge.innerHTML = running
                    ? buildInlineIconTextHtml('fa-circle-notch fa-spin', '运行中')
                    : buildInlineIconTextHtml('fa-circle', '空闲');
            },

            appendLog(action, text) {
                const outputMap = {
                    flash: 'flashLogOutput',
                    debug: 'debugLogOutput',
                    cli: 'cliLogOutput'
                };
                const output = document.getElementById(outputMap[action] || 'debugLogOutput');
                const nextText = output.textContent + I18n.autoMultiline(String(text || ''));
                output.textContent = nextText.length > 200000 ? nextText.slice(-180000) : nextText;
                output.scrollTop = output.scrollHeight;
            },

            clearLog(action) {
                const outputMap = {
                    flash: 'flashLogOutput',
                    debug: 'debugLogOutput',
                    cli: 'cliLogOutput'
                };
                document.getElementById(outputMap[action] || 'debugLogOutput').textContent = '';
            },

            async startAction(action) {
                if (!State.isAdmin) {
                    Toast.error('仅管理员可使用烧录调试功能');
                    return;
                }
                if (this.isBusy()) {
                    Toast.info('请先停止当前任务');
                    return;
                }

                try {
                    await this.refreshTooling(true);
                    const elevationInfo = this.getElevationInfo();
                    if (this.shouldRequestElevation(action) && (!elevationInfo || !elevationInfo.available)) {
                        throw new Error((elevationInfo && elevationInfo.note) || '当前主机未检测到可用的管理员/root 提权方式');
                    }

                    const options = action === 'flash' ? this.collectFlashOptions() : this.collectDebugOptions();
                    const payload = {
                        type: 'start',
                        action,
                        tool: this.currentTool,
                        executablePath: this.getExecutablePathForRequest(),
                        requestElevation: this.shouldRequestElevation(action),
                        options
                    };
                    await this.ensureSocket();
                    this.appendLog(action, `\n[gui] ${action === 'flash' ? '开始烧录' : '启动调试'}\n`);
                    this.ws.send(JSON.stringify(payload));
                } catch (err) {
                    this.appendLog(action, `[error] ${err.message}\n`);
                    Toast.error(err.message);
                }
            },

            stopAction(action) {
                if (!this.running[action] || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
                    return;
                }
                this.ws.send(JSON.stringify({ type: 'stop', sessionKind: action }));
                this.appendLog(action === 'native' ? 'cli' : action, '[gui] 停止请求已发送\n');
            }
        };

        // 本地 Shell
        const LocalShell = {
            term: null,
            fit: null,
            ws: null,
            connected: false,
            available: false,
            platform: 'unknown',
            shellInfo: '',
            initialized: false,
            transportMode: 'native',
            sshDefaults: {
                host: '127.0.0.1',
                port: 22,
                username: '',
                note: ''
            },
            connectionLabel: '',

            isSshLocalhostMode() {
                return this.transportMode === 'ssh-localhost';
            },

            getShellOptions() {
                const shellOptions = {
                    win32: ['cmd', 'powershell'],
                    linux: ['bash', 'zsh', 'fish'],
                    darwin: ['zsh', 'bash']
                };
                return shellOptions[this.platform] || [];
            },

            normalizeShellName(shell) {
                return String(shell || '')
                    .trim()
                    .split(/[\\/]/)
                    .pop()
                    .replace(/\.exe$/i, '')
                    .toLowerCase();
            },

            updateShellOptions() {
                const select = document.getElementById('shellPathInput');
                const options = this.getShellOptions();
                const preferredShell = this.normalizeShellName(this.shellInfo);

                select.innerHTML = '';

                options.forEach((shellName) => {
                    const option = document.createElement('option');
                    option.value = shellName;
                    option.textContent = shellName;
                    select.appendChild(option);
                });

                const preferredOption = options.includes(preferredShell) ? preferredShell : options[0];
                if (preferredOption) {
                    select.value = preferredOption;
                    select.disabled = false;
                } else {
                    const option = document.createElement('option');
                    option.value = '';
                    option.textContent = I18n.auto('当前平台无可选 Shell');
                    select.appendChild(option);
                    select.value = '';
                    select.disabled = true;
                }
            },

            configureTransportUi() {
                const isSshLocalhost = this.isSshLocalhostMode();
                const shellInfo = document.getElementById('shellInfo');
                const shellPathInput = document.getElementById('shellPathInput');
                const sshConfig = document.getElementById('shellSshConfig');
                const modeNote = document.getElementById('shellModeNote');
                const startBtn = document.getElementById('shellStartBtn');
                const stopBtn = document.getElementById('shellStopBtn');

                shellPathInput.style.display = isSshLocalhost ? 'none' : '';
                sshConfig.style.display = isSshLocalhost ? 'flex' : 'none';
                startBtn.innerHTML = isSshLocalhost
                    ? `<i class="fas fa-plug"></i> ${I18n.auto('连接')}`
                    : `<i class="fas fa-play"></i> ${I18n.auto('启动')}`;
                stopBtn.innerHTML = isSshLocalhost
                    ? `<i class="fas fa-times"></i> ${I18n.auto('断开')}`
                    : `<i class="fas fa-stop"></i> ${I18n.auto('停止')}`;

                const shellUser = document.getElementById('shellUser');
                const shellPass = document.getElementById('shellPass');
                const shellPassphrase = document.getElementById('shellPassphrase');
                if (shellUser) {
                    shellUser.setAttribute('placeholder', I18n.auto('Windows 用户名'));
                }
                if (shellPass) {
                    shellPass.setAttribute('placeholder', I18n.auto('Windows 登录密码'));
                }
                if (shellPassphrase) {
                    shellPassphrase.setAttribute('placeholder', I18n.auto('私钥口令'));
                }

                if (isSshLocalhost) {
                    document.getElementById('shellHost').value = this.sshDefaults.host || '127.0.0.1';
                    document.getElementById('shellPort').value = this.sshDefaults.port || 22;
                    document.getElementById('shellUser').value = this.sshDefaults.username || '';
                    shellInfo.textContent = I18n.auto(`SSH 到 ${this.sshDefaults.host || '127.0.0.1'}`);
                    modeNote.style.display = 'block';
                    modeNote.innerHTML = `${escapeHtml(I18n.auto(this.sshDefaults.note || 'Windows 下通过 SSH 连接本机，借助 OpenSSH Server 获取真正的终端语义。'))}<br>${I18n.auto('请先在系统中启用 OpenSSH Server，再使用本机账号登录。').replace('OpenSSH Server', '<code>OpenSSH Server</code>')}`;
                    updateAuthFields('shell', document.getElementById('shellAuthType').value);
                } else {
                    shellInfo.textContent = this.shellInfo;
                    modeNote.style.display = 'none';
                    modeNote.textContent = '';
                }

                this.updateStatus(false);
            },

            async init() {
                if (this.initialized) return;
                this.initialized = true;
                // 检查服务是否可用
                try {
                    const res = await apiFetch(`${Config.API}/api/localshell/status`);
                    if (!res.ok) {
                        throw new Error('unauthorized');
                    }
                    const data = await res.json();
                    this.available = data.available;
                    this.shellInfo = data.shell || '';
                    this.platform = data.platform || 'unknown';
                    this.transportMode = data.mode || (this.platform === 'win32' ? 'ssh-localhost' : 'native');
                    this.sshDefaults = Object.assign({}, this.sshDefaults, data.sshLocalhost || {});
                    this.updateShellOptions();
                    this.configureTransportUi();

                    if (!this.available) {
                        document.getElementById('shellNotAvailable').style.display = 'block';
                        document.getElementById('shellStartBtn').disabled = true;
                        document.getElementById('shellNotAvailableReason').innerHTML =
                            `${escapeHtml(I18n.auto('当前服务器平台暂不支持终端功能'))}<br><small style="color:var(--color-text-3)">${escapeHtml(I18n.auto(`当前服务器: ${this.platform}`))}</small>`;
                    }
                } catch (e) {
                    console.error('[LocalShell] 检查状态失败:', e);
                    this.updateShellOptions();
                    this.configureTransportUi();
                    document.getElementById('shellNotAvailable').style.display = 'block';
                    document.getElementById('shellStartBtn').disabled = true;
                    document.getElementById('shellNotAvailableReason').textContent = I18n.auto('无法检查终端服务状态');
                }

                // 初始化终端
                this.term = new Terminal({
                    theme: Theme.getTerminalTheme(),
                    fontFamily: 'Consolas, Monaco, monospace',
                    fontSize: 14,
                    cursorBlink: true
                });
                this.fit = new FitAddon.FitAddon();
                this.term.loadAddon(this.fit);
                this.term.open(document.getElementById('shellTerminal'));
                this.doFit();
                this.welcome();

                window.addEventListener('resize', () => this.doFit());

                // 终端输入处理
                this.term.onData(data => {
                    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                        this.ws.send(JSON.stringify({ type: 'data', data }));
                    }
                });

                this.term.onResize(({ cols, rows }) => {
                    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                        this.ws.send(JSON.stringify({ type: 'resize', cols, rows }));
                    }
                });

                // 绑定事件
                document.getElementById('shellStartBtn').addEventListener('click', () => this.start());
                document.getElementById('shellStopBtn').addEventListener('click', () => this.stop());
                document.getElementById('shellAuthType').addEventListener('change', (e) => updateAuthFields('shell', e.target.value));
                document.getElementById('shellClearBtn').addEventListener('click', () => {
                    this.term.clear();
                    if (!this.connected) this.welcome();
                });
            },

            applyTheme() {
                if (!this.term) return;
                this.term.setOption('theme', Theme.getTerminalTheme());
                this.doFit();
                if (!this.connected) {
                    this.term.clear();
                    this.welcome();
                }
            },

            doFit() {
                try { this.fit.fit(); } catch {}
            },

            syncSize() {
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({
                        type: 'resize',
                        cols: this.term.cols,
                        rows: this.term.rows
                    }));
                }
            },

            welcome() {
                const colors = Theme.getTerminalWelcomeColors();
                this.term.writeln('');
                this.term.writeln(`\x1b[${colors.frame}m  ╔══════════════════════════════════════════╗\x1b[0m`);
                this.term.writeln(`\x1b[${colors.frame}m  ║\x1b[0m              \x1b[${colors.title}mTerminal\x1b[0m                   \x1b[${colors.frame}m║\x1b[0m`);
                this.term.writeln(`\x1b[${colors.frame}m  ╚══════════════════════════════════════════╝\x1b[0m`);
                this.term.writeln('');
                this.term.writeln(this.isSshLocalhostMode()
                    ? `\x1b[90m  ${I18n.auto('填写本机 SSH 凭据后点击 "连接" 按钮开启终端')}\x1b[0m`
                    : `\x1b[90m  ${I18n.auto('点击 "启动" 按钮开启终端')}\x1b[0m`);
                this.term.writeln('');
            },

            start() {
                if (!State.isAdmin) {
                    Toast.error('权限不足');
                    return;
                }
                if (!this.available) {
                    Toast.error('终端服务不可用');
                    return;
                }

                if (this.ws) {
                    this.stop({ quiet: true });
                }

                this.term.clear();
                if (this.isSshLocalhostMode()) {
                    this.startViaLocalhostSsh();
                } else {
                    this.startViaNativeShell();
                }
            },

            startViaNativeShell() {
                const shellPath = document.getElementById('shellPathInput').value.trim();
                this.ws = new WebSocket(buildWsUrl('/localshell'));

                this.ws.onopen = () => {
                    const msg = {
                        type: 'start',
                        cols: this.term.cols,
                        rows: this.term.rows
                    };
                    if (shellPath) {
                        msg.shell = shellPath;
                    }
                    this.ws.send(JSON.stringify(msg));
                };

                this.ws.onmessage = (e) => {
                    try {
                        const msg = JSON.parse(e.data);
                        switch (msg.type) {
                            case 'started':
                                this.connected = true;
                                this.connectionLabel = msg.shell || this.shellInfo;
                                this.term.clear();
                                this.updateStatus(true, this.connectionLabel);
                                Toast.success('终端已启动');
                                this.doFit();
                                break;
                            case 'data':
                                this.term.write(msg.data);
                                break;
                            case 'exit':
                                this.connected = false;
                                this.connectionLabel = '';
                                this.updateStatus(false);
                                this.term.writeln(`\n\x1b[33m${I18n.auto(`终端已退出 (code: ${msg.exitCode})`)}\x1b[0m`);
                                Toast.info('终端已退出');
                                break;
                            case 'error':
                                Toast.error(msg.message);
                                this.term.writeln(`\x1b[31m${I18n.auto(`错误: ${msg.message}`)}\x1b[0m`);
                                break;
                        }
                    } catch (err) {
                        console.error('[LocalShell] 消息解析错误:', err);
                    }
                };

                this.ws.onerror = () => {
                    this.term.writeln(`\x1b[31m${I18n.auto('连接失败，请确保后端服务正在运行')}\x1b[0m`);
                    Toast.error('WebSocket 连接失败');
                };

                this.ws.onclose = () => {
                    if (this.connected) {
                        this.connected = false;
                        this.connectionLabel = '';
                        this.updateStatus(false);
                    }
                };
            },

            startViaLocalhostSsh() {
                const host = (document.getElementById('shellHost').value || '127.0.0.1').trim() || '127.0.0.1';
                const port = parseInt(document.getElementById('shellPort').value || '22', 10);
                const username = document.getElementById('shellUser').value.trim();
                let authPayload = null;

                if (!Number.isFinite(port) || port < 1 || port > 65535) {
                    Toast.error('SSH 端口范围必须是 1-65535');
                    return;
                }
                if (!username) {
                    Toast.error('请输入 Windows 用户名');
                    return;
                }

                try {
                    authPayload = readCredentialForm('shell');
                } catch (err) {
                    Toast.error(err.message);
                    return;
                }

                this.connectionLabel = `${username}@${host}:${port}`;
                this.term.writeln(`\x1b[33m${I18n.auto(`正在连接 ${this.connectionLabel}...`)}\x1b[0m`);
                this.term.writeln(`\x1b[90m${I18n.auto('目标为本机 OpenSSH Server，用于提供 Windows 终端 PTY 语义')}\x1b[0m\n`);

                this.ws = new WebSocket(buildWsUrl('/ssh'));
                this.ws.onopen = () => {
                    this.ws.send(JSON.stringify({
                        type: 'connect',
                        host,
                        port,
                        username,
                        localShellMode: true,
                        ...authPayload
                    }));
                };

                this.ws.onmessage = (e) => {
                    try {
                        const msg = JSON.parse(e.data);
                        switch (msg.type) {
                            case 'connected':
                                this.connected = true;
                                this.updateStatus(true, this.connectionLabel);
                                Toast.success(`已连接到 ${this.connectionLabel}`);
                                this.doFit();
                                this.syncSize();
                                break;
                            case 'data':
                                this.term.write(msg.data);
                                break;
                            case 'disconnected':
                                if (this.connected) {
                                    this.connected = false;
                                    this.connectionLabel = '';
                                    this.updateStatus(false);
                                    this.term.writeln(`\n\x1b[33m${I18n.auto('本机 SSH 终端已断开')}\x1b[0m`);
                                    Toast.info('本机 SSH 终端已断开');
                                }
                                break;
                            case 'error':
                                Toast.error(msg.message);
                                this.term.writeln(`\x1b[31m${I18n.auto(`错误: ${msg.message}`)}\x1b[0m`);
                                break;
                        }
                    } catch (err) {
                        console.error('[LocalShell] SSH 消息解析错误:', err);
                    }
                };

                this.ws.onerror = () => {
                    this.term.writeln(`\x1b[31m${I18n.auto('SSH 连接失败，请确认 OpenSSH Server 已启用并允许本机登录')}\x1b[0m`);
                    Toast.error('本机 SSH 连接失败');
                };

                this.ws.onclose = () => {
                    if (this.connected) {
                        this.connected = false;
                        this.connectionLabel = '';
                        this.updateStatus(false);
                    }
                };
            },

            stop(options = {}) {
                const quiet = options.quiet === true;
                const wasConnected = this.connected;
                this.connected = false;
                this.connectionLabel = '';
                if (this.ws) {
                    if (this.ws.readyState === WebSocket.OPEN) {
                        this.ws.send(JSON.stringify({
                            type: this.isSshLocalhostMode() ? 'disconnect' : 'stop'
                        }));
                    }
                    this.ws.close();
                    this.ws = null;
                }
                this.updateStatus(false);
                if (!quiet && wasConnected) {
                    this.term.writeln(this.isSshLocalhostMode()
                        ? `\n\x1b[33m${I18n.auto('本机 SSH 终端已断开')}\x1b[0m`
                        : `\n\x1b[33m${I18n.auto('终端已停止')}\x1b[0m`);
                    Toast.info(this.isSshLocalhostMode() ? '本机 SSH 终端已断开' : '终端已停止');
                }
            },

            updateStatus(running, shell = '') {
                const status = document.getElementById('shellStatus');
                const text = document.getElementById('shellStatusText');
                const startBtn = document.getElementById('shellStartBtn');
                const stopBtn = document.getElementById('shellStopBtn');
                const title = document.getElementById('shellTermTitle');
                const idleText = this.isSshLocalhostMode() ? '未连接' : '未启动';
                const activeText = this.isSshLocalhostMode() ? '已连接' : '运行中';
                const idleTitle = this.isSshLocalhostMode() ? 'Web 终端 - 本机 SSH' : 'Web 终端 - 未启动';

                if (running) {
                    status.classList.remove('disconnected');
                    status.classList.add('connected');
                    text.textContent = I18n.auto(activeText);
                    startBtn.style.display = 'none';
                    stopBtn.style.display = 'inline-flex';
                    title.textContent = I18n.auto(`Web 终端 - ${shell || this.shellInfo}`);
                } else {
                    status.classList.remove('connected');
                    status.classList.add('disconnected');
                    text.textContent = I18n.auto(idleText);
                    startBtn.style.display = 'inline-flex';
                    stopBtn.style.display = 'none';
                    title.textContent = I18n.auto(idleTitle);
                }
            }
        };

        // VNC 远程桌面
        const VNCModule = {
            initialized: false,

            init() {
                if (this.initialized) return;

                const container = document.getElementById('vncScreen');

                // 初始化 VNC 客户端（使用外部 vnc-client.js）
                if (typeof VNC !== 'undefined') {
                    VNC.init(container, {
                        onConnect: (host) => {
                            this.updateStatus(true, host);
                            document.getElementById('vncToolbar').style.display = 'flex';
                            document.querySelector('#vncScreen .vnc-placeholder')?.remove();
                            Toast.success(`VNC 已连接到 ${host}`);
                        },
                        onDisconnect: (clean) => {
                            this.updateStatus(false);
                            document.getElementById('vncToolbar').style.display = 'none';
                            if (!clean) {
                                Toast.error('VNC 连接意外断开');
                            } else {
                                Toast.info('VNC 已断开');
                            }
                        },
                        onError: (msg) => {
                            Toast.error(formatConnectionError('VNC', msg));
                        },
                        onDesktopName: (name) => {
                            document.getElementById('vncStatusText').textContent = I18n.auto(`已连接: ${name}`);
                        }
                    });
                    this.initialized = true;
                    console.log('[VNC Module] 初始化完成');
                } else {
                    console.warn('[VNC Module] VNC 客户端未加载，稍后重试');
                    // 延迟重试（等待 ES module 加载）
                    setTimeout(() => this.init(), 500);
                }
            },

            async connect() {
                const host = document.getElementById('vncHost').value.trim();
                const port = document.getElementById('vncPort').value || 5900;
                const password = document.getElementById('vncPassword').value;
                const viewOnly = document.getElementById('vncViewOnly').checked;
                const scaleViewport = document.getElementById('vncScaleViewport').checked;

                if (!host) {
                    Toast.error('请输入 VNC 主机地址');
                    return;
                }

                const targetCheck = await validateTargetForConnection('VNC', host);
                if (!targetCheck.ok) {
                    Toast.error(targetCheck.error);
                    return;
                }

                if (typeof VNC !== 'undefined') {
                    VNC.connect({
                        host,
                        port: parseInt(port),
                        password,
                        viewOnly,
                        scaleViewport
                    });
                } else {
                    Toast.error('VNC 模块未加载，请刷新页面');
                }
            },

            disconnect() {
                if (typeof VNC !== 'undefined') {
                    VNC.disconnect();
                }
            },

            sendCtrlAltDel() {
                if (typeof VNC !== 'undefined') {
                    VNC.sendCtrlAltDel();
                }
            },

            toggleFullscreen() {
                if (typeof VNC !== 'undefined') {
                    if (document.fullscreenElement) {
                        VNC.exitFullscreen();
                    } else {
                        VNC.requestFullscreen();
                    }
                }
            },

            updateStatus(connected, host = '') {
                const status = document.getElementById('vncStatus');
                const text = document.getElementById('vncStatusText');
                const disconnBtn = document.getElementById('vncDisconnectBtn');
                const connBtn = document.getElementById('vncConnectBtn');

                if (connected) {
                    status.classList.remove('disconnected');
                    status.classList.add('connected');
                    text.textContent = I18n.auto(`已连接到 ${host}`);
                    disconnBtn.style.display = 'inline-flex';
                    connBtn.disabled = true;
                } else {
                    status.classList.remove('connected');
                    status.classList.add('disconnected');
                    text.textContent = I18n.auto('未连接');
                    disconnBtn.style.display = 'none';
                    connBtn.disabled = false;
                }
            }
        };

        // UI
        const UI = {
            started: false,
            bootRunId: 0,
            bootProgressFrame: 0,
            bootProgressState: null,
            init() {
                I18n.init();
                About.init();
                Theme.init();
                Settings.init();
                Auth.init();

                // 侧边栏
                document.getElementById('toggleSidebar').addEventListener('click', () => {
                    document.getElementById('sidebar').classList.toggle('collapsed');
                    setTimeout(() => Terminal_.doFit(), 300);
                });

                // 导航
                document.querySelectorAll('.nav-item').forEach(item => {
                    item.addEventListener('click', () => this.switchView(item.dataset.view));
                    item.addEventListener('mousemove', e => {
                        const rect = item.getBoundingClientRect();
                        item.style.setProperty('--x', `${e.clientX - rect.left}px`);
                        item.style.setProperty('--y', `${e.clientY - rect.top}px`);
                    });
                });

                document.getElementById('sshAuthType').addEventListener('change', (e) => updateAuthFields('ssh', e.target.value));
                document.getElementById('sftpAuthType').addEventListener('change', (e) => updateAuthFields('sftp', e.target.value));
                updateAuthFields('ssh', document.getElementById('sshAuthType').value);
                updateAuthFields('sftp', document.getElementById('sftpAuthType').value);

                // SSH
                document.getElementById('saveHostBtn').addEventListener('click', async () => {
                    const host = document.getElementById('sshHost').value.trim();
                    const port = document.getElementById('sshPort').value || 22;
                    const user = document.getElementById('sshUser').value.trim();
                    if (!host || !user) {
                        Toast.error('请输入主机地址和用户名');
                        return;
                    }
                    try {
                        const authPayload = readCredentialForm('ssh', { requireCredential: false });
                        await Hosts.save({ host, port, user, ...authPayload });
                    } catch (err) {
                        Toast.error(err.message);
                    }
                });
                document.getElementById('cancelEditHostBtn').addEventListener('click', () => {
                    setEditingHostIndex(null);
                    document.getElementById('sshHost').value = '';
                    document.getElementById('sshPort').value = 22;
                    document.getElementById('sshUser').value = '';
                    document.getElementById('sshPass').value = '';
                    document.getElementById('sshPrivateKey').value = '';
                    document.getElementById('sshPassphrase').value = '';
                    document.getElementById('sshAuthType').value = 'password';
                    updateAuthFields('ssh', 'password');
                });
                // SSH Stats Monitor
                document.getElementById('sysStatsHint').addEventListener('click', () => Terminal_.toggleStats());
                document.getElementById('sysStatsClearBtn').addEventListener('click', () => Terminal_.clearStats());
                document.getElementById('sysStatsCloseBtn').addEventListener('click', () => Terminal_.toggleStats());

                // TOP Panel
                document.getElementById('topPanelHint').addEventListener('click', () => Terminal_.toggleTop());
                document.getElementById('topCloseBtn').addEventListener('click', () => Terminal_.toggleTop());
                document.getElementById('topRefreshBtn').addEventListener('click', () => Terminal_.refreshTop());
                document.getElementById('topSortBy').addEventListener('change', () => Terminal_.renderTopTable());
                document.getElementById('topShowCount').addEventListener('change', () => Terminal_.renderTopTable());

                // Docker Stats Panel
                document.getElementById('dockerPanelHint').addEventListener('click', () => Terminal_.toggleDockerPanel());
                document.getElementById('dockerCloseBtn').addEventListener('click', () => Terminal_.toggleDockerPanel());
                document.getElementById('dockerRefreshBtn').addEventListener('click', () => Terminal_.refreshDockerStats());
                document.getElementById('dockerModeSwitch').addEventListener('click', e => {
                    const btn = e.target.closest('.docker-mode-tag');
                    if (btn) Terminal_.setDockerMode(btn.dataset.mode);
                });
                document.getElementById('dockerContainerList').addEventListener('click', e => {
                    const item = e.target.closest('.docker-container-item');
                    if (item) Terminal_.selectDockerContainer(item.dataset.containerId);
                });

                // Kill Modal
                document.getElementById('killCancel').addEventListener('click', () => document.getElementById('killModal').classList.remove('active'));
                document.getElementById('killConfirm').addEventListener('click', () => Terminal_.killProcess());
                document.getElementById('killModal').addEventListener('click', e => { if (e.target.id === 'killModal') e.target.classList.remove('active'); });

                // About Modal
                document.getElementById('aboutBtn').addEventListener('click', () => document.getElementById('aboutModal').classList.add('active'));
                document.getElementById('aboutClose').addEventListener('click', () => document.getElementById('aboutModal').classList.remove('active'));
                document.getElementById('aboutModal').addEventListener('click', e => { if (e.target.id === 'aboutModal') e.target.classList.remove('active'); });

                // SFTP
                document.getElementById('sftpConnectBtn').addEventListener('click', () => {
                    const host = document.getElementById('sftpHost').value.trim();
                    const port = document.getElementById('sftpPort').value || 22;
                    const user = document.getElementById('sftpUser').value.trim();
                    if (!host || !user) {
                        Toast.error('请输入主机地址和用户名');
                        return;
                    }
                    try {
                        const authPayload = readCredentialForm('sftp');
                        SFTP.connect(host, port, user, authPayload);
                    } catch (err) {
                        Toast.error(err.message);
                    }
                });
                document.getElementById('sftpDisconnectBtn').addEventListener('click', () => SFTP.disconnect());
                document.getElementById('sftpRefreshBtn').addEventListener('click', () => SFTP.list(State.currentPath));
                document.getElementById('sftpMkdirBtn').addEventListener('click', () => document.getElementById('mkdirModal').classList.add('active'));
                document.getElementById('sftpDownloadBtn').addEventListener('click', () => SFTP.download());
                document.getElementById('sftpDeleteBtn').addEventListener('click', () => { if (State.selectedFiles.length && confirm(`删除 "${State.selectedFiles[0].name}"?`)) SFTP.delete_(); });
                document.getElementById('goPathBtn').addEventListener('click', () => { if (State.sftpConnected) SFTP.navigate(document.getElementById('remotePath').value.trim()); });
                document.getElementById('remotePath').addEventListener('keypress', e => { if (e.key === 'Enter') document.getElementById('goPathBtn').click(); });
                // 导航按钮
                document.getElementById('navBackBtn').addEventListener('click', () => SFTP.goBack());
                document.getElementById('navForwardBtn').addEventListener('click', () => SFTP.goForward());
                document.getElementById('navUpBtn').addEventListener('click', () => SFTP.goUp());

                // 内网白名单
                document.getElementById('privateNetAddBtn').addEventListener('click', () => Security.add());
                document.getElementById('privateNetInput').addEventListener('keypress', e => {
                    if (e.key === 'Enter') Security.add();
                });

                // 上传
                document.getElementById('uploadFilesBtn').addEventListener('click', () => document.getElementById('fileInput').click());
                document.getElementById('uploadFolderBtn').addEventListener('click', () => document.getElementById('folderInput').click());
                document.getElementById('fileInput').addEventListener('change', e => { if (e.target.files.length) { SFTP.upload([...e.target.files]); e.target.value = ''; } });
                document.getElementById('folderInput').addEventListener('change', e => { if (e.target.files.length) { SFTP.upload([...e.target.files]); e.target.value = ''; } });

                // 拖放
                const area = document.getElementById('uploadArea');
                area.addEventListener('dragover', e => { e.preventDefault(); if (State.sftpConnected) area.classList.add('drag-over'); });
                area.addEventListener('dragleave', () => area.classList.remove('drag-over'));
                area.addEventListener('drop', e => { e.preventDefault(); area.classList.remove('drag-over'); if (State.sftpConnected && e.dataTransfer.files.length) SFTP.upload([...e.dataTransfer.files]); });

                // Modal: 新建文件夹
                document.getElementById('mkdirCancel').addEventListener('click', () => document.getElementById('mkdirModal').classList.remove('active'));
                document.getElementById('mkdirConfirm').addEventListener('click', () => {
                    const name = document.getElementById('mkdirName').value.trim();
                    if (name) { SFTP.mkdir(name); document.getElementById('mkdirModal').classList.remove('active'); document.getElementById('mkdirName').value = ''; }
                });
                document.getElementById('mkdirName').addEventListener('keypress', e => { if (e.key === 'Enter') document.getElementById('mkdirConfirm').click(); });
                document.getElementById('mkdirModal').addEventListener('click', e => { if (e.target.id === 'mkdirModal') e.target.classList.remove('active'); });

                // VNC
                document.getElementById('vncConnectBtn').addEventListener('click', () => VNCModule.connect());
                document.getElementById('vncDisconnectBtn').addEventListener('click', () => VNCModule.disconnect());
                document.getElementById('vncCtrlAltDelBtn').addEventListener('click', () => VNCModule.sendCtrlAltDel());
                document.getElementById('vncFullscreenBtn').addEventListener('click', () => VNCModule.toggleFullscreen());
                document.getElementById('vncViewOnly').addEventListener('change', (e) => {
                    if (typeof VNC !== 'undefined') VNC.setViewOnly(e.target.checked);
                });
                document.getElementById('vncScaleViewport').addEventListener('change', (e) => {
                    if (typeof VNC !== 'undefined') VNC.setScaleViewport(e.target.checked);
                });

                // Reveal 效果
                document.addEventListener('mousemove', e => {
                    document.querySelectorAll('.host-card').forEach(el => {
                        const rect = el.getBoundingClientRect();
                        el.style.setProperty('--x', `${e.clientX - rect.left}px`);
                        el.style.setProperty('--y', `${e.clientY - rect.top}px`);
                    });
                });

            },
            stopBootProgressLoop() {
                if (this.bootProgressFrame) {
                    cancelAnimationFrame(this.bootProgressFrame);
                    this.bootProgressFrame = 0;
                }
                this.bootProgressState = null;
            },
            pause(ms) {
                return new Promise((resolve) => setTimeout(resolve, ms));
            },
            nextFrame() {
                return new Promise((resolve) => requestAnimationFrame(() => resolve()));
            },
            renderBootProgress(state) {
                if (!state || state.showBootOverlay !== true) return;
                const elapsed = performance.now() - state.startedAt;
                const fakeProgress = state.minDurationMs > 0
                    ? Math.min(0.96, 0.08 + (elapsed / state.minDurationMs) * 0.88)
                    : state.actualProgress;
                const displayProgress = state.done
                    ? 1
                    : Math.min(0.97, Math.max(state.actualProgress, fakeProgress));
                Auth.updateLoadingProgress(displayProgress, state.stage);
            },
            startBootProgressLoop(state) {
                if (!state || state.showBootOverlay !== true) return;
                this.stopBootProgressLoop();
                this.bootProgressState = state;
                const tick = () => {
                    if (this.bootProgressState !== state || this.bootRunId !== state.runId) {
                        return;
                    }
                    this.renderBootProgress(state);
                    this.bootProgressFrame = requestAnimationFrame(tick);
                };
                tick();
            },
            async startDashboardBoot(runId, options = {}) {
                const showBootOverlay = options.showBootOverlay !== false;
                const bootState = showBootOverlay ? {
                    runId,
                    showBootOverlay,
                    startedAt: performance.now(),
                    minDurationMs: 0,
                    actualProgress: 0.06,
                    stage: '正在准备界面...',
                    done: false
                } : null;

                if (showBootOverlay) {
                    Auth.showLoading(
                        options.bootTitle || '正在启动工作台...',
                        options.bootSubtitle || '先载入界面，再分阶段连接服务模块。'
                    );
                    this.startBootProgressLoop(bootState);
                } else {
                    Auth.hideLogin();
                }

                const updateStage = (progress, stage) => {
                    if (this.bootRunId !== runId) {
                        return false;
                    }
                    if (bootState) {
                        bootState.actualProgress = Math.max(bootState.actualProgress, Math.max(0, Math.min(1, progress)));
                        if (stage) {
                            bootState.stage = stage;
                        }
                        this.renderBootProgress(bootState);
                    }
                    return true;
                };

                const runStage = async (progress, stage, task = null) => {
                    if (!updateStage(progress, stage)) {
                        return false;
                    }
                    await this.nextFrame();
                    if (typeof task === 'function') {
                        try {
                            await task();
                        } catch (err) {
                            console.error(`[UI Boot] ${stage} 失败:`, err);
                        }
                    }
                    await this.nextFrame();
                    return this.bootRunId === runId;
                };

                if (!await runStage(0.14, '正在渲染工作台...')) return;

                if (!this.started) {
                    if (!await runStage(0.36, '正在初始化终端模块...', async () => {
                        Terminal_.init();
                    })) return;
                    if (!await runStage(0.58, '正在初始化串口与远程桌面模块...', async () => {
                        Serial.init();
                        FlashDebug.init();
                        VNCModule.init();
                    })) return;
                    this.started = true;
                } else {
                    if (!await runStage(0.58, '正在初始化终端模块...')) return;
                }

                if (FlashDebug.initialized) {
                    FlashDebug.applyAccessState();
                }

                if (State.isAdmin) {
                    if (!await runStage(0.72, '正在同步本机终端能力...', async () => {
                        await LocalShell.init();
                    })) return;
                }

                if (!await runStage(0.86, '正在加载主机列表...', async () => {
                    await Hosts.load();
                })) return;

                if (State.isAdmin) {
                    if (!await runStage(0.94, '正在加载安全设置...', async () => {
                        await Security.load();
                    })) return;
                }

                if (!bootState) return;

                const remaining = Math.max(0, bootState.minDurationMs - (performance.now() - bootState.startedAt));
                if (remaining > 0) {
                    await this.pause(remaining);
                }
                if (this.bootRunId !== runId) {
                    return;
                }
                bootState.done = true;
                bootState.actualProgress = 1;
                bootState.stage = '启动完成';
                this.renderBootProgress(bootState);
                await this.pause(180);
                if (this.bootRunId !== runId) {
                    return;
                }
                this.stopBootProgressLoop();
                Auth.hideLogin();
            },
            showDashboard(options = {}) {
                const runId = ++this.bootRunId;
                this.stopBootProgressLoop();
                document.getElementById('dashboard').classList.add('visible');
                this.applyRole();
                About.render();
                Settings.render();
                void this.startDashboardBoot(runId, options);
            },
            hideDashboard() {
                this.bootRunId += 1;
                this.stopBootProgressLoop();
                document.getElementById('dashboard').classList.remove('visible');
            },
            resetConnections() {
                if (Terminal_.ws) {
                    Terminal_.ws.close();
                    Terminal_.ws = null;
                }
                if (LocalShell.ws) {
                    LocalShell.ws.close();
                    LocalShell.ws = null;
                    LocalShell.connected = false;
                }
                if (typeof VNC !== 'undefined') {
                    VNC.disconnect();
                }
                State.sshConnected = false;
                State.sftpConnected = false;
                State.sftpSession = null;
                State.currentPath = '/';
            },
            applyRole() {
                const shellNav = document.querySelector('.nav-item[data-view="shell"]');
                const shellView = document.getElementById('view-shell');
                const securityView = document.getElementById('view-security');
                const securityActive = securityView?.classList.contains('active');
                if (!State.isAdmin) {
                    if (shellNav) shellNav.style.display = 'none';
                    if (shellView) shellView.style.display = 'none';
                    if (securityView) securityView.style.display = 'none';
                    const activeView = document.querySelector('.nav-item.active')?.dataset.view;
                    if (activeView === 'shell') {
                        this.switchView('ssh');
                    } else if (securityActive) {
                        this.switchView('settings');
                    }
                } else {
                    if (shellNav) shellNav.style.display = '';
                    if (shellView) shellView.style.display = '';
                    if (securityView) securityView.style.display = '';
                }
            },
            switchView(name) {
                let nextView = name;
                if (nextView === 'shell' && !State.isAdmin) nextView = 'ssh';
                if (nextView === 'security' && !State.isAdmin) nextView = 'settings';
                const activeNav = nextView === 'security' ? 'settings' : nextView;
                document.querySelectorAll('.nav-item').forEach(i => i.classList.toggle('active', i.dataset.view === activeNav));
                document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === `view-${nextView}`));
                if (nextView === 'settings') Settings.render();
                if (nextView === 'ssh') setTimeout(() => Terminal_.doFit(), 100);
                if (nextView === 'shell') setTimeout(() => LocalShell.doFit(), 100);
                if (nextView === 'serial') setTimeout(() => Serial.doFit(), 100);
            }
        };

        document.addEventListener('DOMContentLoaded', () => UI.init());
    })();
