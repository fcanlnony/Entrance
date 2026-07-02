(function() {
    'use strict';

    const AUTH_TYPE_KEY = 'key';
    const AUTH_TYPE_PASSWORD = 'password';
    const SAMPLE_PREFIX = `__ETOP_${Math.random().toString(36).slice(2, 10)}__`;
    const CPU_CARD = 'cpu';
    const MEM_CARD = 'mem';
    const DISK_CARD = 'disk';
    const NET_CARD = 'net';
    const TRANSLATIONS = {
        en: {
            subtitle: 'Remote host pulse monitor powered by saved Entrance SSH records.',
            savedServer: 'Saved server',
            interval: 'Interval',
            refresh: 'Refresh',
            connect: 'Connect',
            disconnect: 'Disconnect',
            idle: 'Idle',
            loadingHosts: 'Loading hosts',
            loadingHostsOption: 'Loading saved hosts...',
            loadingHostsLog: 'Loading saved server records from Entrance...',
            connected: 'Connected',
            connecting: 'Connecting',
            disconnected: 'Disconnected',
            hostLoadFailed: 'Host load failed',
            noHostSelected: 'No host selected',
            credentialNeeded: 'Credential needed',
            wsError: 'WebSocket error',
            sshError: 'SSH error',
            noSavedHosts: 'No saved hosts',
            verifyUserFailed: 'Unable to resolve current Entrance user.',
            loadHostsFailed: 'Unable to load saved hosts.',
            noSavedHostsLog: 'No saved hosts found. Add a server in the Entrance Hosts view first.',
            noSavedHostsEmpty: 'No saved hosts are available. Save a server record in Entrance first.',
            selectHostEmpty: 'Select a saved host to start sampling CPU, memory, disk, and network activity.',
            selectHostLog: 'Select a saved host before connecting.',
            loadedHosts: 'Loaded {count} saved {hostLabel}.',
            hostSingular: 'host',
            hostPlural: 'hosts',
            intervalSet: 'Sampling interval set to {interval}.',
            connectingTo: 'Connecting to {target}...',
            connectedSampling: 'Connected. Sampling every {interval}.',
            sampleTimeout: 'Sample timed out; waiting for the next interval.',
            sshCommandFailed: 'SSH command failed.',
            sshClosed: 'SSH connection closed.',
            disconnectedLog: 'Disconnected.',
            lastSample: 'Last sample {time} from {host}.',
            remoteHost: 'remote host',
            usage: 'usage',
            used: 'used',
            memory: 'Memory',
            disk: 'Disk',
            network: 'Network',
            root: 'root',
            waitingSample: 'Waiting for sample',
            collectingBaseline: 'Collecting baseline sample',
            cpuActive: '{value}% active across all cores',
            waitingMemory: 'Waiting for memory counters',
            waitingDisk: 'Waiting for root filesystem usage',
            waitingNetwork: 'Collecting network baseline sample',
            diskUsage: '{used} / {total} on {mount}',
            networkDetail: 'RX {rx} · TX {tx}',
            missingPrivateKey: 'This host has no saved private key. Edit the host record in Entrance first.',
            missingPassword: 'This host has no saved password. Edit the host record in Entrance first.',
            reloadTitle: 'Reload saved hosts',
            ready: 'Ready.'
        },
        zh: {
            subtitle: '通过 Entrance 已保存的 SSH 主机记录监控远程主机脉搏。',
            savedServer: '已保存服务器',
            interval: '间隔',
            refresh: '刷新',
            connect: '连接',
            disconnect: '断开',
            idle: '空闲',
            loadingHosts: '正在加载主机',
            loadingHostsOption: '正在加载已保存主机...',
            loadingHostsLog: '正在从 Entrance 加载已保存的服务器记录...',
            connected: '已连接',
            connecting: '正在连接',
            disconnected: '已断开',
            hostLoadFailed: '主机加载失败',
            noHostSelected: '未选择主机',
            credentialNeeded: '需要凭据',
            wsError: 'WebSocket 错误',
            sshError: 'SSH 错误',
            noSavedHosts: '暂无保存的主机',
            verifyUserFailed: '无法识别当前 Entrance 用户。',
            loadHostsFailed: '无法加载已保存主机。',
            noSavedHostsLog: '未找到已保存主机。请先在 Entrance 主机视图中添加服务器。',
            noSavedHostsEmpty: '暂无可用的已保存主机。请先在 Entrance 中保存服务器记录。',
            selectHostEmpty: '选择已保存主机后开始采样 CPU、内存、磁盘和网络活动。',
            selectHostLog: '连接前请选择一个已保存主机。',
            loadedHosts: '已加载 {count} 个已保存主机。',
            hostSingular: 'host',
            hostPlural: 'hosts',
            intervalSet: '采样间隔已设置为 {interval}。',
            connectingTo: '正在连接 {target}...',
            connectedSampling: '已连接。每 {interval} 采样一次。',
            sampleTimeout: '采样超时，等待下一次间隔。',
            sshCommandFailed: 'SSH 命令执行失败。',
            sshClosed: 'SSH 连接已关闭。',
            disconnectedLog: '已断开连接。',
            lastSample: '上次采样 {time}，来源 {host}。',
            remoteHost: '远程主机',
            usage: '占用',
            used: '已用',
            memory: '内存',
            disk: '磁盘',
            network: '网络',
            root: '根分区',
            waitingSample: '等待采样',
            collectingBaseline: '正在收集基线样本',
            cpuActive: '全部核心活跃 {value}%',
            waitingMemory: '等待内存计数器',
            waitingDisk: '等待根文件系统用量',
            waitingNetwork: '正在收集网络基线样本',
            diskUsage: '{used} / {total}，挂载点 {mount}',
            networkDetail: '接收 {rx} · 发送 {tx}',
            missingPrivateKey: '该主机没有保存私钥。请先在 Entrance 中编辑主机记录。',
            missingPassword: '该主机没有保存密码。请先在 Entrance 中编辑主机记录。',
            reloadTitle: '重新加载已保存主机',
            ready: '就绪。'
        }
    };

    window.EntrancePlugin = {
        async mount(root, context) {
            const app = createEtopApp(root, context);
            await app.init();
        }
    };

    function createEtopApp(root, context) {
        const state = {
            context,
            hosts: [],
            user: null,
            ws: null,
            connected: false,
            language: context.language === 'zh' ? 'zh' : 'en',
            selectedHost: null,
            intervalMs: 1000,
            timer: null,
            buffer: '',
            inFlight: false,
            inFlightTimer: null,
            lastCpu: null,
            lastNet: null,
            networkScale: 1024 * 1024,
            latest: {
                cpu: null,
                mem: null,
                disk: null,
                net: null
            }
        };

        const els = {
            title: root.querySelector('[data-etop-title]'),
            status: root.querySelector('[data-etop-status]'),
            hosts: root.querySelector('[data-etop-hosts]'),
            interval: root.querySelector('[data-etop-interval]'),
            refresh: root.querySelector('[data-etop-refresh]'),
            connect: root.querySelector('[data-etop-connect]'),
            empty: root.querySelector('[data-etop-empty]'),
            log: root.querySelector('[data-etop-log]'),
            rings: {
                [CPU_CARD]: root.querySelector('[data-etop-ring="cpu"]'),
                [MEM_CARD]: root.querySelector('[data-etop-ring="mem"]'),
                [DISK_CARD]: root.querySelector('[data-etop-ring="disk"]'),
                [NET_CARD]: root.querySelector('[data-etop-ring="net"]')
            },
            details: {
                [CPU_CARD]: root.querySelector('[data-etop-detail="cpu"]'),
                [MEM_CARD]: root.querySelector('[data-etop-detail="mem"]'),
                [DISK_CARD]: root.querySelector('[data-etop-detail="disk"]'),
                [NET_CARD]: root.querySelector('[data-etop-detail="net"]')
            }
        };

        function t(key, vars = {}) {
            const table = TRANSLATIONS[state.language] || TRANSLATIONS.en;
            const template = table[key] || TRANSLATIONS.en[key] || key;
            return template.replace(/\{(\w+)\}/g, (_match, name) => {
                return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : '';
            });
        }

        function applyTranslations() {
            root.querySelectorAll('[data-etop-i18n]').forEach(element => {
                element.textContent = t(element.dataset.etopI18n);
            });
            if (els.refresh) {
                els.refresh.title = t('reloadTitle');
            }
            if (els.empty) {
                const text = els.empty.querySelector('span');
                if (text) {
                    text.textContent = state.hosts.length ? t('selectHostEmpty') : t('noSavedHostsEmpty');
                }
            }
            renderHosts();
            renderMetrics();
            setConnectButton(state.connected);
            if (state.status) {
                setStatus(state.status.stateName, state.status.key, state.status.vars);
            }
            if (state.log) {
                setLog(state.log.key, state.log.vars);
            }
        }

        function handleHostMessage(event) {
            const data = event.data || {};
            if (data.type !== 'entrance-theme' || !data.language) return;
            const next = data.language === 'zh' ? 'zh' : 'en';
            if (state.language === next) return;
            state.language = next;
            context.language = next;
            applyTranslations();
        }

        return {
            async init() {
                if (els.title) els.title.textContent = context.plugin.name || 'etop';
                applyTranslations();
                buildRings();
                bindEvents();
                setStatus('idle', 'loadingHosts');
                setLog('loadingHostsLog');
                await loadHosts();
                window.addEventListener('beforeunload', cleanup);
                window.addEventListener('message', handleHostMessage);
            }
        };

        function bindEvents() {
            els.refresh?.addEventListener('click', async () => {
                await loadHosts();
            });
            els.connect?.addEventListener('click', () => {
                if (state.connected) {
                    disconnect();
                    return;
                }
                connectSelectedHost();
            });
            els.interval?.addEventListener('change', () => {
                const next = parseInt(els.interval.value, 10);
                state.intervalMs = Number.isFinite(next) && next >= 1000 ? next : 1000;
                setLog('intervalSet', { interval: formatInterval(state.intervalMs) });
                if (state.connected) {
                    startSampling();
                }
            });
        }

        async function loadHosts() {
            setControlsBusy(true);
            try {
                const verifyRes = await context.api.fetch('/api/auth/verify', { method: 'POST' });
                const verify = await verifyRes.json().catch(() => ({}));
                if (!verifyRes.ok || !verify.username) {
                    throw new Error(verify.error || t('verifyUserFailed'));
                }
                state.user = verify.username;

                const hostsRes = await context.api.fetch(`/api/userdata/${encodeURIComponent(state.user)}/hosts`);
                const hosts = await hostsRes.json().catch(() => []);
                if (!hostsRes.ok) {
                    throw new Error(hosts.error || t('loadHostsFailed'));
                }

                state.hosts = Array.isArray(hosts) ? hosts : [];
                renderHosts();
                setStatus(state.connected ? 'connected' : 'idle', state.connected ? 'connected' : 'idle');
                setLog(state.hosts.length
                    ? 'loadedHosts'
                    : 'noSavedHostsLog', {
                        count: state.hosts.length,
                        hostLabel: t(state.hosts.length === 1 ? 'hostSingular' : 'hostPlural')
                    });
            } catch (err) {
                setStatus('error', 'hostLoadFailed');
                setLogText(err.message);
                renderHosts();
            } finally {
                setControlsBusy(false);
            }
        }

        function renderHosts() {
            if (!els.hosts) return;
            if (!state.hosts.length) {
                els.hosts.innerHTML = `<option value="">${escapeHtml(t('noSavedHosts'))}</option>`;
                els.hosts.disabled = true;
                if (els.empty) {
                    els.empty.style.display = 'flex';
                    els.empty.querySelector('span').textContent = t('noSavedHostsEmpty');
                }
                return;
            }
            els.hosts.disabled = false;
            els.hosts.innerHTML = state.hosts.map((host, index) => {
                const label = `${host.user || '?'}@${host.host || '?'}:${host.port || 22}`;
                return `<option value="${index}">${escapeHtml(label)}</option>`;
            }).join('');
            if (els.empty) {
                els.empty.style.display = state.connected ? 'none' : 'flex';
                els.empty.querySelector('span').textContent = t('selectHostEmpty');
            }
        }

        function connectSelectedHost() {
            const index = parseInt(els.hosts?.value || '', 10);
            const host = state.hosts[index];
            if (!host) {
                setStatus('error', 'noHostSelected');
                setLog('selectHostLog');
                return;
            }

            let authPayload;
            try {
                authPayload = getHostCredentialPayload(host);
            } catch (err) {
                setStatus('error', 'credentialNeeded');
                setLogText(err.message);
                return;
            }

            cleanupConnection();
            resetSamples();
            state.selectedHost = host;
            setStatus('idle', 'connecting');
            setLog('connectingTo', { target: `${host.user}@${host.host}:${host.port || 22}` });
            setControlsBusy(true);

            const ws = new WebSocket(buildWsUrl('/ssh'));
            state.ws = ws;
            ws.onopen = () => {
                ws.send(JSON.stringify({
                    type: 'connect',
                    host: host.host,
                    port: Number(host.port || 22),
                    username: host.user,
                    ...authPayload
                }));
            };
            ws.onmessage = event => handleWsMessage(event);
            ws.onerror = () => {
                setStatus('error', 'wsError');
                setLog('wsError');
                setControlsBusy(false);
            };
            ws.onclose = () => {
                const wasConnected = state.connected;
                cleanupConnection();
                setControlsBusy(false);
                setConnectButton(false);
                if (wasConnected) {
                    setStatus('idle', 'disconnected');
                    setLog('sshClosed');
                }
            };
        }

        function handleWsMessage(event) {
            let message = null;
            try {
                message = JSON.parse(event.data);
            } catch {
                return;
            }

            if (message.type === 'connected') {
                state.connected = true;
                setControlsBusy(false);
                setConnectButton(true);
                setStatus('connected', 'connected');
                if (els.empty) els.empty.style.display = 'none';
                setLog('connectedSampling', { interval: formatInterval(state.intervalMs) });
                startSampling();
                return;
            }

            if (message.type === 'data') {
                collectShellOutput(String(message.data || ''));
                return;
            }

            if (message.type === 'error') {
                setStatus('error', 'sshError');
                setLogText(message.message || t('sshCommandFailed'));
                return;
            }

            if (message.type === 'disconnected') {
                disconnect();
            }
        }

        function startSampling() {
            stopSampling();
            sendSampleCommand();
            state.timer = window.setInterval(sendSampleCommand, state.intervalMs);
        }

        function stopSampling() {
            if (state.timer) {
                window.clearInterval(state.timer);
                state.timer = null;
            }
        }

        function sendSampleCommand() {
            if (!state.ws || state.ws.readyState !== WebSocket.OPEN || state.inFlight) return;
            const command = buildSampleCommand();
            state.inFlight = true;
            state.ws.send(JSON.stringify({ type: 'data', data: `${command}\n` }));
            if (state.inFlightTimer) window.clearTimeout(state.inFlightTimer);
            state.inFlightTimer = window.setTimeout(() => {
                state.inFlight = false;
                setLog('sampleTimeout');
            }, Math.max(2500, state.intervalMs * 2));
        }

        function buildSampleCommand() {
            const begin = `${SAMPLE_PREFIX}_BEGIN`;
            const end = `${SAMPLE_PREFIX}_END`;
            return [
                `printf '${begin}\\n'`,
                `awk '/^cpu /{idle=$5+$6; total=0; for(i=2;i<=NF;i++) total+=$i; printf "CPU|%s|%s\\n", total, idle}' /proc/stat`,
                `awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2} END{printf "MEM|%s|%s\\n", t, a}' /proc/meminfo`,
                `df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); printf "DISK|%s|%s|%s|%s\\n",$3,$2,$5,$6}'`,
                `awk -F'[: ]+' 'BEGIN{rx=0;tx=0} $2!="lo" && $2!="" {rx+=$3; tx+=$11} END{printf "NET|%s|%s\\n", rx, tx}' /proc/net/dev`,
                `printf '${end}\\n'`
            ].join('; ');
        }

        function collectShellOutput(chunk) {
            state.buffer += chunk.replace(/\r/g, '');
            const begin = `${SAMPLE_PREFIX}_BEGIN`;
            const end = `${SAMPLE_PREFIX}_END`;
            let beginIndex = state.buffer.indexOf(begin);
            let endIndex = state.buffer.indexOf(end, beginIndex + begin.length);
            while (beginIndex >= 0 && endIndex >= 0) {
                const segment = state.buffer.slice(beginIndex + begin.length, endIndex);
                state.buffer = state.buffer.slice(endIndex + end.length);
                parseSample(segment);
                beginIndex = state.buffer.indexOf(begin);
                endIndex = state.buffer.indexOf(end, beginIndex + begin.length);
            }
            if (state.buffer.length > 20000) {
                state.buffer = state.buffer.slice(-8000);
            }
        }

        function parseSample(segment) {
            state.inFlight = false;
            if (state.inFlightTimer) {
                window.clearTimeout(state.inFlightTimer);
                state.inFlightTimer = null;
            }

            const sample = {};
            segment.split('\n').forEach(line => {
                const trimmed = line.trim();
                if (!trimmed || !trimmed.includes('|')) return;
                const parts = trimmed.split('|');
                sample[parts[0]] = parts.slice(1);
            });

            const now = Date.now();
            updateCpu(sample.CPU);
            updateMemory(sample.MEM);
            updateDisk(sample.DISK);
            updateNetwork(sample.NET, now);
            renderMetrics();
            setLog('lastSample', {
                time: new Date(now).toLocaleTimeString(),
                host: state.selectedHost?.host || t('remoteHost')
            });
        }

        function updateCpu(parts) {
            if (!parts || parts.length < 2) return;
            const total = Number(parts[0]);
            const idle = Number(parts[1]);
            if (!Number.isFinite(total) || !Number.isFinite(idle)) return;
            if (state.lastCpu) {
                const totalDelta = total - state.lastCpu.total;
                const idleDelta = idle - state.lastCpu.idle;
                const usage = totalDelta > 0 ? clamp(((totalDelta - idleDelta) / totalDelta) * 100, 0, 100) : 0;
                state.latest.cpu = { percent: usage };
            }
            state.lastCpu = { total, idle };
        }

        function updateMemory(parts) {
            if (!parts || parts.length < 2) return;
            const totalKb = Number(parts[0]);
            const availableKb = Number(parts[1]);
            if (!Number.isFinite(totalKb) || !Number.isFinite(availableKb) || totalKb <= 0) return;
            const usedKb = Math.max(0, totalKb - availableKb);
            state.latest.mem = {
                percent: clamp((usedKb / totalKb) * 100, 0, 100),
                usedBytes: usedKb * 1024,
                totalBytes: totalKb * 1024
            };
        }

        function updateDisk(parts) {
            if (!parts || parts.length < 4) return;
            const usedKb = Number(parts[0]);
            const totalKb = Number(parts[1]);
            const percent = Number(parts[2]);
            state.latest.disk = {
                percent: Number.isFinite(percent) ? clamp(percent, 0, 100) : 0,
                usedBytes: Number.isFinite(usedKb) ? usedKb * 1024 : 0,
                totalBytes: Number.isFinite(totalKb) ? totalKb * 1024 : 0,
                mount: parts[3] || '/'
            };
        }

        function updateNetwork(parts, now) {
            if (!parts || parts.length < 2) return;
            const rx = Number(parts[0]);
            const tx = Number(parts[1]);
            if (!Number.isFinite(rx) || !Number.isFinite(tx)) return;
            if (state.lastNet) {
                const seconds = Math.max(0.001, (now - state.lastNet.time) / 1000);
                const rxRate = Math.max(0, (rx - state.lastNet.rx) / seconds);
                const txRate = Math.max(0, (tx - state.lastNet.tx) / seconds);
                const totalRate = rxRate + txRate;
                state.networkScale = Math.max(state.networkScale * 0.92, totalRate * 1.25, 1024 * 1024);
                state.latest.net = {
                    percent: clamp((totalRate / state.networkScale) * 100, 0, 100),
                    rxRate,
                    txRate,
                    totalRate
                };
            }
            state.lastNet = { rx, tx, time: now };
        }

        function renderMetrics() {
            const cpu = state.latest.cpu;
            updateRing(CPU_CARD, cpu ? cpu.percent : 0, cpu ? `${cpu.percent.toFixed(0)}%` : '--', t('usage'));
            setDetail(CPU_CARD, cpu ? t('cpuActive', { value: cpu.percent.toFixed(1) }) : t('collectingBaseline'));

            const mem = state.latest.mem;
            updateRing(MEM_CARD, mem ? mem.percent : 0, mem ? `${mem.percent.toFixed(0)}%` : '--', t('used'));
            setDetail(MEM_CARD, mem ? `${formatBytes(mem.usedBytes)} / ${formatBytes(mem.totalBytes)}` : t('waitingMemory'));

            const disk = state.latest.disk;
            updateRing(DISK_CARD, disk ? disk.percent : 0, disk ? `${disk.percent.toFixed(0)}%` : '--', disk ? disk.mount : t('root'));
            setDetail(DISK_CARD, disk
                ? t('diskUsage', { used: formatBytes(disk.usedBytes), total: formatBytes(disk.totalBytes), mount: disk.mount })
                : t('waitingDisk'));

            const net = state.latest.net;
            updateRing(NET_CARD, net ? net.percent : 0, net ? formatRateShort(net.totalRate) : '--', 'RX + TX');
            setDetail(NET_CARD, net ? t('networkDetail', { rx: formatRate(net.rxRate), tx: formatRate(net.txRate) }) : t('waitingNetwork'));
        }

        function buildRings() {
            Object.keys(els.rings).forEach(key => {
                if (!els.rings[key]) return;
                els.rings[key].innerHTML = ringHtml('--', 0, key === NET_CARD ? 'B/s' : '%');
            });
        }

        function ringHtml(text, percent, unit) {
            const radius = 50;
            const circumference = 2 * Math.PI * radius;
            const offset = circumference * (1 - clamp(percent, 0, 100) / 100);
            return `
                <svg viewBox="0 0 120 120" aria-hidden="true">
                    <circle class="etop-track" cx="60" cy="60" r="${radius}"></circle>
                    <circle class="etop-progress" cx="60" cy="60" r="${radius}" style="stroke-dasharray:${circumference.toFixed(2)};stroke-dashoffset:${offset.toFixed(2)}"></circle>
                </svg>
                <div class="etop-ring-center">
                    <div class="etop-value">${escapeHtml(text)}</div>
                    <div class="etop-unit">${escapeHtml(unit)}</div>
                </div>
            `;
        }

        function updateRing(key, percent, text, unit) {
            if (!els.rings[key]) return;
            els.rings[key].innerHTML = ringHtml(text, percent, unit);
        }

        function setDetail(key, text) {
            if (els.details[key]) els.details[key].textContent = text;
        }

        function resetSamples() {
            state.buffer = '';
            state.inFlight = false;
            state.lastCpu = null;
            state.lastNet = null;
            state.networkScale = 1024 * 1024;
            state.latest = { cpu: null, mem: null, disk: null, net: null };
            renderMetrics();
        }

        function disconnect() {
            if (state.ws && state.ws.readyState === WebSocket.OPEN) {
                state.ws.send(JSON.stringify({ type: 'disconnect' }));
            }
            cleanupConnection();
            setControlsBusy(false);
            setConnectButton(false);
            setStatus('idle', 'disconnected');
            setLog('disconnectedLog');
            if (els.empty) els.empty.style.display = state.hosts.length ? 'flex' : 'none';
        }

        function cleanupConnection() {
            stopSampling();
            if (state.inFlightTimer) {
                window.clearTimeout(state.inFlightTimer);
                state.inFlightTimer = null;
            }
            state.inFlight = false;
            state.connected = false;
            if (state.ws) {
                const ws = state.ws;
                state.ws = null;
                ws.onopen = null;
                ws.onmessage = null;
                ws.onerror = null;
                ws.onclose = null;
                if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
                    ws.close();
                }
            }
        }

        function cleanup() {
            disconnect();
            window.removeEventListener('beforeunload', cleanup);
            window.removeEventListener('message', handleHostMessage);
        }

        function setStatus(stateName, key, vars = {}) {
            if (!els.status) return;
            state.status = { stateName, key, vars };
            els.status.dataset.state = stateName;
            const icon = stateName === 'connected' ? 'fa-circle-check' : stateName === 'error' ? 'fa-triangle-exclamation' : 'fa-circle';
            els.status.innerHTML = `<i class="fas ${icon}"></i><span>${escapeHtml(t(key, vars))}</span>`;
        }

        function setLog(key, vars = {}) {
            state.log = { key, vars };
            if (els.log) els.log.textContent = t(key, vars);
        }

        function setLogText(text) {
            state.log = null;
            if (els.log) els.log.textContent = text;
        }

        function setControlsBusy(busy) {
            if (els.refresh) els.refresh.disabled = busy;
            if (els.hosts) els.hosts.disabled = busy || !state.hosts.length || state.connected;
            if (els.interval) els.interval.disabled = busy;
            if (els.connect) els.connect.disabled = busy || (!state.connected && !state.hosts.length);
        }

        function setConnectButton(connected) {
            if (!els.connect) return;
            els.connect.classList.toggle('primary', !connected);
            els.connect.innerHTML = connected
                ? `<i class="fas fa-xmark"></i><span>${escapeHtml(t('disconnect'))}</span>`
                : `<i class="fas fa-plug"></i><span>${escapeHtml(t('connect'))}</span>`;
            if (els.hosts) els.hosts.disabled = connected || !state.hosts.length;
        }

        function buildWsUrl(path) {
            const url = new URL(path, context.apiBase || window.location.origin);
            url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
            if (context.token) {
                url.searchParams.set('token', context.token);
            }
            return url.toString();
        }

        function getHostCredentialPayload(host) {
            const privateKey = String(host.privateKey || '').replace(/\r\n/g, '\n').trim();
            const password = host.pass || host.password || '';
            const passphrase = host.passphrase || '';
            const authType = normalizeAuthType(host.authType, privateKey);

            if (authType === AUTH_TYPE_KEY) {
                if (!privateKey) {
                    throw new Error(t('missingPrivateKey'));
                }
                return passphrase
                    ? { authType: AUTH_TYPE_KEY, privateKey, passphrase }
                    : { authType: AUTH_TYPE_KEY, privateKey };
            }

            if (!password) {
                throw new Error(t('missingPassword'));
            }
            return { authType: AUTH_TYPE_PASSWORD, password };
        }
    }

    function normalizeAuthType(authType, privateKey) {
        const lowered = String(authType || '').trim().toLowerCase();
        if (lowered === AUTH_TYPE_KEY || lowered === 'privatekey' || lowered === 'private_key') return AUTH_TYPE_KEY;
        if (lowered === AUTH_TYPE_PASSWORD || lowered === 'pass') return AUTH_TYPE_PASSWORD;
        return privateKey ? AUTH_TYPE_KEY : AUTH_TYPE_PASSWORD;
    }

    function clamp(value, min, max) {
        return Math.max(min, Math.min(max, Number(value) || 0));
    }

    function formatInterval(ms) {
        return `${(ms / 1000).toFixed(ms % 1000 ? 1 : 0)}s`;
    }

    function formatBytes(bytes) {
        const value = Number(bytes) || 0;
        const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
        let size = value;
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex += 1;
        }
        return `${size >= 10 || unitIndex === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unitIndex]}`;
    }

    function formatRate(bytesPerSecond) {
        return `${formatBytes(bytesPerSecond)}/s`;
    }

    function formatRateShort(bytesPerSecond) {
        const value = Number(bytesPerSecond) || 0;
        if (value < 1024) return `${value.toFixed(0)}`;
        if (value < 1024 * 1024) return `${(value / 1024).toFixed(0)}K`;
        if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)}M`;
        return `${(value / 1024 / 1024 / 1024).toFixed(1)}G`;
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
})();
