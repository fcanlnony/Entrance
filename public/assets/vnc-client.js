/**
 * VNC Client Module
 * Frontend VNC client wrapper for the backend WebSocket proxy.
 * Uses the noVNC RFB protocol implementation.
 */

(function(global) {
    'use strict';

    function getWsBase() {
        const fallback = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}`;
        const raw = String(new URLSearchParams(location.search).get('wsBase') || '').trim();
        if (!raw) {
            return fallback;
        }
        try {
            const parsed = new URL(raw);
            if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
                return fallback;
            }
            return parsed.toString().replace(/\/$/, '');
        } catch {
            return fallback;
        }
    }

    function t(message) {
        if (global.I18n && typeof global.I18n.auto === 'function') {
            return global.I18n.auto(message);
        }
        return message;
    }

    const VNC = {
        rfb: null,
        connected: false,
        host: null,
        container: null,

        callbacks: {
            onConnect: null,
            onDisconnect: null,
            onError: null,
            onCredentialsRequired: null,
            onDesktopName: null
        },

        init(container, callbacks = {}) {
            this.container = container;
            this.callbacks = { ...this.callbacks, ...callbacks };
            console.log('[VNC Client] Initialized');
        },

        async connect(options) {
            const {
                host,
                port = 5900,
                password = '',
                viewOnly = false,
                scaleViewport = true,
                resizeSession = false,
                qualityLevel = 6,
                compressionLevel = 2
            } = options;

            if (this.rfb) {
                this.disconnect();
            }

            this.host = host;

            if (typeof RFB === 'undefined') {
                console.error('[VNC Client] noVNC (RFB) not loaded');
                if (this.callbacks.onError) {
                    this.callbacks.onError(t('VNC 库加载失败，请刷新页面重试'));
                }
                return;
            }

            const token = global.Auth && typeof global.Auth.getToken === 'function'
                ? global.Auth.getToken()
                : (global.localStorage ? (localStorage.getItem('authToken') || '') : '');
            const wsUrl = new URL('/vnc', `${getWsBase()}/`);
            wsUrl.searchParams.set('host', host);
            wsUrl.searchParams.set('port', String(port));
            if (token) {
                wsUrl.searchParams.set('token', token);
            }

            console.log(`[VNC Client] Connecting: ${host}:${port}`);
            console.log(`[VNC Client] WebSocket URL: ${wsUrl.toString()}`);

            try {
                this.rfb = new RFB(this.container, wsUrl.toString(), {
                    credentials: password ? { password } : undefined,
                    wsProtocols: ['binary']
                });

                this.rfb.viewOnly = viewOnly;
                this.rfb.scaleViewport = scaleViewport;
                this.rfb.resizeSession = resizeSession;
                this.rfb.qualityLevel = qualityLevel;
                this.rfb.compressionLevel = compressionLevel;

                this.rfb.addEventListener('connect', () => {
                    console.log('[VNC Client] Connected');
                    this.connected = true;
                    if (this.callbacks.onConnect) {
                        this.callbacks.onConnect(host);
                    }
                });

                this.rfb.addEventListener('disconnect', (event) => {
                    console.log('[VNC Client] Disconnected', event.detail);
                    this.connected = false;
                    this.rfb = null;
                    if (this.callbacks.onDisconnect) {
                        this.callbacks.onDisconnect(event.detail.clean);
                    }
                });

                this.rfb.addEventListener('credentialsrequired', () => {
                    console.log('[VNC Client] Credentials required');
                    if (password) {
                        this.rfb.sendCredentials({ password });
                    } else if (this.callbacks.onCredentialsRequired) {
                        this.callbacks.onCredentialsRequired();
                    } else if (this.callbacks.onError) {
                        this.callbacks.onError(t('VNC 服务器需要密码'));
                    }
                });

                this.rfb.addEventListener('securityfailure', (event) => {
                    console.error('[VNC Client] Security failure:', event.detail);
                    if (this.callbacks.onError) {
                        this.callbacks.onError(t(`认证失败: ${event.detail.reason || '密码错误'}`));
                    }
                });

                this.rfb.addEventListener('desktopname', (event) => {
                    console.log('[VNC Client] Desktop name:', event.detail.name);
                    if (this.callbacks.onDesktopName) {
                        this.callbacks.onDesktopName(event.detail.name);
                    }
                });

                this.rfb.addEventListener('clipboard', (event) => {
                    console.log('[VNC Client] Clipboard:', event.detail.text);
                });
            } catch (err) {
                console.error('[VNC Client] Connection error:', err);
                if (this.callbacks.onError) {
                    this.callbacks.onError(err.message);
                }
            }
        },

        disconnect() {
            if (this.rfb) {
                this.rfb.disconnect();
                this.rfb = null;
            }
            this.connected = false;
            this.host = null;
            console.log('[VNC Client] Connection closed');
        },

        sendCtrlAltDel() {
            if (this.rfb) {
                this.rfb.sendCtrlAltDel();
            }
        },

        sendKey(keysym, code, down) {
            if (this.rfb) {
                this.rfb.sendKey(keysym, code, down);
            }
        },

        clipboardPaste(text) {
            if (this.rfb) {
                this.rfb.clipboardPasteFrom(text);
            }
        },

        setScaleViewport(scale) {
            if (this.rfb) {
                this.rfb.scaleViewport = scale;
            }
        },

        setViewOnly(viewOnly) {
            if (this.rfb) {
                this.rfb.viewOnly = viewOnly;
            }
        },

        requestFullscreen() {
            if (this.container) {
                if (this.container.requestFullscreen) {
                    this.container.requestFullscreen();
                } else if (this.container.webkitRequestFullscreen) {
                    this.container.webkitRequestFullscreen();
                } else if (this.container.mozRequestFullScreen) {
                    this.container.mozRequestFullScreen();
                }
            }
        },

        exitFullscreen() {
            if (document.exitFullscreen) {
                document.exitFullscreen();
            } else if (document.webkitExitFullscreen) {
                document.webkitExitFullscreen();
            } else if (document.mozCancelFullScreen) {
                document.mozCancelFullScreen();
            }
        },

        isConnected() {
            return this.connected;
        },

        getHost() {
            return this.host;
        },

        focus() {
            if (this.rfb) {
                this.rfb.focus();
            }
        },

        blur() {
            if (this.rfb) {
                this.rfb.blur();
            }
        }
    };

    global.VNC = VNC;
})(typeof window !== 'undefined' ? window : this);
