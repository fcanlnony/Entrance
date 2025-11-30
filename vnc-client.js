/**
 * VNC Client Module
 * 前端 VNC 客户端封装，用于与后端 WebSocket 代理通信
 * 支持 noVNC (RFB) 协议
 */

(function(global) {
    'use strict';

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

        /**
         * 初始化 VNC 客户端
         * @param {HTMLElement} container - VNC 画布容器
         * @param {Object} callbacks - 回调函数
         */
        init(container, callbacks = {}) {
            this.container = container;
            this.callbacks = { ...this.callbacks, ...callbacks };
            console.log('[VNC Client] 初始化完成');
        },

        /**
         * 连接到 VNC 服务器（通过 WebSocket 代理）
         * @param {Object} options - 连接选项
         */
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

            // 检查 RFB 是否可用 (noVNC)
            if (typeof RFB === 'undefined') {
                console.error('[VNC Client] noVNC (RFB) 未加载');
                if (this.callbacks.onError) {
                    this.callbacks.onError('VNC 库加载失败，请刷新页面重试');
                }
                return;
            }

            // 构建 WebSocket URL（通过后端代理）
            const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${wsProtocol}//${location.host}/vnc?host=${encodeURIComponent(host)}&port=${port}`;

            console.log(`[VNC Client] 正在连接: ${host}:${port}`);
            console.log(`[VNC Client] WebSocket URL: ${wsUrl}`);

            try {
                // 创建 RFB 连接
                this.rfb = new RFB(this.container, wsUrl, {
                    credentials: password ? { password } : undefined,
                    wsProtocols: ['binary']
                });

                // 配置选项
                this.rfb.viewOnly = viewOnly;
                this.rfb.scaleViewport = scaleViewport;
                this.rfb.resizeSession = resizeSession;
                this.rfb.qualityLevel = qualityLevel;
                this.rfb.compressionLevel = compressionLevel;

                // 绑定事件
                this.rfb.addEventListener('connect', () => {
                    console.log('[VNC Client] 已连接');
                    this.connected = true;
                    if (this.callbacks.onConnect) {
                        this.callbacks.onConnect(host);
                    }
                });

                this.rfb.addEventListener('disconnect', (e) => {
                    console.log('[VNC Client] 已断开', e.detail);
                    this.connected = false;
                    this.rfb = null;
                    if (this.callbacks.onDisconnect) {
                        this.callbacks.onDisconnect(e.detail.clean);
                    }
                });

                this.rfb.addEventListener('credentialsrequired', () => {
                    console.log('[VNC Client] 需要认证');
                    if (password) {
                        this.rfb.sendCredentials({ password });
                    } else if (this.callbacks.onCredentialsRequired) {
                        this.callbacks.onCredentialsRequired();
                    } else if (this.callbacks.onError) {
                        this.callbacks.onError('VNC 服务器需要密码');
                    }
                });

                this.rfb.addEventListener('securityfailure', (e) => {
                    console.error('[VNC Client] 安全认证失败:', e.detail);
                    if (this.callbacks.onError) {
                        this.callbacks.onError(`认证失败: ${e.detail.reason || '密码错误'}`);
                    }
                });

                this.rfb.addEventListener('desktopname', (e) => {
                    console.log('[VNC Client] 桌面名称:', e.detail.name);
                    if (this.callbacks.onDesktopName) {
                        this.callbacks.onDesktopName(e.detail.name);
                    }
                });

                this.rfb.addEventListener('clipboard', (e) => {
                    console.log('[VNC Client] 剪贴板:', e.detail.text);
                });

            } catch (err) {
                console.error('[VNC Client] 连接错误:', err);
                if (this.callbacks.onError) {
                    this.callbacks.onError(err.message);
                }
            }
        },

        /**
         * 断开连接
         */
        disconnect() {
            if (this.rfb) {
                this.rfb.disconnect();
                this.rfb = null;
            }
            this.connected = false;
            this.host = null;
            console.log('[VNC Client] 已断开连接');
        },

        /**
         * 发送 Ctrl+Alt+Del
         */
        sendCtrlAltDel() {
            if (this.rfb) {
                this.rfb.sendCtrlAltDel();
            }
        },

        /**
         * 发送按键
         */
        sendKey(keysym, code, down) {
            if (this.rfb) {
                this.rfb.sendKey(keysym, code, down);
            }
        },

        /**
         * 发送剪贴板内容
         */
        clipboardPaste(text) {
            if (this.rfb) {
                this.rfb.clipboardPasteFrom(text);
            }
        },

        /**
         * 设置缩放视图
         */
        setScaleViewport(scale) {
            if (this.rfb) {
                this.rfb.scaleViewport = scale;
            }
        },

        /**
         * 设置只读模式
         */
        setViewOnly(viewOnly) {
            if (this.rfb) {
                this.rfb.viewOnly = viewOnly;
            }
        },

        /**
         * 请求全屏
         */
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

        /**
         * 退出全屏
         */
        exitFullscreen() {
            if (document.exitFullscreen) {
                document.exitFullscreen();
            } else if (document.webkitExitFullscreen) {
                document.webkitExitFullscreen();
            } else if (document.mozCancelFullScreen) {
                document.mozCancelFullScreen();
            }
        },

        /**
         * 获取连接状态
         */
        isConnected() {
            return this.connected;
        },

        /**
         * 获取当前主机
         */
        getHost() {
            return this.host;
        },

        /**
         * 聚焦到 VNC 画布
         */
        focus() {
            if (this.rfb) {
                this.rfb.focus();
            }
        },

        /**
         * 模糊（失去焦点）
         */
        blur() {
            if (this.rfb) {
                this.rfb.blur();
            }
        }
    };

    // 暴露到全局
    global.VNC = VNC;

})(typeof window !== 'undefined' ? window : this);
