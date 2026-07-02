(function() {
    'use strict';

    window.EntrancePlugin = {
        mount(root, context = {}) {
            const render = () => {
                const language = context.language === 'zh' ? 'zh' : 'en';
                const text = language === 'zh' ? '你好，插件' : 'hello plugins';
                const title = root.querySelector('[data-hello-plugin-title]');
                if (title) {
                    title.textContent = text;
                    return;
                }
                root.textContent = text;
            };

            window.addEventListener('message', (event) => {
                const data = event.data || {};
                if (data.type !== 'entrance-theme' || !data.language) return;
                context.language = data.language === 'zh' ? 'zh' : 'en';
                render();
            });

            render();
        }
    };
})();
