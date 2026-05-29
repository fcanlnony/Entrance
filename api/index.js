(function() {
    'use strict';

    window.EntrancePlugin = {
        mount(root, context) {
            const title = root.querySelector('[data-plugin-title]');
            const description = root.querySelector('[data-plugin-description]');
            const status = root.querySelector('[data-plugin-status]');

            if (title) {
                title.textContent = context.plugin.name;
            }
            if (description) {
                description.textContent = context.plugin.description;
            }
            if (status) {
                status.textContent = `Theme: ${context.theme}, scheme: ${context.colorScheme}`;
            }
        }
    };
})();
