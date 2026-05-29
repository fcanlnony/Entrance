(function() {
    'use strict';

    window.EntrancePlugin = {
        mount(root) {
            const title = root.querySelector('[data-hello-plugin-title]');
            if (title) {
                title.textContent = 'hello plugins';
                return;
            }
            root.textContent = 'hello plugins';
        }
    };
})();
