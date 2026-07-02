(function() {
    'use strict';

    let exampleChart = null;

    window.EntrancePlugin = {
        async mount(root, context) {
            const title = root.querySelector('[data-plugin-title]');
            const description = root.querySelector('[data-plugin-description]');
            const status = root.querySelector('[data-plugin-status]');
            const vendors = root.querySelector('[data-plugin-vendors]');
            const chartCanvas = root.querySelector('[data-plugin-chart]');

            if (title) {
                title.textContent = context.plugin.name;
            }
            if (description) {
                description.textContent = context.plugin.description;
            }
            if (vendors) {
                vendors.textContent = Object.keys(context.api.listVendors()).join(', ');
            }
            if (status) {
                status.textContent = `Theme: ${context.theme}, scheme: ${context.colorScheme}`;
            }
            if (!chartCanvas) {
                return;
            }

            try {
                const Chart = await context.api.loadVendor('chart.js');
                const accent = getComputedStyle(document.documentElement)
                    .getPropertyValue('--color-accent')
                    .trim() || '#3b82f6';
                if (exampleChart) {
                    exampleChart.destroy();
                }
                exampleChart = new Chart(chartCanvas, {
                    type: 'line',
                    data: {
                        labels: ['Manifest', 'Runtime API', 'Vendor Loader', 'Iframe'],
                        datasets: [{
                            label: 'Example',
                            data: [1, 3, 4, 5],
                            borderColor: accent,
                            backgroundColor: `${accent}22`,
                            fill: true,
                            tension: 0.35
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: { precision: 0 }
                            }
                        }
                    }
                });
                if (status) {
                    status.textContent = `Theme: ${context.theme}, scheme: ${context.colorScheme}, Chart.js loaded from bundled vendor assets.`;
                }
            } catch (err) {
                if (status) {
                    status.textContent = `Failed to load bundled vendor API: ${err.message}`;
                }
            }
        }
    };
})();
