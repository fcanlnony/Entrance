# Plugin API

The `api/` directory in this repository is the canonical plugin package reference. It contains:

- `version.json` - manifest example and field contract
- `index.js` - JavaScript entry example
- `index.html` - optional HTML template example
- `hello-plugins/` - minimal smoke-test plugin that renders `hello plugins`

Installed plugins are stored under `.plugins/` in `ENTRANCE_DATA_DIR`. Do not commit installed runtime plugins.

## Package Layout

A plugin ZIP may contain files at the ZIP root or in one top-level directory. After resolving that plugin root, the expected layout is:

```text
example/
  version.json
  index.js
  index.html
```

`version.json` and the JavaScript entry are required. `index.html` is optional.

## `version.json`

```json
{
  "id": "hello-plugin",
  "name": "Hello Plugin",
  "version": "1.0.0",
  "description": "A small Entrance plugin.",
  "author": "Your Name",
  "homepage": "https://example.com/hello-plugin",
  "entry": "index.js",
  "html": "index.html"
}
```

Field rules:

- `name` - required, plugin display name, max 120 characters
- `version` - required, plugin version, max 64 characters
- `description` - required, card description, max 500 characters
- `author` - required, displayed in plugin cards, max 120 characters
- `id` - optional; if set, use lowercase letters, numbers, dots, underscores, or hyphens, length 2-64; if omitted, Entrance derives one from `name`
- `homepage` - optional; must be `http` or `https` when provided
- `entry` - optional; defaults to `index.js`; path is relative to the plugin root and must point to a bundled `.js` file
- `html` - optional; defaults to `index.html`; path is relative to the plugin root and must point to an `.html` file when provided

## `index.js`

The JavaScript entry should expose `window.EntrancePlugin.mount(root, context)`. `mount()` may be synchronous or return a promise.

```javascript
window.EntrancePlugin = {
  async mount(root, context) {
    root.textContent = context.plugin.name;
  }
};
```

## Runtime Context

`context` contains:

- `context.plugin` - the normalized manifest plus install metadata
- `context.theme` - current `light` or `dark` theme
- `context.colorScheme` - current color scheme key
- `context.language` - current UI language key, `en` or `zh`
- `context.apiBase` - current Entrance origin, useful when constructing absolute URLs
- `context.vendors` - metadata for the bundled browser-side vendor registry copied from existing `node_modules`

`context.vendors` is an object keyed by vendor name. Each record contains:

- `name` - stable vendor key
- `type` - `script`, `module`, or `style`
- `url` - browser asset URL served by Entrance
- `styles` - optional stylesheet URLs auto-loaded before the vendor API is returned
- `global` - browser global exposed by classic script vendors
- `export` - named export or `default` for module/script adapters
- `preloaded` - whether the stylesheet is already loaded by the plugin page

## Runtime API

`context.api` contains:

- `context.api.fetch(path, options)` - wrapper around `fetch()` that resolves against `context.apiBase` and automatically adds the current Entrance bearer token
- `context.api.getVendor(name)` - returns one vendor metadata record or `null`
- `context.api.listVendors()` - returns the full vendor metadata map
- `context.api.loadVendor(name)` - loads a supported vendor from the host asset registry and returns its browser API

Plugins run inside a browser iframe, so they cannot `require()` arbitrary host-side Node modules directly. The supported path is to load the browser-compatible dependencies that Entrance already copies from `node_modules` into `public/assets/vendor/`.

## Bundled Vendor Modules

Current built-in vendor names are:

- `chart.js` - loads `/assets/vendor/chart.js/chart.umd.js` and returns `Chart`
- `xterm` - loads `/assets/vendor/xterm/xterm.js`, auto-loads `xterm.css`, and returns `Terminal`
- `xterm-addon-fit` - loads `/assets/vendor/xterm-addon-fit/xterm-addon-fit.js` and returns `FitAddon`
- `novnc` - dynamically imports `/assets/vendor/novnc/core/rfb.js` and returns the default `RFB` export
- `fontawesome` - ensures `/assets/vendor/fontawesome/css/all.min.css` is available; plugin pages already preload this stylesheet

## Vendor Loader Example

The example plugin in this directory uses `Chart.js` through the runtime API:

```javascript
window.EntrancePlugin = {
  async mount(root, context) {
    const Chart = await context.api.loadVendor('chart.js');
    const canvas = root.querySelector('[data-plugin-chart]');
    new Chart(canvas, {
      type: 'line',
      data: {
        labels: ['Manifest', 'Runtime API', 'Vendor Loader'],
        datasets: [{ data: [1, 3, 5] }]
      }
    });
  }
};
```

Typical usage for the other bundled vendors:

```javascript
const Terminal = await context.api.loadVendor('xterm');
const FitAddon = await context.api.loadVendor('xterm-addon-fit');
const RFB = await context.api.loadVendor('novnc');
```

## `index.html`

When `html` is present, Entrance injects the file body into the plugin root before calling `mount()`. This lets the plugin keep static markup in HTML and behavior in JavaScript.

```html
<main>
  <h1 data-title>hello plugins</h1>
</main>
```

## Example Plugins

- `api/index.js` + `api/index.html` show a plugin that lists bundled vendor modules and loads `Chart.js` through `context.api.loadVendor('chart.js')`
- `api/hello-plugins/` is the minimal smoke-test plugin used by `npm run test:plugins`
