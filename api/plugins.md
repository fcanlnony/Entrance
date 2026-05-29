# Plugin API / 插件 API

## English

The `api/` directory in this repository is the canonical plugin package reference. It contains:

- `version.json` - manifest example and field contract
- `index.js` - JavaScript entry example
- `index.html` - optional HTML template example
- `hello-plugins/` - minimal test plugin that renders `hello plugins`

Installed plugins are stored under `.plugins/` in `ENTRANCE_DATA_DIR`. Do not commit installed runtime plugins.

### Package Layout

A plugin ZIP may contain files at the ZIP root or in one top-level directory. After resolving that plugin root, the expected layout is:

```text
example/
  version.json
  index.js
  index.html
```

`version.json` and the JavaScript entry are required. `index.html` is optional.

### `version.json`

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

### `index.js`

The JavaScript entry should expose `window.EntrancePlugin.mount(root, context)`.

```javascript
window.EntrancePlugin = {
  mount(root, context) {
    root.textContent = 'hello plugins';
  }
};
```

`context` contains:

- `context.plugin` - the normalized manifest and install metadata
- `context.theme` - current `light` or `dark` theme
- `context.colorScheme` - current color scheme key
- `context.api.fetch(path, options)` - wrapper around `fetch()` that adds the current Entrance bearer token

### `index.html`

When `html` is present, Entrance injects the file body into the plugin root before calling `mount()`. This lets the plugin keep static markup in HTML and behavior in JavaScript.

```html
<main>
  <h1 data-title>hello plugins</h1>
</main>
```

### Test Plugin

The repository includes `api/hello-plugins/`, a minimal plugin that displays `hello plugins` when opened through Plugin Navigator. You can ZIP that directory and install it from Plugin Install.

## 中文

本仓库根目录的 `api/` 目录是插件包规范参考，包含：

- `version.json` - manifest 示例和字段约束
- `index.js` - JavaScript 入口示例
- `index.html` - 可选 HTML 模板示例
- `hello-plugins/` - 最小测试插件，打开后显示 `hello plugins`

已安装插件会保存到 `ENTRANCE_DATA_DIR` 下的 `.plugins/`。不要提交运行时安装的插件目录。

### 插件包结构

插件 ZIP 可以直接把文件放在 ZIP 根目录，也可以包含一个顶层插件目录。解析出插件根目录后，推荐结构为：

```text
example/
  version.json
  index.js
  index.html
```

`version.json` 和 JavaScript 入口必需。`index.html` 可选。

### `version.json`

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

字段规则：

- `name` - 必填，插件显示名称，最多 120 个字符
- `version` - 必填，插件版本，最多 64 个字符
- `description` - 必填，卡片描述，最多 500 个字符
- `author` - 必填，显示在插件卡片中，最多 120 个字符
- `id` - 可选；如果设置，只能使用小写字母、数字、点、下划线或短横线，长度 2-64；如果省略，Entrance 会根据 `name` 生成
- `homepage` - 可选；填写时必须使用 `http` 或 `https`
- `entry` - 可选；默认 `index.js`；路径相对于插件根目录，必须指向已打包的 `.js` 文件
- `html` - 可选；默认 `index.html`；路径相对于插件根目录，填写时必须指向 `.html` 文件

### `index.js`

JavaScript 入口应暴露 `window.EntrancePlugin.mount(root, context)`。

```javascript
window.EntrancePlugin = {
  mount(root, context) {
    root.textContent = 'hello plugins';
  }
};
```

`context` 包含：

- `context.plugin` - 规范化后的 manifest 和安装元数据
- `context.theme` - 当前 `light` 或 `dark` 主题
- `context.colorScheme` - 当前配色方案 key
- `context.api.fetch(path, options)` - `fetch()` 包装器，会自动带上当前 Entrance bearer token

### `index.html`

当配置了 `html` 时，Entrance 会先把该文件的 body 内容注入插件根节点，然后再调用 `mount()`。这样插件可以把静态结构放在 HTML，把行为放在 JavaScript。

```html
<main>
  <h1 data-title>hello plugins</h1>
</main>
```

### 测试插件

仓库内置 `api/hello-plugins/` 最小插件，通过插件导航打开后会显示 `hello plugins`。可以把该目录打包成 ZIP，然后在插件安装页上传测试。
