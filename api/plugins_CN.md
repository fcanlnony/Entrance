# 插件 API

本仓库根目录的 `api/` 目录是插件包规范参考，包含：

- `version.json` - manifest 示例和字段约束
- `index.js` - JavaScript 入口示例
- `index.html` - 可选 HTML 模板示例
- `hello-plugins/` - 最小冒烟测试插件，打开后显示 `hello plugins`

已安装插件会保存到 `ENTRANCE_DATA_DIR` 下的 `.plugins/`。不要提交运行时安装的插件目录。

## 插件包结构

插件 ZIP 可以直接把文件放在 ZIP 根目录，也可以包含一个顶层插件目录。解析出插件根目录后，推荐结构为：

```text
example/
  version.json
  index.js
  index.html
```

`version.json` 和 JavaScript 入口必需。`index.html` 可选。

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

字段规则：

- `name` - 必填，插件显示名称，最多 120 个字符
- `version` - 必填，插件版本，最多 64 个字符
- `description` - 必填，卡片描述，最多 500 个字符
- `author` - 必填，显示在插件卡片中，最多 120 个字符
- `id` - 可选；如果设置，只能使用小写字母、数字、点、下划线或短横线，长度 2-64；如果省略，Entrance 会根据 `name` 生成
- `homepage` - 可选；填写时必须使用 `http` 或 `https`
- `entry` - 可选；默认 `index.js`；路径相对于插件根目录，必须指向已打包的 `.js` 文件
- `html` - 可选；默认 `index.html`；路径相对于插件根目录，填写时必须指向 `.html` 文件

## `index.js`

JavaScript 入口应暴露 `window.EntrancePlugin.mount(root, context)`。`mount()` 可以是同步函数，也可以返回 Promise。

```javascript
window.EntrancePlugin = {
  async mount(root, context) {
    root.textContent = context.plugin.name;
  }
};
```

## 运行时上下文

`context` 包含：

- `context.plugin` - 规范化后的 manifest 和安装元数据
- `context.theme` - 当前 `light` 或 `dark` 主题
- `context.colorScheme` - 当前配色方案 key
- `context.language` - 当前界面语言 key，值为 `en` 或 `zh`
- `context.apiBase` - 当前 Entrance 的 origin，适合拼接绝对 URL
- `context.vendors` - 从现有 `node_modules` 复制到浏览器侧后的 vendor 注册表元数据

`context.vendors` 以 vendor 名称为 key，每条记录包含：

- `name` - 稳定的 vendor 名称
- `type` - `script`、`module` 或 `style`
- `url` - 由 Entrance 提供的浏览器资源 URL
- `styles` - 可选样式表 URL；在返回 vendor API 前会自动加载
- `global` - 传统 script vendor 暴露到浏览器全局的名字
- `export` - 需要提取的命名导出，或 `default`
- `preloaded` - 表示该样式是否已经由插件页预先加载

## 运行时 API

`context.api` 包含：

- `context.api.fetch(path, options)` - `fetch()` 包装器，会基于 `context.apiBase` 解析路径，并自动带上当前 Entrance bearer token
- `context.api.getVendor(name)` - 返回单个 vendor 元数据；不存在则返回 `null`
- `context.api.listVendors()` - 返回完整 vendor 元数据映射
- `context.api.loadVendor(name)` - 从宿主资源注册表加载受支持的 vendor，并返回它对应的浏览器 API

插件运行在浏览器 iframe 中，因此不能直接 `require()` 宿主侧任意 Node 模块。当前支持的方式是加载 Entrance 已经从 `node_modules` 拷贝到 `public/assets/vendor/` 的浏览器兼容依赖。

## 内置 Vendor 模块

当前内置的 vendor 名称如下：

- `chart.js` - 加载 `/assets/vendor/chart.js/chart.umd.js`，返回 `Chart`
- `xterm` - 加载 `/assets/vendor/xterm/xterm.js`，自动加载 `xterm.css`，返回 `Terminal`
- `xterm-addon-fit` - 加载 `/assets/vendor/xterm-addon-fit/xterm-addon-fit.js`，返回 `FitAddon`
- `novnc` - 动态导入 `/assets/vendor/novnc/core/rfb.js`，返回默认导出 `RFB`
- `fontawesome` - 确保 `/assets/vendor/fontawesome/css/all.min.css` 可用；插件页默认已经预加载这个样式

## Vendor Loader 示例

当前目录下的示例插件通过运行时 API 调用 `Chart.js`：

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

其他内置 vendor 的典型调用方式：

```javascript
const Terminal = await context.api.loadVendor('xterm');
const FitAddon = await context.api.loadVendor('xterm-addon-fit');
const RFB = await context.api.loadVendor('novnc');
```

## `index.html`

当配置了 `html` 时，Entrance 会先把该文件的 body 内容注入插件根节点，然后再调用 `mount()`。这样插件可以把静态结构放在 HTML，把行为放在 JavaScript。

```html
<main>
  <h1 data-title>hello plugins</h1>
</main>
```

## 示例插件

- `api/index.js` + `api/index.html` 展示了一个通过 `context.api.loadVendor('chart.js')` 加载 `Chart.js`，并列出当前 vendor 注册表的示例插件
- `api/hello-plugins/` 是 `npm run test:plugins` 使用的最小冒烟测试插件
