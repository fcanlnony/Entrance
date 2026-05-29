# API

## Authentication

- `POST /api/auth/login` - sign in and return a token
- `POST /api/auth/session` - refresh the current token using a new keepalive duration
- `POST /api/auth/verify` - verify a token

All APIs require `Authorization: Bearer <token>` in the request header.

## User Data

- `GET /api/userdata/:userId/hosts` - get saved hosts
- `POST /api/userdata/:userId/hosts` - add a host
- `DELETE /api/userdata/:userId/hosts/:index` - delete a host

## SFTP

- `POST /api/sftp/connect` - open a connection
- `POST /api/sftp/disconnect/:sessionId` - close a connection
- `GET /api/sftp/list/:sessionId` - list a directory
- `GET /api/sftp/home/:sessionId` - get the home directory
- `POST /api/sftp/mkdir/:sessionId` - create a directory
- `DELETE /api/sftp/delete/:sessionId` - delete a file or directory
- `POST /api/sftp/upload/:sessionId` - upload files
- `GET /api/sftp/download/:sessionId` - download a file
- `POST /api/sftp/download-zip/:sessionId` - download a ZIP bundle

Example SFTP connection payloads:

```javascript
// Password auth
{
  "host": "192.168.1.10",
  "port": 22,
  "username": "root",
  "authType": "password",
  "password": "xxx"
}

// Private key auth
{
  "host": "192.168.1.10",
  "port": 22,
  "username": "root",
  "authType": "key",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "passphrase": "optional"
}
```

## Plugins

- `GET /api/plugins` - list installed plugins
- `POST /api/plugins/install` - install a plugin ZIP package (admin)
- `DELETE /api/plugins/:id` - delete an installed plugin (admin)
- `GET /api/plugins/:id/page` - open the plugin runtime page
- `GET /api/plugins/:id/assets/*` - serve files from the plugin root directory

For the plugin package format, `api/version.json` constraints, and `index.js` runtime contract, see [Plugin API](../api/plugins.md).

## Security Configuration

- `GET /api/security/private-networks` - get the private CIDR allowlist (admin)
- `PUT /api/security/private-networks` - update the private CIDR allowlist (admin)

## SSH (WebSocket)

Connect to `ws://host:port/ssh?token=...` with messages like:

```javascript
// Connect
{ "type": "connect", "host": "192.168.1.1", "port": 22, "username": "root", "password": "xxx" }

// Connect with private key
{
  "type": "connect",
  "host": "192.168.1.1",
  "port": 22,
  "username": "root",
  "authType": "key",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "passphrase": "optional"
}

// Send data
{ "type": "data", "data": "ls -la\n" }

// Resize terminal
{ "type": "resize", "cols": 80, "rows": 24 }

// Disconnect
{ "type": "disconnect" }

// Start system stats (sample /proc/stat, /proc/meminfo, /proc/diskstats every second)
{ "type": "startStats" }

// Stop system stats
{ "type": "stopStats" }

// Start process stats (sample uptime and ps aux every 2 seconds)
{ "type": "startTop" }

// Stop process stats
{ "type": "stopTop" }

// Refresh process list manually
{ "type": "refreshTop" }

// Send a signal to a process
{ "type": "kill", "pid": 1234, "signal": 15 }

// Start Docker stats (sample docker stats --no-stream every 3 seconds)
{ "type": "startDockerStats" }

// Stop Docker stats
{ "type": "stopDockerStats" }

// Refresh Docker stats manually
{ "type": "refreshDockerStats" }
```

System stats payload returned by the server:

```javascript
{
  "type": "stats",
  "data": {
    "stat": "cpu  12345 678 ...",      // /proc/stat output
    "meminfo": "MemTotal: ...",         // /proc/meminfo output
    "diskstats": "8 0 sda ..."          // /proc/diskstats output
  }
}
```

Process stats payload returned by the server:

```javascript
{
  "type": "top",
  "data": {
    "uptime": "10:15:03 up 5 days...",  // uptime output
    "ps": "USER PID %CPU %MEM ..."       // ps aux output
  }
}
```

Docker stats payload returned by the server:

```javascript
{
  "type": "dockerStats",
  "data": {
    "available": true,                // whether Docker is available
    "error": null,                    // error message when unavailable
    "containers": [                   // container list from docker stats --format json
      {
        "ID": "abc123...",
        "Name": "my-container",
        "CPUPerc": "1.25%",
        "MemPerc": "12.50%",
        "MemUsage": "256MiB / 2GiB",
        "NetIO": "1.2MB / 3.4MB",
        "BlockIO": "10MB / 20MB",
        "PIDs": "15"
      }
    ]
  }
}
```

Kill-process result returned by the server:

```javascript
{
  "type": "killResult",
  "data": {
    "success": true,
    "message": "SIGTERM sent to PID 1234"
  }
}
```

## VNC (WebSocket)

Connect to `ws://host:port/vnc`; the server proxies traffic to the target VNC server.

Message format:

```javascript
// Initial target info
{ "type": "connect", "host": "192.168.1.1", "port": 5900 }
```

## Local Shell (WebSocket)

Linux/macOS uses `ws://host:port/localshell` for the server-local terminal. On Windows, the Web Terminal page switches internally to `ws://host:port/ssh` and connects to `127.0.0.1`.

Message format:

```javascript
// Start shell
{ "type": "start", "cols": 80, "rows": 24, "cwd": "/home/user" }

// Send input
{ "type": "data", "data": "ls -la\n" }

// Resize
{ "type": "resize", "cols": 120, "rows": 40 }

// Stop shell
{ "type": "stop" }
```

Status API:

- `GET /api/localshell/status` - get local shell service status

## Flash & Debug

- `GET /api/flashdebug/tooling?tool=openocd|pyocd|probe-rs[&path=/abs/path]` - detect executable paths, probe lists, OpenOCD config catalogs, and available elevation methods on the current platform
- `POST /api/flashdebug/upload` - upload firmware files to a temporary directory on the current Entrance host

Connect to `ws://host:port/flashdebug?token=...` with messages like:

```javascript
// Start flashing
{
  "type": "start",
  "action": "flash",
  "tool": "openocd",
  "requestElevation": true,
  "executablePath": "",
  "options": {
    "probeSelection": "cmsis-dap",
    "targetConfig": "target/stm32f4x.cfg",
    "interfaceConfig": "",
    "speed": "4000",
    "firmwarePath": "/tmp/app.bin",
    "verify": true,
    "resetAfterFlash": true,
    "extraArgs": ""
  }
}

// Start live debugging
{
  "type": "start",
  "action": "debug",
  "tool": "pyocd",
  "requestElevation": false,
  "options": {
    "probeSelection": "",
    "target": "stm32f103rc",
    "speed": "1000000",
    "gdbPort": 3333,
    "telnetPort": 4444,
    "elfPath": "/tmp/app.elf",
    "extraArgs": ""
  }
}

// Stop current task
{ "type": "stop" }
```

The server returns:

- `started` - task started, includes the final command preview
- `output` - stdout/stderr/system output stream
- `exit` - process exit status
- `error` - startup failure or runtime error

## Serial Data Formats (WebSerial)

The serial terminal automatically parses two mutually exclusive formats without interference.

### Waveform Data Format

Used for real-time waveform rendering in the format `VariableName:NumericValue`:

```text
ADC1:1024
Temp:25.5
Sin:-0.866
Voltage:3.3
```

Single-line multi-variable input is also supported:

```text
a:2, b:4, temp:25.5
```

- Variable name: starts with a letter or underscore; may contain letters, numbers, and underscores
- Value: integer or float, supports negatives
- One or more data points per line, separated by newlines
- Each variable gets a distinct color automatically

### Stat Chart Data Format

Used for bar-chart comparisons in the format `varName:[key1:value1, key2:value2, ...]`:

```text
stats:[a:2, b:3, c:5, d:6]
```

Single-line multiple variables are also supported:

```text
var1:[a:4, b:6], var2:[a:6, b:3, c:2]
```

Multi-line parsing is supported as well:

```text
cpu:[user:45, system:12, idle:43]
memory:[used:8192, free:4096, cached:2048]
```

- Variable name such as `stats` or `var1`: used as the X-axis label
- Subkeys such as `a`, `b`, `c`: each subkey uses a distinct color
- Value: integer or float, supports negatives
- Matching subkey names reuse the same color across variables for easier comparison
