# 容器部署

## Docker 启动示例

```bash
# 构建镜像
docker build -t entrance-tools .

# 仅首次创建一次运行环境
docker volume create entrance-tools-data
[ -f ./.docker-auth_secret ] || openssl rand -base64 32 > ./.docker-auth_secret

# 运行（端口映射 + 持久化数据）
docker run -d --name entrance-tools \
  -p 3000:3000 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.docker-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

如果要让容器监听其他端口，例如 `4000`，需要同时修改容器内监听端口与宿主机映射：

```bash
docker run -d --name entrance-tools \
  -p 4000:4000 \
  -e PORT=4000 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.docker-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

这里故意不传 `SSH_PASSWORD_KEY`。容器会在持久化卷 `/data/.ssh_password_key` 中自动生成并长期复用它；只要卷不丢，重建容器也不会导致历史加密数据失效。

## Docker Compose 启动示例

项目已包含 `compose.yml`，默认将宿主机 `./data` 挂载到容器内 `/data`：

```bash
mkdir -p ./data
[ -f ./.compose-auth_secret ] || openssl rand -base64 32 > ./.compose-auth_secret

export AUTH_SECRET="$(tr -d '\n' < ./.compose-auth_secret)"
docker compose up -d --build
```

若需指定端口，可在启动前设置 `PORT`：

```bash
export PORT=4000
docker compose up -d --build
```

同样建议不要在每次 `docker compose up` 前重新生成 `SSH_PASSWORD_KEY`。保留 `./data` 目录后，Entrance 会自动复用 `./data/.ssh_password_key`。

## Podman 用户说明

Podman 用户将上述示例中的 `docker` 替换为 `podman` 即可。如果需要 Host 网络和串口设备，可参考：

```bash
[ -f ./.podman-auth_secret ] || openssl rand -base64 32 > ./.podman-auth_secret

podman run -d --name entrance-tools \
  --network host \
  --device /dev/ttyS0 \
  --device /dev/ttyS1 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.podman-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

> 将 `--device /dev/ttyS*` 替换为你机器上实际存在的串口设备（例如 `/dev/ttyUSB0` 或 `/dev/ttyACM0`）。Host 网络模式下无需 `-p` 端口映射。
