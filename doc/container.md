# Container Deployment

## Docker Example

```bash
# Build the image
docker build -t entrance-tools .

# Create runtime resources once
docker volume create entrance-tools-data
[ -f ./.docker-auth_secret ] || openssl rand -base64 32 > ./.docker-auth_secret

# Run with port mapping and persistent data
docker run -d --name entrance-tools \
  -p 3000:3000 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.docker-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

To expose a different port, for example `4000`, change both the internal listen port and the host port mapping:

```bash
docker run -d --name entrance-tools \
  -p 4000:4000 \
  -e PORT=4000 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.docker-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

`SSH_PASSWORD_KEY` is intentionally omitted here. The container generates it once in the persistent volume at `/data/.ssh_password_key` and keeps reusing it. As long as the volume remains, rebuilding the container will not break historical encrypted data.

## Docker Compose Example

The repository already includes `compose.yml`, which mounts host `./data` into container `/data` by default:

```bash
mkdir -p ./data
[ -f ./.compose-auth_secret ] || openssl rand -base64 32 > ./.compose-auth_secret

export AUTH_SECRET="$(tr -d '\n' < ./.compose-auth_secret)"
docker compose up -d --build
```

To use a different port, set `PORT` before startup:

```bash
export PORT=4000
docker compose up -d --build
```

Likewise, do not regenerate `SSH_PASSWORD_KEY` before every `docker compose up`. If you keep `./data`, Entrance will automatically reuse `./data/.ssh_password_key`.

## Podman Notes

Podman users can substitute `docker` with `podman`. If you need host networking and serial devices:

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

> Replace `--device /dev/ttyS*` with the actual serial devices on your machine, such as `/dev/ttyUSB0` or `/dev/ttyACM0`. Host networking does not require `-p` port mapping.
