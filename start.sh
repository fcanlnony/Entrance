#!/bin/bash

set -e

PORT_ARG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --port=*)
            PORT_ARG="${1#--port=}"
            if [ -z "$PORT_ARG" ]; then
                echo "Error: --port requires a value." >&2
                exit 1
            fi
            shift
            ;;
        --port)
            if [ $# -lt 2 ] || [ -z "$2" ]; then
                echo "Error: --port requires a value." >&2
                exit 1
            fi
            PORT_ARG="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--port=PORT]" >&2
            exit 1
            ;;
    esac
done

if [ ! -d ./.data ]; then
    mkdir -p ./.data
    [ -f ./.data/auth_secret ] || openssl rand -base64 32 > ./.data/auth_secret
fi

export ENTRANCE_DATA_DIR="$(pwd)/.data"
export AUTH_SECRET="$(tr -d '\n' < ./.data/auth_secret)"

if [ -n "$PORT_ARG" ]; then
    npm start -- --port "$PORT_ARG"
else
    npm start
fi
