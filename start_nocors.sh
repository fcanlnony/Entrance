#!/bin/bash

set -e

export ENTRANCE_CORS_DISABLE=1

exec ./start.sh "$@"
