#!/usr/bin/env bash
set -euo pipefail

# Load local environment variables
. .env

REMOTE_DIR="~/dependency-track"

# Ensure the remote directory exists
ssh apinf@"${SERVER_HOST}" "mkdir -p ${REMOTE_DIR}"

# Transfer docker-compose.yml and .env to the remote host
scp docker-compose.yml .env apinf@"${SERVER_HOST}":"${REMOTE_DIR}/"

# Start the stack on the remote host
ssh apinf@"${SERVER_HOST}" "cd ${REMOTE_DIR} && docker compose up -d"