#!/bin/sh
set -eu

mkdir -p "${MALAPP_DATA_DIR:-/var/lib/malapp}" "${MALAPP_WORKSPACE_ROOT:-/workspace}"

exec "$@"
