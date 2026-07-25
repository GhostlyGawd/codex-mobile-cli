#!/bin/sh
set -eu

password_file=${CODER_PG_PASSWORD_FILE:?CODER_PG_PASSWORD_FILE is required}
if [ ! -r "$password_file" ]; then
  echo "Coder database password file is not readable" >&2
  exit 1
fi

password=$(tr -d '\r\n' < "$password_file")
case "$password" in
  ""|*[!A-Za-z0-9._~-]*)
    echo "Coder database password must be non-empty and URL-safe" >&2
    exit 1
    ;;
esac

host=${CODER_PG_HOST:?CODER_PG_HOST is required}
port=${CODER_PG_PORT:-5432}
user=${CODER_PG_USER:?CODER_PG_USER is required}
database=${CODER_PG_DATABASE:?CODER_PG_DATABASE is required}

export CODER_PG_CONNECTION_URL="postgres://${user}:${password}@${host}:${port}/${database}?sslmode=disable"
unset password
exec /opt/coder server
