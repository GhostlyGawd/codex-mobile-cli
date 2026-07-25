#!/usr/bin/env bash
set -Eeuo pipefail

read_secret() {
  local path=$1
  if [[ ! -r "$path" ]]; then
    echo "Required database secret is not readable: $path" >&2
    exit 1
  fi
  tr -d '\r\n' < "$path"
}

validate_identifier() {
  local label=$1 value=$2
  if [[ ! "$value" =~ ^[a-z_][a-z0-9_]{0,62}$ ]]; then
    echo "$label must be a lowercase PostgreSQL identifier" >&2
    exit 1
  fi
}

validate_identifier APP_DB_USER "${APP_DB_USER:?APP_DB_USER is required}"
validate_identifier APP_DB_NAME "${APP_DB_NAME:?APP_DB_NAME is required}"
validate_identifier CODER_DB_USER "${CODER_DB_USER:?CODER_DB_USER is required}"
validate_identifier CODER_DB_NAME "${CODER_DB_NAME:?CODER_DB_NAME is required}"

app_password=$(read_secret "${APP_DB_PASSWORD_FILE:?APP_DB_PASSWORD_FILE is required}")
coder_password=$(read_secret "${CODER_DB_PASSWORD_FILE:?CODER_DB_PASSWORD_FILE is required}")
if [[ -z "$app_password" || -z "$coder_password" ]]; then
  echo "Database role passwords must not be empty" >&2
  exit 1
fi

psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  --variable=app_user="$APP_DB_USER" \
  --variable=app_db="$APP_DB_NAME" \
  --variable=app_password="$app_password" \
  --variable=coder_user="$CODER_DB_USER" \
  --variable=coder_db="$CODER_DB_NAME" \
  --variable=coder_password="$coder_password" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', :'app_user', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec

SELECT format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', :'coder_user', :'coder_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'coder_user')
\gexec

SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L', :'app_db', :'app_user', 'UTF8')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'app_db')
\gexec

SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L', :'coder_db', :'coder_user', 'UTF8')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'coder_db')
\gexec

SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'app_db')
\gexec
SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I', :'app_db', :'app_user')
\gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'coder_db')
\gexec
SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I', :'coder_db', :'coder_user')
\gexec
SQL

unset app_password coder_password
