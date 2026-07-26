#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
export PATH HOME
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG COMPOSE_FILE
unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINERS_CONF CONTAINERS_STORAGE_CONF
unset CONTAINERS_REGISTRIES_CONF CONTAINERS_POLICY REGISTRY_AUTH_FILE XDG_CONFIG_HOME

usage() {
  echo "usage: $0 [--bootstrap] [--template-name NAME] [--receipt-directory ABSOLUTE_DIRECTORY]" >&2
  exit 2
}

template_name=codex-mobile-envbuilder
receipt_directory=
bootstrap=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bootstrap) bootstrap=true; shift ;;
    --template-name) [ "$#" -ge 2 ] || usage; template_name=$2; shift 2 ;;
    --receipt-directory) [ "$#" -ge 2 ] || usage; receipt_directory=$2; shift 2 ;;
    *) usage ;;
  esac
done

case "$template_name" in
  ''|*[!a-z0-9-]*|-*|*-) echo "template name must use lowercase letters, digits, and interior hyphens" >&2; exit 1 ;;
esac
[ "${#template_name}" -le 32 ] || { echo "template name exceeds 32 characters" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "template import requires root" >&2; exit 1; }

repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}
template_dir="$repo_root/infra/coder/templates/codex-mobile-envbuilder"
release_id=
if [ -f "$repo_root/infra/release.env" ]; then
  release_id=$(awk -F= '$1 == "RELEASE_ID" {print $2}' "$repo_root/infra/release.env")
fi

env_value() {
  awk -F= -v key="$1" '$1 == key {sub(/^[^=]*=/, ""); print; found=1} END {if (!found) exit 1}' "$env_file"
}

[ -f "$env_file" ] || { echo "missing environment file: $env_file" >&2; exit 1; }
[ -f "$template_dir/main.tf" ] || { echo "missing Coder template: $template_dir" >&2; exit 1; }
[ -x /usr/local/bin/coder ] || { echo "Coder CLI is not installed" >&2; exit 1; }
[ -x /usr/bin/python3 ] || { echo "python3 is required" >&2; exit 1; }
if [ "$bootstrap" = true ]; then
  [ -z "$receipt_directory" ] || { echo "bootstrap import cannot write a release receipt" >&2; exit 1; }
  [ -z "$release_id" ] || { echo "bootstrap import is forbidden after release activation" >&2; exit 1; }
  release_message="initial owner-approved bootstrap"
else
  case "$release_id" in sha-[0-9a-f]*) ;; *) echo "invalid immutable release ID" >&2; exit 1 ;; esac
  /usr/bin/python3 -I "$repo_root/scripts/infra_release_manifest.py" verify \
    --repo-root "$repo_root" --require-images --require-image-audit \
    --podman-url "$podman_url"
  release_message=$release_id
fi
if [ -n "$receipt_directory" ]; then
  case "$receipt_directory" in /*) ;; *) echo "receipt directory must be absolute" >&2; exit 1 ;; esac
  expected_receipt_directory="${RELEASE_ROOT:-/opt/codex-mobile}/activations"
  [ "$receipt_directory" = "$expected_receipt_directory" ] || {
    echo "receipt directory must be $expected_receipt_directory" >&2
    exit 1
  }
  [ ! -L "$receipt_directory" ] || { echo "receipt directory must not be a symlink" >&2; exit 1; }
  install -d -o root -g root -m 0700 "$receipt_directory"
fi

secrets_dir=$(env_value SECRETS_DIR)
coder_url=$(env_value CODER_ACCESS_URL)
coder_control_address=$(env_value CODER_BIND_ADDRESS)
coder_control_port=$(env_value CODER_BIND_PORT)
organization_id=$(env_value CODER_ORGANIZATION_ID)
workspace_io_device=$(env_value WORKSPACE_IO_DEVICE)
token_file="$secrets_dir/coder_api_token"
[ -s "$token_file" ] || { echo "missing scoped Coder API token: $token_file" >&2; exit 1; }
printf '%s\n' "$organization_id" \
  | grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' \
  || { echo "CODER_ORGANIZATION_ID must be a canonical UUID" >&2; exit 1; }
case "$workspace_io_device" in
  /dev/*) ;;
  *) echo "WORKSPACE_IO_DEVICE must be the explicit /dev source backing DATA_ROOT" >&2; exit 1 ;;
esac
WORKSPACE_IO_DEVICE=$workspace_io_device \
  WORKSPACE_STORAGE_ROOT=${WORKSPACE_STORAGE_ROOT:-/srv/codex-mobile/workspaces} \
  WORKSPACE_STORAGE_MOUNT=${WORKSPACE_STORAGE_MOUNT:-/srv/codex-mobile} \
  /bin/sh "$repo_root/infra/systemd/verify-workspace-storage.sh"

CODER_SESSION_TOKEN=$(tr -d '\r\n' < "$token_file")
[ -n "$CODER_SESSION_TOKEN" ] || { echo "Coder API token is empty" >&2; exit 1; }
CODER_URL=$coder_url
CODER_DISABLE_NETWORK_TELEMETRY=true
CODER_NO_VERSION_WARNING=true
export CODER_SESSION_TOKEN CODER_URL CODER_DISABLE_NETWORK_TELEMETRY CODER_NO_VERSION_WARNING

# The template version and daemon share this exact tag, ensuring the Docker
# provider runs only inside the dedicated private-Podman provisioner boundary.
systemctl start codex-mobile-workspace-runtime.service
systemctl start codex-mobile-provisioner.service
/usr/local/bin/coder templates push --yes \
  --org "$organization_id" \
  --directory "$template_dir" \
  --provisioner-tag runtime=private-podman \
  --variable "workspace_io_device=$workspace_io_device" \
  --variable "coder_control_address=$coder_control_address" \
  --variable "coder_control_port=$coder_control_port" \
  --message "Pinned Codex Mobile EnvBuilder template $release_message" \
  "$template_name"

template_record=$(/usr/bin/python3 -I - "$CODER_URL" "$organization_id" "$template_name" <<'PY'
import json
import os
import sys
import urllib.parse
import urllib.request
import uuid

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

base, organization, name = sys.argv[1:]
parsed = urllib.parse.urlsplit(base)
if (
    parsed.scheme not in ("http", "https")
    or not parsed.hostname
    or parsed.username
    or parsed.password
    or parsed.query
    or parsed.fragment
    or parsed.path not in ("", "/")
):
    raise SystemExit("CODER_ACCESS_URL is invalid")
request = urllib.request.Request(
    f"{base.rstrip('/')}/api/v2/organizations/{organization}/templates/{name}",
    headers={"Coder-Session-Token": os.environ["CODER_SESSION_TOKEN"]},
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
with opener.open(request, timeout=15) as response:
    document = json.load(response)
template_id = str(uuid.UUID(document["id"]))
active_version_id = str(uuid.UUID(document["active_version_id"]))
print(f"{template_id}|{active_version_id}")
PY
)
template_id=${template_record%%|*}
active_version_id=${template_record#*|}
[ "$template_record" = "$template_id|$active_version_id" ] || {
  echo "Coder template activation response is invalid" >&2
  exit 1
}
if [ "$bootstrap" = false ]; then
  [ "$template_id" = "$(env_value CODER_TEMPLATE_ID)" ] || {
    echo "activated Coder template ID does not match CODER_TEMPLATE_ID" >&2
    exit 1
  }
fi

if [ -n "$receipt_directory" ]; then
  /usr/bin/python3 -I - "$repo_root/infra/release-manifest.json" "$receipt_directory" \
    "$template_id" "$active_version_id" <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import sys

manifest_path, receipt_directory, template_id, active_version_id = sys.argv[1:]
manifest_bytes = pathlib.Path(manifest_path).read_bytes()
manifest = json.loads(manifest_bytes)
receipt = {
    "schema_version": 2,
    "release_id": manifest["release_id"],
    "release_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    "template_id": template_id,
    "active_template_version_id": active_version_id,
    "template_sha256": manifest["coder"]["template_sha256"],
    "provisioner_tag": manifest["coder"]["provisioner_tag"],
    "workspace_base_image": manifest["images"]["workspace_base"],
    "envbuilder_image": manifest["images"]["envbuilder"],
    "image_audit": manifest["image_audit"],
    "activated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
}
destination = pathlib.Path(receipt_directory) / (
    f"{manifest['release_id']}-{active_version_id}.json"
)
descriptor = os.open(
    destination,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
    0o600,
)
try:
    content = json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n"
    view = memoryview(content)
    while view:
        view = view[os.write(descriptor, view):]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
fi

echo "Coder template imported and activated."
if [ "$bootstrap" = true ]; then
  echo "Set CODER_TEMPLATE_ID=$template_id in $env_file, then run the full deployment preflight."
else
  echo "Activated template $template_id version $active_version_id for $release_id."
fi
