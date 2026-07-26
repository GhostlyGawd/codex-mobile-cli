#!/usr/bin/env sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
output=${OUTPUT_DIRECTORY:-$root/artifacts/supply-chain}
mkdir -p "$output"

for tool in syft trivy gitleaks go python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool is required at the version pinned in .tool-versions" >&2
    exit 1
  }
done

trivy_version=$(trivy --version --format json | python3 -c 'import json, sys; print(json.load(sys.stdin).get("Version", ""))')
[ "$trivy_version" = 0.72.0 ] || {
  echo "trivy 0.72.0 is required; found ${trivy_version:-unknown}" >&2
  exit 1
}
syft_version=$(syft version --output json | python3 -c 'import json, sys; print(json.load(sys.stdin).get("version", ""))')
[ "$syft_version" = 1.46.0 ] || {
  echo "syft 1.46.0 is required; found ${syft_version:-unknown}" >&2
  exit 1
}

python3 scripts/generate-supply-chain.py --check
gitleaks dir . --no-banner --redact --exit-code 1
trivy filesystem \
  --scanners misconfig,secret,license --license-full \
  --ignorefile .trivyignore.yaml \
  --skip-dirs .git \
  --skip-dirs tmp \
  --skip-dirs artifacts \
  --skip-dirs coverage \
  --skip-dirs infra/tests/__pycache__ \
  --skip-files infra/workspace/Dockerfile.dockerignore \
  --skip-dirs infra/coder/templates/codex-mobile-envbuilder/.terraform \
  --exit-code 1 --severity HIGH,CRITICAL .
syft scan dir:. \
  --exclude '**/.git/**' \
  --exclude '**/.terraform/**' \
  --exclude '**/__pycache__/**' \
  --exclude '**/.cache/**' \
  --exclude '**/artifacts/**' \
  --exclude '**/tmp/**' \
  --exclude '**/coverage/**' \
  --output "cyclonedx-json=$output/syft-source.cdx.json"
(
  cd services/control-plane
  go run github.com/google/go-licenses/v2@v2.0.1 report ./... > "$output/go-licenses.csv"
  go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
)

echo "Security and supply-chain audit passed. Ephemeral detailed reports: $output"
echo "Built OCI images still require a separate trivy image scan on a Docker/Podman host."
