# syntax=docker/dockerfile:1.12

ARG WORKSPACE_BASE_IMAGE=localhost/codex-mobile/workspace-base:2026-07-15

# Build the audited EnvBuilder derivative from one exact upstream source
# archive. The patch removes the Coder server SDK from the runtime graph,
# upgrades the vulnerable dependency set where fixes exist, and preserves the
# workspace-agent log protocol with a small bounded client.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS envbuilder-builder

ARG TARGETARCH
WORKDIR /build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY infra/workspace/envbuilder/source-lock.json /provenance/source-lock.json
COPY infra/workspace/envbuilder/envbuilder-v1.3.0-codex-mobile.patch /provenance/envbuilder.patch

RUN set -eu \
    && case "${TARGETARCH}" in amd64|arm64) ;; *) echo "unsupported EnvBuilder architecture: ${TARGETARCH:-unset}" >&2; exit 1 ;; esac \
    && printf '%s  %s\n' \
      '5a1f27db2ed6226ccd401d5bd2a6c617a42ca4fe07071a9021f29af3a2b053a8' \
      /provenance/source-lock.json | sha256sum --check --strict - \
    && printf '%s  %s\n' \
      'aea2941874a27d4deac96a0efe3a006ca6ea56d7cff982caa3a36877fc1756c3' \
      /provenance/envbuilder.patch | sha256sum --check --strict - \
    && archive=/tmp/envbuilder.tar.gz \
    && curl --fail --show-error --silent --location \
      --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
      --max-filesize 8388608 \
      --output "${archive}" \
      'https://codeload.github.com/coder/envbuilder/tar.gz/da95f80ea89fc615b85441da107c29004061df6a' \
    && test "$(stat -c '%s' "${archive}")" -le 8388608 \
    && printf '%s  %s\n' \
      'f1c6334ee08736dec2585d96ad0afacc1888994bf2a2cdcf86e982b229fb8a85' \
      "${archive}" | sha256sum --check --strict - \
    && tar -tzf "${archive}" > /tmp/envbuilder-members.txt \
    && test "$(wc -l < /tmp/envbuilder-members.txt)" -eq 122 \
    && awk 'BEGIN { prefix = "envbuilder-da95f80ea89fc615b85441da107c29004061df6a/" } $0 != prefix && index($0, prefix) != 1 { exit 1 } $0 ~ /(^|\/)\.\.?($|\/)/ || $0 ~ /\\/ || $0 ~ /\/\// { exit 1 }' \
      /tmp/envbuilder-members.txt \
    && tar -tvzf "${archive}" | awk 'substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { exit 1 }' \
    && mkdir /src \
    && tar --extract --gzip --file "${archive}" --directory /src \
      --strip-components=1 --no-same-owner --no-same-permissions \
    && test -z "$(find /src -type l -print -quit)" \
    && printf '%s  %s\n' \
      '43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1' \
      /src/LICENSE | sha256sum --check --strict - \
    && cd /src \
    && git init --quiet \
    && git add --all \
    && git -c user.name='Codex Mobile source verifier' \
      -c user.email='source-verifier@invalid.example' \
      commit --quiet --message='Exact EnvBuilder 1.3.0 upstream source' \
    && git apply --check --index /provenance/envbuilder.patch \
    && git apply --index /provenance/envbuilder.patch \
    && git diff --cached --check \
    && printf '%s\n' \
      cmd/envbuilder/main.go \
      cmd/envbuilder/main_internal_test.go \
      go.mod \
      go.sum \
      integration/integration_test.go \
      log/coder.go \
      log/coder_internal_test.go \
      log/log.go > /tmp/expected-patched-files.txt \
    && git diff --cached --name-only | LC_ALL=C sort > /tmp/actual-patched-files.txt \
    && cmp /tmp/expected-patched-files.txt /tmp/actual-patched-files.txt \
    && GOTOOLCHAIN=local go mod tidy -diff \
    && GOTOOLCHAIN=local go mod verify \
    && mkdir -p /out \
    && for pass in one two; do \
      GOTOOLCHAIN=local GOCACHE="/tmp/go-build-${pass}" \
        CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
        go build -mod=readonly -trimpath -buildvcs=false \
          -ldflags='-s -w -X github.com/coder/envbuilder/buildinfo.tag=1.3.0-codex-mobile.1' \
          -o "/out/envbuilder-${pass}" ./cmd/envbuilder; \
    done \
    && cmp /out/envbuilder-one /out/envbuilder-two \
    && grep -aF '1.3.0-codex-mobile.1' /out/envbuilder-one >/dev/null \
    && go version -m /out/envbuilder-one > /out/envbuilder-go-version.txt \
    && grep -F $'\tbuild\tCGO_ENABLED=0' /out/envbuilder-go-version.txt \
    && grep -F $'\tbuild\tGOOS=linux' /out/envbuilder-go-version.txt \
    && grep -F $'\tbuild\tGOARCH='"${TARGETARCH}" /out/envbuilder-go-version.txt \
    && ! grep -E 'github.com/coder/(coder|tailscale)|tailscale.com' /out/envbuilder-go-version.txt \
    && mv /out/envbuilder-one /out/envbuilder \
    && rm /out/envbuilder-two \
    && rm -rf \
      /go/pkg/mod \
      /root/.cache/go-build \
      /tmp/go-build-one \
      /tmp/go-build-two \
      /tmp/envbuilder.tar.gz \
      /src/.git

# The workspace base is built and verified first. The build script resolves
# this reference to its immutable local image ID before the trusted helper seed
# is copied, closing the mutable-tag race between the two image builds.
FROM ${WORKSPACE_BASE_IMAGE} AS workspace-base

FROM scratch

ARG WORKSPACE_HELPER_AMD64_SHA256=ba7080f880206d90e05d751245c3635b9bdcbcbbc6152d61c3ec4221fd5bdf14
ARG WORKSPACE_HELPER_ARM64_SHA256=3042240a601842f35233e383835a3e40aef6b05640b44f723bafefb133fdf9aa

LABEL org.opencontainers.image.title="Codex Mobile EnvBuilder" \
      org.opencontainers.image.description="Source-built EnvBuilder derivative with a trusted workspace-helper volume seed" \
      org.opencontainers.image.version="1.3.0-codex-mobile.1" \
      org.opencontainers.image.source="https://github.com/GhostlyGawd/codex-mobile-cli" \
      org.opencontainers.image.licenses="LicenseRef-First-Party-No-License" \
      com.codex-mobile.envbuilder-upstream-repository="https://github.com/coder/envbuilder" \
      com.codex-mobile.envbuilder-upstream-version="1.3.0" \
      com.codex-mobile.envbuilder-upstream-commit="da95f80ea89fc615b85441da107c29004061df6a" \
      com.codex-mobile.envbuilder-upstream-archive-sha256="f1c6334ee08736dec2585d96ad0afacc1888994bf2a2cdcf86e982b229fb8a85" \
      com.codex-mobile.envbuilder-upstream-license="Apache-2.0" \
      com.codex-mobile.envbuilder-patch-sha256="aea2941874a27d4deac96a0efe3a006ca6ea56d7cff982caa3a36877fc1756c3" \
      com.codex-mobile.envbuilder-source-lock-sha256="5a1f27db2ed6226ccd401d5bd2a6c617a42ca4fe07071a9021f29af3a2b053a8" \
      org.opencontainers.image.workspace-helper-amd64-sha256="${WORKSPACE_HELPER_AMD64_SHA256}" \
      org.opencontainers.image.workspace-helper-arm64-sha256="${WORKSPACE_HELPER_ARM64_SHA256}"

COPY --from=envbuilder-builder --chown=0:0 --chmod=0755 \
  /out/envbuilder \
  /.envbuilder/bin/envbuilder
COPY --from=envbuilder-builder --chown=0:0 --chmod=0444 \
  /src/LICENSE \
  /usr/share/licenses/envbuilder/LICENSE
COPY --from=envbuilder-builder --chown=0:0 --chmod=0444 \
  /provenance/source-lock.json \
  /usr/share/doc/codex-mobile/envbuilder-source-lock.json
COPY --from=workspace-base --chown=0:0 \
  /opt/codex-mobile-helper/ \
  /opt/codex-mobile-helper/

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    KANIKO_DIR=/.envbuilder

WORKDIR /
ENTRYPOINT ["/.envbuilder/bin/envbuilder"]
