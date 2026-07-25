# syntax=docker/dockerfile:1.12

# This image is built only from the locally verified workspace base and the
# immutable upstream EnvBuilder image. Its /opt helper directory seeds a named
# volume before EnvBuilder replaces the container root filesystem.
ARG WORKSPACE_BASE_IMAGE=localhost/codex-mobile/workspace-base:2026-07-15
ARG ENVBUILDER_BASE_IMAGE=ghcr.io/coder/envbuilder:1.3.0@sha256:b34ade2fb90a8536df76e7a15c6dd8c6352d0ae835a187b13467fa0c8a71e280

FROM ${WORKSPACE_BASE_IMAGE} AS workspace-base
FROM ${ENVBUILDER_BASE_IMAGE}

ARG WORKSPACE_HELPER_AMD64_SHA256=f6fc430a2200d13ee0ef04dd576875b4f9a7c95a04287cbdec2deec3b495493c
ARG WORKSPACE_HELPER_ARM64_SHA256=c7e4577a465b55721043612f9b6919248806576816388b01898f6c2784dc163e

LABEL org.opencontainers.image.title="Codex Mobile EnvBuilder" \
      org.opencontainers.image.description="Pinned EnvBuilder with a trusted workspace-helper volume seed" \
      org.opencontainers.image.version="1.3.0-helper-2026-07-15" \
      org.opencontainers.image.source="https://github.com/GhostlyGawd/codex-mobile-cli" \
      org.opencontainers.image.workspace-helper-amd64-sha256="${WORKSPACE_HELPER_AMD64_SHA256}" \
      org.opencontainers.image.workspace-helper-arm64-sha256="${WORKSPACE_HELPER_ARM64_SHA256}"

COPY --from=workspace-base --chown=0:0 --chmod=0755 \
  /opt/codex-mobile-helper/ \
  /opt/codex-mobile-helper/
