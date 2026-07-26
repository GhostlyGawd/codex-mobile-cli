# syntax=docker/dockerfile:1.12
ARG GO_VERSION=1.26.5
ARG GO_IMAGE_DIGEST=sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651
FROM docker.io/library/golang:${GO_VERSION}-bookworm@${GO_IMAGE_DIGEST} AS build

ARG CONTROL_PLANE_PACKAGE=./services/control-plane/cmd/control-plane
ARG TARGETARCH
ARG CODER_CLI_VERSION=2.34.6
ARG CODER_CLI_AMD64_SHA256=091acfd4356ab2f02bcaf561928841e9aecc630a28bc9678658d4ae47632df09
ARG CODER_CLI_ARM64_SHA256=d16b0f9393404e1d85669ec620aa90d2a0c10b1977c11c95e11b2d6b9bb0917d
WORKDIR /src
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags='-s -w' -o /out/control-plane "${CONTROL_PLANE_PACKAGE}"
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
      -o /out/http-healthcheck ./infra/docker/http-healthcheck.go

# The official Coder release archive contains a statically linked CLI plus the
# applicable Community and Enterprise license texts. The CLI is used only for
# one fixed, non-TTY workspace-helper command; no generic remote-command API is
# exposed by the control plane.
RUN coder_arch="${TARGETARCH:-$(dpkg --print-architecture)}" \
    && case "${coder_arch}" in \
         amd64) coder_sha="${CODER_CLI_AMD64_SHA256}" ;; \
         arm64) coder_sha="${CODER_CLI_ARM64_SHA256}" ;; \
         *) echo "unsupported Coder CLI architecture: ${coder_arch}" >&2; exit 1 ;; \
       esac \
    && coder_archive="coder_${CODER_CLI_VERSION}_linux_${coder_arch}.tar.gz" \
    && curl --fail --show-error --location --proto '=https' --tlsv1.2 \
      --output "/tmp/${coder_archive}" \
      "https://github.com/coder/coder/releases/download/v${CODER_CLI_VERSION}/${coder_archive}" \
    && printf '%s  %s\n' "${coder_sha}" "/tmp/${coder_archive}" \
      | sha256sum --check --strict - \
    && install -d -m 0755 /tmp/coder-release /out/coder-licenses \
    && tar -xzf "/tmp/${coder_archive}" -C /tmp/coder-release \
    && install -m 0755 /tmp/coder-release/coder /out/coder \
    && install -m 0644 /tmp/coder-release/LICENSE /out/coder-licenses/LICENSE \
    && install -m 0644 /tmp/coder-release/LICENSE.enterprise /out/coder-licenses/LICENSE.enterprise

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build --chown=0:0 --chmod=0755 /out/control-plane /usr/local/bin/control-plane
COPY --from=build --chown=0:0 --chmod=0755 /out/http-healthcheck /usr/local/bin/http-healthcheck
COPY --from=build --chown=0:0 --chmod=0755 /out/coder /usr/local/bin/coder
COPY --from=build --chown=0:0 --chmod=0644 /out/coder-licenses/LICENSE /usr/share/licenses/coder/LICENSE
COPY --from=build --chown=0:0 --chmod=0644 /out/coder-licenses/LICENSE.enterprise /usr/share/licenses/coder/LICENSE.enterprise

ENV HOME=/tmp \
    PATH=/usr/local/bin \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/control-plane"]
