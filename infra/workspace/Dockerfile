# syntax=docker/dockerfile:1.12
# Go 1.26.5 official-image manifest digest checked 2026-07-15:
# https://hub.docker.com/_/golang
FROM docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS workspace-helper-builder

ARG TARGETARCH
WORKDIR /src/services/control-plane
COPY services/control-plane/go.mod services/control-plane/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY services/control-plane/internal ./internal
COPY services/control-plane/cmd/workspace-helper ./cmd/workspace-helper
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    helper_arch="${TARGETARCH:-$(go env GOARCH)}" \
    && case "${helper_arch}" in amd64|arm64) ;; *) echo "unsupported helper architecture: ${helper_arch}" >&2; exit 1 ;; esac \
    && CGO_ENABLED=0 GOOS=linux GOARCH="${helper_arch}" \
      go build -trimpath -buildvcs=false -ldflags='-s -w' \
      -o /out/codex-mobile-workspace-helper ./cmd/workspace-helper

# Ubuntu 24.04 official-image index digest checked 2026-07-15:
# https://hub.docker.com/_/ubuntu
FROM docker.io/library/ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ARG DEBIAN_FRONTEND=noninteractive
ARG WORKSPACE_IMAGE_VERSION=2026-07-15
ARG TARGETARCH
ARG CODEX_CLI_VERSION=0.144.5
ARG CODEX_CLI_AMD64_SHA256=23a7022a493c5404c50c62a4ad5655836adbee019d93c73114954d8daff20053
ARG CODEX_CLI_ARM64_SHA256=7703bbb6cbd4ba3df60c32d200bca2987691047353d3a6c825af2b8bc99f1808

LABEL org.opencontainers.image.title="Codex Mobile workspace base" \
      org.opencontainers.image.description="Non-root local fallback for Coder workspaces" \
      org.opencontainers.image.version="${WORKSPACE_IMAGE_VERSION}" \
      org.opencontainers.image.source="https://github.com/GhostlyGawd/codex-mobile-cli" \
      org.opencontainers.image.codex-version="${CODEX_CLI_VERSION}"

# Ubuntu archive package versions (including tmux and ripgrep) are recorded in
# the image. Codex uses the release-package assets covered by the official
# codex-package_SHA256SUMS file for rust-v0.144.5.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Package versions are captured in ubuntu-package-versions.txt inside the
# promoted image; security updates intentionally resolve at rebuild time.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get dist-upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
      bash \
      build-essential \
      bzip2 \
      ca-certificates \
      coreutils \
      curl \
      dash \
      diffutils \
      dnsutils \
      fd-find \
      file \
      findutils \
      git \
      git-lfs \
      gnupg \
      gzip \
      iproute2 \
      iputils-ping \
      jq \
      less \
      locales \
      lsof \
      nano \
      netcat-openbsd \
      nodejs \
      npm \
      openssh-client \
      pkg-config \
      procps \
      psmisc \
      python3 \
      python3-pip \
      python3-venv \
      ripgrep \
      rsync \
      socat \
      tar \
      tmux \
      tree \
      tzdata \
      unzip \
      vim-tiny \
      wget \
      xz-utils \
      zip \
      zsh \
    && git lfs install --system --skip-repo \
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    && install -d -m 0755 /usr/share/doc/codex-mobile \
    && dpkg-query -W -f='${Package}=${Version}\n' | sort \
      > /usr/share/doc/codex-mobile/ubuntu-package-versions.txt \
    && case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
         amd64) codex_arch=x86_64; codex_sha="${CODEX_CLI_AMD64_SHA256}" ;; \
         arm64) codex_arch=aarch64; codex_sha="${CODEX_CLI_ARM64_SHA256}" ;; \
         *) echo "unsupported Codex architecture: ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
       esac \
    && codex_asset="codex-package-${codex_arch}-unknown-linux-musl.tar.gz" \
    && curl --fail --show-error --location --proto '=https' --tlsv1.2 \
      --output "/tmp/${codex_asset}" \
      "https://github.com/openai/codex/releases/download/rust-v${CODEX_CLI_VERSION}/${codex_asset}" \
    && printf '%s  %s\n' "${codex_sha}" "/tmp/${codex_asset}" | sha256sum --check --strict - \
    && printf '%s  %s\n%s  %s\n' \
      "${CODEX_CLI_AMD64_SHA256}" codex-package-x86_64-unknown-linux-musl.tar.gz \
      "${CODEX_CLI_ARM64_SHA256}" codex-package-aarch64-unknown-linux-musl.tar.gz \
      > /usr/share/doc/codex-mobile/codex-package_SHA256SUMS \
    && install -d -m 0755 /opt/codex /opt/codex-mobile-helper \
    && tar -xzf "/tmp/${codex_asset}" -C /opt/codex \
    && install -m 0755 /opt/codex/bin/codex /opt/codex-mobile-helper/codex-real \
    && install -m 0755 /opt/codex/bin/codex-code-mode-host /opt/codex-mobile-helper/codex-code-mode-host \
    && install -o 0 -g 0 -m 0444 /etc/ssl/certs/ca-certificates.crt /opt/codex-mobile-helper/ca-certificates.crt \
    && ln -s codex-mobile-workspace-helper /opt/codex-mobile-helper/codex \
    && ln -s /opt/codex-mobile-helper/codex /usr/local/bin/codex \
    && ln -s /opt/codex-mobile-helper/codex-code-mode-host /usr/local/bin/codex-code-mode-host \
    && /opt/codex-mobile-helper/codex-real --version | grep -F "codex-cli ${CODEX_CLI_VERSION}" \
    && test "$(getent group 1000 | cut -d: -f1)" = ubuntu \
    && test "$(getent passwd 1000 | cut -d: -f1)" = ubuntu \
    && groupmod --new-name codex ubuntu \
    && usermod --login codex --home /home/codex --move-home --shell /bin/bash ubuntu \
    && install -d -o codex -g codex -m 0700 \
      /workspaces \
      /workspaces/repository \
      /workspaces/.home \
      /workspaces/.codex-home \
    && printf 'umask 077\n' > /etc/profile.d/codex-mobile-umask.sh \
    && chmod 0644 /etc/profile.d/codex-mobile-umask.sh \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# The control plane invokes this one fixed helper through Coder SSH. Keep the
# authoritative copy under /opt: the Coder template mounts that directory from
# a per-workspace, read-only volume so an approved Dev Container cannot replace
# the executable while transforming the rest of the root filesystem.
COPY --from=workspace-helper-builder --chown=0:0 --chmod=0755 \
  /out/codex-mobile-workspace-helper /opt/codex-mobile-helper/codex-mobile-workspace-helper
RUN ln -s /opt/codex-mobile-helper/codex-mobile-workspace-helper \
      /usr/local/bin/codex-mobile-workspace-helper

ENV HOME=/workspaces/.home \
    CODEX_HOME=/workspaces/.codex-home \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

USER 1000:1000
WORKDIR /workspaces/repository
CMD ["/bin/sleep", "infinity"]
