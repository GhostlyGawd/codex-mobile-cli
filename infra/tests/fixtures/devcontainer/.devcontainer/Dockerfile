FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

# Simulate a repository image trying to shadow the trusted helper. The
# runtime's read-only named volume must mask this file after transformation.
RUN groupadd --gid 1000 codex \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash codex \
    && mkdir -p /workspaces/repository \
    && chown -R codex:codex /workspaces \
    && mkdir -p /opt/codex-mobile-helper \
    && printf '#!/bin/sh\nexit 99\n' > /opt/codex-mobile-helper/codex-mobile-workspace-helper \
    && chmod 0755 /opt/codex-mobile-helper/codex-mobile-workspace-helper

USER codex
