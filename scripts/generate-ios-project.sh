#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_XCODE="26.6"
readonly EXPECTED_XCODEGEN="2.45.4"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "xcodebuild is required; run this command on macOS with Xcode ${EXPECTED_XCODE}." >&2
  exit 1
fi

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "xcodegen ${EXPECTED_XCODEGEN} is required (for example: mise install)." >&2
  exit 1
fi

xcode_version="$(xcodebuild -version | awk 'NR == 1 { print $2 }')"
xcodegen_version="$(xcodegen --version | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"

if [[ "${xcode_version}" != "${EXPECTED_XCODE}" ]]; then
  echo "Expected Xcode ${EXPECTED_XCODE}, found ${xcode_version}. Select it with DEVELOPER_DIR." >&2
  exit 1
fi

if [[ "${xcodegen_version}" != "${EXPECTED_XCODEGEN}" ]]; then
  echo "Expected XcodeGen ${EXPECTED_XCODEGEN}, found ${xcodegen_version}." >&2
  exit 1
fi

cd "${ROOT}/apps/ios"
cp "${ROOT}/packages/api-contract/openapi.yaml" \
  "${ROOT}/apps/ios/Sources/GeneratedAPI/openapi.yaml"
xcodegen generate --spec project.yml
readonly RESOLVED_DIRECTORY="CodexMobile.xcodeproj/project.xcworkspace/xcshareddata/swiftpm"
mkdir -p "${RESOLVED_DIRECTORY}"
cp Package.resolved "${RESOLVED_DIRECTORY}/Package.resolved"
echo "Generated apps/ios/CodexMobile.xcodeproj with the pinned toolchain."
