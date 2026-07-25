#!/usr/bin/env sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
mkdir -p coverage

go work sync
GO111MODULE=off go fmt ./services/control-plane/...
go vet ./services/control-plane/...
go test -race ./services/control-plane/...
go test ./services/control-plane/... -coverprofile=coverage/control-plane.out
go test -tags=integration ./services/control-plane/... -run '^$'
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o coverage/control-plane-linux-amd64 ./services/control-plane/cmd/control-plane
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o coverage/workspace-helper-linux-amd64 ./services/control-plane/cmd/workspace-helper
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o coverage/control-plane-linux-arm64 ./services/control-plane/cmd/control-plane
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o coverage/workspace-helper-linux-arm64 ./services/control-plane/cmd/workspace-helper
python3 ./scripts/verify-workspace-helper-checksums.py
sh ./infra/tests/run-static-tests.sh
bash ./scripts/test-ios-static.sh
python3 ./scripts/generate-supply-chain.py --check
python3 ./scripts/validate-release-artifacts.py

if command -v xcodebuild >/dev/null 2>&1 && command -v xcodegen >/dev/null 2>&1; then
  bash ./scripts/generate-ios-project.sh
  xcodebuild -project apps/ios/CodexMobile.xcodeproj -scheme CodexMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
    -onlyUsePackageVersionsFromResolvedFile \
    -skipPackagePluginValidation \
    CODE_SIGNING_ALLOWED=NO test
else
  echo 'SKIP: Xcode 26.6/XcodeGen 2.45.4 iOS build requires a configured macOS host.'
fi
