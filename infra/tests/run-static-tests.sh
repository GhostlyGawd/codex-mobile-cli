#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"
python3 -m unittest discover -s infra/tests -p 'test_*.py' -v
python3 scripts/check-billing-policy.py --repo-root "$repo_root" \
  --deployment-profile owner_pc_beta
