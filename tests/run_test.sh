#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p tests/fixtures
uv run tools/make_fixture.py tests/fixtures/test.binarycookies

xcodebuild -project GetSafariCookies.xcodeproj -scheme GetSafariCookies \
  -configuration Debug -derivedDataPath build build >/dev/null
BIN="build/Build/Products/Debug/GetSafariCookies"

"$BIN" tests/fixtures/test.binarycookies > build/actual.txt
diff -u tests/fixtures/expected.txt build/actual.txt
echo "PASS"
