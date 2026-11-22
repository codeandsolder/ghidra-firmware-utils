#!/usr/bin/env bash
set -euo pipefail
# Same release as the normal extension build, verified against the release digest.
root=$(mktemp -d "$RUNNER_TEMP/ghidra-XXXXXXXX")
trap 'rm -rf -- "$root"' EXIT
archive=ghidra_12.0_PUBLIC_20251205.zip
curl --fail --location --retry 3 --output "$root/$archive" "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0_build/$archive"
printf '%s  %s\n' af43e8cfb2fa4490cf6020c3a2bde25c159d83f45236a0542688a024e8fc1941 "$root/$archive" | sha256sum --check
unzip -q "$root/$archive" -d "$root"
./gradlew --no-daemon -PGHIDRA_INSTALL_DIR="$root/ghidra_12.0_PUBLIC" efidecompressSharedLibrary copyLibraries buildExtension
