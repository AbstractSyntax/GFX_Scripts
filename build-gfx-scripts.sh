#!/usr/bin/env bash
# Regenerates GFX1_v6.ps1 through GFX16_v6.ps1 from template/GFX_Setup.ps1.
# Run this on Linux after editing the template. The GFX setup scripts stay PowerShell.
#   ./build-gfx-scripts.sh

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="${root}/template/GFX_Setup.ps1"

if [[ ! -f "${template}" ]]; then
  echo "Missing template: ${template}" >&2
  exit 1
fi

if ! grep -q '__MACHINE_NAME__' "${template}"; then
  echo "template/GFX_Setup.ps1 is missing the __MACHINE_NAME__ token." >&2
  exit 1
fi

for n in $(seq 1 16); do
  machine="gfx${n}"
  out="${root}/GFX${n}_v6.ps1"
  tmp="$(mktemp)"

  # Token swap, then Windows CRLF line endings for the PowerShell scripts.
  tr -d '\r' < "${template}" \
    | sed "s/__MACHINE_NAME__/${machine}/g" \
    | awk 'BEGIN { ORS="\r\n" } { print }' > "${tmp}"

  if grep -q '__MACHINE_NAME__' "${tmp}"; then
    rm -f "${tmp}"
    echo "Token still present after building ${machine}" >&2
    exit 1
  fi

  mv "${tmp}" "${out}"
  echo "Wrote ${out}"
done

echo "Regenerated GFX1_v6.ps1 through GFX16_v6.ps1."
