#!/usr/bin/env bash
# Human-confirmed revocation (RT-05): after a person confirms the compromise, the rest is automatic.
# The CRL lands on the shared mount; each edge detects it, reloads its broker and drops the device.
set -euo pipefail
cd "$(dirname "$0")/.."
device="${1:?usage: revoke_device.sh <device-cn>}"
read -r -p "Confirm compromise of $device and revoke its certificate? [type the device name] " answer
[[ "$answer" == "$device" ]] || { echo "not confirmed"; exit 1; }
pki/pki.sh revoke "$device"
echo "CRL published; edges apply it within seconds."
