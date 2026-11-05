#!/bin/bash
# Chaos helper for RT-23: "wan down" cuts the tunnel on every path; "wan fiber-down" only fiber.
# SMS keeps working on "down" because it models the cellular signalling channel, not 4G data.
set -euo pipefail
case "${1:-}" in
  down)
    nft add table inet chaos
    nft 'add chain inet chaos output { type filter hook output priority -10; policy accept; }'
    nft add rule inet chaos output udp dport 51820 drop ;;
  fiber-down)
    nft add table inet chaos
    nft 'add chain inet chaos output { type filter hook output priority -10; policy accept; }'
    nft add rule inet chaos output ip daddr "$HUB_FIBER_IP" udp dport 51820 drop ;;
  up) nft delete table inet chaos 2>/dev/null || true ;;
  status) nft list table inet chaos 2>/dev/null || echo "wan: no chaos rules" ;;
  *) echo "usage: wan down|fiber-down|up|status" >&2; exit 2 ;;
esac
