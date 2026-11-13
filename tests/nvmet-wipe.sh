#!/bin/bash
# Tear down abe's exports in nvmet configfs the way a reboot would: unlink
# every subsystem from its port, remove the port if it is then empty, disable
# and remove the namespaces, remove the subsystem. By default only abe's
# subsystems (named by a 32-hex volume id) are touched; --all takes down
# every subsystem and port, and abe's nftables fence (table inet abe) with
# them. Needs root. abe should be stopped first, or it will not notice
# (its re-export pass runs at startup and on GET /reexport).
#   sudo tests/nvmet-wipe.sh [--all]
set -euo pipefail
root=${ABE_NVMET_PATH:-/sys/kernel/config/nvmet}
all=0
[ "${1:-}" = "--all" ] && all=1
[ -d "$root" ] || { echo "no $root"; exit 0; }

mine() { [ "$all" = 1 ] || [[ "$1" =~ ^[0-9a-f]{32}$ ]]; }

n=0
for link in "$root"/ports/*/subsystems/*; do
    [ -L "$link" ] || continue
    mine "$(basename "$link")" || continue
    rm "$link"
    port=$(dirname "$(dirname "$link")")
    if [ -z "$(ls -A "$port/subsystems")" ]; then
        rmdir "$port"
    fi
done
for sub in "$root"/subsystems/*; do
    [ -d "$sub" ] || continue
    mine "$(basename "$sub")" || continue
    for ns in "$sub"/namespaces/*; do
        [ -d "$ns" ] || continue
        echo 0 > "$ns/enable" 2>/dev/null || true
        rmdir "$ns"
    done
    rmdir "$sub"
    n=$((n + 1))
done
if [ "$all" = 1 ]; then
    nft destroy table inet abe 2>/dev/null || true
fi
echo "removed $n subsystem(s); ports left: $(ls "$root/ports" | tr '\n' ' ')"
