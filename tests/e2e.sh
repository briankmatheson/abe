#!/bin/bash
# End-to-end check of a running abe against the local nvmet: create a raw
# volume, connect to it from this host, find it by stable id, write/read,
# disconnect, delete. Needs root (nvme-cli) and a running abe.
#   sudo ABE_URL=http://127.0.0.1:80 tests/e2e.sh
set -euo pipefail
URL=${ABE_URL:-http://127.0.0.1:80}
pass() { echo "  ok  $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }

r=$(curl -sf "$URL/configure?bytes=$((64<<20))&raw=true") || fail "configure"
id=$(echo "$r" | jq -r .id); port=$(echo "$r" | jq -r .port); traddr=$(echo "$r" | jq -r .traddr); nqn=$(echo "$r" | jq -r .nqn)
[ "$nqn" = "$id" ] || fail "nqn != id"
pass "configure id=$id port=$port traddr=$traddr"

curl -sf "$URL/volumes" | jq -e --arg id "$id" --arg p "$port" '.[] | select(.id==$id and .port==$p and .bytes==67108864)' >/dev/null || fail "/volumes lists it"
pass "/volumes"

dashed=$(echo "$id" | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/')
byid=/dev/disk/by-id/nvme-uuid.$dashed
[ "$traddr" = 0.0.0.0 ] && traddr=127.0.0.1
nvme connect -t tcp -a "$traddr" -s "$port" -n "$id" >/dev/null || fail "nvme connect"
for i in $(seq 1 50); do [ -e "$byid" ] && break; sleep 0.1; done
[ -e "$byid" ] || { nvme disconnect -n "$id" >/dev/null; fail "$byid never appeared"; }
pass "connected, $byid -> $(readlink -f "$byid")"

echo "hello abe" | dd of="$byid" bs=512 count=1 conv=sync,fsync status=none
blockdev --flushbufs "$byid"
dd if="$byid" bs=512 count=1 status=none | grep -q "hello abe" || fail "readback"
pass "write/read"

nvme disconnect -n "$id" >/dev/null || fail "disconnect"
curl -sf -X DELETE "$URL/id/$id" >/dev/null || fail "delete"
curl -sf "$URL/volumes" | jq -e --arg id "$id" 'map(select(.id==$id)) | length == 0' >/dev/null || fail "still listed after delete"
curl -s -o /dev/null -w '%{http_code}' -X DELETE "$URL/id/$id" | grep -q 404 || fail "second delete not 404"
pass "disconnect + delete"
echo "all passed"
