#!/bin/bash
# End-to-end check of a running abe against the local nvmet. Needs root
# (nvme-cli, parted, lvs), a running abe, and for the restart scenarios a
# systemd unit called abe on this host. Every scenario cleans up after
# itself; whatever is left on exit is deleted too.
#   sudo ABE_URL=http://127.0.0.1:80 tests/e2e.sh
#
# Scenarios: the original create/connect/write/read/clone/delete pass, then
# port reuse, concurrency, name idempotency, trim, GPT intact, bases and
# seal, re-export across a stop/wipe/start, and the port range running out.
set -euo pipefail
# Default to the address abe is bound to on this host (ABE_LISTEN in
# /etc/default/abe), else the loopback.
if [ -z "${ABE_URL:-}" ] && [ -r /etc/default/abe ]; then
    ABE_URL=$(sed -n 's/^ABE_LISTEN=\(.*\)/http:\/\/\1/p' /etc/default/abe | tail -1)
fi
URL=${ABE_URL:-http://127.0.0.1:80}
modprobe nvme-tcp 2>/dev/null || true   # the initiator side; abe loads the target side
FIO_BS=${E2E_FIO_BS:-4k}
HERE=$(cd "$(dirname "$0")" && pwd)
pass() { echo "  ok  $*"; }
skip() { echo "  skip $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }

tmp=$(mktemp -d)
# Ids of every volume this run created, one per line. A file rather than an
# array because mk() runs inside $(...) and an array append there is lost.
created=$tmp/created; : > "$created"
dropin=/run/systemd/system/abe.service.d/e2e.conf
cleanup() {
    set +e
    while read -r id; do
        [ -n "$id" ] || continue
        nvme disconnect -n "$id" >/dev/null 2>&1
        curl -s -o /dev/null -X DELETE "$URL/id/$id"
    done < "$created"
    if [ -e "$dropin" ]; then
        rm -f "$dropin"; rmdir "$(dirname "$dropin")" 2>/dev/null
        systemctl daemon-reload; systemctl restart abe
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT

# ---- helpers ---------------------------------------------------------------

# mk <query> -> reply JSON (the id is remembered for cleanup)
mk() {
    local r
    r=$(curl -sf "$URL/configure?$1") || fail "configure?$1"
    echo "$r" | jq -r .id >> "$created"
    echo "$r"
}
# status <method> <path> -> HTTP code
status() { curl -s -o /dev/null -w '%{http_code}' -X "$1" "$URL$2"; }
dashed() { echo "$1" | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'; }
byid() { echo "/dev/disk/by-id/nvme-uuid.$(dashed "$1")"; }
# connect <id> <port> -> waits for the by-id device
connect() {
    local dev; dev=$(byid "$1")
    nvme connect -t tcp -a "$TRADDR" -s "$2" -n "$1" >/dev/null || fail "nvme connect $1 on $2"
    for _ in $(seq 1 100); do [ -e "$dev" ] && break; sleep 0.1; done
    [ -e "$dev" ] || { nvme disconnect -n "$1" >/dev/null; fail "$dev never appeared"; }
    udevadm settle 2>/dev/null || true
    echo "$dev"
}
disconnect() { nvme disconnect -n "$1" >/dev/null || fail "nvme disconnect $1"; }
# marker <dev> <text>: write at the start; readback <dev> <text>: expect it
marker() { echo "$2" | dd of="$1" bs=512 count=1 conv=sync,fsync status=none; blockdev --flushbufs "$1"; }
readback() { dd if="$1" bs=512 count=1 status=none | grep -q "$2"; }
del() { curl -sf -X DELETE "$URL/id/$1" >/dev/null || fail "delete $1"; }
volume() { curl -sf "$URL/volumes" | jq -e --arg id "$1" '.[] | select(.id==$id)'; }
wait_api() {
    for _ in $(seq 1 120); do curl -sf "$URL/version" >/dev/null 2>&1 && return 0; sleep 0.5; done
    fail "abe did not come back at $URL"
}
have_systemd() { command -v systemctl >/dev/null && systemctl is-active --quiet abe; }

# ---- 0. what we are talking to --------------------------------------------

v=$(curl -sf "$URL/version") || fail "/version"
echo "$v" | jq -e '.version and (.features | index("reexport")) and (.features | index("ports")) and (.features | index("name")) and (.features | index("trim"))' >/dev/null || fail "/version: $v"
pass "/version $(echo "$v" | jq -c .)"
u=$(curl -sf "$URL/utilization") || fail "/utilization"
VG=$(echo "$u" | jq -r .vg)
THIN=$(echo "$u" | jq -r '.thin_pool // empty')
if [ -n "$THIN" ]; then
    echo "$v" | jq -e '(.features | index("base")) and (.features | index("clone"))' >/dev/null || fail "thin pool but no base/clone feature"
fi
TRADDR=$(curl -sf "$URL/volumes" | jq -r '.[0].traddr // empty')

# ---- 1. the original pass: create, connect, write, read, clone, delete ----

r=$(mk "bytes=$((64<<20))&raw=true")
id=$(echo "$r" | jq -r .id); port=$(echo "$r" | jq -r .port); TRADDR=$(echo "$r" | jq -r .traddr); nqn=$(echo "$r" | jq -r .nqn)
[ "$nqn" = "$id" ] || fail "nqn != id"
[ "$(echo "$r" | jq -r .bytes)" = 67108864 ] || fail "configure reply bytes != 64MiB: $(echo "$r" | jq -c .bytes)"
[ "$(echo "$r" | jq -r .existing)" = false ] || fail "a fresh volume says existing"
pass "configure id=$id port=$port traddr=$TRADDR bytes=$(echo "$r" | jq -r .bytes)"
echo "$r" | jq -e --arg bs "$FIO_BS" '.perf.write_mib_s > 0 and .perf.bs == $bs and .perf.seconds >= 4 and .perf.trimmed == true' >/dev/null || fail "perf missing or wrong in configure reply: $(echo "$r" | jq -c .perf)"
pass "perf $(echo "$r" | jq -r '"\(.perf.write_mib_s) MiB/s, \(.perf.write_iops) IOPS, \(.perf.write_lat_us) us at \(.perf.bs), trimmed=\(.perf.trimmed)"')"

volume "$id" | jq -e --arg p "$port" 'select(.port==$p and .bytes==67108864 and .base==null and .sealed==false and .name==null)' >/dev/null || fail "/volumes lists it"
pass "/volumes"

[ "$TRADDR" = 0.0.0.0 ] && TRADDR=127.0.0.1
dev=$(connect "$id" "$port")
pass "connected, $dev -> $(readlink -f "$dev")"
marker "$dev" "hello abe"
readback "$dev" "hello abe" || fail "readback"
pass "write/read"
disconnect "$id"

curl -sf "$URL/utilization" | jq -e '.bytes > 0 and .used_bytes <= .bytes and .free_bytes == .bytes - .used_bytes and .volumes >= 1 and (.warnings | type == "array") and (.reexport | type == "object")' >/dev/null || fail "/utilization"
pass "/utilization (reexport summary: $(curl -sf "$URL/utilization" | jq -c .reexport))"

if [ -n "$THIN" ]; then
    c=$(curl -sf "$URL/clone/$id?bytes=$((128<<20))") || fail "clone"
    cid=$(echo "$c" | jq -r .id); cport=$(echo "$c" | jq -r .port); echo "$cid" >> "$created"
    echo "$c" | jq -e --arg id "$id" '.origin == $id and .layers == 1 and .bytes == 134217728 and (.warning == null) and .existing == false' >/dev/null || fail "clone reply: $c"
    volume "$cid" | jq -e --arg o "$id" 'select(.origin==$o and .layers==1 and .bytes==134217728)' >/dev/null || fail "/volumes lists the clone"
    cdev=$(connect "$cid" "$cport")
    readback "$cdev" "hello abe" || { disconnect "$cid"; fail "clone does not hold the origin's data"; }
    disconnect "$cid"
    del "$cid"
    pass "clone $cid (origin data visible, grown to 128MiB, deleted)"
else
    skip "clone (no thin pool)"
fi

del "$id"
curl -sf "$URL/volumes" | jq -e --arg id "$id" 'map(select(.id==$id)) | length == 0' >/dev/null || fail "still listed after delete"
[ "$(status DELETE "/id/$id")" = 404 ] || fail "second delete not 404"
pass "disconnect + delete"

# ---- 2. port reuse: A B C, delete B, D gets B's port ----------------------

a=$(mk "bytes=$((32<<20))&raw=true"); b=$(mk "bytes=$((32<<20))&raw=true"); c=$(mk "bytes=$((32<<20))&raw=true")
bport=$(echo "$b" | jq -r .port)
del "$(echo "$b" | jq -r .id)"
d=$(mk "bytes=$((32<<20))&raw=true")
[ "$(echo "$d" | jq -r .port)" = "$bport" ] || fail "D got port $(echo "$d" | jq -r .port), B had $bport"
for x in "$a" "$c" "$d"; do del "$(echo "$x" | jq -r .id)"; done
pass "port reuse: D took B's port $bport"

# ---- 3. concurrency: 8 parallel creates -----------------------------------

for i in $(seq 1 8); do
    curl -sf "$URL/configure?bytes=$((32<<20))&raw=true" > "$tmp/c$i" &
done
wait
ids=(); ports=()
for i in $(seq 1 8); do
    [ -s "$tmp/c$i" ] || fail "parallel create $i failed"
    ids+=("$(jq -r .id "$tmp/c$i")"); ports+=("$(jq -r .port "$tmp/c$i")")
done
printf "%s\n" "${ids[@]}" >> "$created"
[ "$(printf '%s\n' "${ports[@]}" | sort -u | wc -l)" = 8 ] || fail "8 creates gave ports: ${ports[*]}"
[ "$(printf '%s\n' "${ids[@]}" | sort -u | wc -l)" = 8 ] || fail "8 creates gave ids: ${ids[*]}"
for i in "${!ids[@]}"; do
    volume "${ids[$i]}" >/dev/null || fail "${ids[$i]} not in /volumes"
    connect "${ids[$i]}" "${ports[$i]}" >/dev/null
    disconnect "${ids[$i]}"
done
for i in "${ids[@]}"; do del "$i"; done
pass "concurrency: 8 parallel creates, 8 distinct ports (${ports[*]}), all connectable"

# ---- 4. name idempotency ---------------------------------------------------

curl -sf "$URL/configure?bytes=$((32<<20))&raw=true&name=e2e-x" > "$tmp/n1" &
curl -sf "$URL/configure?bytes=$((32<<20))&raw=true&name=e2e-x" > "$tmp/n2" &
wait
[ -s "$tmp/n1" ] && [ -s "$tmp/n2" ] || fail "named creates failed"
n1=$(jq -r .id "$tmp/n1"); n2=$(jq -r .id "$tmp/n2"); echo "$n1" >> "$created"
[ "$n1" = "$n2" ] || fail "name=e2e-x gave two ids $n1 $n2"
[[ "$(jq -r .existing "$tmp/n1")$(jq -r .existing "$tmp/n2")" == *true* ]] || fail "neither named reply says existing"
[ "$(lvs --noheadings -o lv_tags "$VG" | grep -c 'abe_name=e2e-x')" = 1 ] || fail "not exactly one LV tagged abe_name=e2e-x"
volume "$n1" | jq -e 'select(.name=="e2e-x")' >/dev/null || fail "/volumes does not show name"
n3=$(curl -sf "$URL/configure?bytes=$((32<<20))&raw=true&name=e2e-x") || fail "named retry"
[ "$(echo "$n3" | jq -r '.id + " " + (.existing|tostring)')" = "$n1 true" ] || fail "retry did not return the same volume: $n3"
[ "$(status GET "/configure?bytes=$((64<<20))&raw=true&name=e2e-x")" = 409 ] || fail "bigger request on the same name not 409"
[ "$(status GET "/configure?bytes=$((32<<20))&name=bad%20name")" = 400 ] || fail "bad name not 400"
del "$n1"
pass "name idempotency: e2e-x -> $n1 once"

# ---- 5. trim: a 2 GiB raw thin volume occupies (almost) nothing -----------

if [ -n "$THIN" ]; then
    t=$(mk "bytes=$((2<<30))&raw=true")
    tid=$(echo "$t" | jq -r .id)
    [ "$(echo "$t" | jq -r .perf.trimmed)" = true ] || fail "perf.trimmed not true: $(echo "$t" | jq -c .perf)"
    used=$(volume "$tid" | jq -r .used_bytes)
    [ "$used" -lt $((64<<20)) ] || fail "2 GiB volume uses $used bytes after fio+trim"
    tdev=$(connect "$tid" "$(echo "$t" | jq -r .port)")
    cmp -n $((64<<20)) /dev/zero "$tdev" || { disconnect "$tid"; fail "first 64 MiB not zero after trim"; }
    disconnect "$tid"
    del "$tid"
    pass "trim: 2 GiB raw volume uses $used bytes, reads zeros"
else
    skip "trim accounting (no thin pool)"
fi

# ---- 6. GPT intact on a non-raw volume -------------------------------------

g=$(mk "bytes=$((64<<20))")
gid=$(echo "$g" | jq -r .id)
echo "$g" | jq -e '.perf.trimmed == true' >/dev/null || fail "non-raw perf: $(echo "$g" | jq -c .perf)"
gdev=$(connect "$gid" "$(echo "$g" | jq -r .port)")
for _ in $(seq 1 100); do [ -e "/dev/disk/by-partlabel/$gid" ] && break; sleep 0.1; done
[ -e "/dev/disk/by-partlabel/$gid" ] || { disconnect "$gid"; fail "/dev/disk/by-partlabel/$gid missing"; }
parted -s "$gdev" print | grep -qE '^ *1 ' || { disconnect "$gid"; fail "parted lists no partition 1 on $gdev"; }
disconnect "$gid"
del "$gid"
pass "GPT intact: by-partlabel/$gid and partition 1 present"

# ---- 7. bases: make, fill, seal, clone twice, delete the base -------------

if [ -n "$THIN" ]; then
    b=$(mk "base=e2e-img&bytes=$((64<<20))")
    bid=$(echo "$b" | jq -r .id)
    echo "$b" | jq -e '.base == "e2e-img" and .sealed == false and .existing == false and .perf == null and .port != ""' >/dev/null || fail "base reply: $b"
    b2=$(curl -sf "$URL/configure?base=e2e-img&bytes=$((64<<20))") || fail "base again"
    [ "$(echo "$b2" | jq -r '.id + " " + (.existing|tostring)')" = "$bid true" ] || fail "second base request made another: $b2"
    [ "$(status GET "/configure?base=e2e-img&bytes=$((128<<20))")" = 409 ] || fail "bigger base request not 409"
    [ "$(status GET "/clone/$bid")" = 409 ] || fail "clone of an unsealed base not 409"
    bdev=$(connect "$bid" "$(echo "$b" | jq -r .port)")
    marker "$bdev" "base image"
    disconnect "$bid"
    s=$(curl -sf "$URL/seal/$bid") || fail "seal"
    echo "$s" | jq -e --arg id "$bid" '.id == $id and .base == "e2e-img" and .sealed == true and .bytes == 67108864' >/dev/null || fail "seal reply: $s"
    curl -sf "$URL/seal/$bid" >/dev/null || fail "sealing twice"
    [ "$(status GET "/id/$bid")" = 409 ] || fail "GET /id on a sealed base not 409"
    volume "$bid" | jq -e 'select(.port==null and .sealed==true and .base=="e2e-img")' >/dev/null || fail "/volumes after seal"
    b3=$(curl -sf "$URL/configure?base=e2e-img&bytes=$((64<<20))") || fail "sealed base request"
    echo "$b3" | jq -e --arg id "$bid" '.id == $id and .sealed == true and .port == ""' >/dev/null || fail "sealed base reply: $b3"
    cl=()
    for n in 1 2; do
        c=$(curl -sf "$URL/clone/$bid?bytes=$((64<<20))&name=e2e-clone-$n") || fail "clone $n of the base"
        cid=$(echo "$c" | jq -r .id); echo "$cid" >> "$created"; cl+=("$cid")
        volume "$cid" | jq -e --arg o "$bid" 'select(.origin==$o and .base==null and .sealed==false and .name=="e2e-clone-'"$n"'")' >/dev/null || fail "/volumes for clone $n"
        cdev=$(connect "$cid" "$(echo "$c" | jq -r .port)")
        readback "$cdev" "base image" || { disconnect "$cid"; fail "clone $n does not read the base marker"; }
        disconnect "$cid"
        used=$(volume "$cid" | jq -r .used_bytes)
        [ "$used" -lt $((8<<20)) ] || fail "clone $n uses $used bytes"
    done
    del "$bid"
    for cid in "${cl[@]}"; do
        c=$(curl -sf "$URL/id/$cid") || fail "re-attach clone"
        cdev=$(connect "$cid" "$(echo "$c" | jq -r .port)")
        readback "$cdev" "base image" || { disconnect "$cid"; fail "clone lost its data when the base went"; }
        disconnect "$cid"
        del "$cid"
    done
    pass "bases: $bid filled, sealed, cloned twice, deleted; clones kept the data"
else
    skip "bases (no thin pool)"
fi

# ---- 8. re-export after stop / configfs wipe / start ----------------------

if have_systemd; then
    r1=$(mk "bytes=$((32<<20))&raw=true"); r2=$(mk "bytes=$((32<<20))&raw=true")
    rid1=$(echo "$r1" | jq -r .id); rid2=$(echo "$r2" | jq -r .id)
    rp1=$(echo "$r1" | jq -r .port); rp2=$(echo "$r2" | jq -r .port)
    d1=$(connect "$rid1" "$rp1"); marker "$d1" "marker one"; disconnect "$rid1"
    d2=$(connect "$rid2" "$rp2"); marker "$d2" "marker two"; disconnect "$rid2"
    systemctl stop abe
    "$HERE/nvmet-wipe.sh" >/dev/null
    [ -z "$(ls "${ABE_NVMET_PATH:-/sys/kernel/config/nvmet}/subsystems" 2>/dev/null | grep -E '^[0-9a-f]{32}$')" ] || fail "wipe left abe subsystems behind"
    systemctl start abe
    wait_api
    curl -sf "$URL/utilization" | jq -e '.reexport.exported >= 2 and (.reexport.failed | length) == 0' >/dev/null || fail "re-export summary: $(curl -sf "$URL/utilization" | jq -c .reexport)"
    [ "$(volume "$rid1" | jq -r .port)" = "$rp1" ] || fail "$rid1 came back on $(volume "$rid1" | jq -r .port), was $rp1"
    [ "$(volume "$rid2" | jq -r .port)" = "$rp2" ] || fail "$rid2 came back on $(volume "$rid2" | jq -r .port), was $rp2"
    d1=$(connect "$rid1" "$rp1"); readback "$d1" "marker one" || { disconnect "$rid1"; fail "marker one gone"; }; disconnect "$rid1"
    d2=$(connect "$rid2" "$rp2"); readback "$d2" "marker two" || { disconnect "$rid2"; fail "marker two gone"; }; disconnect "$rid2"
    curl -sf "$URL/reexport" | jq -e '.already >= 2 and (.failed | length) == 0' >/dev/null || fail "GET /reexport"
    del "$rid1"; del "$rid2"
    pass "re-export: both volumes back on $rp1 and $rp2 with their data"
else
    skip "re-export (no local abe.service)"
fi

# ---- 9. port range exhausted ----------------------------------------------

if have_systemd && [ "$(curl -sf "$URL/volumes" | jq length)" = 0 ]; then
    mkdir -p "$(dirname "$dropin")"
    printf '[Service]\nEnvironment=ABE_PORT_MIN=44001\nEnvironment=ABE_PORT_MAX=44002\n' > "$dropin"
    systemctl daemon-reload; systemctl restart abe; wait_api
    before=$(lvs --noheadings -o lv_name "$VG" | grep -cE '^ *[0-9a-f]{32} *$' || true)
    x1=$(mk "bytes=$((32<<20))&raw=true"); x2=$(mk "bytes=$((32<<20))&raw=true")
    code=$(curl -s -o "$tmp/x3" -w '%{http_code}' "$URL/configure?bytes=$((32<<20))&raw=true")
    [ "$code" = 503 ] || fail "third create in a 2-port range gave $code: $(cat "$tmp/x3")"
    grep -q 'no free nvmet port in 44001-44002' "$tmp/x3" || fail "503 body: $(cat "$tmp/x3")"
    after=$(lvs --noheadings -o lv_name "$VG" | grep -cE '^ *[0-9a-f]{32} *$' || true)
    [ "$after" = $((before + 2)) ] || fail "a third LV was left behind ($before -> $after)"
    del "$(echo "$x1" | jq -r .id)"; del "$(echo "$x2" | jq -r .id)"
    rm -f "$dropin"; rmdir "$(dirname "$dropin")" 2>/dev/null || true
    systemctl daemon-reload; systemctl restart abe; wait_api
    pass "range exhausted: third create -> 503, no LV left behind"
else
    skip "range exhausted (needs a local abe.service and no other volumes)"
fi

echo "all passed"
