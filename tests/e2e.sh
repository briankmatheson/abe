#!/bin/bash
# End-to-end check of a running abe against the local nvmet. Needs root
# (nvme-cli, parted, lvs, nft), a running abe, and for the restart
# scenarios a systemd unit called abe on this host. Every scenario cleans
# up after itself; whatever is left on exit is deleted too.
#   sudo tests/e2e.sh                       # reads /etc/default/abe
#   sudo ABE_URL=https://10.22.1.1:443 tests/e2e.sh
#   sudo ABE_TLS=off ABE_URL=http://127.0.0.1:8080 tests/e2e.sh
#
# Scenarios: the original create/connect/write/read/clone/delete pass, then
# port reuse, concurrency, name idempotency, trim, GPT intact, bases and
# seal, re-export across a stop/wipe/start, the port range running out,
# TLS without a client cert, the nvmet fence (basic, from a second local
# address, adoption across a restart) and GET /reexport rebuilding it.
#
# This is also the model for scripting abe: every request goes through
# $CURL, which carries --cacert/--cert/--key when ABE_TLS is on.
set -euo pipefail
# ABE_TLS, ABE_TLS_CERT/KEY/CA and ABE_LISTEN: the environment wins, then
# /etc/default/abe, then abe's own defaults.
cfg() { [ -r /etc/default/abe ] && sed -n "s/^$1=\(.*\)/\1/p" /etc/default/abe | tail -1 | tr -d '"'"'"; true; }
ABE_TLS=${ABE_TLS:-$(cfg ABE_TLS)}; ABE_TLS=${ABE_TLS:-on}
ABE_TLS_CERT=${ABE_TLS_CERT:-$(cfg ABE_TLS_CERT)}; ABE_TLS_CERT=${ABE_TLS_CERT:-/etc/abe/cert.pem}
ABE_TLS_KEY=${ABE_TLS_KEY:-$(cfg ABE_TLS_KEY)}; ABE_TLS_KEY=${ABE_TLS_KEY:-/etc/abe/key.pem}
ABE_TLS_CA=${ABE_TLS_CA:-$(cfg ABE_TLS_CA)}; ABE_TLS_CA=${ABE_TLS_CA:-/etc/abe/ca.pem}
if [ "$ABE_TLS" = off ]; then
    SCHEME=http; CURL="curl"
else
    SCHEME=https; CURL="curl --cacert $ABE_TLS_CA --cert $ABE_TLS_CERT --key $ABE_TLS_KEY"
fi
# Default to the address abe is bound to on this host (ABE_LISTEN), else
# the loopback. A wildcard bind is reached through the loopback.
if [ -z "${ABE_URL:-}" ]; then
    listen=$(cfg ABE_LISTEN); listen=${listen:-127.0.0.1:443}
    ABE_URL="$SCHEME://${listen/0.0.0.0/127.0.0.1}"
fi
URL=$ABE_URL
# The address abe sees our requests from (what it fences ports to).
APIHOST=$(echo "$URL" | sed -E 's#^[a-z]+://##; s#/.*##; s#:[0-9]+$##')
MYIP=$(ip -o route get "$APIHOST" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
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
        $CURL -s -o /dev/null -X DELETE "$URL/id/$id"
    done < "$created"
    if [ -e "$dropin" ]; then
        rm -f "$dropin"; rmdir "$(dirname "$dropin")" 2>/dev/null
        systemctl daemon-reload; systemctl restart abe
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT

# ---- helpers ---------------------------------------------------------------

# mk <query> [curl args...] -> reply JSON (the id is remembered for cleanup)
mk() {
    local q=$1 r; shift
    r=$($CURL -sf "$@" "$URL/configure?$q") || fail "configure?$q"
    echo "$r" | jq -r .id >> "$created"
    echo "$r"
}
# status <method> <path> -> HTTP code
status() { $CURL -s -o /dev/null -w '%{http_code}' -X "$1" "$URL$2"; }
dashed() { echo "$1" | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'; }
byid() { echo "/dev/disk/by-id/nvme-uuid.$(dashed "$1")"; }
# connect <id> <port> [nvme connect args...] -> waits for the by-id device
connect() {
    local id=$1 port=$2 dev; shift 2; dev=$(byid "$id")
    nvme connect -t tcp -a "$TRADDR" -s "$port" -n "$id" "$@" >/dev/null || fail "nvme connect $id on $port $*"
    for _ in $(seq 1 100); do [ -e "$dev" ] && break; sleep 0.1; done
    [ -e "$dev" ] || { nvme disconnect -n "$id" >/dev/null; fail "$dev never appeared"; }
    udevadm settle 2>/dev/null || true
    echo "$dev"
}
disconnect() { nvme disconnect -n "$1" >/dev/null || fail "nvme disconnect $1"; }
# marker <dev> <text>: write at the start; readback <dev> <text>: expect it
marker() { echo "$2" | dd of="$1" bs=512 count=1 conv=sync,fsync status=none; blockdev --flushbufs "$1"; }
readback() { dd if="$1" bs=512 count=1 status=none | grep -q "$2"; }
del() { $CURL -sf -X DELETE "$URL/id/$1" >/dev/null || fail "delete $1"; }
volume() { $CURL -sf "$URL/volumes" | jq -e --arg id "$1" '.[] | select(.id==$id)'; }
wait_api() {
    for _ in $(seq 1 120); do $CURL -sf "$URL/version" >/dev/null 2>&1 && return 0; sleep 0.5; done
    fail "abe did not come back at $URL"
}
have_systemd() { command -v systemctl >/dev/null && systemctl is-active --quiet abe; }
# fenced <ip> <port>: is that pair in the nvmet fence right now?
fenced() { nft list set inet abe allowed 2>/dev/null | tr -d '\n\t' | grep -qE "(\{|,) *$1 \. $2 *(,|\})"; }
# nvme connect that is expected to be refused: true when it was
refused() { ! nvme connect -t tcp -a "$TRADDR" -s "$2" -n "$1" --ctrl-loss-tmo 2 "${@:3}" >/dev/null 2>&1 || { nvme disconnect -n "$1" >/dev/null 2>&1; false; }; }

# ---- 0. what we are talking to --------------------------------------------

v=$($CURL -sf "$URL/version") || fail "/version"
echo "$v" | jq -e '.version and (.features | index("reexport")) and (.features | index("ports")) and (.features | index("name")) and (.features | index("trim")) and (.features | index("tls")) and (.features | index("fence"))' >/dev/null || fail "/version: $v"
if [ "$ABE_TLS" = off ]; then
    [ "$(echo "$v" | jq -r .tls)" = false ] || fail "/version says tls but ABE_TLS=off"
else
    [ "$(echo "$v" | jq -r .tls)" = true ] || fail "/version does not say tls: $v"
fi
pass "/version $(echo "$v" | jq -c .)"
u=$($CURL -sf "$URL/utilization") || fail "/utilization"
VG=$(echo "$u" | jq -r .vg)
THIN=$(echo "$u" | jq -r '.thin_pool // empty')
if [ -n "$THIN" ]; then
    echo "$v" | jq -e '(.features | index("base")) and (.features | index("clone"))' >/dev/null || fail "thin pool but no base/clone feature"
fi
TRADDR=$($CURL -sf "$URL/volumes" | jq -r '.[0].traddr // empty')

# ---- 1. the original pass: create, connect, write, read, clone, delete ----

r=$(mk "bytes=$((64<<20))&raw=true")
id=$(echo "$r" | jq -r .id); port=$(echo "$r" | jq -r .port); TRADDR=$(echo "$r" | jq -r .traddr); nqn=$(echo "$r" | jq -r .nqn)
[ "$nqn" = "$id" ] || fail "nqn != id"
[ "$(echo "$r" | jq -r .bytes)" = 67108864 ] || fail "configure reply bytes != 64MiB: $(echo "$r" | jq -c .bytes)"
[ "$(echo "$r" | jq -r .existing)" = false ] || fail "a fresh volume says existing"
CLIENT=$(echo "$r" | jq -r '.client // empty'); [ -n "$CLIENT" ] || fail "configure reply has no client: $r"
[ -z "$MYIP" ] || [ "$CLIENT" = "$MYIP" ] || fail "abe fenced to $CLIENT, we came from $MYIP"
MYIP=$CLIENT
pass "configure id=$id port=$port traddr=$TRADDR bytes=$(echo "$r" | jq -r .bytes) client=$CLIENT"
echo "$r" | jq -e --arg bs "$FIO_BS" '.perf.write_mib_s > 0 and .perf.bs == $bs and .perf.seconds >= 4 and .perf.trimmed == true' >/dev/null || fail "perf missing or wrong in configure reply: $(echo "$r" | jq -c .perf)"
pass "perf $(echo "$r" | jq -r '"\(.perf.write_mib_s) MiB/s, \(.perf.write_iops) IOPS, \(.perf.write_lat_us) us at \(.perf.bs), trimmed=\(.perf.trimmed)"')"

volume "$id" | jq -e --arg p "$port" --arg c "$MYIP" 'select(.port==$p and .bytes==67108864 and .base==null and .sealed==false and .name==null and .client==$c)' >/dev/null || fail "/volumes lists it with client $MYIP"
pass "/volumes"

[ "$TRADDR" = 0.0.0.0 ] && TRADDR=127.0.0.1
dev=$(connect "$id" "$port")
pass "connected, $dev -> $(readlink -f "$dev")"
marker "$dev" "hello abe"
readback "$dev" "hello abe" || fail "readback"
pass "write/read"
disconnect "$id"

$CURL -sf "$URL/utilization" | jq -e '.bytes > 0 and .used_bytes <= .bytes and .free_bytes == .bytes - .used_bytes and .volumes >= 1 and (.warnings | type == "array") and (.reexport | type == "object")' >/dev/null || fail "/utilization"
pass "/utilization (reexport summary: $($CURL -sf "$URL/utilization" | jq -c .reexport))"

if [ -n "$THIN" ]; then
    c=$($CURL -sf "$URL/clone/$id?bytes=$((128<<20))") || fail "clone"
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
$CURL -sf "$URL/volumes" | jq -e --arg id "$id" 'map(select(.id==$id)) | length == 0' >/dev/null || fail "still listed after delete"
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
    $CURL -sf "$URL/configure?bytes=$((32<<20))&raw=true" > "$tmp/c$i" &
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

$CURL -sf "$URL/configure?bytes=$((32<<20))&raw=true&name=e2e-x" > "$tmp/n1" &
$CURL -sf "$URL/configure?bytes=$((32<<20))&raw=true&name=e2e-x" > "$tmp/n2" &
wait
[ -s "$tmp/n1" ] && [ -s "$tmp/n2" ] || fail "named creates failed"
n1=$(jq -r .id "$tmp/n1"); n2=$(jq -r .id "$tmp/n2"); echo "$n1" >> "$created"
[ "$n1" = "$n2" ] || fail "name=e2e-x gave two ids $n1 $n2"
[[ "$(jq -r .existing "$tmp/n1")$(jq -r .existing "$tmp/n2")" == *true* ]] || fail "neither named reply says existing"
[ "$(lvs --noheadings -o lv_tags "$VG" | grep -c 'abe_name=e2e-x')" = 1 ] || fail "not exactly one LV tagged abe_name=e2e-x"
volume "$n1" | jq -e 'select(.name=="e2e-x")' >/dev/null || fail "/volumes does not show name"
n3=$($CURL -sf "$URL/configure?bytes=$((32<<20))&raw=true&name=e2e-x") || fail "named retry"
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
    b2=$($CURL -sf "$URL/configure?base=e2e-img&bytes=$((64<<20))") || fail "base again"
    [ "$(echo "$b2" | jq -r '.id + " " + (.existing|tostring)')" = "$bid true" ] || fail "second base request made another: $b2"
    [ "$(status GET "/configure?base=e2e-img&bytes=$((128<<20))")" = 409 ] || fail "bigger base request not 409"
    [ "$(status GET "/clone/$bid")" = 409 ] || fail "clone of an unsealed base not 409"
    bdev=$(connect "$bid" "$(echo "$b" | jq -r .port)")
    marker "$bdev" "base image"
    disconnect "$bid"
    s=$($CURL -sf "$URL/seal/$bid") || fail "seal"
    echo "$s" | jq -e --arg id "$bid" '.id == $id and .base == "e2e-img" and .sealed == true and .bytes == 67108864' >/dev/null || fail "seal reply: $s"
    $CURL -sf "$URL/seal/$bid" >/dev/null || fail "sealing twice"
    [ "$(status GET "/id/$bid")" = 409 ] || fail "GET /id on a sealed base not 409"
    volume "$bid" | jq -e 'select(.port==null and .sealed==true and .base=="e2e-img")' >/dev/null || fail "/volumes after seal"
    b3=$($CURL -sf "$URL/configure?base=e2e-img&bytes=$((64<<20))") || fail "sealed base request"
    echo "$b3" | jq -e --arg id "$bid" '.id == $id and .sealed == true and .port == ""' >/dev/null || fail "sealed base reply: $b3"
    cl=()
    for n in 1 2; do
        c=$($CURL -sf "$URL/clone/$bid?bytes=$((64<<20))&name=e2e-clone-$n") || fail "clone $n of the base"
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
        c=$($CURL -sf "$URL/id/$cid") || fail "re-attach clone"
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
    $CURL -sf "$URL/utilization" | jq -e '.reexport.exported >= 2 and (.reexport.failed | length) == 0' >/dev/null || fail "re-export summary: $($CURL -sf "$URL/utilization" | jq -c .reexport)"
    [ "$(volume "$rid1" | jq -r .port)" = "$rp1" ] || fail "$rid1 came back on $(volume "$rid1" | jq -r .port), was $rp1"
    [ "$(volume "$rid2" | jq -r .port)" = "$rp2" ] || fail "$rid2 came back on $(volume "$rid2" | jq -r .port), was $rp2"
    d1=$(connect "$rid1" "$rp1"); readback "$d1" "marker one" || { disconnect "$rid1"; fail "marker one gone"; }; disconnect "$rid1"
    d2=$(connect "$rid2" "$rp2"); readback "$d2" "marker two" || { disconnect "$rid2"; fail "marker two gone"; }; disconnect "$rid2"
    $CURL -sf "$URL/reexport" | jq -e '.already >= 2 and (.failed | length) == 0' >/dev/null || fail "GET /reexport"
    del "$rid1"; del "$rid2"
    pass "re-export: both volumes back on $rp1 and $rp2 with their data"
else
    skip "re-export (no local abe.service)"
fi

# ---- 9. port range exhausted ----------------------------------------------

if have_systemd && [ "$($CURL -sf "$URL/volumes" | jq length)" = 0 ]; then
    mkdir -p "$(dirname "$dropin")"
    printf '[Service]\nEnvironment=ABE_PORT_MIN=44001\nEnvironment=ABE_PORT_MAX=44002\n' > "$dropin"
    systemctl daemon-reload; systemctl restart abe; wait_api
    before=$(lvs --noheadings -o lv_name "$VG" | grep -cE '^ *[0-9a-f]{32} *$' || true)
    x1=$(mk "bytes=$((32<<20))&raw=true"); x2=$(mk "bytes=$((32<<20))&raw=true")
    code=$($CURL -s -o "$tmp/x3" -w '%{http_code}' "$URL/configure?bytes=$((32<<20))&raw=true")
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

# ---- 10. TLS: no client cert -> refused -----------------------------------

if [ "$ABE_TLS" = off ]; then
    skip "no cert -> refused (ABE_TLS=off)"
else
    code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$ABE_TLS_CA" "$URL/version" 2>/dev/null) && fail "no client cert but curl succeeded ($code)"
    [ "${code:-000}" = 000 ] || fail "no client cert gave an HTTP status $code"
    code=$(curl -sk -o /dev/null -w '%{http_code}' "$URL/version" 2>/dev/null) && fail "curl -k without a cert succeeded ($code)"
    [ "${code:-000}" = 000 ] || fail "curl -k without a cert gave an HTTP status $code"
    curl -sf --cacert "$ABE_TLS_CA" --cert "$ABE_TLS_CERT" --key "$ABE_TLS_KEY" "$URL/version" >/dev/null || fail "with the cert /version failed"
    pass "no client cert -> handshake refused (with --cacert, and with -k)"
fi

# ---- 11. fence basic: the set follows configure and DELETE ----------------

f=$(mk "bytes=$((32<<20))&raw=true")
fid=$(echo "$f" | jq -r .id); fport=$(echo "$f" | jq -r .port)
fenced "$MYIP" "$fport" || fail "after configure the fence lacks $MYIP . $fport: $(nft list set inet abe allowed 2>&1 | tr -s ' \n\t' ' ')"
fdev=$(connect "$fid" "$fport"); marker "$fdev" "fenced"; readback "$fdev" "fenced" || fail "readback through the fence"; disconnect "$fid"
del "$fid"
! fenced "$MYIP" "$fport" || fail "after DELETE the fence still has $MYIP . $fport"
pass "fence: $MYIP . $fport present after configure, gone after DELETE"

# ---- 12. fence negative: from a second local address ---------------------

ALT=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -vxF -e "$MYIP" -e "$TRADDR" -e "$APIHOST" | head -1 || true)
if [ -z "$ALT" ]; then
    skip "fence negative (no second local IPv4 besides $MYIP)"
else
    a=$(mk "bytes=$((32<<20))&raw=true" --interface "$ALT")
    aid=$(echo "$a" | jq -r .id); aport=$(echo "$a" | jq -r .port)
    [ "$(echo "$a" | jq -r .client)" = "$ALT" ] || fail "configure via $ALT fenced to $(echo "$a" | jq -r .client)"
    fenced "$ALT" "$aport" || fail "fence lacks $ALT . $aport"
    ! fenced "$MYIP" "$aport" || fail "fence also has $MYIP . $aport"
    refused "$aid" "$aport" || fail "nvme connect from $MYIP to $aport (fenced to $ALT) succeeded"
    adev=$(connect "$aid" "$aport" --host-traddr "$ALT")
    marker "$adev" "from alt"; readback "$adev" "from alt" || { disconnect "$aid"; fail "write/read from $ALT"; }
    disconnect "$aid"
    # GET /id from the default source moves the port to us
    g=$($CURL -sf "$URL/id/$aid") || fail "GET /id/$aid"
    [ "$(echo "$g" | jq -r .client)" = "$MYIP" ] || fail "GET /id fenced to $(echo "$g" | jq -r .client), not $MYIP"
    fenced "$MYIP" "$aport" || fail "after GET /id the fence lacks $MYIP . $aport"
    ! fenced "$ALT" "$aport" || fail "after GET /id the fence still has $ALT . $aport"
    refused "$aid" "$aport" --host-traddr "$ALT" || fail "nvme connect from $ALT still works after the port moved to $MYIP"
    adev=$(connect "$aid" "$aport"); readback "$adev" "from alt" || { disconnect "$aid"; fail "data written from $ALT not seen from $MYIP"; }
    disconnect "$aid"
    del "$aid"
    pass "fence negative: $aport open to $ALT only (connect from $MYIP refused), then moved to $MYIP by GET /id"
fi

# ---- 13. adoption on re-export ---------------------------------------------

if have_systemd; then
    # a connected volume without a client tag (a 0.4.0 export) is adopted
    p1=$(mk "bytes=$((32<<20))&raw=true")
    pid1=$(echo "$p1" | jq -r .id); pp1=$(echo "$p1" | jq -r .port)
    pdev=$(connect "$pid1" "$pp1"); marker "$pdev" "adopt me"
    lvchange --deltag "abe_client=$MYIP" "$VG/$pid1" >/dev/null || fail "lvchange --deltag"
    systemctl restart abe; wait_api
    ux=$($CURL -sf "$URL/utilization")
    echo "$ux" | jq -e '(.reexport.closed | length) == 0 and (.reexport.failed | length) == 0' >/dev/null || fail "adoption: $(echo "$ux" | jq -c .reexport)"
    [ "$(volume "$pid1" | jq -r .client)" = "$MYIP" ] || fail "after restart $pid1 is fenced to $(volume "$pid1" | jq -r .client)"
    [ "$(lvs --noheadings -o lv_tags "$VG/$pid1" | tr -d ' ' | tr ',' '\n' | grep -c "^abe_client=$MYIP$")" = 1 ] || fail "abe_client tag not written back"
    fenced "$MYIP" "$pp1" || fail "fence lacks $MYIP . $pp1 after adoption"
    marker "$pdev" "adopted"; readback "$pdev" "adopted" || fail "write/read after adoption"
    journalctl -u abe -b --since "-2min" --no-pager -q 2>/dev/null | grep -q "adopted $MYIP for $pid1 on $pp1" || echo "  note: no 'adopted' line in the journal (fine if journalctl is unavailable)"
    disconnect "$pid1"; del "$pid1"
    # an unconnected one without a tag stays closed until GET /id
    p2=$(mk "bytes=$((32<<20))&raw=true")
    pid2=$(echo "$p2" | jq -r .id); pp2=$(echo "$p2" | jq -r .port)
    lvchange --deltag "abe_client=$MYIP" "$VG/$pid2" >/dev/null || fail "lvchange --deltag"
    systemctl restart abe; wait_api
    ux=$($CURL -sf "$URL/utilization")
    echo "$ux" | jq -e --arg id "$pid2" '(.reexport.closed | index($id)) != null' >/dev/null || fail "$pid2 not in reexport.closed: $(echo "$ux" | jq -c .reexport)"
    echo "$ux" | jq -e '.warnings | map(select(test("closed until attached again"))) | length == 1' >/dev/null || fail "no closed-ports warning: $(echo "$ux" | jq -c .warnings)"
    [ "$(volume "$pid2" | jq -r .client)" = null ] || fail "$pid2 has a client while closed"
    ! fenced "$MYIP" "$pp2" || fail "closed port $pp2 is in the fence"
    refused "$pid2" "$pp2" || fail "nvme connect to the closed port $pp2 succeeded"
    g=$($CURL -sf "$URL/id/$pid2") || fail "GET /id/$pid2"
    [ "$(echo "$g" | jq -r .client)" = "$MYIP" ] || fail "GET /id did not reopen $pp2 to $MYIP: $g"
    fenced "$MYIP" "$pp2" || fail "fence lacks $MYIP . $pp2 after GET /id"
    pdev=$(connect "$pid2" "$pp2"); disconnect "$pid2"
    del "$pid2"
    pass "adoption: connected $pid1 adopted on restart; idle $pid2 closed, reopened by GET /id"
else
    skip "adoption (no local abe.service)"
fi

# ---- 14. GET /reexport rebuilds the fence --------------------------------

q1=$(mk "bytes=$((32<<20))&raw=true"); q2=$(mk "bytes=$((32<<20))&raw=true")
qid1=$(echo "$q1" | jq -r .id); qp1=$(echo "$q1" | jq -r .port)
qid2=$(echo "$q2" | jq -r .id); qp2=$(echo "$q2" | jq -r .port)
nft destroy table inet abe
! nft list table inet abe >/dev/null 2>&1 || fail "table still there after destroy"
rx=$($CURL -sf "$URL/reexport") || fail "GET /reexport"
echo "$rx" | jq -e '.already >= 2 and (.failed | length) == 0 and (.closed | length) == 0' >/dev/null || fail "reexport after destroy: $rx"
nft list table inet abe >/dev/null 2>&1 || fail "GET /reexport did not bring the table back"
for p in $qp1 $qp2; do fenced "$MYIP" "$p" || fail "rebuilt fence lacks $MYIP . $p"; done
n=$($CURL -sf "$URL/volumes" | jq '[.[] | select(.port != null)] | length')
[ "$(nft -j list set inet abe allowed | jq '[.nftables[].set.elem // [] | .[]] | length')" = "$n" ] || fail "fence has $(nft -j list set inet abe allowed | jq -c '[.nftables[].set.elem // [] | .[]]') for $n exported volumes"
qdev=$(connect "$qid1" "$qp1"); disconnect "$qid1"
del "$qid1"; del "$qid2"
pass "GET /reexport rebuilt the fence with every exported port"

echo "all passed"
