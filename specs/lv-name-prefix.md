# ABE: prefix volume LV names with `abe-`

Status: draft, not started. Written 2026-11-15. Baseline: abe `877d01b` (0.6.1).
Intended home: `abe/specs/lv-name-prefix.md`.

## Why

ABE names each volume's logical volume after the volume **id** — a bare 32-hex
string like `1d402652ee62489e99dac9b643b89894`. In `lvs` output these are
indistinguishable from any other LV in the VG, and from the thin pool, bases
(`base-<image>`) and anything else that shares the group. We want every ABE
*volume* LV to carry an `abe-` prefix — `abe-1d402652…` — so they are obvious at
a glance and safe to select with `lvs | grep '^  abe-'`.

## The rule everything follows from

**The volume id stays the one identifier ABE exposes; only the on-disk LV name
changes.** The id remains the NVMe NQN, the namespace `device_uuid` (hence
`/dev/disk/by-id/nvme-uuid.<id>`), the HTTP API id, and the value held in
`Lv.name` throughout the code. The LV on disk becomes `abe-<id>`. Nothing that
compares, tags, or looks up by id has to change — comparability is preserved
because the in-memory id is untouched; `lvs | sed 's/^  abe-//'` maps 1:1 back.

Bases keep their own `base-<image>` names (already distinct); the thin pool and
any non-volume LV are untouched.

## Design (two helpers + one parse tweak)

1. **`fn lv_of(name: &str) -> String`** — the on-disk LV name for a logical
   name: `if is_volume_id(name) { format!("abe-{name}") } else { name.into() }`.
   Volume ids get the prefix; `base-<image>` and everything else pass through.

2. **Route the path builders through it.** Two functions already centralise most
   references:
   - `lv_path_for_uuid(name)` — the `/dev/<vg>/<lv>` device path. Change it to
     `format!("/dev/{}/{}", vg_name(), lv_of(name))`.
   - add **`fn vg_lv(name) -> String`** = `format!("{}/{}", vg_name(), lv_of(name))`
     for the `"<vg>/<lv>"` arguments `lvchange`/`lvremove`/`lvcreate -s` take, and
     replace the inline `format!("{}/{id}", vg_name())` sites with it.

3. **`parse_lvs`: strip the prefix on read.** `name = f[0].strip_prefix("abe-")
   .filter(|s| is_volume_id(s)).unwrap_or(f[0])`. So `Lv.name` is the bare id
   again for volumes, and `base-*`/pool/thin are left exactly as-is. Everything
   downstream (`is_volume_id`, `l.name == id`, `find_tagged`, tag lookups) keeps
   working unchanged.

`is_volume_id` is unchanged — it validates the 32-hex id, which is what
`Lv.name` still holds.

## Call sites to convert (all via the two helpers)

- `create_lv` — the `-n <name>` on `lvcreate` (thick and thin).
- the clone path — `lvcreate -s -n <name> <vg>/<origin>` (both the new name and
  the origin, which may be a base).
- `lvremove` — normal delete and the failed-create cleanup.
- `lvchange` — re-export activation (`-ay`) and the tag edits.
- the GPT/parted calls and the device path returned to the caller
  (`lv_path_for_uuid`).

Explicitly **not** touched: the NVMe subsystem name / NQN, the namespace
`device_uuid` and `by-id` wiring, the API ids, the tags themselves.

## Tests

- Unit: `lv_of` (`<id>` → `abe-<id>`, `base-x` → `base-x`, pool name → unchanged);
  `parse_lvs` round-trips a line named `abe-<id>` back to `Lv.name == <id>` and
  leaves `base-<image>` and the pool as-is.
- `cargo test` green, rustfmt clean, `tests/lint-links.sh` green.
- `make e2e` (two fake-free LVM path) and a manual create → export → connect →
  delete on the box, confirming the LV shows as `abe-<id>` while the initiator
  still sees `/dev/disk/by-id/nvme-uuid.<id>`.

## Migration (required)

Existing volumes are bare `<id>` LVs; the new code looks for `abe-<id>`. On
upgrade, rename them once, idempotently and volumes-only:

```sh
vg=abe   # ABE_VG
lvs --noheadings -o lv_name "$vg" | awk '{print $1}' | while read lv; do
  case "$lv" in
    abe-*) ;;                                   # already done
    *) [ "${#lv}" -eq 32 ] && echo "$lv" | grep -qiE '^[0-9a-f]{32}$' \
         && lvrename "$vg/$lv" "$vg/abe-$lv" ;;  # only 32-hex volume LVs
  esac
done
```

Ship it as a packaged step (postinst or a `abe migrate-lv-names` subcommand) so
it runs before the new daemon starts. Bases and the pool are left alone. A
volume that is currently exported should be unexported (or the box drained)
first, since `lvrename` needs the LV not held open — fold this into the ordering
note when building it.

## Out of scope

- Prefixing bases (`base-<image>` stays) or the thin pool.
- Changing the NVMe id / NQN / `by-id` surface in any way.
- Any on-wire or API change — this is purely cosmetic at the LVM layer.

## Things to settle before building

1. **Exported volumes during migration.** `lvrename` fails on an open LV. Decide
   between draining the host, or unexport→rename→re-export per volume in the
   migration step.
2. **Who owns the migration.** `.deb` postinst vs. an explicit `abe` subcommand
   the operator runs. Postinst is automatic but runs as the package installs,
   possibly while volumes are live.
3. **`ABE_VG` other than `abe`.** The helper uses `vg_name()`, so it already
   follows `ABE_VG`; confirm the migration script reads the same.
