# Post-auth Arbitrary File Write via `esps.system.importprofile`

## Submission Type

- Category: CVE
- Language: English
- Product: H3C Magic NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_importprofile_arbitrary_file_write_report.md`
- PoC: `poc/postauth_importprofile_arbitrary_file_write.sh`

## Classification

This issue is classified as CVE because it is an authenticated path-traversal /
arbitrary file write with **root** privileges. The `esps.system.importprofile`
RPC method extracts an attacker-supplied tar archive using
`cd / && tar -xzvf /tmp/NX15.tar.gz`, so archive member names are not constrained
to any directory. The container is validated only by a product/version string
and an MD5 checksum, both of which the attacker chooses.

## Relationship to `file.write`

`file.write` is a **simpler equivalent primitive** and is reported separately as
`../file_write_root_rce/`: it needs no archive, no validation bypass and no
`type=cfg` handling — one JSON object writes any path as root.

`importprofile` remains a distinct finding because it is the only primitive that
can express four things `file.write` cannot:

| Capability | `file.write` | `importprofile` |
|---|---|---|
| new file with **executable bit** | no (0644) | yes (tar member mode) |
| **symbolic link** | no (no such API) | yes (tar `SYMTYPE`) |
| **create directory** | no | yes |
| **delete** file/directory | no (truncate to 0 only) | yes (`rm -rvf /mnt/config/*`) |

All four were verified on the device: a script written by `file.write` to a new
path is not runnable via `file.exec`, while the same script delivered by
`importprofile` with `mode=0755` executes and returns `uid=0(root)`; a symlink
member is resolved normally when read back; and `importprofile`'s internal
`rm -rf` is the only deletion primitive available in this firmware.

The destructive `/mnt/config` behaviour described below is therefore an
`importprofile`-specific risk, not shared with `file.write`.

## Impact

- **Create or overwrite any file on the root filesystem** as root — verified by
  writing `XGCTF{}` to `/www/download/flag.txt` and reading it back over HTTP.
- **Configuration destruction**: the method also executes
  `rm -rvf /mnt/config/*`, wiping the persistent configuration layer
  (`/mnt/config` is a jffs2 mount that is copied over `/etc/config` at boot). If
  `uci -c /mnt/config commit` then succeeds, the device reboots into the
  factory / setup-wizard state, in which `/api/wizard/config` is reachable
  without authentication. This forms a self-sustaining chain:

  ```text
  importprofile (authenticated) -> wipe persistent config + set marker
    -> reboot -> factory/wizard state (factoryMode=1)
    -> /api/wizard/config reachable unauthenticated
    -> attacker can set arbitrary WAN / Wi-Fi / admin-password configuration
  ```

## Reproduction

See `report/` for the full analysis and `poc/` for a runnable script.

```bash
./poc/postauth_importprofile_arbitrary_file_write.sh http://<target> '<admin>'
# ...
# [*] NX15.cfg  369 bytes  md5=...
# {"code": 5,"message":"COMMON:Internal error"}
# [*] GET /download/flag.txt:
# XGCTF{}
```

> `curl` alone cannot build the archive, so the PoC is a short `sh` script that
> drives `curl`. The XOR obfuscation, the tar layout and the `NX15.info`
> checksum are all reproduced from the firmware.

## Metrics

```text
CWE-73   External Control of File Name or Path
CWE-22   Improper Limitation of a Pathname to a Restricted Directory
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H   (7.2)
```

## Notes

The XOR-"encryption" routine (`XOR 0x55`, self-inverse) and the archive layout
are documented in the report, so the PoC is fully reproducible. Callers should
be aware that the method has unavoidable destructive side effects on
`/mnt/config` even when the import fails.

See [`../README.md`](../README.md) for the per-product index and how the primitives relate.
