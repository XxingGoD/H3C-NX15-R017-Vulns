# H3C Magic NX15 — vulnerability research

Reports and proof-of-concept code for vulnerabilities found in **H3C Magic NX15**
firmware **`NX15V100R017`**.

## Reports

| Issue | Type | CWE | CVSS 3.1 |
|---|---|---|---|
| [`usrlist` command injection](H3C/NX15R017/usrlist_cmdi_root_rce/) | root command execution via `/usr/bin/usrlist` | CWE-78 | 7.2 |
| [`file.write` → rpcd plugin overwrite](H3C/NX15R017/file_write_root_rce/) | root code execution via the `file.write` RPC path | CWE-73 / CWE-94 | 7.2 |
| [`importprofile` arbitrary file write](H3C/NX15R017/importprofile_arbitrary_file_write/) | root arbitrary file write via tar extraction | CWE-73 / CWE-22 | 7.2 |
| [`usrlist` stack overflow](H3C/NX15R017/usrlist_stack_overflow_dos/) | denial of service (crash-restart loop) | CWE-121 | 4.9 |

Two further hardening gaps are documented inside those reports rather than as
separate entries: the `/api/esps` body filter accepts everything except the
single-quote byte (CWE-20, 2.7), and that byte can itself be smuggled through as
`\u0027`.

Each directory follows the same layout:

```text
<issue>/
├── README.md      summary, reproduction, metrics
├── report/        full technical analysis
└── poc/           runnable proof of concept
```

Start at [`H3C/NX15R017/`](H3C/NX15R017/) for the per-product index, which also
explains how the primitives relate.

## Sample

| Item | Value |
|---|---|
| Firmware | `NX15V100R017` (`softwareverinternal=NX15V100D025`) |
| SoC / SDK | Realtek RTL819xD v1.0 / Realtek SDK v3.4.14-r21961 |
| Architecture | MIPS32 Release 2, little endian, o32, uClibc 0.9.33 |
| Kernel | Linux 4.4.176-svn22943 |

```text
firmware image    a46ce7e8db354f1ad19629074a7a216663a046f5996e5d9020a8fed67c2d6f4b
usr/bin/usrlist   16f1ce7ca0aaed47cc81ba3185550acd16c9724fe4fdb9990c18c9de6c4b721a
```

## How the primitives relate

The `usrlist` findings are delivered through `file.write` — which is **itself** a
root arbitrary file write, reported separately. It is the delivery primitive,
not a prerequisite vulnerability: neither finding requires the other.

`file.write` and `importprofile` are **complementary**, not redundant:

| Capability | `file.write` | `importprofile` |
|---|---|---|
| content to arbitrary path | yes | yes |
| overwrite existing file (mode preserved) | yes | yes |
| new file with executable bit | **no** (0644) | yes (tar mode) |
| symbolic link | **no** | yes (tar `SYMTYPE`) |
| create directory | **no** | yes |

A new file created by `file.write` is 0644 and cannot be run by `file.exec`; the
same payload delivered by `importprofile` with `mode=0755` executes and returns
`uid=0(root)`.

`importprofile` adds no delete primitive: its two `rm` calls are the feature's
own fixed-path / temp-file housekeeping, not attacker-controlled deletion.

## Scope and honesty notes

- All findings require an administrator session (`/api/esps` and `/api/upload`
  sit behind `FCGI_UserAuth`). CVSS uses `PR:H`, not `PR:L` — administrator
  access is significant control under the CVSS 3.1 specification. The value
  matches what was accepted for other `NX15V100R017` CVEs.
- A **network-reachable, unauthenticated** path to `/var/run/agentlist` was
  traced statically (EasyMesh frames on `br0`, ethertype `0x893A`) but is gated
  by the mesh backhaul SSID and was **not** verified end to end. **No
  unauthenticated claim is made.**
- The stack overflow is reported as **denial of service only**. Control-flow
  hijacking was shown to be structurally unreachable — the accumulation buffer
  overlaps the `strcat` source, so the saved return address cannot be reached
  before the function dies inside libc. The mechanism and the crash evidence are
  in that report; claiming RCE there would be unsupportable.
- `file.write` reaching `/usr/libexec/rpcd/*` is a **different code path** from
  `CVE-2026-18900` (which covers `file.exec`). As far as I can tell no CVE
  covers the `file.write` / `file.read` paths.

## Responsible use

The PoCs are real: `importprofile_arbitrary_file_write` wipes the persistent
configuration layer, and `usrlist_stack_overflow_dos` drives a crash-restart
loop that may need a reboot to recover. Use them only against equipment you own
or are explicitly authorised to test.

The destructive tests in these reports were run on my own device and reverted
afterwards; each report documents how it was restored.

## References

- Firmware download portal:
  <https://www.h3c.com/cn/Service/Document_Software/Software_Download/Consume_product/>

## License

MIT — see [LICENSE](LICENSE).
