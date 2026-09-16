# H3C Magic NX15 (NX15V100R017) — vulnerability reports and PoCs

Findings in H3C Magic NX15 firmware **`NX15V100R017`** (internal
`NX15V100D025`), each with a full report and a runnable PoC.

| Directory | Issue | CWE | CVSS 3.1 |
|---|---|---|---|
| [`usrlist_cmdi_root_rce/`](usrlist_cmdi_root_rce/) | root command injection via `usrlist` | CWE-78 | 7.2 |
| [`usrlist_stack_overflow_dos/`](usrlist_stack_overflow_dos/) | stack buffer overflow -> denial of service | CWE-121 | 4.9 |
| [`file_write_root_rce/`](file_write_root_rce/) | `file.write` overwrites an rpcd plugin -> root RCE | CWE-73 / CWE-94 | 7.2 |
| [`importprofile_arbitrary_file_write/`](importprofile_arbitrary_file_write/) | arbitrary file write as root | CWE-73 / CWE-22 | 7.2 |

Two further hardening gaps are documented inside those reports rather than as
separate entries: the `/api/esps` body filter accepts everything except the
single-quote byte (CWE-20, 2.7), and that single quote can itself be smuggled
through as `\u0027`.

## How the primitives relate

The `usrlist` findings (`usrlist_cmdi_root_rce`, `usrlist_stack_overflow_dos`)
are delivered through `file.write` — which is **itself** a root arbitrary file
write, reported separately as `file_write_root_rce`. It is the delivery
primitive, not a prerequisite vulnerability: neither finding requires the other.

`file.write` and `importprofile` are **complementary**, not redundant:

| Capability | `file.write` | `importprofile` |
|---|---|---|
| content to arbitrary path | yes | yes |
| overwrite existing file (mode preserved) | yes | yes |
| new file with executable bit | **no** (0644) | yes (tar mode) |
| symbolic link | **no** | yes (tar `SYMTYPE`) |
| create directory | **no** | yes |
| delete file/directory | **no** | yes |

A new file created by `file.write` is 0644 and cannot be run by `file.exec`;
the same payload delivered by `importprofile` with `mode=0755` executes and
returns `uid=0(root)`.


Each directory follows the same layout:

```text
<issue>/
├── README.md      summary, reproduction, metrics
├── report/        full technical analysis
└── poc/           runnable proof of concept
```

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

## Scope and honesty notes

- The `usrlist` issues are delivered through the **authenticated**
  `/api/esps` `file.write` method. A network-reachable path
  (EasyMesh on `br0`, ethertype `0x893A`) was traced statically but is gated by
  the mesh backhaul SSID and was **not** verified end to end — no
  unauthenticated claim is made.
- The stack overflow is reported as **denial of service only**. Control-flow
  hijacking is not achievable: the accumulation buffer overlaps the `strcat`
  source, so the saved return address cannot be reached. See
  `usrlist_stack_overflow_dos/report/` for the derivation.
- The destructive test cases were reverted on the test device afterwards.

## Responsible use

These PoCs, especially `importprofile_arbitrary_file_write` and
`usrlist_stack_overflow_dos`, will disrupt the target: the former wipes the
persistent configuration layer, the latter drives a crash-restart loop that may
require a reboot to recover. Use them only against equipment you own or are
explicitly authorised to test.

## References

- Firmware download portal:
  <https://www.h3c.com/cn/Service/Document_Software/Software_Download/Consume_product/>
