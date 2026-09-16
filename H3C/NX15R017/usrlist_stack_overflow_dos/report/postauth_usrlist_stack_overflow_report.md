# Post-auth Denial of Service via `usrlist` stack buffer overflow

- **Vendor / Product**: H3C / Magic NX15
- **Affected version**: `NX15V100R017` (internal `NX15V100D025`)
- **Vulnerability type**: Stack-based Buffer Overflow (CWE-121)
- **Privilege required**: authenticated administrator
- **Impact**: persistent denial of service (crash-restart loop)
- **CVSS 3.1**: `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H` = **4.9**

---

## 1. Root cause

`/usr/bin/usrlist`, function `sub_416874` (`0x416874`–`0x416E9C`):

```c
char v8[1024];                                           // [sp+30h]  stack buffer
...
while ( fgets(v10, 1024, v5) != 0 )
{
    v10[strlen(v10) - 1] = 0;
    if ( i == 1 ) strncpy(v8, v10, 1023);
    else          strcat(v8, v10);                       // 0x00416c28  unbounded
    *(_WORD *)&v8[strlen(v8)] = 124;                     // +2 bytes per line
    memset(v10, 0, sizeof(v10));                         // see §3 — this is why
}
```

Accumulated length is `sum(line lengths) + 2 * (lines - 1)`. Neither the line
count nor the line length is bounded, so any file whose lines sum past 1024
bytes overflows `v8` and overwrites saved stack data.

## 2. No hardening

Compared against every other H3C binary in the same firmware:

```text
usr/bin/usrlist      __stack_chk_fail : ABSENT     __*_chk (FORTIFY) : ABSENT
reference set:
  www/api, libsmartw.so, esps_wifi, smartnet, magiclink, edc,
  onlineupdate, ddnsd, miniupnpd
                     __stack_chk_fail : PRESENT    __*_chk : PRESENT
```

`usrlist` is the only H3C binary in the image lacking both.

---

## 3. Why this is a denial of service and not RCE

This section exists because a reader will reasonably ask. The answer is a
structural property of the function.

Frame layout (literal offsets from `llvm-objdump`):

| object | frame offset | offset relative to `v8` |
|---|---|---|
| `v8[1024]` (accumulator) | `$fp+0x030` | 0 |
| `v9[256]` | `$fp+0x430` | 1024 |
| **`v10[1024]` (fgets buffer)** | **`$fp+0x530`** | **1280** |
| `v11` (line count) | `$fp+0x930` | 2304 |
| `$fp` | `$fp+0x940` | 2320 |
| **`$ra`** | **`$fp+0x944`** | **2324** |
| frame size | | 0x948 = 2376 |

`v10` is **both** the destination of `fgets` and the **source** of
`strcat(v8, v10)`. Two consequences:

1. **Length ceiling.** Once `strlen(v8) >= 1280`, `v8[1280]` *is* `v10[0]`. The
   `memset(v10, 0, 1024)` at the end of every iteration zeroes it, so on the next
   iteration `strlen(v8)` falls back to 1280 and writing resumes from there. The
   accumulation can never stably pass 1280.
2. **Source/destination overlap.** At `strlen(v8) >= 1280`, `strcat`'s
   destination region overlaps its own source. uClibc's byte-wise copy
   overwrites the bytes it is still reading, never finds a terminator, and runs
   away — crashing inside libc.

Reachable extent:

```text
max stable write offset = 1280 (ceiling) + 1023 (max single line) = 2303
plus the 2-byte '|' write            -> 2304  (low byte of v11)

$ra is at 2324  ->  20 bytes beyond anything reachable
```

**`$ra` is therefore structurally unreachable.** Any overflow large enough to
touch it must first overlap `v10`, and that overlap destroys `strcat`'s own
source.

### Observed crash signature (consistent with the reasoning)

```text
ra  = 00416c30 in usrlist[400000+21000]      <- always strcat's return address
epc = 77xxxx98 in libuClibc-0.9.33.so        <- always inside libc
type = invalid write access                  <- always a write fault
"invalid instruction fetch"                  <- 0 occurrences
```

`$ra` is never loaded from the overwritten slot, so control flow is never
hijacked.

> **Measurement caveat.** Early runs appeared to show an irregular size
> threshold (e.g. "no crash at L<=600, crash at L>=700"). That was a measurement
> artefact: `dmesg` is a ring buffer, and `procd` gives up respawning after
> enough rapid failures, so later samples reported "no process" and were misread
> as "still crashing". No threshold is claimed.

---

## 4. Trigger is automatic

```text
sub_4188E0                                uloop_timeout_set(&unk_430494, 1000)   ← 1s timer
  └─ sub_4139F8
       └─ sub_4170E0   USRLIST_Terminal_ReadMacTable
            └─ sub_416874   ← overflow
```

`/etc/init.d/usrlist` sets `procd_set_param respawn`, so the process is
restarted until procd's respawn budget is exhausted.

## 5. Observed behaviour

Before:

```text
uptime        up 43 min
usrlist PID   10244
agentlist     absent
/var/log/usrlist  543 lines
```

After writing 16 lines x 120 characters (1936 bytes):

```text
PID sequence: 10244 -> 5300 -> 5411 -> ...      (procd respawn loop)

sampling every 2.5 s:
  t+0.0s  not in process table   <- crashed
  t+2.5s  not in process table   <- crashed
  t+5.0s  PID 5411 running
  t+7.5s  PID 5411 running
  t+10.0s PID 5411 running
  t+12.5s not in process table   <- crashed

uptime still up 43 min  -> process crash, not a kernel panic
/tmp/coredump present   (core_pattern target set by /etc/init.d/usrlist)
```

After removing `/var/run/agentlist`:

```text
PID constant at 5508 for 20 s  -> recovered
```

---

## 6. Remediation

- Bounds-check every `strcat`; abort and log when the destination would be
  exceeded.
- Cap the accepted file size and line count (`v12` already carries the count and
  could be used to bound the loop).
- Build with `-fstack-protector-all` and `-D_FORTIFY_SOURCE=2`, matching the
  rest of the firmware.

## 7. References

- Firmware download portal:
  <https://www.h3c.com/cn/Service/Document_Software/Software_Download/Consume_product/>
- Companion reports for the same firmware: see the sibling
  directories of this one (each contains its own report and PoC).
