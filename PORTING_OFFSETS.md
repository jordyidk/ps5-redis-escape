# Porting Offsets

This file lists the offsets that are **not derived live** and must be known or ported for each target firmware/build.

The current bundle is for PS5 Redis 3.00. Runtime addresses such as Redis eboot base, heap addresses, `B_sds`, libkernel base, and sprayed object addresses are discovered live and are not listed as port requirements.

## Redis Eboot

These are mandatory.

### CClosure Base Derivation

Used to convert the leaked Lua `CClosure.f` pointer into `eboot_base`.

```text
auxwrap_offset
```

Current 3.00:

```text
auxwrap_offset = 0xB56D0
```

### Dispatch / Pivot Offsets

```text
dispatch_func_offsets:
  c24f0
  c1900
  c1970

dispatch_target_offset
dispatch_followup_target_offset
```

Current 3.00:

```text
c24f0 = 0xD39A0
c1900 = 0xD2E70
c1970 = 0xD2EE0

dispatch_target_offset = 0xDAB70
dispatch_followup_target_offset = 0x1CE08
```

The current wrapper uses `0xDAB70` as the dispatch target because it is Redis `memcpy` PLT.

## Redis ROP Gadgets

These are Redis-eboot-relative and must be ported.

```text
REDIS_EBOOT_POP_RDI_RET
REDIS_EBOOT_POP_RSI_RET
REDIS_EBOOT_POP_RDX_RET3
REDIS_EBOOT_POP_RCX_RET
REDIS_EBOOT_POP_RAX_RET
REDIS_EBOOT_POP_R8_PAD_RET
REDIS_EBOOT_POP_R14_RET
REDIS_EBOOT_POP_RSP_RET
REDIS_EBOOT_XCHG_ESP_EAX_RET
REDIS_EBOOT_XCHG_EDI_EAX_RET
REDIS_EBOOT_MOV_RAX_PTR_RDI_RET
REDIS_EBOOT_MOV_RAX_PTR_RAX_RET
REDIS_EBOOT_MOV_PTR_RDI_RAX_RET
REDIS_EBOOT_MOV_DWORD_PTR_RDI_EAX_RET
REDIS_EBOOT_MOV_RDI_RAX_PAD_RET
REDIS_EBOOT_MOV_RSI_RDI_TEST_EDX_POP_RBP_RET
REDIS_EBOOT_LEA_RAX_RAX_RDX8_RET
REDIS_EBOOT_ADD_RAX_RDX_RET
REDIS_EBOOT_MOV_RCX_RAX_RET
REDIS_EBOOT_JMP_RCX
REDIS_EBOOT_CALL_RAX
REDIS_EBOOT_PUSH_RAX_RET
REDIS_EBOOT_RET_IMM_BY_MOD
```

## Redis GOT Offsets

These are Redis-eboot-relative and must be ported.

```text
REDIS_EBOOT_MEMCPY_GOT
REDIS_EBOOT_GETPID_GOT
REDIS_EBOOT_GETTIMEOFDAY_GOT
REDIS_EBOOT_SEND_GOT
REDIS_EBOOT_SCENKERNELDLSYM_GOT
```

Current 3.00:

```text
memcpy GOT         = 0x125F58
getpid GOT         = 0x125FC8
gettimeofday GOT   = 0x126010
send GOT           = 0x126538
sceKernelDlsym GOT = 0x1262C8
```

## Redis PLT Offsets

These are Redis-eboot-relative and must be ported.

Needed for direct eboot PLT call modes, especially notification.

```text
REDIS_EBOOT_MEMCPY_PLT
REDIS_EBOOT_DLSYM_PLT
REDIS_EBOOT_OPEN_PLT
REDIS_EBOOT_WRITE_PLT
REDIS_EBOOT_CLOSE_PLT
REDIS_EBOOT_SEND_PLT
```

Current 3.00:

```text
memcpy PLT = 0xDAB70
dlsym PLT  = 0xDB250
open PLT   = 0xDAC60
write PLT  = 0xDAC70
close PLT  = 0xDAC80
send PLT   = 0xDB730
```

## libc Offsets

These are only required for libc-derived, wrapper, and setcontext paths.

```text
LIBC_PIVOT_MOV_RSP_RDI38_POP_RDI_RET
LIBC_MOV_R8_R14_CALL_PTR_RAX48
LIBC_POP_RDI_RET
LIBC_POP_RSI_RET
LIBC_POP_RDX_POP_RBP_RET
LIBC_MEMCPY_EXPORT
LIBC_GETPID_GOT
LIBC_GETTIMEOFDAY_GOT
LIBC_SETCONTEXT
LIBC_SAVECONTEXT
LIBC_LONGJMP
```

Current 3.00 key values:

```text
LIBC_MEMCPY_EXPORT    = 0x3AD0
LIBC_GETPID_GOT       = 0x1280C0
LIBC_GETTIMEOFDAY_GOT = 0x128198
LIBC_SETCONTEXT       = 0x412F8
```

## libkernel / libkernel_sys Export Offsets

The library bases are derived live. These export/data offsets are not.

Required for resolver and wrapper/syscall work:

```text
libkernel:
  getpid
  gettimeofday
  send
  sceKernelDlsym
  mprotect
  errno_ptr
  get_module_handle
  dynlib_dlsym
  dynlib_get_list
  self_info_ptr
  module_count
  module_active
  module_table

libkernel_sys:
  getpid
  gettimeofday
  send
  sceKernelDlsym
  mprotect
  errno_ptr
  get_module_handle
  dynlib_dlsym
  dynlib_get_list
  self_info_ptr
  module_count
  module_active
  module_table
```

Current 3.00 key values:

```text
libkernel:
  getpid          = 0x410
  gettimeofday   = 0x9D0
  send           = 0x12660
  sceKernelDlsym = 0x2FC60
  mprotect       = 0x730

libkernel_sys:
  getpid          = 0x500
  gettimeofday   = 0xBE0
  send           = 0x13270
  sceKernelDlsym = 0x30870
  mprotect       = 0x900
```

## Object / Layout Assumptions To Revalidate

These are not firmware offsets in the normal sense, but the exploit assumes them.

```text
Redis robj:
  type/encoding at +0x0
  refcount      at +0x4
  ptr           at +0x8
  robj overwrite size = 0x10

embstr inline data:
  data = robj + 19

Lua CClosure:
  printed function address corresponds to GCObject+8
  C function pointer read from object window +0x18

module pivot context:
  ctx + 0x38 -> stack pointer for current pivot shape
```


## Derived Live

These do **not** need fixed per-firmware values.

```text
Redis eboot base
libkernel base
libkernel_sys base
libc base, when using derived modes
heap base
B_sds
CClosure object addresses
sprayed raw string addresses
sidecar fd
victim robj address
layout filler result
HLL calibration register/value
```

## Minimal Port Set

For a first higher-firmware native ROP/notification smoke test, port these first:

```text
auxwrap_offset
dispatch c24f0 offset
dispatch target offset
dispatch followup offset
Redis ROP gadgets
Redis open/write/close/send/memcpy GOT/PLT offsets
```

For libkernel/syscall work, add:

```text
Redis getpid/gettimeofday/sceKernelDlsym GOT offsets
libkernel/libkernel_sys export offsets
libc GOT/export offsets if using libc-derived wrappers
```
