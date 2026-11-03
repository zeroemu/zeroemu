// Syscall round-trip benchmark: 1,000,000 getpid() calls, then exit(0).
    .global _start
    .text
_start:
    movz x9, #0x4240
    movk x9, #0xf, lsl #16      // 1,000,000
1:  mov x8, #172                // getpid
    svc #0
    subs x9, x9, #1
    b.ne 1b
    mov x0, #0
    mov x8, #94
    svc #0
