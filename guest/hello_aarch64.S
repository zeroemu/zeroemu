// Smallest possible Linux arm64 program: write(1, msg, len); exit(0).
    .global _start
    .text
_start:
    mov x0, #1
    adr x1, msg
    mov x2, #(msg_end - msg)
    mov x8, #64         // write
    svc #0
    mov x0, #0
    mov x8, #94         // exit_group
    svc #0
msg:
    .ascii "hello from a Linux arm64 binary, running with no kernel\n"
msg_end:
