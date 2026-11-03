// Smallest possible Linux x86_64 program: write(1, msg, len); exit(0).
    .global _start
    .text
_start:
    mov $1, %edi
    lea msg(%rip), %rsi
    mov $(msg_end - msg), %edx
    mov $1, %eax        // write
    syscall
    xor %edi, %edi
    mov $231, %eax      // exit_group
    syscall
msg:
    .ascii "hello from a Linux x86_64 binary, running with no kernel\n"
msg_end:
