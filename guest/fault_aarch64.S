// Dereferences NULL; droidrt must report a clean guest fault, not crash.
    .global _start
    .text
_start:
    mov x0, #0
    ldr x1, [x0]
