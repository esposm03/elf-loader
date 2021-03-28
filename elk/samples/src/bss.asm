        global _start

        section .text

_start:
        lea rax, [rel zero]

        xor rdi, rdi
        mov rax, 60
        syscall

        section .bss

zero:   resq 16
