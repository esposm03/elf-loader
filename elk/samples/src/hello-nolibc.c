// This mimics libc's `exit` function, but has a different name,
// because *even* with -nostartfiles and -nodefaultlibs, and no #include
// directives, GCC will complain that `exit`, which is declared *somewhere*
// as "noreturn", does in fact return.
void ftl_exit(int code) {
    // note: in AT&T syntax, it's "mov src, dst"
    // the exact opposite of what we're used to in this series!
    // also, the "%" in register names like "%edi" needs to be 
    // escaped, that's why it's doubled as "%%"
    __asm__ (
            " \
            mov     %[code], %%edi \n\t\
            mov     $60, %%rax \n\t\
            syscall"
            : // no outputs
            : [code] "r" (code)
            );
}

void ftl_print(char *msg) {
    // this is a little ad-hoc "strlen"
    int len = 0;
    while (msg[len]) {
        len++;
    }

    __asm__ (
            " \
            mov      $1, %%rdi \n\t\
            mov      %[msg], %%rsi \n\t\
            mov      %[len], %%edx \n\t\
            mov      $1, %%rax \n\t\
            syscall"
            // outputs
            :
            // inputs
            : [msg] "r" (msg), [len] "r" (len)
            );
}

// here's our fake `main()` function
int main() {
    ftl_print("Hello from C!\n");
    return 0;
}

// and here's the *actual* entry point
void _start() {
    ftl_exit(main());
}
