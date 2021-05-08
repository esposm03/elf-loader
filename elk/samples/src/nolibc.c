void _start() {
    // note: GCC inline assembly syntax is kinda funky, just go with it
    __asm__ ("movq $42,%rdi\n\t"
             "mov $60,%rax\n\t"
             "syscall");
}
