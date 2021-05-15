#!/usr/bin/env sh

# hello-dl: print data from `.so`
nasm -f elf64 dl.asm
nasm -f elf64 msg.asm
ld -shared msg.o -o libmsg.so
ld -rpath '$ORIGIN' -pie --dynamic-linker /lib/ld-linux-x86-64.so.2 dl.o libmsg.so -o ../hello-dl

mv *.so ..
rm *.o
