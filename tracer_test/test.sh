gcc -g -o test test.c
objdump -d test > test.asm
hexdump -C test > test.bin
