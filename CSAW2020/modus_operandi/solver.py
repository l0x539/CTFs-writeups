#!/usr/bin/env python3

from pwn import *

p = remote("crypto.chal.csaw.io", 5001)

while 1:
    p.sendline("A"*32)
    print(p.recvuntil("Ciphertext is:  "))
    resp = p.recvline().decode("latin-1").strip()
    print(resp)
    print(p.recvuntil("ECB or CBC?"))
    if resp[:32] == resp[32:64]:
        p.sendline("ECB")
    else:
        p.sendline("CBC")
    print(p.clean())
