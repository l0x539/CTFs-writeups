# roprop writeup From DarkCTF

Leaking libc addresses using a buffer offer from the plt.got table, jumping back to main, then executing one_gadget.

## notes:

Had to use a one gadget `execve` remotely on libc.

## how?

After leaking two addresses, we can determine the libc version from: [libc databases](https://libc.blukat.me/).

## exploit:

python script using pwntools.
