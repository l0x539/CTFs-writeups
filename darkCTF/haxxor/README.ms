# haxxor from darkArmy CTF

### XOR:

```py
>>> "".join(chr(ord(x)^ord(y)) for x, y in zip(bytes.fromhex("5552415c2b3525105a4657071b3e0b5f494b034515").decode("latin-1"), "darkCTF{"*100))
"1337hack>'%lXjM$-*q.V"
>>> "".join(chr(ord(x)^ord(y)) for x, y in zip(bytes.fromhex("5552415c2b3525105a4657071b3e0b5f494b034515").decode("latin-1"), "1337hack"*100))
'darkCTF{kud0s_h4xx0r}'
```
