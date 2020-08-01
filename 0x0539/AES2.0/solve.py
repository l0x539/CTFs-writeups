import time
from binascii import hexlify

def egcd(a, b):
    if a==0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b//a), y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("Mod does not exist")
    return x%m

class PRNG:
        def __init__(self,state,A,B):
                self.si = state
                self.A = A
                self.B = B
                self.m = 0xfff1

        def next(self):
                ni = ((self.A * self.si + self.B) + 1337)  % self.m
                self.si = ni
                return ni

state1 = 0xffd8^0xec2b
state2 = 0xffe0^0xdcc2
state4 = 0x6534^0x4a46
state5 = 0x4946^0xb550

m = 0xfff1

# state1 * A + B + 1337 = modinv(state2, m)
# state4 * A + B + 1337 = modinv(state5, m)

#A = (state1-state4)/(state2-state5)
'''
for i in range(0x100):
    state2 = (0xff00+i)^0xdcc2
    A = (state1-state4)/(modinv(state2,m)-modinv(state5, m))
    if A-int(A) == 0:
        print(A, state2)


for i in range(0xFFF1):
    for j in range(0xFFF1):
        A = (state1-state4)/((state2+(i*m))-(state5+(j*m)))
        if A-int(A) == 0:
            print(A)
'''
#print(A)
#B = modinv(state2, m) - state1*A - 1337
#print()
#with open

def xor(a, b):
    e = []
    for i in range(len(a)):
        e.append(a[i]^b[i])
    return e

# gen  = PRNG(0x1123, A=0x4321, B=0xA432)
# gen2 = PRNG(0x4B5F, A=0x4321, B=0xA432)

# encrypt
[((0x4321 * 0x1123 + 0xA432) + 1337) % 0xFFF1, ((0x4321 * 0x4B5F + 0xA432) + 1337) % 0xFFF1, ((0x4321 * 0x6635 + 0xA432) + 1337) % 0xFFF1, ((0x4321 * 0x4761 + 0xA432) + 1337) % 0xFFF1, ((0x4321 * 0x58c3 + 0xA432) + 1337) % 0xFFF1]
k = [0x4b5f, 0x6635, 0x4761, 0x58c3, 0x80c6] #

p = [0x4142, 0x6162, 0xB539, 0xDEAD, 0xBEEF] # [known, known, uknown, known, known]

e = xor(p, k)

e = [0xa1d, 0x757, 0xf258, 0x866e, 0x3e29]

# solve

print("[-] We don't know the key:")

print("[+] Discorvered bytes [0x4142, 0x6162, XXXX, 0xDEAD, 0xBEEF]")

print("[/] Calculating A and B")

state1 = 0xa1d^0x4142
state2 = 0x757^0x6162
state4 = 0x866E^0xDEAD
state5 = 0x3e29^0xBEEF
m      = 0xFFF1

# (A * state1 + B + 1337) % m == state2
# (A * state4 + B + 1337) % m == state5
# 
'''
kal = 0
A = (state1-state4)/(state2-state5)
d = time.time()-1
print("[+] Resolving Calculation validity...")
A_solves = 0

for i in range(0xFFF1-1337):
    for j in range(0xFFF1-1337-i):
        A = (state1-state4)/((state2+(i*m))-(state5+(j*m)))
        if A-int(A) == 0:
            A_solves += 1
            print()
            print(A)
            if A == 0x4321:
                break
    if time.time()-d >= 1:
        d= time.time()
        bslash = "\\"
        print("\r"+f"[{'/' if kal == 0 else '-' if kal == 1 else bslash if kal == 2 else '|' }]", i, j, end="\r")
        kal += 1
        kal = kal if kal < 4 else 0

B = state2 - (A * state1 +1337)

print(f"[{'+' if A==0x4321 else '-'}] A = {A} =?=> {0x4321}")
print(f"[{'+' if B==0xA432 else '-'}] B = {B} =?=> {0xA432}")


if A != 0x4321:
    print("[-] Not sloving: wrong calculation.\nExiting...")
    exit()
'''
print("[+] Solving:")

kal = 0
d = time.time()-1
print("[+] Resolving Calculation validity...")
As = []

# (A * state1 + B + 1337) % m == state2
# (A * state4 + B + 1337) % m == state5

'''
_min2 = 1337
#_max2 = 0xFFF1 * state1
_min5 = 1337
#_max5 = 0xFFFF * state4 + 
from math import gcd

_max = gcd(state1, state4)
_min = (state1 * state4)//_max
print("state1", state1)
print("state4", state4)
print("min", _min)
print("max", _max)
for i in range(_min, _max):
    for j in range(_min, _max):
        a = (state1-state4)/((state2+(m*x1))-(state5+(m*x2)))
        if a-int(a) == 0:
            A = a
            As.append(A)
            print()
            print(A)
    if time.time()-d >= 0.2:
        d= time.time()
        bslash = "\\"
        print("\r"+f"[{'/' if kal == 0 else '-' if kal == 1 else bslash if kal == 2 else '|' }]", i, end="\r")
        kal += 1
        kal = kal if kal < 4 else 0 
'''

def e(pl,k):
        try:
                bi = ""
                res = ""
                for i in range(0,len(pl)):
                        c1 = (bin(ord(pl[i]))[2:]).rjust(8,"0")
                        c2 = (bin(ord(k[i]))[2:]).rjust(8,"0")
                        for j in range(0,8):
                                bi+=str((int(c1[j]) + int(c2[j])) % 2) # XOR
                while not bi == "":
                        b = chr(int(bi[:8].rjust(8,"0"),2))
                        bi = bi[8:]
                        res+=b
                return res
        except:
                return

def d(ct,k):
        return e(ct,k)


def gks(l, A, B):
        ks = ""
        gen = PRNG(A,state1,B)
        for x in range((l // 2)+1):
                ks += hex(gen.next())[2:].rjust(4,"0")
        return ks.decode('hex')[:l]


def reskal(kal):
    if kal == 0:
        return '/'
    elif kal == 1:
        return '-'
    elif kal == 2:
        return '\\'
    elif kal == 3:
        return '|'
    return reskal(kal%4)
    #return'/' if (kal == 0) else ('-' if kal == 1 else (bslash if kal == 2 else '|'))

import sys

with open("flag.jpeg.enc", "rb") as f:
    data = f.read()
    f.close()

state1 = 0xffd8^0xec2b
state2 = 0xffe0^0xdcc2
state4 = 0x6534^0x4a46
state5 = 0x4946^0xb550

m = 0xfff1

# (A * state1 + B + 1337) % m == state2
# (A * state4 + B + 1337) % m == state5

A = (state2-state5)/(state1-state4)

kal = 0
T = time.time()-1
c = data

for i in range(0, 0x10000):
    k = gks(15, A, state2-(A*state1+1337))
    p = d(c[:15], k)
    if 'JFIF' in str(p):
        print(hexlify(p))
        print("Found!")
        input("continue?")
        exit()
    
print("no")
exit()

for i in range(0xFF):
    B = (0xFF00+i) - (A * state1 +1337)
    k = gks(len(c), A, B)
    bslash = "\\"
    #sys.stdout.write('['+ reskal(kal) + '] Attempt N: ' + str(i))

    p = d(c, k)
    sec = p[6:10]
    if sec == "JFIF":
        print("yes")
        break

if p[6:10] != "JFIF":
    print("[-] Failed!")
    exit()

with open("jpeg_43.jpg", "rb") as f:
    sig = f.read()[:2]
    f.close()

with open("flag.jpeg", "wb") as f:
    f.write(sig+p)
    f.close()

print("[+] Decrypted!")
print("As", As)
print("sig", hexlify(sig))

