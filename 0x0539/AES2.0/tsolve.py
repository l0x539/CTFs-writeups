import time
from chall import d, gks


with open("flag.jpeg.enc", "rb") as f:
    data = f.read()
    f.close()

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

class dPRNG:
        def __init__(self,state,A,B):
            self.s0 = 0
            self.si = state
            self.A = A
            self.B = B
            self.m = 0xfff1

        def next(self):
            if self.s0 == 0:
                self.s0 = 1
                return self.si
            ni = ((self.A * self.si + self.B) + 1337)  % self.m
            self.si = ni
            return ni

def dgks(l, state,  A, B):
        ks = ""
        gen = dPRNG(state,A,B)
        for x in range((l / 2)+1):
                ks += hex(gen.next())[2:].rjust(4,"0")
        return ks.decode('hex')[:l]

state1 = 0xffd8^0xec2b
state2 = 0xffe0^0xdcc2
state3 = 0x0010^0xc0a7
state4 = 0x4a46^0x6534
state5 = 0x4946^0xb550
m = 0xfff1


A = 0x8205
B = 0xbc1d

k = dgks(len(data), state1, A, B)

decs = d(data,k)
with open("flag.jpeg", "wb") as f:
    f.write(decs)
    f.close()

exit()
# (A * state1 + B + 1337) % m == STATE2
# (A * state4 + B + 1337) % m == STATE5
#  A * state1 + B + 1337 = state2 + n * 0xFFF1


#  A * 0x13f3 + B + 1337 = 0x2322 + n(i) * 0xFFF1    # eq1
#  A * 0x2f72 + B + 1337 = 0xfc16 + n(i+1) * 0xFFF1    # eq2
#  A * 0xc0b7 + B + 1337 = 0x2f72 + n(i+3) * 0xFFF1    # eq3



# A = (invmod(state5)-invmod(state2))/(state4-state1)
# A = (range() - range())/(state4-state1)

# find state5

T = time.time()
for i in range(0x10000):
    print "\r " + str(time.time()-T),
    T = time.time()
    for j in range(0x10000):
        k = gks(10, state1, i, j)
        p = d(data[10], k)
        if "JFIF" in p:
            print("Found!")
            print(i, j)
            exit()





exit()
i = 0
STATE5 = state5
while 1:
    STATE5 = STATE5+(i*m)
    if STATE5%(state4-state1) == 0:

        print("Found state5!")
        STATE5 = ()
        break
    sys.write("\r" + str(hex(STATE5)))
i=0
STATE2 = state2
while 1:
    STATE2 = STATE2+(i*m)
    if STATE2%(state4-state1) == 0:
        print("Found state2!")
        break

print("calculating")

A = (STATE5-STATE2)/(state4-state1)
B = STATE2 - (A*state1 + 1337)

print("A", A, "B", B)

kal = 0
c = data


