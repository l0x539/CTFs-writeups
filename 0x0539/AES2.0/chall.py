import sys
import string

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

def gks(l, state,  A, B):
	ks = ""
	gen = PRNG(state,A,B)
	for x in range((l / 2)+1):
		ks += hex(gen.next())[2:].rjust(4,"0")
	return ks.decode('hex')[:l]

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

def main():
	if len(sys.argv) == 2:
		f = open(sys.argv[1],"rb").read()
		k = gks(len(f))
		enc = e(f,k)
		open(sys.argv[1]+".enc", "wb").write(enc)
	else:
		print "Usage: python chall.py image.jpeg"

if __name__ == '__main__':
	main()
