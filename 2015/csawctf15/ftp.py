#!/usr/bin/python
import sys
import string
from z3 import *

ceiling = string.atoi(sys.argv[1])
array = [ BitVec('a%i'%i,32) for i in range(0,ceiling)]
m = BitVec('m',32)
s = Solver()
s.add(m == 0xffffffff)

y = BitVec('y',32)

for i in range(0,ceiling):
    s.add(array[i] <= 126)
    s.add(array[i] >= 32)

s.add(y==(33*(5381)+array[0]))
for i in range(1,ceiling):
  y = 33*y+array[i]
s.add((y*33)&m==0xd386d1ff)

print s.check()
print s.model()

'''
jwang@avantgarde:~/Documents/csaw15$ for i in eq 1 8 do python ftp.py $i; done
<snipped>
sat
[a4 = 40,
 a3 = 76,
 a1 = 111,
 a2 = 112,
 a0 = 99,
 a5 = 68,
 y = 177672,
 m = 4294967295]
sat
[a4 = 78,
 a3 = 34,
 a1 = 70,
 a6 = 51,
 a2 = 93,
 a0 = 124,
 a5 = 120,
 y = 177697,
 m = 4294967295]
sat
[a3 = 87,
 a5 = 81,
 a6 = 53,
 a0 = 97,
 a1 = 77,
 a7 = 114,
 a2 = 86,
 a4 = 103,
 y = 177670,
 m = 4294967295]


USER blankwall
PASS copL(D
RDF
flag{n0_c0ok1e_ju$t_a_f1ag_f0r_you}
'''
