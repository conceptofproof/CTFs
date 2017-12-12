cipher DQ 0x47cf6d49120447e7
       DQ 0x2846fb67171be9b0
        
key1   DQ 0x0000010cffffff6c
       DQ 0x00000154ffffffdc

key2   DQ 0x000000ccffffff1c
       DQ 0x000000ecffffff57

key3   DQ 0x000000b4fffffdcc
       DQ 0x0000005cfffffdec

key4   DQ 0x0000000700000040
       DQ 0x0000008cfffffdbc

key5   DQ 0x73257b6e6f637469
       DQ 0x3b031b0100000a7d

key6   DQ 0x000000c308c48348
       DQ 0x6800732500020001

key7   DQ 0x0000000000841f0f
       DQ 0x08ec83480000c3f3

key8   DQ 0x5d415c415d5b08c4
       DQ 0x2e6690c35f415e41

key9   DQ 0xc38348dc14ff41ff
       DQ 0x8348ea75dd394801

keya   DQ 0x0000000000841f0f
       DQ 0x8944f6894cea894c

iv     DQ 0xfffe07e803fdc148
       DQ 0xdb312074ed8548ff

section .text
    global _start
_start:
    
    movdqu xmm1, [cipher]
    movdqu xmm0, [key1]
    pxor xmm1, xmm0
    
    movdqu xmm0, [key2]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [key3]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [key4]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [key5]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [key6]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [key7]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [key8]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [key9]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [keya]
    AESIMC xmm0, xmm0
    aesdec xmm1, xmm0
    
    movdqu xmm0, [iv]
    aesdeclast xmm1, xmm0
    
    int3


; gdb-peda$ p $xmm1.uint128
; $1 = 0x214449646c6975425f6e695f65646f63
; python -c 'print "".join(reversed("214449646c6975425f6e695f65646f63".decode("hex")))'
code_in_BuildID!
